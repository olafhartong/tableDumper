package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// The query API stops a request after three minutes unless the client asks
// for more time; ten minutes is the documented maximum. The HTTP client's
// -timeout still applies.
const logAnalyticsPreferHeader = "wait=600"

type logAnalyticsSource struct {
	httpClient  *http.Client
	endpoint    string
	workspaceID string
	token       string
	timespan    string
}

type logAnalyticsQueryError struct {
	StatusCode int
	Status     string
	Body       string
}

func (e *logAnalyticsQueryError) Error() string {
	return fmt.Sprintf("log analytics query failed: %s: %s", e.Status, e.Body)
}

// logAnalyticsPartialResultError is returned when the service answers HTTP 200
// with an error object. The accompanying rows are incomplete and are discarded.
type logAnalyticsPartialResultError struct {
	Body string
}

func (e *logAnalyticsPartialResultError) Error() string {
	return fmt.Sprintf("log analytics query returned an incomplete result, which was not used: %s", e.Body)
}

type logAnalyticsResponse struct {
	Tables []logAnalyticsTable `json:"tables"`
	Error  json.RawMessage     `json:"error"`
}

type logAnalyticsTable struct {
	Name    string               `json:"name"`
	Columns []logAnalyticsColumn `json:"columns"`
	Rows    [][]any              `json:"rows"`
}

type logAnalyticsColumn struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// timespanQuerySource is implemented by sources that accept a service-side time
// range in addition to the query's own filter.
type timespanQuerySource interface {
	withTimespan(start, end time.Time) querySource
}

// withTimespan returns a copy that also sends the service-side timespan. The
// query text remains the authoritative filter.
func (s *logAnalyticsSource) withTimespan(start, end time.Time) querySource {
	copy := *s
	copy.timespan = start.UTC().Format(time.RFC3339Nano) + "/" + end.UTC().Format(time.RFC3339Nano)
	return &copy
}

func (s *logAnalyticsSource) RunQuery(ctx context.Context, query string, progress io.Writer) (queryResponse, error) {
	payload := map[string]string{"query": query}
	if s.timespan != "" {
		payload["timespan"] = s.timespan
	}
	requestBody, err := json.Marshal(payload)
	if err != nil {
		return queryResponse{}, fmt.Errorf("encode query request: %w", err)
	}

	queryURL := s.endpoint + "/workspaces/" + url.PathEscape(s.workspaceID) + "/query"
	resp, body, err := postQueryWithThrottleRetry(ctx, s.httpClient, queryURL, s.token, requestBody, map[string]string{"Prefer": logAnalyticsPreferHeader}, "Log Analytics query", progress)
	if err != nil {
		return queryResponse{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return queryResponse{}, &logAnalyticsQueryError{
			StatusCode: resp.StatusCode,
			Status:     resp.Status,
			Body:       strings.TrimSpace(string(body)),
		}
	}
	return parseLogAnalyticsResponse(body)
}

func parseLogAnalyticsResponse(body []byte) (queryResponse, error) {
	var payload logAnalyticsResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		return queryResponse{}, fmt.Errorf("decode query response: %w", err)
	}
	if len(payload.Error) > 0 && string(payload.Error) != "null" {
		return queryResponse{}, &logAnalyticsPartialResultError{Body: compactJSON(payload.Error)}
	}
	if len(payload.Tables) != 1 {
		return queryResponse{}, fmt.Errorf("decode query response: expected one result table, got %d", len(payload.Tables))
	}

	table := payload.Tables[0]
	response := queryResponse{
		Schema:  make([]queryColumn, len(table.Columns)),
		Results: make([]map[string]any, 0, len(table.Rows)),
	}
	seen := make(map[string]bool, len(table.Columns))
	for i, column := range table.Columns {
		if column.Name == "" || seen[column.Name] {
			return queryResponse{}, errors.New("decode query response: result table contains an empty or duplicate column name")
		}
		seen[column.Name] = true
		response.Schema[i] = queryColumn{Name: column.Name, Type: column.Type}
	}
	for index, values := range table.Rows {
		if len(values) != len(table.Columns) {
			return queryResponse{}, fmt.Errorf("decode query response: row %d has %d values for %d columns", index+1, len(values), len(table.Columns))
		}
		row := make(map[string]any, len(values))
		for i, value := range values {
			row[table.Columns[i].Name] = normalizeLogAnalyticsValue(table.Columns[i].Type, value)
		}
		response.Results = append(response.Results, row)
	}
	return response, nil
}

// Dynamic values arrive as JSON text. Decode objects and arrays so they are
// written, traversed, and ingested as nested values; scalars stay unchanged.
func normalizeLogAnalyticsValue(columnType string, value any) any {
	text, ok := value.(string)
	if !ok || !strings.EqualFold(columnType, "dynamic") {
		return value
	}
	if decoded, ok := decodeJSONObject(text); ok {
		return decoded
	}
	return value
}

func (s *logAnalyticsSource) IsResultSizeExceeded(err error) bool {
	var body string
	var partialErr *logAnalyticsPartialResultError
	var queryErr *logAnalyticsQueryError
	switch {
	case errors.As(err, &partialErr):
		body = partialErr.Body
	case errors.As(err, &queryErr):
		body = queryErr.Body
	default:
		return false
	}
	body = strings.ToLower(body)
	if strings.Contains(body, "e_query_result_set_too_large") {
		return true
	}
	for _, marker := range []string{"result set", "result size", "response size", "record count", "records limit", "row limit"} {
		if strings.Contains(body, marker) && (strings.Contains(body, "exceed") || strings.Contains(body, "too large") || strings.Contains(body, "limit")) {
			return true
		}
	}
	return false
}

func (s *logAnalyticsSource) IsTableNotFound(err error, table string) bool {
	var queryErr *logAnalyticsQueryError
	return errors.As(err, &queryErr) && queryErr.StatusCode == http.StatusBadRequest && kustoErrorNamesMissingTable(queryErr.Body, table)
}

// kqlTimespanDuration converts a literal accepted by isSafeKQLTimespanLiteral.
func kqlTimespanDuration(literal string) (time.Duration, error) {
	literal = strings.TrimSpace(literal)
	if !isSafeKQLTimespanLiteral(literal) {
		return 0, fmt.Errorf("invalid KQL timespan literal %q", literal)
	}
	unitStart := strings.IndexFunc(literal, func(r rune) bool { return (r < '0' || r > '9') && r != '.' })
	units := map[string]time.Duration{"d": 24 * time.Hour, "h": time.Hour, "m": time.Minute, "s": time.Second, "ms": time.Millisecond}
	number, ok := new(big.Rat).SetString(literal[:unitStart])
	if !ok {
		return 0, fmt.Errorf("invalid KQL timespan literal %q", literal)
	}
	nanoseconds := new(big.Rat).Mul(number, new(big.Rat).SetInt64(int64(units[literal[unitStart:]])))
	whole := new(big.Int).Quo(nanoseconds.Num(), nanoseconds.Denom())
	if !whole.IsInt64() {
		return 0, fmt.Errorf("KQL timespan literal %q is too large", literal)
	}
	return time.Duration(whole.Int64()), nil
}
