package app

import (
	"context"
	"errors"
	"io"
	"net/http"
	"regexp"
)

const (
	sourceDefender     = "defender"
	sourceLogAnalytics = "loganalytics"
)

// querySource runs KQL against one data service. Counting, partitioning,
// pseudonymization, and export are shared by every source.
type querySource interface {
	RunQuery(ctx context.Context, query string, progress io.Writer) (queryResponse, error)
	// IsResultSizeExceeded reports a service limit that a smaller query can avoid.
	IsResultSizeExceeded(err error) bool
	// IsTableNotFound reports a semantic error that the named table does not exist.
	IsTableNotFound(err error, table string) bool
}

func newQuerySource(ctx context.Context, httpClient *http.Client, cfg config) (querySource, string, error) {
	switch cfg.Source {
	case sourceLogAnalytics:
		token, authMode, err := acquireToken(ctx, httpClient, logAnalyticsAuthConfig(cfg))
		if err != nil {
			return nil, "", err
		}
		return &logAnalyticsSource{httpClient: httpClient, endpoint: cfg.LogAnalyticsEndpoint, workspaceID: cfg.WorkspaceID, token: token}, authMode, nil
	default:
		token, authMode, err := acquireToken(ctx, httpClient, mdeAuthConfig(cfg))
		if err != nil {
			return nil, "", err
		}
		return newDefenderQuerySource(httpClient, cfg.Endpoint, token), authMode, nil
	}
}

type defenderQuerySource struct {
	httpClient *http.Client
	endpoint   string
	token      string
}

func newDefenderQuerySource(httpClient *http.Client, endpoint, token string) *defenderQuerySource {
	return &defenderQuerySource{httpClient: httpClient, endpoint: endpoint, token: token}
}

func (s *defenderQuerySource) RunQuery(ctx context.Context, query string, progress io.Writer) (queryResponse, error) {
	_, response, err := runAdvancedQueryWithProgress(ctx, s.httpClient, s.endpoint, s.token, query, progress)
	return response, err
}

func (s *defenderQuerySource) IsResultSizeExceeded(err error) bool {
	return isQueryResultSizeExceeded(err)
}

func (s *defenderQuerySource) IsTableNotFound(err error, table string) bool {
	var queryErr *advancedQueryError
	return errors.As(err, &queryErr) && queryErr.StatusCode == http.StatusBadRequest && kustoErrorNamesMissingTable(queryErr.Body, table)
}

var kustoUnresolvedExpressionPattern = regexp.MustCompile(`(?i)failed to resolve (?:table|table or column) expression named '([^']+)'`)

// kustoErrorNamesMissingTable matches the Kusto semantic error raised when a
// tabular expression cannot be resolved, and only for the requested table so
// a missing column or a different table is never reported as an absent table.
func kustoErrorNamesMissingTable(body, table string) bool {
	if table == "" {
		return false
	}
	for _, match := range kustoUnresolvedExpressionPattern.FindAllStringSubmatch(body, -1) {
		if match[1] == table {
			return true
		}
	}
	return false
}
