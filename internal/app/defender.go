package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	defaultThrottleRetryDelay = 30 * time.Second
	maxThrottleRetryDelay     = 15 * time.Minute
)

var queryRetrySecondsPattern = regexp.MustCompile(`(?i)(?:run queries again in|retry (?:again )?in|retry after)\s+(\d+)\s*seconds?`)

type queryResponse struct {
	Schema  []queryColumn    `json:"Schema"`
	Results []map[string]any `json:"Results"`
	Stats   map[string]any   `json:"Stats"`
}

type queryColumn struct {
	Name string `json:"Name"`
	Type string `json:"Type"`
}

type advancedQueryError struct {
	StatusCode int
	Status     string
	Body       string
}

func (e *advancedQueryError) Error() string {
	return fmt.Sprintf("advanced query failed: %s: %s", e.Status, e.Body)
}

func runAdvancedQuery(ctx context.Context, httpClient *http.Client, endpoint, token, query string) ([]byte, queryResponse, error) {
	return runAdvancedQueryWithProgress(ctx, httpClient, endpoint, token, query, nil)
}

func runAdvancedQueryWithProgress(ctx context.Context, httpClient *http.Client, endpoint, token, query string, progress io.Writer) ([]byte, queryResponse, error) {
	requestBody, err := json.Marshal(map[string]string{"Query": query})
	if err != nil {
		return nil, queryResponse{}, fmt.Errorf("encode query request: %w", err)
	}

	url := endpoint + "/security/runHuntingQuery"
	throttleCount := 0
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(requestBody))
		if err != nil {
			return nil, queryResponse{}, fmt.Errorf("build query request: %w", err)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")

		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, queryResponse{}, fmt.Errorf("run advanced query: %w", err)
		}

		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			return nil, queryResponse{}, fmt.Errorf("read query response: %w", readErr)
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			throttleCount++
			delay := advancedQueryRetryDelay(resp.Header, body, throttleCount, time.Now())
			progressf(progress, "[!] advanced query throttled (429); waiting %s before retrying", delay)
			if err := waitForAdvancedQueryRetry(ctx, delay); err != nil {
				return nil, queryResponse{}, fmt.Errorf("wait to retry advanced query: %w", err)
			}
			continue
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, queryResponse{}, &advancedQueryError{
				StatusCode: resp.StatusCode,
				Status:     resp.Status,
				Body:       strings.TrimSpace(string(body)),
			}
		}

		parsed, err := parseQueryResponse(body)
		if err != nil {
			return nil, queryResponse{}, fmt.Errorf("decode query response: %w", err)
		}

		return body, parsed, nil
	}
}

func advancedQueryRetryDelay(header http.Header, body []byte, throttleCount int, now time.Time) time.Duration {
	if retryAfter := strings.TrimSpace(header.Get("Retry-After")); retryAfter != "" {
		if seconds, err := strconv.ParseInt(retryAfter, 10, 64); err == nil && seconds >= 0 {
			return time.Duration(seconds) * time.Second
		}
		if retryAt, err := http.ParseTime(retryAfter); err == nil {
			if delay := retryAt.Sub(now); delay > 0 {
				return delay
			}
			return 0
		}
	}

	if matches := queryRetrySecondsPattern.FindSubmatch(body); len(matches) == 2 {
		if seconds, err := strconv.ParseInt(string(matches[1]), 10, 64); err == nil {
			return time.Duration(seconds) * time.Second
		}
	}

	delay := defaultThrottleRetryDelay
	for attempt := 1; attempt < throttleCount && delay < maxThrottleRetryDelay; attempt++ {
		delay *= 2
	}
	if delay > maxThrottleRetryDelay {
		return maxThrottleRetryDelay
	}
	return delay
}

func waitForAdvancedQueryRetry(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	}

	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func parseQueryResponse(body []byte) (queryResponse, error) {
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return queryResponse{}, err
	}

	return queryResponse{
		Schema:  parseQueryColumns(lookupAny(payload, "Schema", "schema")),
		Results: parseQueryRows(lookupAny(payload, "Results", "results")),
		Stats:   parseStringAnyMap(lookupAny(payload, "Stats", "stats")),
	}, nil
}

func marshalQueryResponse(response queryResponse) ([]byte, error) {
	payload := map[string]any{
		"Schema":  response.Schema,
		"Results": response.Results,
	}
	if response.Stats != nil {
		payload["Stats"] = response.Stats
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode query response: %w", err)
	}
	return body, nil
}
