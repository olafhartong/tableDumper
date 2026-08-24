package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type queryResponse struct {
	Schema  []queryColumn    `json:"Schema"`
	Results []map[string]any `json:"Results"`
	Stats   map[string]any   `json:"Stats"`
}

type queryColumn struct {
	Name string `json:"Name"`
	Type string `json:"Type"`
}

func runAdvancedQuery(ctx context.Context, httpClient *http.Client, endpoint, token, query string) ([]byte, queryResponse, error) {
	requestBody, err := json.Marshal(map[string]string{"Query": query})
	if err != nil {
		return nil, queryResponse{}, fmt.Errorf("encode query request: %w", err)
	}

	url := endpoint + "/security/runHuntingQuery"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(requestBody))
	if err != nil {
		return nil, queryResponse{}, fmt.Errorf("build query request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, queryResponse{}, fmt.Errorf("run advanced query: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, queryResponse{}, fmt.Errorf("read query response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, queryResponse{}, fmt.Errorf("advanced query failed: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	parsed, err := parseQueryResponse(body)
	if err != nil {
		return nil, queryResponse{}, fmt.Errorf("decode query response: %w", err)
	}

	return body, parsed, nil
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
