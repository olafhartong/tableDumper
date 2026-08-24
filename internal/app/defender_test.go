package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRunAdvancedQuery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method %s", r.Method)
		}
		if got := r.URL.Path; got != "/security/runHuntingQuery" {
			t.Fatalf("unexpected path %s", got)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer token-value" {
			t.Fatalf("unexpected authorization header %q", got)
		}

		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"schema":[{"name":"DeviceName","type":"String"}],"results":[{"DeviceName":"host1"},{"DeviceName":"host2"}]}`)
	}))
	defer server.Close()

	body, response, err := runAdvancedQuery(context.Background(), &http.Client{Timeout: 5 * time.Second}, server.URL, "token-value", "DeviceInfo | limit 2")
	if err != nil {
		t.Fatalf("runAdvancedQuery returned error: %v", err)
	}
	if len(response.Results) != 2 {
		t.Fatalf("unexpected row count %d", len(response.Results))
	}
	if len(response.Schema) != 1 {
		t.Fatalf("unexpected schema length %d", len(response.Schema))
	}
	if !strings.Contains(string(body), `"DeviceName":"host1"`) {
		t.Fatalf("unexpected body %s", string(body))
	}
}

func TestRunAdvancedQueryRetriesThrottleResponse(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		readAdvancedQueryRequest(t, r)
		attempts++
		if attempts == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			io.WriteString(w, `{"error":{"code":"CpuQuotaExceeded","message":"You have exceeded processing resources allocated to this tenant"}}`)
			return
		}
		io.WriteString(w, `{"Results":[{"DeviceName":"host1"}]}`)
	}))
	defer server.Close()

	var progress bytes.Buffer
	_, response, err := runAdvancedQueryWithProgress(context.Background(), server.Client(), server.URL, "token-value", "DeviceInfo | limit 1", &progress)
	if err != nil {
		t.Fatalf("runAdvancedQueryWithProgress returned error: %v", err)
	}
	if attempts != 2 {
		t.Fatalf("unexpected attempt count %d", attempts)
	}
	if len(response.Results) != 1 {
		t.Fatalf("unexpected response %#v", response)
	}
	if !strings.Contains(progress.String(), "[!] advanced query throttled (429); waiting 0s before retrying") {
		t.Fatalf("unexpected progress %q", progress.String())
	}
}

func TestAdvancedQueryRetryDelayUsesQuotaMessage(t *testing.T) {
	body := []byte(`{"error":{"code":"CpuQuotaExceeded","message":"You have exceeded processing resources allocated to this tenant. You can run queries again in 2871 seconds"}}`)
	if got := advancedQueryRetryDelay(nil, body, 1, time.Now()); got != 2871*time.Second {
		t.Fatalf("unexpected retry delay %s", got)
	}
}

func readAdvancedQueryRequest(t *testing.T, r *http.Request) string {
	t.Helper()
	if r.Method != http.MethodPost {
		t.Fatalf("unexpected method %s", r.Method)
	}
	if r.URL.Path != "/security/runHuntingQuery" {
		t.Fatalf("unexpected path %s", r.URL.Path)
	}
	if got := r.Header.Get("Authorization"); got != "Bearer token-value" {
		t.Fatalf("unexpected authorization header %q", got)
	}

	var payload map[string]string
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		t.Fatalf("decode query request: %v", err)
	}
	return payload["Query"]
}

func TestParseQueryResponseSupportsLegacyAndGraphShapes(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "legacy mde shape",
			body: `{"Schema":[{"Name":"DeviceName","Type":"String"}],"Results":[{"DeviceName":"host1"}]}`,
		},
		{
			name: "graph xdr shape",
			body: `{"schema":[{"name":"DeviceName","type":"String"}],"results":[{"DeviceName":"host1"}]}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, err := parseQueryResponse([]byte(tt.body))
			if err != nil {
				t.Fatalf("parseQueryResponse returned error: %v", err)
			}
			if len(response.Schema) != 1 || response.Schema[0].Name != "DeviceName" {
				t.Fatalf("unexpected schema %#v", response.Schema)
			}
			if len(response.Results) != 1 || response.Results[0]["DeviceName"] != "host1" {
				t.Fatalf("unexpected results %#v", response.Results)
			}
		})
	}
}
