package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

const testWorkspaceID = "6f1c2b9e-3a4d-4c8e-9b7a-1d2e3f405162"

type logAnalyticsTestRequest struct {
	Query    string `json:"query"`
	Timespan string `json:"timespan"`
}

// newLogAnalyticsTestServer emulates POST /v1/workspaces/{id}/query and
// records every request body.
func newLogAnalyticsTestServer(t *testing.T, handle func(w http.ResponseWriter, request logAnalyticsTestRequest)) (*httptest.Server, *[]logAnalyticsTestRequest) {
	t.Helper()
	var mu sync.Mutex
	requests := &[]logAnalyticsTestRequest{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/workspaces/"+testWorkspaceID+"/query" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Prefer"); got != "wait=600" {
			t.Errorf("unexpected Prefer header %q", got)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("unexpected Content-Type %q", got)
		}
		var request logAnalyticsTestRequest
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&request); err != nil {
			t.Errorf("decode Log Analytics request: %v", err)
		}
		mu.Lock()
		*requests = append(*requests, request)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		handle(w, request)
	}))
	t.Cleanup(server.Close)
	return server, requests
}

func logAnalyticsTableBody(t *testing.T, columns [][2]string, rows ...[]any) string {
	t.Helper()
	table := logAnalyticsTable{Name: "PrimaryResult", Columns: make([]logAnalyticsColumn, len(columns)), Rows: rows}
	for i, column := range columns {
		table.Columns[i] = logAnalyticsColumn{Name: column[0], Type: column[1]}
	}
	if table.Rows == nil {
		table.Rows = [][]any{}
	}
	body, err := json.Marshal(map[string]any{"tables": []logAnalyticsTable{table}})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

var signinColumns = [][2]string{
	{"TimeGenerated", "datetime"}, {"UserPrincipalName", "string"}, {"CorrelationId", "guid"}, {"DurationMs", "long"},
	{"IsInteractive", "bool"}, {"LocationDetails", "dynamic"}, {"ConditionalAccessPolicies", "dynamic"},
	{"Latency", "timespan"}, {"RiskScore", "decimal"}, {"ResultDescription", "string"},
}

func TestParseLogAnalyticsResponseNormalizesArrayRows(t *testing.T) {
	body := `{"tables":[{"name":"PrimaryResult","columns":[` +
		`{"name":"TimeGenerated","type":"datetime"},{"name":"UserPrincipalName","type":"string"},{"name":"CorrelationId","type":"guid"},` +
		`{"name":"DurationMs","type":"long"},{"name":"IsInteractive","type":"bool"},{"name":"LocationDetails","type":"dynamic"},` +
		`{"name":"ConditionalAccessPolicies","type":"dynamic"},{"name":"Latency","type":"timespan"},{"name":"RiskScore","type":"decimal"},` +
		`{"name":"ResultDescription","type":"string"}],"rows":[` +
		`["2026-09-01T10:15:00.1234567Z","j.doe@contoso.com","74be27de-1e4e-49d9-b579-fe0b331d3642",1234,true,"{\"city\":\"Utrecht\",\"geoCoordinates\":{\"latitude\":52.09}}","[]","00:00:10","0.10101",null],` +
		`["2026-09-01T10:16:00.9Z","bob.vance@fabrikam.com","0b3a5e2f-8c1d-4f6a-9e7b-2c4d6e8f0a1b",0,false,"\"plain dynamic string\"","[{\"id\":\"policy\"}]","00:00:00.5","1",""]]}]}`
	response, err := parseLogAnalyticsResponse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Schema) != 10 || response.Schema[0] != (queryColumn{Name: "TimeGenerated", Type: "datetime"}) || response.Schema[5].Type != "dynamic" {
		t.Fatalf("unexpected schema %#v", response.Schema)
	}
	if len(response.Results) != 2 {
		t.Fatalf("unexpected rows %#v", response.Results)
	}
	first := response.Results[0]
	if first["UserPrincipalName"] != "j.doe@contoso.com" || first["DurationMs"] != float64(1234) || first["IsInteractive"] != true || first["Latency"] != "00:00:10" || first["RiskScore"] != "0.10101" || first["ResultDescription"] != nil {
		t.Fatalf("scalar values were not preserved: %#v", first)
	}
	location, ok := first["LocationDetails"].(map[string]any)
	if !ok || location["city"] != "Utrecht" {
		t.Fatalf("dynamic object was not decoded: %#v", first["LocationDetails"])
	}
	if policies, ok := first["ConditionalAccessPolicies"].([]any); !ok || len(policies) != 0 {
		t.Fatalf("dynamic array was not decoded: %#v", first["ConditionalAccessPolicies"])
	}
	if second := response.Results[1]; second["LocationDetails"] != `"plain dynamic string"` || second["ResultDescription"] != "" {
		t.Fatalf("non-container dynamic or empty string changed: %#v", second)
	}

	// The same columns under Defender's type spelling must produce the same
	// partition key and ADX schema.
	defenderSchema := []queryColumn{{"TimeGenerated", "DateTime"}, {"UserPrincipalName", "String"}, {"CorrelationId", "Guid"}, {"DurationMs", "Int64"}, {"IsInteractive", "Boolean"}, {"LocationDetails", "Dynamic"}, {"ConditionalAccessPolicies", "Dynamic"}, {"Latency", "Timespan"}, {"RiskScore", "Decimal"}, {"ResultDescription", "String"}}
	laKey, err := newQueryPartitionKey(response.Schema)
	if err != nil {
		t.Fatal(err)
	}
	defenderKey, err := newQueryPartitionKey(defenderSchema)
	if err != nil {
		t.Fatal(err)
	}
	if laKey.expression != defenderKey.expression || strings.Contains(laKey.expression, "LocationDetails") {
		t.Fatalf("partition keys differ by source: %s versus %s", laKey.expression, defenderKey.expression)
	}
	laDefs, _ := buildADXColumnDefs(response.Schema)
	defenderDefs, _ := buildADXColumnDefs(defenderSchema)
	if fmt.Sprint(laDefs) != fmt.Sprint(defenderDefs) {
		t.Fatalf("ADX column types differ by source:\n%v\n%v", laDefs, defenderDefs)
	}
}

func TestParseLogAnalyticsResponseRejectsMalformedTables(t *testing.T) {
	for name, body := range map[string]string{
		"no tables":        `{"tables":[]}`,
		"empty body":       ``,
		"two tables":       `{"tables":[{"name":"PrimaryResult","columns":[],"rows":[]},{"name":"Other","columns":[],"rows":[]}]}`,
		"short row":        `{"tables":[{"name":"PrimaryResult","columns":[{"name":"A","type":"string"},{"name":"B","type":"string"}],"rows":[["a"]]}]}`,
		"duplicate column": `{"tables":[{"name":"PrimaryResult","columns":[{"name":"A","type":"string"},{"name":"A","type":"long"}],"rows":[]}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseLogAnalyticsResponse([]byte(body)); err == nil {
				t.Fatal("malformed response accepted")
			}
		})
	}
}

func TestLogAnalyticsTableDumpCountsThenPartitionsThroughRun(t *testing.T) {
	directory := t.TempDir()
	output := filepath.Join(directory, "signinlogs.json")
	row := func(i int) []any {
		return []any{fmt.Sprintf("2026-09-01T10:%02d:00Z", i), fmt.Sprintf("user%d@contoso.com", i), fmt.Sprintf("00000000-0000-4000-8000-00000000000%d", i), i, i%2 == 0, `{"city":"Utrecht"}`, "[]", "00:00:01", "1.5", "Success"}
	}
	server, requests := newLogAnalyticsTestServer(t, func(w http.ResponseWriter, request logAnalyticsTestRequest) {
		query := request.Query
		switch {
		case strings.HasSuffix(query, "\n| count"):
			io.WriteString(w, logAnalyticsTableBody(t, [][2]string{{"Count", "long"}}, []any{5}))
		case strings.HasSuffix(query, "\n| take 0"):
			io.WriteString(w, logAnalyticsTableBody(t, signinColumns))
		case strings.Contains(query, "| summarize Count=count() by DumpPartition="):
			io.WriteString(w, logAnalyticsTableBody(t, [][2]string{{"DumpPartition", "long"}, {"Count", "long"}}, []any{0, 2}, []any{1, 3}))
		case strings.HasSuffix(query, "% 2) == 0"):
			io.WriteString(w, logAnalyticsTableBody(t, signinColumns, row(0), row(2)))
		case strings.HasSuffix(query, "% 2) == 1"):
			io.WriteString(w, logAnalyticsTableBody(t, signinColumns, row(1), row(3), row(4)))
		default:
			t.Errorf("unexpected query %q", query)
			w.WriteHeader(http.StatusBadRequest)
		}
	})

	var stdout, stderr bytes.Buffer
	err := Run(context.Background(), []string{
		"--env-file", "", "--auth", "none", "--source", "loganalytics", "--workspace-id", testWorkspaceID,
		"--la-endpoint", server.URL + "/v1/", "--dump-table", "SigninLogs", "--dump-lookback", "1d",
		"--dump-row-limit", "4", "--output", output, "--adx-export", "--pseudonymize",
	}, nil, &stdout, &stderr)
	if err != nil {
		t.Fatalf("Run returned error: %v\n%s", err, stderr.String())
	}
	if len(*requests) != 5 {
		t.Fatalf("expected count, schema, partition count, and two downloads; got %d requests", len(*requests))
	}

	windowPattern := regexp.MustCompile(`^SigninLogs\n\| where TimeGenerated >= \(datetime\(([^)]+)\) - 1d\) and TimeGenerated < datetime\(([^)]+)\)`)
	var timespan string
	for _, request := range *requests {
		match := windowPattern.FindStringSubmatch(request.Query)
		if match == nil || match[1] != match[2] {
			t.Fatalf("query does not filter the fixed TimeGenerated window: %q", request.Query)
		}
		if timespan == "" {
			timespan = request.Timespan
		}
		if request.Timespan == "" || request.Timespan != timespan {
			t.Fatalf("every table dump request must send the same timespan, got %q and %q", timespan, request.Timespan)
		}
		end, err := time.Parse(time.RFC3339Nano, match[2])
		if err != nil {
			t.Fatal(err)
		}
		startText, endText, ok := strings.Cut(request.Timespan, "/")
		spanStart, startErr := time.Parse(time.RFC3339Nano, startText)
		spanEnd, endErr := time.Parse(time.RFC3339Nano, endText)
		if !ok || startErr != nil || endErr != nil || spanStart.After(end.Add(-24*time.Hour)) || spanEnd.Before(end) || spanEnd.Sub(spanStart) > 24*time.Hour+2*time.Second {
			t.Fatalf("timespan %q does not tightly cover the query window ending %s", request.Timespan, end)
		}
	}

	body, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var written queryResponse
	if err := json.Unmarshal(body, &written); err != nil {
		t.Fatal(err)
	}
	if len(written.Results) != 5 || len(written.Schema) != len(signinColumns) || written.Schema[0].Type != "datetime" {
		t.Fatalf("unexpected output envelope: %s", body)
	}
	if strings.Contains(string(body), "contoso.com") {
		t.Fatalf("SigninLogs UserPrincipalName was not pseudonymized: %s", body)
	}
	if _, ok := written.Results[0]["LocationDetails"].(map[string]any); !ok {
		t.Fatalf("dynamic column was written as text: %#v", written.Results[0])
	}
	dataPath, schemaPath := adxArtifactPaths(output)
	schema, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"TimeGenerated:datetime", "DurationMs:long", "IsInteractive:bool", "LocationDetails:dynamic", "CorrelationId:guid"} {
		if !strings.Contains(string(schema), want) {
			t.Fatalf("ADX schema missing %q:\n%s", want, schema)
		}
	}
	if data, err := os.ReadFile(dataPath); err != nil || bytes.Count(data, []byte("\n")) != 5 {
		t.Fatalf("unexpected ADX data file: %v\n%s", err, data)
	}
	if !strings.Contains(stdout.String(), "Dumped 5 rows from SigninLogs") {
		t.Fatalf("unexpected summary: %s", stdout.String())
	}
}

func TestLogAnalyticsTimespanOnlyFiltersTimeGeneratedDumps(t *testing.T) {
	server, requests := newLogAnalyticsTestServer(t, func(w http.ResponseWriter, request logAnalyticsTestRequest) {
		if strings.HasSuffix(request.Query, "\n| count") {
			io.WriteString(w, logAnalyticsTableBody(t, [][2]string{{"Count", "long"}}, []any{1}))
			return
		}
		io.WriteString(w, logAnalyticsTableBody(t, [][2]string{{"EventTime", "datetime"}}, []any{"2026-09-01T10:00:00Z"}))
	})
	source := &logAnalyticsSource{httpClient: server.Client(), endpoint: server.URL + "/v1", workspaceID: testWorkspaceID}
	cfg := config{Source: sourceLogAnalytics, DumpTable: "CustomEvents_CL", DumpLookback: "7d", DumpTimeColumn: "EventTime", DumpRowLimit: 10, Output: filepath.Join(t.TempDir(), "custom.json")}
	var progress bytes.Buffer
	if _, err := dumpTable(context.Background(), source, cfg, nil, &progress); err != nil {
		t.Fatal(err)
	}
	cfg.Output = filepath.Join(t.TempDir(), "query.json")
	if _, err := dumpQuery(context.Background(), source, cfg, "SigninLogs | take 1", nil, io.Discard); err != nil {
		t.Fatal(err)
	}
	for _, request := range *requests {
		if request.Timespan != "" {
			t.Fatalf("timespan %q sent for a non-TimeGenerated dump or a free-form query", request.Timespan)
		}
	}
	if !strings.Contains(progress.String(), "not sending a service timespan") {
		t.Fatalf("omitted timespan was not reported:\n%s", progress.String())
	}
}

func TestLogAnalyticsRetriesThrottledQuery(t *testing.T) {
	attempts := 0
	server, _ := newLogAnalyticsTestServer(t, func(w http.ResponseWriter, request logAnalyticsTestRequest) {
		attempts++
		if attempts == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			io.WriteString(w, `{"error":{"code":"ThrottledError","message":"Your request has been throttled"}}`)
			return
		}
		io.WriteString(w, logAnalyticsTableBody(t, [][2]string{{"Computer", "string"}}, []any{"host1"}))
	})
	source := &logAnalyticsSource{httpClient: server.Client(), endpoint: server.URL + "/v1", workspaceID: testWorkspaceID, token: "token-value"}
	var progress bytes.Buffer
	response, err := source.RunQuery(context.Background(), "Heartbeat | take 1", &progress)
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 2 || len(response.Results) != 1 || response.Results[0]["Computer"] != "host1" {
		t.Fatalf("unexpected retry result after %d attempts: %#v", attempts, response)
	}
	if !strings.Contains(progress.String(), "[!] Log Analytics query throttled (429); waiting 0s before retrying") {
		t.Fatalf("unexpected progress %q", progress.String())
	}
}

const logAnalyticsPartialSizeBody = `{"tables":[{"name":"PrimaryResult","columns":[{"name":"Payload","type":"string"}],"rows":[["first"]]}],"error":{"code":"PartialError","message":"There were some errors when processing your query.","details":[{"code":"EngineError","message":"Something went wrong processing your query on the server.","innererror":{"code":"-2133196797","message":"The results of this query exceed the set limit of 64000000 bytes, so not all records were returned (E_QUERY_RESULT_SET_TOO_LARGE, 0x80DA0003, see https://aka.ms/kustoquerylimits for more information and possible solutions).","severity":2,"severityName":"Error"}}]}}`

func TestLogAnalyticsPartialSizeResultRetriesWithPartitions(t *testing.T) {
	baseQuery := "AppTraces\n| project Payload"
	server, _ := newLogAnalyticsTestServer(t, func(w http.ResponseWriter, request logAnalyticsTestRequest) {
		switch query := request.Query; {
		case query == baseQuery+"\n| count":
			io.WriteString(w, logAnalyticsTableBody(t, [][2]string{{"Count", "long"}}, []any{2}))
		case query == baseQuery:
			io.WriteString(w, logAnalyticsPartialSizeBody)
		case query == baseQuery+"\n| take 0":
			io.WriteString(w, logAnalyticsTableBody(t, [][2]string{{"Payload", "string"}}))
		case strings.Contains(query, "| summarize"):
			io.WriteString(w, logAnalyticsTableBody(t, [][2]string{{"DumpPartition", "long"}, {"Count", "long"}}, []any{0, 1}, []any{1, 1}))
		case strings.HasSuffix(query, "== 0"):
			io.WriteString(w, logAnalyticsTableBody(t, [][2]string{{"Payload", "string"}}, []any{"first"}))
		case strings.HasSuffix(query, "== 1"):
			io.WriteString(w, logAnalyticsTableBody(t, [][2]string{{"Payload", "string"}}, []any{"second"}))
		default:
			t.Errorf("unexpected query %q", query)
		}
	})
	source := &logAnalyticsSource{httpClient: server.Client(), endpoint: server.URL + "/v1", workspaceID: testWorkspaceID}
	cfg := config{Source: sourceLogAnalytics, DumpRowLimit: 10, Output: filepath.Join(t.TempDir(), "traces.json")}
	var progress bytes.Buffer
	output, err := dumpQuery(context.Background(), source, cfg, baseQuery, nil, &progress)
	if err != nil {
		t.Fatal(err)
	}
	if output.Rows != 2 || output.Stats.Partitions != 2 || !strings.Contains(progress.String(), "exceeded the service result-size limit") {
		t.Fatalf("partial result was not replaced by a partitioned collection: %#v\n%s", output, progress.String())
	}
}

func TestLogAnalyticsPartialResultIsNeverAccepted(t *testing.T) {
	server, _ := newLogAnalyticsTestServer(t, func(w http.ResponseWriter, request logAnalyticsTestRequest) {
		if strings.HasSuffix(request.Query, "\n| count") {
			io.WriteString(w, logAnalyticsTableBody(t, [][2]string{{"Count", "long"}}, []any{3}))
			return
		}
		io.WriteString(w, `{"tables":[{"name":"PrimaryResult","columns":[{"name":"Computer","type":"string"}],"rows":[["host1"]]}],"error":{"code":"PartialError","message":"There were some errors when processing your query.","details":[{"code":"EngineError","message":"Query execution was cancelled because it exceeded the allowed execution time."}]}}`)
	})
	source := &logAnalyticsSource{httpClient: server.Client(), endpoint: server.URL + "/v1", workspaceID: testWorkspaceID}
	output := filepath.Join(t.TempDir(), "heartbeat.json")
	cfg := config{Source: sourceLogAnalytics, DumpTable: "Heartbeat", DumpLookback: "1h", DumpTimeColumn: "TimeGenerated", DumpRowLimit: 10, Output: output}
	_, err := dumpTable(context.Background(), source, cfg, nil, io.Discard)
	var partial *logAnalyticsPartialResultError
	if !errors.As(err, &partial) || source.IsResultSizeExceeded(err) {
		t.Fatalf("expected a non-retryable partial-result failure, got %v", err)
	}
	if _, statErr := os.Stat(output); !os.IsNotExist(statErr) {
		t.Fatal("partial result was written to the output file")
	}
}

func TestQuerySourcesRecognizeMissingTables(t *testing.T) {
	defender := newDefenderQuerySource(nil, "", "")
	la := &logAnalyticsSource{}
	defenderMissing := &advancedQueryError{StatusCode: http.StatusBadRequest, Body: `{"error":{"code":"BadRequest","message":"'where' operator: Failed to resolve table or column expression named 'SigninLogs'. Fix semantic errors in your query.","innerError":{"date":"2026-09-13T10:00:00","request-id":"2a1e0b6c-0000-0000-0000-000000000000"}}}`}
	defenderColumn := &advancedQueryError{StatusCode: http.StatusBadRequest, Body: `{"error":{"code":"BadRequest","message":"'where' operator: Failed to resolve scalar expression named 'Timestamp'. Fix semantic errors in your query."}}`}
	laMissing := &logAnalyticsQueryError{StatusCode: http.StatusBadRequest, Body: `{"error":{"message":"The request had some invalid properties","code":"BadArgumentError","correlationId":"578c8e21-0000-0000-0000-000000000000","innererror":{"code":"SemanticError","message":"A semantic error occurred.","innererror":{"code":"SEM0100","message":"'where' operator: Failed to resolve table or column expression named 'DeviceProcessEvents'"}}}}`}
	laColumn := &logAnalyticsQueryError{StatusCode: http.StatusBadRequest, Body: `{"error":{"code":"BadArgumentError","innererror":{"code":"SemanticError","innererror":{"code":"SEM0100","message":"'where' operator: Failed to resolve scalar expression named 'Timestamp'"}}}}`}
	cases := []struct {
		name   string
		source querySource
		err    error
		table  string
		want   bool
	}{
		{"defender missing table", defender, fmt.Errorf("count rows in SigninLogs: %w", defenderMissing), "SigninLogs", true},
		{"defender other table", defender, defenderMissing, "AuditLogs", false},
		{"defender missing column", defender, defenderColumn, "DeviceEvents", false},
		{"defender server error", defender, &advancedQueryError{StatusCode: http.StatusInternalServerError, Body: defenderMissing.Body}, "SigninLogs", false},
		{"defender does not read other sources", defender, laMissing, "DeviceProcessEvents", false},
		{"log analytics missing table", la, fmt.Errorf("count rows: %w", laMissing), "DeviceProcessEvents", true},
		{"log analytics table name case", la, laMissing, "deviceprocessevents", false},
		{"log analytics missing column", la, laColumn, "SigninLogs", false},
		{"log analytics partial result", la, &logAnalyticsPartialResultError{Body: laMissing.Body}, "DeviceProcessEvents", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.source.IsTableNotFound(tc.err, tc.table); got != tc.want {
				t.Fatalf("IsTableNotFound = %v, want %v", got, tc.want)
			}
		})
	}
	if !la.IsResultSizeExceeded(&logAnalyticsPartialResultError{Body: logAnalyticsPartialSizeBody}) || la.IsResultSizeExceeded(laMissing) || la.IsResultSizeExceeded(defenderMissing) {
		t.Fatal("Log Analytics result-size classification is wrong")
	}
}

func TestParseFlagsLogAnalyticsSource(t *testing.T) {
	t.Setenv("LOG_ANALYTICS_WORKSPACE_ID", "")
	cfg, err := parseFlags([]string{"--source", "LogAnalytics", "--workspace-id", testWorkspaceID, "--dump-table", "SigninLogs", "--la-endpoint", "https://api.loganalytics.us/v1/"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Source != sourceLogAnalytics || cfg.DumpTimeColumn != "TimeGenerated" || cfg.LogAnalyticsEndpoint != "https://api.loganalytics.us/v1" || cfg.LogAnalyticsResource != defaultLogAnalyticsResource {
		t.Fatalf("unexpected Log Analytics config: %#v", cfg)
	}
	if cfg, err = parseFlags([]string{"--source", "loganalytics", "--workspace-id", testWorkspaceID, "--dump-table", "CommonSecurityLog", "--dump-time-column", "Timestamp"}, io.Discard); err != nil || cfg.DumpTimeColumn != "Timestamp" {
		t.Fatalf("explicit time column was replaced: %q, %v", cfg.DumpTimeColumn, err)
	}
	if cfg, err = parseFlags([]string{"--dump-table", "DeviceInfo"}, io.Discard); err != nil || cfg.Source != sourceDefender || cfg.DumpTimeColumn != "Timestamp" {
		t.Fatalf("defender defaults changed: %#v, %v", cfg, err)
	}
	t.Setenv("LOG_ANALYTICS_WORKSPACE_ID", testWorkspaceID)
	if cfg, err = parseFlags([]string{"--source", "loganalytics", "--query", "SigninLogs | take 1"}, io.Discard); err != nil || cfg.WorkspaceID != testWorkspaceID {
		t.Fatalf("workspace ID was not read from the environment: %q, %v", cfg.WorkspaceID, err)
	}
	t.Setenv("LOG_ANALYTICS_WORKSPACE_ID", "")

	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--source", "sentinel", "--dump-table", "SigninLogs"}, "unsupported -source"},
		{[]string{"--source", "loganalytics", "--dump-table", "SigninLogs"}, "requires -workspace-id"},
		{[]string{"--source", "loganalytics", "--workspace-id", "/subscriptions/x/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws", "--query", "SigninLogs"}, "invalid -workspace-id"},
		{[]string{"--source", "loganalytics", "--workspace-id", testWorkspaceID, "--query", "SigninLogs", "--la-resource", " "}, "la resource must not be empty"},
	} {
		if _, err := parseFlags(tc.args, io.Discard); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("parseFlags(%v) error = %v, want %q", tc.args, err, tc.want)
		}
	}
}

func TestLogAnalyticsServicePrincipalTokenUsesLogAnalyticsResource(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.URL.Path != "/tenant-id/oauth2/token" || r.PostForm.Get("resource") != "https://api.loganalytics.io" || r.PostForm.Get("client_id") != "client-id" {
			t.Errorf("unexpected token request %s %v", r.URL.Path, r.PostForm)
		}
		io.WriteString(w, `{"access_token":"la-token"}`)
	}))
	defer server.Close()
	cfg := config{Source: sourceLogAnalytics, AuthMode: "auto", TenantID: "tenant-id", ClientID: "client-id", ClientSecret: "secret", Resource: defaultResource, LogAnalyticsResource: defaultLogAnalyticsResource, LogAnalyticsEndpoint: defaultLogAnalyticsEndpoint, WorkspaceID: testWorkspaceID, LoginBaseURL: server.URL}
	if got := logAnalyticsAuthConfig(cfg); got.Resource != defaultLogAnalyticsResource || got.TenantID != "tenant-id" || got.AuthMode != "auto" {
		t.Fatalf("unexpected Log Analytics auth config %#v", got)
	}
	source, authMode, err := newQuerySource(context.Background(), server.Client(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	la, ok := source.(*logAnalyticsSource)
	if !ok || authMode != "sp" || la.token != "la-token" || la.endpoint != defaultLogAnalyticsEndpoint || la.workspaceID != testWorkspaceID {
		t.Fatalf("unexpected source %#v (%s)", source, authMode)
	}
}

func TestKQLTimespanDuration(t *testing.T) {
	for literal, want := range map[string]time.Duration{"30d": 720 * time.Hour, "1.5h": 90 * time.Minute, "90m": 90 * time.Minute, "30s": 30 * time.Second, "500ms": 500 * time.Millisecond, ".5s": 500 * time.Millisecond, "2.d": 48 * time.Hour} {
		if got, err := kqlTimespanDuration(literal); err != nil || got != want {
			t.Errorf("kqlTimespanDuration(%q) = %s, %v; want %s", literal, got, err, want)
		}
	}
	for _, literal := range []string{"30", "1w", "999999999d", "1h) | take 1"} {
		if _, err := kqlTimespanDuration(literal); err == nil {
			t.Errorf("kqlTimespanDuration(%q) accepted an invalid literal", literal)
		}
	}
}

func TestLogAnalyticsTableDumpRetriesPartitionThatExceedsByteLimit(t *testing.T) {
	payload := [][2]string{{"TimeGenerated", "datetime"}, {"Payload", "string"}}
	row := func(i int) []any { return []any{fmt.Sprintf("2026-09-01T10:%02d:00Z", i), fmt.Sprintf("event-%d", i)} }
	server, _ := newLogAnalyticsTestServer(t, func(w http.ResponseWriter, request logAnalyticsTestRequest) {
		switch query := request.Query; {
		case strings.HasSuffix(query, "\n| count"):
			io.WriteString(w, logAnalyticsTableBody(t, [][2]string{{"Count", "long"}}, []any{4}))
		case strings.HasSuffix(query, "\n| take 0"):
			io.WriteString(w, logAnalyticsTableBody(t, payload))
		case strings.HasSuffix(query, "% 2)"):
			io.WriteString(w, logAnalyticsTableBody(t, [][2]string{{"DumpPartition", "long"}, {"Count", "long"}}, []any{0, 2}, []any{1, 2}))
		case strings.HasSuffix(query, "% 2) == 0"):
			io.WriteString(w, logAnalyticsPartialSizeBody)
		case strings.HasSuffix(query, "% 4)"):
			io.WriteString(w, logAnalyticsTableBody(t, [][2]string{{"DumpPartition", "long"}, {"Count", "long"}}, []any{0, 1}, []any{1, 1}, []any{2, 1}, []any{3, 1}))
		case strings.Contains(query, "% 4) == "):
			partition := int(query[len(query)-1] - '0')
			io.WriteString(w, logAnalyticsTableBody(t, payload, row(partition)))
		default:
			t.Errorf("unexpected query %q", query)
			w.WriteHeader(http.StatusBadRequest)
		}
	})
	source := &logAnalyticsSource{httpClient: server.Client(), endpoint: server.URL + "/v1", workspaceID: testWorkspaceID}
	cfg := config{Source: sourceLogAnalytics, DumpTable: "AADNonInteractiveUserSignInLogs", DumpLookback: "1d", DumpTimeColumn: "TimeGenerated", DumpRowLimit: 4, Output: filepath.Join(t.TempDir(), "signins.json")}
	var progress bytes.Buffer
	output, err := dumpTable(context.Background(), source, cfg, nil, &progress)
	if err != nil {
		t.Fatalf("dumpTable returned error: %v\n%s", err, progress.String())
	}
	if output.Rows != 4 || output.Stats.Chunks != 4 || output.Stats.Partitions != 4 {
		t.Fatalf("unexpected output %#v", output)
	}
	if !strings.Contains(progress.String(), "retrying with at least 4 hash partitions") {
		t.Fatalf("partition retry was not reported:\n%s", progress.String())
	}
	body, err := os.ReadFile(cfg.Output)
	if err != nil {
		t.Fatal(err)
	}
	var written queryResponse
	if err := json.Unmarshal(body, &written); err != nil || len(written.Results) != 4 {
		t.Fatalf("unexpected output file: %v\n%s", err, body)
	}
}

func TestLogAnalyticsTableDumpFailsWhenOneRowExceedsByteLimit(t *testing.T) {
	server, requests := newLogAnalyticsTestServer(t, func(w http.ResponseWriter, request logAnalyticsTestRequest) {
		switch query := request.Query; {
		case strings.HasSuffix(query, "\n| count"):
			io.WriteString(w, logAnalyticsTableBody(t, [][2]string{{"Count", "long"}}, []any{2}))
		case strings.HasSuffix(query, "\n| take 0"):
			io.WriteString(w, logAnalyticsTableBody(t, [][2]string{{"Payload", "string"}}))
		case strings.HasSuffix(query, "% 2)"):
			io.WriteString(w, logAnalyticsTableBody(t, [][2]string{{"DumpPartition", "long"}, {"Count", "long"}}, []any{0, 1}, []any{1, 1}))
		default:
			io.WriteString(w, logAnalyticsPartialSizeBody)
		}
	})
	source := &logAnalyticsSource{httpClient: server.Client(), endpoint: server.URL + "/v1", workspaceID: testWorkspaceID}
	cfg := config{Source: sourceLogAnalytics, DumpTable: "AppTraces", DumpLookback: "1d", DumpTimeColumn: "TimeGenerated", DumpRowLimit: 10, Output: filepath.Join(t.TempDir(), "traces.json")}
	_, err := dumpTable(context.Background(), source, cfg, nil, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "individual row that exceeds the service result-size limit") {
		t.Fatalf("expected an individual row size error, got %v", err)
	}
	if len(*requests) != 5 {
		t.Fatalf("expected count, single query, schema, partition count, and one partition download; got %d requests", len(*requests))
	}
	if _, statErr := os.Stat(cfg.Output); !os.IsNotExist(statErr) {
		t.Fatal("incomplete result was written to the output file")
	}
}
