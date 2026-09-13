package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// newManifestDefenderServer emulates runHuntingQuery for unauthenticated runs.
func newManifestDefenderServer(t *testing.T, handle func(w http.ResponseWriter, query string)) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]string
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode query request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		handle(w, payload["Query"])
	}))
	t.Cleanup(server.Close)
	return server
}

func runManifestCollection(t *testing.T, args ...string) error {
	t.Helper()
	return Run(context.Background(), append([]string{"--env-file", "", "--auth", "none"}, args...), nil, io.Discard, io.Discard)
}

func readManifest(t *testing.T, path string) (collectionManifest, []byte) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := loadCollectionManifest(path)
	if err != nil {
		t.Fatalf("written manifest does not load: %v\n%s", err, body)
	}
	return *manifest, body
}

func manifestEntry(t *testing.T, manifest collectionManifest, source, name string) manifestTable {
	t.Helper()
	for _, table := range manifest.Tables {
		if table.Source == source && table.Name == name {
			return table
		}
	}
	t.Fatalf("manifest has no %s table %s: %#v", source, name, manifest.Tables)
	return manifestTable{}
}

func assertManifestFileHash(t *testing.T, manifestPath, relative, digest string, size *int64) {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(filepath.Dir(manifestPath), filepath.FromSlash(relative)))
	if err != nil {
		t.Fatalf("manifest file %q is not relative to the manifest: %v", relative, err)
	}
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != digest || (size != nil && *size != int64(len(body))) {
		t.Fatalf("manifest hash or size for %s does not match the file on disk", relative)
	}
}

func TestManifestRecordsEachTableStatus(t *testing.T) {
	const graphMissingTable = `{"error":{"code":"BadRequest","message":"'where' operator: Failed to resolve table or column expression named 'EmailEvents'. Fix semantic errors in your query.","innerError":{"date":"2026-09-13T10:00:00","request-id":"1f0c7f3e-0000-0000-0000-000000000000"}}}`
	omitEmptySchema := false
	server := newManifestDefenderServer(t, func(w http.ResponseWriter, query string) {
		table, _, _ := strings.Cut(query, "\n")
		switch {
		case table == "EmailEvents":
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, graphMissingTable)
		case table == "DeviceProcessEvents" && strings.HasSuffix(query, "\n| count"):
			io.WriteString(w, `{"Results":[{"Count":2}]}`)
		case table == "DeviceProcessEvents":
			io.WriteString(w, `{"Schema":[{"Name":"Timestamp","Type":"DateTime"},{"Name":"DeviceName","Type":"String"},{"Name":"ProcessId","Type":"Int64"},{"Name":"AdditionalFields","Type":"Dynamic"}],"Results":[{"Timestamp":"2026-09-12T08:00:00Z","DeviceName":"host1","ProcessId":4,"AdditionalFields":{}},{"Timestamp":"2026-09-12T09:00:00Z","DeviceName":"host2","ProcessId":8,"AdditionalFields":{}}]}`)
		case table == "DeviceLogonEvents" && strings.HasSuffix(query, "\n| count"):
			io.WriteString(w, `{"Results":[{"Count":0}]}`)
		case table == "DeviceLogonEvents" && strings.HasSuffix(query, "\n| take 0"):
			io.WriteString(w, `{"Schema":[{"Name":"Timestamp","Type":"DateTime"},{"Name":"LogonType","Type":"String"}],"Results":[]}`)
		case table == "DeviceLogonEvents" && omitEmptySchema:
			io.WriteString(w, `{"Results":[]}`)
		case table == "DeviceLogonEvents":
			io.WriteString(w, `{"Schema":[{"Name":"Timestamp","Type":"DateTime"},{"Name":"LogonType","Type":"String"}],"Results":[]}`)
		case table == "DeviceNetworkEvents" && strings.HasSuffix(query, "\n| count"):
			io.WriteString(w, `{"Results":[{"Count":1}]}`)
		case table == "DeviceNetworkEvents":
			w.WriteHeader(http.StatusServiceUnavailable)
			io.WriteString(w, `{"error":{"code":"ServiceUnavailable","message":"Advanced hunting is temporarily unavailable."}}`)
		default:
			t.Errorf("unexpected query %q", query)
		}
	})

	directory := t.TempDir()
	manifestPath := filepath.Join(directory, "collection", "manifest.json")
	dump := func(table string, extra ...string) error {
		return runManifestCollection(t, append([]string{"--endpoint", server.URL, "--dump-table", table, "--dump-lookback", "2d", "--output", filepath.Join(directory, "data", strings.ToLower(table)+".json"), "--manifest", manifestPath}, extra...)...)
	}

	if err := dump("DeviceProcessEvents", "--adx-export"); err != nil {
		t.Fatal(err)
	}
	if err := dump("DeviceLogonEvents"); err != nil {
		t.Fatal(err)
	}
	if err := dump("EmailEvents"); err == nil || !strings.Contains(err.Error(), "Failed to resolve table") {
		t.Fatalf("absent table must still fail the run, got %v", err)
	}
	if err := dump("DeviceNetworkEvents"); err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("failed collection must still fail the run, got %v", err)
	}

	manifest, body := readManifest(t, manifestPath)
	if info, err := os.Stat(manifestPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("manifest permissions: %v %v", info, err)
	}
	if manifest.Tool.Name != "tableDumper" || manifest.Tool.Version == "" || manifest.Pseudonymization.Enabled {
		t.Fatalf("unexpected manifest header: %s", body)
	}
	var names []string
	for _, table := range manifest.Tables {
		names = append(names, table.Name)
	}
	if strings.Join(names, ",") != "DeviceLogonEvents,DeviceNetworkEvents,DeviceProcessEvents,EmailEvents" {
		t.Fatalf("tables are not sorted by source and name: %v", names)
	}

	captured := manifestEntry(t, manifest, sourceDefender, "DeviceProcessEvents")
	if captured.Status != manifestCaptured || *captured.RowCount != 2 || *captured.Partitions != 1 || captured.File != "../data/deviceprocessevents.json" || captured.Note != "" {
		t.Fatalf("unexpected captured entry: %#v", captured)
	}
	if got, _ := json.Marshal(captured.Columns); string(got) != `[{"name":"Timestamp","type":"datetime"},{"name":"DeviceName","type":"string"},{"name":"ProcessId","type":"long"},{"name":"AdditionalFields","type":"dynamic"}]` {
		t.Fatalf("columns were not normalized to Kusto types: %s", got)
	}
	assertManifestFileHash(t, manifestPath, captured.File, captured.SHA256, captured.Bytes)
	assertManifestFileHash(t, manifestPath, captured.ADXDataFile, captured.ADXDataSHA256, nil)
	if captured.TimeColumn != "Timestamp" || captured.Window == nil || captured.Window.End.Sub(captured.Window.Start) != 48*time.Hour || time.Since(captured.Window.End) > time.Minute {
		t.Fatalf("unexpected window: %#v", captured.Window)
	}

	empty := manifestEntry(t, manifest, sourceDefender, "DeviceLogonEvents")
	if empty.Status != manifestCapturedEmpty || *empty.RowCount != 0 || len(empty.Columns) != 2 || empty.Columns[1] != (manifestColumn{Name: "LogonType", Type: "string"}) {
		t.Fatalf("captured_empty entry lost its columns: %#v", empty)
	}
	assertManifestFileHash(t, manifestPath, empty.File, empty.SHA256, empty.Bytes)

	absent := manifestEntry(t, manifest, sourceDefender, "EmailEvents")
	if absent.Status != manifestAbsentInSource || absent.RowCount != nil || absent.File != "" || len(absent.Columns) != 0 || absent.Window == nil {
		t.Fatalf("unexpected absent entry: %#v", absent)
	}
	failed := manifestEntry(t, manifest, sourceDefender, "DeviceNetworkEvents")
	if failed.Status != manifestNotCaptured || !strings.Contains(failed.Note, "503") || failed.RowCount != nil || failed.File != "" {
		t.Fatalf("unexpected not_captured entry: %#v", failed)
	}

	// The service omits the schema for an empty result: columns come from take 0.
	omitEmptySchema = true
	if err := dump("DeviceLogonEvents"); err != nil {
		t.Fatal(err)
	}
	manifest, _ = readManifest(t, manifestPath)
	if empty := manifestEntry(t, manifest, sourceDefender, "DeviceLogonEvents"); empty.Status != manifestCapturedEmpty || len(empty.Columns) != 2 {
		t.Fatalf("empty result without a schema lost its columns: %#v", empty)
	}
}

func TestManifestMergesRunsAcrossSources(t *testing.T) {
	defenderRows := `[{"DeviceName":"host1"}]`
	defender := newManifestDefenderServer(t, func(w http.ResponseWriter, query string) {
		var rows []map[string]any
		json.Unmarshal([]byte(defenderRows), &rows)
		if strings.HasSuffix(query, "\n| count") {
			json.NewEncoder(w).Encode(map[string]any{"Results": []map[string]any{{"Count": len(rows)}}})
			return
		}
		json.NewEncoder(w).Encode(queryResponse{Schema: []queryColumn{{"DeviceName", "String"}}, Results: rows})
	})
	la, _ := newLogAnalyticsTestServer(t, func(w http.ResponseWriter, request logAnalyticsTestRequest) {
		if strings.HasSuffix(request.Query, "\n| count") {
			io.WriteString(w, logAnalyticsTableBody(t, [][2]string{{"Count", "long"}}, []any{0}))
			return
		}
		io.WriteString(w, logAnalyticsTableBody(t, [][2]string{{"TimeGenerated", "datetime"}, {"UserPrincipalName", "string"}}))
	})

	directory := t.TempDir()
	manifestPath := filepath.Join(directory, "manifest.json")
	if err := runManifestCollection(t, "--endpoint", defender.URL, "--query", "DeviceInfo | project DeviceName", "--manifest", manifestPath, "--manifest-table", "IncidentDevices", "--output", filepath.Join(directory, "devices.json")); err != nil {
		t.Fatal(err)
	}
	first, _ := readManifest(t, manifestPath)
	if err := runManifestCollection(t, "--source", "loganalytics", "--workspace-id", testWorkspaceID, "--la-endpoint", la.URL+"/v1", "--dump-table", "SigninLogs", "--manifest", manifestPath, "--output", filepath.Join(directory, "signins.json")); err != nil {
		t.Fatal(err)
	}
	defenderRows = `[{"DeviceName":"host1"},{"DeviceName":"host2"},{"DeviceName":"host3"}]`
	if err := runManifestCollection(t, "--endpoint", defender.URL, "--query", "DeviceInfo | project DeviceName", "--manifest", manifestPath, "--manifest-table", "IncidentDevices", "--output", filepath.Join(directory, "devices.json")); err != nil {
		t.Fatal(err)
	}

	manifest, body := readManifest(t, manifestPath)
	if len(manifest.Tables) != 2 || manifest.Tables[0].Source != sourceDefender || manifest.Tables[1].Source != sourceLogAnalytics {
		t.Fatalf("runs were not merged into one sorted manifest:\n%s", body)
	}
	if !manifest.CreatedAt.Equal(first.CreatedAt) || !manifest.UpdatedAt.After(first.UpdatedAt) {
		t.Fatalf("created_at must survive merges and updated_at must advance: %s", body)
	}
	devices := manifestEntry(t, manifest, sourceDefender, "IncidentDevices")
	if devices.Status != manifestCaptured || *devices.RowCount != 3 || devices.Query != "DeviceInfo | project DeviceName" || devices.Window != nil || devices.TimeColumn != "" {
		t.Fatalf("re-run did not replace its entry or query mode recorded a window: %#v", devices)
	}
	assertManifestFileHash(t, manifestPath, devices.File, devices.SHA256, devices.Bytes)
	signins := manifestEntry(t, manifest, sourceLogAnalytics, "SigninLogs")
	if signins.Status != manifestCapturedEmpty || signins.TimeColumn != "TimeGenerated" || len(signins.Columns) != 2 || signins.Columns[0].Type != "datetime" {
		t.Fatalf("unexpected Log Analytics entry: %#v", signins)
	}

	// Rewriting an unchanged manifest keeps the table section byte-identical.
	again, err := loadCollectionManifest(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	again.Tables[0], again.Tables[1] = again.Tables[1], again.Tables[0]
	rewritten := filepath.Join(directory, "rewritten.json")
	if err := writeCollectionManifest(rewritten, again); err != nil {
		t.Fatal(err)
	}
	if after, _ := os.ReadFile(rewritten); !bytes.Equal(after, body) {
		t.Fatalf("serialization depends on table order:\n%s\n%s", body, after)
	}
}

func TestManifestCapturedEmptyPartitionedQueryRecordsColumns(t *testing.T) {
	baseQuery := "DeviceEvents\n| project Timestamp, ReportId, Payload"
	server := newManifestDefenderServer(t, func(w http.ResponseWriter, query string) {
		switch {
		case query == baseQuery+"\n| count":
			io.WriteString(w, `{"Results":[{"Count":0}]}`)
		case query == baseQuery:
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, `{"error":{"code":"BadRequest","message":"Query execution has exceeded the allowed result size. Optimize your query by limiting the amount of results and try again."}}`)
		case query == baseQuery+"\n| take 0":
			io.WriteString(w, `{"Schema":[{"Name":"Timestamp","Type":"DateTime"},{"Name":"ReportId","Type":"Int64"},{"Name":"Payload","Type":"Dynamic"}],"Results":[]}`)
		case strings.Contains(query, "| summarize Count=count() by DumpPartition="):
			io.WriteString(w, `{"Schema":[{"Name":"DumpPartition","Type":"Int64"},{"Name":"Count","Type":"Int64"}],"Results":[]}`)
		default:
			t.Errorf("unexpected query %q", query)
		}
	})
	directory := t.TempDir()
	manifestPath := filepath.Join(directory, "manifest.json")
	output := filepath.Join(directory, "events.json")
	if err := runManifestCollection(t, "--endpoint", server.URL, "--query", baseQuery, "--output", output, "--manifest", manifestPath, "--manifest-table", "DeviceEvents"); err != nil {
		t.Fatal(err)
	}
	written, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var response queryResponse
	if err := json.Unmarshal(written, &response); err != nil || len(response.Schema) != 3 || response.Results == nil || len(response.Results) != 0 {
		t.Fatalf("zero-partition output lost its schema: %s", written)
	}
	manifest, _ := readManifest(t, manifestPath)
	entry := manifestEntry(t, manifest, sourceDefender, "DeviceEvents")
	if entry.Status != manifestCapturedEmpty || *entry.Partitions != 0 || len(entry.Columns) != 3 || entry.Columns[2] != (manifestColumn{Name: "Payload", Type: "dynamic"}) {
		t.Fatalf("zero-partition captured_empty entry lost its columns: %#v", entry)
	}
	assertManifestFileHash(t, manifestPath, entry.File, entry.SHA256, entry.Bytes)
}

func validManifestForTest() collectionManifest {
	rows, empty, partitions, size := 2, 0, 1, int64(10)
	digest := strings.Repeat("0a", sha256.Size)
	end := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	return collectionManifest{
		SchemaVersion: collectionManifestSchemaVersion,
		Tool:          manifestTool{Name: "tableDumper", Version: "(devel)"},
		CreatedAt:     end, UpdatedAt: end,
		Tables: []manifestTable{
			{Source: sourceDefender, Name: "DeviceProcessEvents", Status: manifestCaptured, TimeColumn: "Timestamp", Window: &manifestWindow{Start: end.Add(-time.Hour), End: end}, Columns: []manifestColumn{{"Timestamp", "datetime"}}, RowCount: &rows, Partitions: &partitions, File: "device.json", SHA256: digest, Bytes: &size, ADXDataFile: "device.adx.json", ADXDataSHA256: digest},
			{Source: sourceDefender, Name: "DeviceLogonEvents", Status: manifestCapturedEmpty, Columns: []manifestColumn{{"LogonType", "string"}}, RowCount: &empty, Partitions: &partitions, File: "logons.json", SHA256: digest, Bytes: &size},
			{Source: sourceLogAnalytics, Name: "SigninLogs", Status: manifestNotCaptured, Note: "query failed with HTTP 503"},
			{Source: sourceLogAnalytics, Name: "AADRiskyUsers", Status: manifestAbsentInSource},
		},
	}
}

func TestManifestLoadRejectsInvariantViolations(t *testing.T) {
	three, zero := 3, 0
	cases := map[string]func(*collectionManifest){
		"captured without rows":       func(m *collectionManifest) { m.Tables[0].RowCount = &zero },
		"captured without file":       func(m *collectionManifest) { m.Tables[0].File, m.Tables[0].SHA256, m.Tables[0].Bytes = "", "", nil },
		"captured without columns":    func(m *collectionManifest) { m.Tables[0].Columns = nil },
		"captured_empty with rows":    func(m *collectionManifest) { m.Tables[1].RowCount = &three },
		"captured_empty no row count": func(m *collectionManifest) { m.Tables[1].RowCount = nil },
		"captured_empty no columns":   func(m *collectionManifest) { m.Tables[1].Columns = nil },
		"not_captured without note":   func(m *collectionManifest) { m.Tables[2].Note = "" },
		"not_captured with rows":      func(m *collectionManifest) { m.Tables[2].RowCount = &zero },
		"absent with columns":         func(m *collectionManifest) { m.Tables[3].Columns = []manifestColumn{{"A", "string"}} },
		"absent with file":            func(m *collectionManifest) { m.Tables[3].File = "x.json" },
		"unknown status":              func(m *collectionManifest) { m.Tables[3].Status = "empty" },
		"unknown source":              func(m *collectionManifest) { m.Tables[3].Source = "splunk" },
		"unsafe table name":           func(m *collectionManifest) { m.Tables[3].Name = "Signin Logs" },
		"duplicate entry":             func(m *collectionManifest) { m.Tables = append(m.Tables, m.Tables[3]) },
		"duplicate columns":           func(m *collectionManifest) { m.Tables[0].Columns = append(m.Tables[0].Columns, m.Tables[0].Columns[0]) },
		"hash without file":           func(m *collectionManifest) { m.Tables[0].ADXDataSHA256 = "" },
		"malformed sha256":            func(m *collectionManifest) { m.Tables[0].SHA256 = "abc" },
		"absolute file":               func(m *collectionManifest) { m.Tables[0].File = "/data/device.json" },
		"window without time column":  func(m *collectionManifest) { m.Tables[0].TimeColumn = "" },
		"inverted window":             func(m *collectionManifest) { m.Tables[0].Window.Start = m.Tables[0].Window.End.Add(time.Hour) },
		"unsupported schema version":  func(m *collectionManifest) { m.SchemaVersion = 2 },
		"pseudonymized query text": func(m *collectionManifest) {
			m.Pseudonymization = manifestPseudonymization{true, "irreversible", "0123456789abcdef"}
			m.Tables[2].Query = "SigninLogs"
		},
		"pseudonymized without key_id": func(m *collectionManifest) {
			m.Pseudonymization = manifestPseudonymization{Enabled: true, Mode: "irreversible"}
		},
		"mode without pseudonymizing": func(m *collectionManifest) { m.Pseudonymization = manifestPseudonymization{Mode: "reversible"} },
	}
	directory := t.TempDir()
	valid := validManifestForTest()
	body, _ := json.Marshal(valid)
	validPath := filepath.Join(directory, "valid.json")
	if err := os.WriteFile(validPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCollectionManifest(validPath); err != nil {
		t.Fatalf("valid manifest rejected: %v", err)
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			manifest := validManifestForTest()
			mutate(&manifest)
			body, _ := json.Marshal(manifest)
			path := filepath.Join(t.TempDir(), "manifest.json")
			if err := os.WriteFile(path, body, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadCollectionManifest(path); err == nil {
				t.Fatalf("invalid manifest accepted:\n%s", body)
			}
			if err := writeCollectionManifest(filepath.Join(t.TempDir(), "out.json"), &manifest); err == nil {
				t.Fatal("invalid manifest written")
			}
		})
	}

	unknownField := bytes.Replace(body, []byte(`"schema_version":1`), []byte(`"schema_version":1,"extra":true`), 1)
	if err := os.WriteFile(validPath, unknownField, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCollectionManifest(validPath); err == nil {
		t.Fatal("manifest with an unknown field accepted")
	}
	requests := 0
	server := newManifestDefenderServer(t, func(w http.ResponseWriter, query string) { requests++ })
	if err := runManifestCollection(t, "--endpoint", server.URL, "--dump-table", "DeviceInfo", "--output", filepath.Join(directory, "out.json"), "--manifest", validPath); err == nil || requests != 0 {
		t.Fatalf("run with an invalid manifest must fail before querying: %v after %d requests", err, requests)
	}
}

func TestParseFlagsValidatesManifestOptions(t *testing.T) {
	directory := t.TempDir()
	output := filepath.Join(directory, "results.json")
	dataPath, schemaPath := adxArtifactPaths(output)
	queryFile := filepath.Join(directory, "incident.kql")
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--dump-table", "DeviceInfo", "--output", output, "--manifest", output}, "must not use an output artifact path"},
		{[]string{"--dump-table", "DeviceInfo", "--output", output, "--adx-export", "--manifest", dataPath}, "must not use an output artifact path"},
		{[]string{"--dump-table", "DeviceInfo", "--output", output, "--adx-export", "--manifest", schemaPath}, "must not use an output artifact path"},
		{[]string{"--dump-table", "DeviceInfo", "--output", output, "--opengraph-export", "--manifest", openGraphIconArtifactPath(output)}, "must not use an output artifact path"},
		{[]string{"--dump-table", "DeviceInfo", "--pseudonymize", "--pseudonym-map", filepath.Join(directory, "vault.json"), "--manifest", filepath.Join(directory, "vault.json")}, "-manifest and -pseudonym-map must use different paths"},
		{[]string{"--dump-table", "DeviceInfo", "--pseudonymize", "--pseudonym-replacements-file", filepath.Join(directory, "r.json"), "--manifest", filepath.Join(directory, "r.json")}, "-manifest and -pseudonym-replacements-file must use different paths"},
		{[]string{"--query-file", queryFile, "--manifest-table", "Incident", "--manifest", queryFile}, "-manifest and -query-file must use different paths"},
		{[]string{"--query", "SigninLogs", "--manifest", filepath.Join(directory, "m.json")}, "requires -manifest-table"},
		{[]string{"--dump-table", "DeviceInfo", "--manifest", filepath.Join(directory, "m.json"), "--manifest-table", "Other"}, "only used with -query"},
		{[]string{"--query", "SigninLogs", "--manifest-table", "Incident"}, "-manifest-table requires -manifest"},
		{[]string{"--query", "SigninLogs", "--manifest", filepath.Join(directory, "m.json"), "--manifest-table", "Incident | take 1"}, "invalid -manifest-table"},
		{[]string{"--adx-cluster", "https://c.kusto.windows.net", "--adx-database", "db", "--adx-table", "T", "--adx-upload-file", "x.json", "--manifest", filepath.Join(directory, "m.json")}, "-manifest requires -query"},
	} {
		if _, err := parseFlags(tc.args, io.Discard); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("parseFlags(%v) error = %v, want %q", tc.args, err, tc.want)
		}
	}
	cfg, err := parseFlags([]string{"--query", "SigninLogs | take 1", "--manifest", filepath.Join(directory, "m.json"), "--manifest-table", "IncidentSignins"}, io.Discard)
	if err != nil || cfg.Manifest == "" || cfg.ManifestTable != "IncidentSignins" {
		t.Fatalf("valid manifest options rejected: %v", err)
	}
}

func TestPseudonymizedManifestContainsNoOriginals(t *testing.T) {
	const tenantID = "3c9e1f7a-5b2d-4e8f-a6c1-9d0b7e2f4a35"
	originals := []string{"jdoe", "j.doe@contoso.com", "contoso", "FIN-LAPTOP-042", testWorkspaceID, tenantID}
	query := "SigninLogs\n| where UserPrincipalName == 'j.doe@contoso.com' or DeviceDetail.displayName == 'FIN-LAPTOP-042'\n| project TimeGenerated, UserPrincipalName, AccountName"
	failingQuery := "AuditLogs\n| where InitiatedBy has 'jdoe'"
	server, _ := newLogAnalyticsTestServer(t, func(w http.ResponseWriter, request logAnalyticsTestRequest) {
		switch {
		case strings.HasPrefix(request.Query, "AuditLogs"):
			// Service errors can echo the query and its identifiers.
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, `{"error":{"code":"BadArgumentError","message":"The request had some invalid properties","innererror":{"code":"SyntaxError","message":"Query could not be parsed at 'has 'jdoe'' on line [2,22]"}}}`)
		case strings.HasSuffix(request.Query, "\n| count"):
			io.WriteString(w, logAnalyticsTableBody(t, [][2]string{{"Count", "long"}}, []any{1}))
		default:
			io.WriteString(w, logAnalyticsTableBody(t, [][2]string{{"TimeGenerated", "datetime"}, {"UserPrincipalName", "string"}, {"AccountName", "string"}}, []any{"2026-09-12T08:00:00Z", "j.doe@contoso.com", `CONTOSO\jdoe`}))
		}
	})

	directory := t.TempDir()
	manifestPath := filepath.Join(directory, "manifest.json")
	vaultPath := filepath.Join(directory, "vault.json")
	common := []string{"--source", "loganalytics", "--workspace-id", testWorkspaceID, "--tenant-id", tenantID, "--la-endpoint", server.URL + "/v1", "--manifest", manifestPath, "--pseudonymize", "--pseudonym-map", vaultPath, "--pseudonym-map-irreversible"}
	if err := runManifestCollection(t, append(common, "--query", query, "--manifest-table", "IncidentSignins", "--output", filepath.Join(directory, "signins.json"))...); err != nil {
		t.Fatal(err)
	}
	if err := runManifestCollection(t, append(common, "--query", failingQuery, "--manifest-table", "IncidentAudit", "--output", filepath.Join(directory, "audit.json"))...); err == nil {
		t.Fatal("failing query succeeded")
	}

	manifest, body := readManifest(t, manifestPath)
	for _, original := range originals {
		if strings.Contains(strings.ToLower(string(body)), strings.ToLower(original)) {
			t.Fatalf("pseudonymized manifest contains original %q:\n%s", original, body)
		}
	}
	if bytes.Contains(body, []byte(`"query"`)) {
		t.Fatalf("pseudonymized manifest recorded query text:\n%s", body)
	}
	vault, err := newPseudonymizer(vaultPath)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Pseudonymization != (manifestPseudonymization{Enabled: true, Mode: "irreversible", KeyID: vault.KeyID()}) || bytes.Contains(body, []byte(`"seed"`)) {
		t.Fatalf("unexpected pseudonymization record:\n%s", body)
	}
	if entry := manifestEntry(t, manifest, sourceLogAnalytics, "IncidentSignins"); entry.Status != manifestCaptured {
		t.Fatalf("unexpected captured entry: %#v", entry)
	}
	if entry := manifestEntry(t, manifest, sourceLogAnalytics, "IncidentAudit"); entry.Status != manifestNotCaptured || !regexp.MustCompile(`HTTP 400`).MatchString(entry.Note) {
		t.Fatalf("unexpected failure entry: %#v", entry)
	}

	// A run with a different pseudonymization setup cannot join the collection.
	before := body
	if err := runManifestCollection(t, "--source", "loganalytics", "--workspace-id", testWorkspaceID, "--la-endpoint", server.URL+"/v1", "--manifest", manifestPath, "--query", query, "--manifest-table", "PlainSignins", "--output", filepath.Join(directory, "plain.json")); err == nil || !strings.Contains(err.Error(), "different pseudonymization") {
		t.Fatalf("unpseudonymized run joined a pseudonymized manifest: %v", err)
	}
	if after, _ := os.ReadFile(manifestPath); !bytes.Equal(after, before) {
		t.Fatal("rejected run changed the manifest")
	}
	if _, err := os.Stat(filepath.Join(directory, "plain.json")); !os.IsNotExist(err) {
		t.Fatal("rejected run collected data before checking the manifest")
	}
}
