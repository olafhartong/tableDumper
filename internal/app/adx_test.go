package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestADXArtifactPaths(t *testing.T) {
	dataPath, schemaPath := adxArtifactPaths("/tmp/results.json")
	if dataPath != "/tmp/results.adx.json" {
		t.Fatalf("unexpected data path %q", dataPath)
	}
	if schemaPath != "/tmp/results.adx.kql" {
		t.Fatalf("unexpected schema path %q", schemaPath)
	}
}

func TestDefaultADXTableName(t *testing.T) {
	if got := defaultADXTableName("/tmp/defender-results.json"); got != "defender_results" {
		t.Fatalf("defaultADXTableName() = %q, want %q", got, "defender_results")
	}
	if got := defaultADXTableName("/tmp/123.json"); got != "_123" {
		t.Fatalf("defaultADXTableName() = %q, want %q", got, "_123")
	}
}

func TestReadIngestSource(t *testing.T) {
	t.Run("raw query response", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "response.json")
		content := `{"Schema":[{"Name":"DeviceName","Type":"String"}],"Results":[{"DeviceName":"host1"}]}`
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("write file: %v", err)
		}

		source, err := readIngestSource(path)
		if err != nil {
			t.Fatalf("readIngestSource returned error: %v", err)
		}
		if len(source.Schema) != 1 || len(source.Rows) != 1 {
			t.Fatalf("unexpected source %#v", source)
		}
	})

	t.Run("ndjson", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "rows.ndjson")
		content := strings.Join([]string{
			`{"DeviceName":"host1","Count":1}`,
			`{"DeviceName":"host2","Count":2}`,
			"",
		}, "\n")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("write file: %v", err)
		}

		source, err := readIngestSource(path)
		if err != nil {
			t.Fatalf("readIngestSource returned error: %v", err)
		}
		if len(source.Rows) != 2 {
			t.Fatalf("unexpected rows %#v", source.Rows)
		}
	})

	t.Run("ndjson supports large rows", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "large-rows.ndjson")

		row, err := json.Marshal(map[string]any{
			"DeviceName": "host1",
			"Payload":    strings.Repeat("x", 70*1024),
		})
		if err != nil {
			t.Fatalf("marshal row: %v", err)
		}
		if err := os.WriteFile(path, append(row, '\n'), 0o600); err != nil {
			t.Fatalf("write file: %v", err)
		}

		source, err := readIngestSource(path)
		if err != nil {
			t.Fatalf("readIngestSource returned error: %v", err)
		}
		if len(source.Rows) != 1 {
			t.Fatalf("unexpected rows %#v", source.Rows)
		}
		if got := source.Rows[0]["Payload"]; got != strings.Repeat("x", 70*1024) {
			t.Fatalf("unexpected payload length %d", len(got.(string)))
		}
	})
}

func TestBuildADXSchemaFile(t *testing.T) {
	content, err := buildADXSchemaFile([]queryColumn{
		{Name: "Timestamp", Type: "DateTime"},
		{Name: "DeviceName", Type: "String"},
		{Name: "ReportId", Type: "Int64"},
	}, "DefenderEvents", "DefenderEvents_json", "results.adx.json")
	if err != nil {
		t.Fatalf("buildADXSchemaFile returned error: %v", err)
	}
	if !strings.Contains(content, ".create table DefenderEvents (Timestamp:datetime, DeviceName:string, ReportId:long)") {
		t.Fatalf("unexpected schema file content %s", content)
	}
	if !strings.Contains(content, `"Path":"$.DeviceName"`) {
		t.Fatalf("expected JSON mapping path in schema file %s", content)
	}
}

func TestWriteADXArtifacts(t *testing.T) {
	dir := t.TempDir()
	cfg := config{
		Output:    filepath.Join(dir, "results.json"),
		ADXExport: true,
	}
	response := queryResponse{
		Schema: []queryColumn{
			{Name: "DeviceName", Type: "String"},
			{Name: "Timestamp", Type: "DateTime"},
		},
		Results: []map[string]any{
			{"DeviceName": "host1", "Timestamp": "2026-04-08T10:00:00Z"},
			{"DeviceName": "host2", "Timestamp": "2026-04-08T11:00:00Z"},
		},
	}

	dataPath, schemaPath, err := writeADXArtifacts(cfg, response)
	if err != nil {
		t.Fatalf("writeADXArtifacts returned error: %v", err)
	}

	dataContent, err := os.ReadFile(dataPath)
	if err != nil {
		t.Fatalf("read data file: %v", err)
	}
	if got := strings.Count(strings.TrimSpace(string(dataContent)), "\n") + 1; got != 2 {
		t.Fatalf("unexpected row count in ADX data file %d", got)
	}
	if !strings.Contains(string(dataContent), `"DeviceName":"host1"`) {
		t.Fatalf("unexpected data content %s", string(dataContent))
	}

	schemaContent, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("read schema file: %v", err)
	}
	if !strings.Contains(string(schemaContent), "results.adx.json") {
		t.Fatalf("unexpected schema content %s", string(schemaContent))
	}
	if !strings.Contains(string(schemaContent), `ingestion json mapping "results_json"`) {
		t.Fatalf("unexpected mapping name in schema content %s", string(schemaContent))
	}
}

func TestBuildADXColumnDefsSanitizesNames(t *testing.T) {
	defs, err := buildADXColumnDefs([]queryColumn{
		{Name: "Device-Name", Type: "String"},
		{Name: "Device Name", Type: "String"},
		{Name: "1Count", Type: "Int64"},
	})
	if err != nil {
		t.Fatalf("buildADXColumnDefs returned error: %v", err)
	}
	got := []string{defs[0].ColumnName, defs[1].ColumnName, defs[2].ColumnName}
	want := []string{"Device_Name", "Device_Name_2", "_1Count"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("column %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestInferSchemaFromResultsSkipsODataMetadataFields(t *testing.T) {
	schema := inferSchemaFromResults([]map[string]any{
		{
			"id":                "edge-1",
			"weight":            1.0,
			"weight@odata.type": "#Int64",
		},
	})

	for _, col := range schema {
		if col.Name == "weight@odata.type" {
			t.Fatalf("unexpected metadata field in inferred schema: %#v", schema)
		}
	}
}

func TestEnsureADXTableAndMappingAndIngest(t *testing.T) {
	var mgmtCommands []string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/rest/mgmt":
			var payload map[string]string
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode mgmt payload: %v", err)
			}
			mgmtCommands = append(mgmtCommands, payload["csl"])
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"Tables":[]}`)
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := config{
		ADXCluster:   server.URL,
		ADXDatabase:  "TestDB",
		ADXTable:     "DefenderEvents",
		ADXBatchSize: 2,
	}
	rows := []map[string]any{
		{"DeviceName": "host1", "Count": 1.0},
		{"DeviceName": "host2", "Count": 2.0},
		{"DeviceName": "host3", "Count": 3.0},
	}
	schema := inferSchemaFromResults(rows)

	if err := ensureADXTableAndMapping(context.Background(), server.Client(), cfg.ADXCluster, cfg.ADXDatabase, "token", cfg.ADXTable, "DefenderEvents_json", schema); err != nil {
		t.Fatalf("ensureADXTableAndMapping returned error: %v", err)
	}
	batches, err := ingestRowsToADX(context.Background(), server.Client(), cfg.ADXCluster, cfg.ADXDatabase, cfg.ADXTable, "DefenderEvents_json", "token", rows, cfg.ADXBatchSize)
	if err != nil {
		t.Fatalf(" ingestRowsToADX returned error: %v", err)
	}

	if len(mgmtCommands) != 4 {
		t.Fatalf("unexpected management command count %d", len(mgmtCommands))
	}
	if !strings.Contains(mgmtCommands[0], ".create table DefenderEvents") {
		t.Fatalf("unexpected create table command %q", mgmtCommands[0])
	}
	if !strings.Contains(mgmtCommands[1], `ingestion json mapping "DefenderEvents_json"`) {
		t.Fatalf("unexpected mapping command %q", mgmtCommands[1])
	}
	if batches != 2 {
		t.Fatalf("unexpected batch count %d", batches)
	}
	if !strings.Contains(mgmtCommands[2], ".ingest inline into table DefenderEvents") {
		t.Fatalf("unexpected inline ingest command %q", mgmtCommands[2])
	}
	if !strings.Contains(mgmtCommands[2], "ingestionMappingReference='DefenderEvents_json'") {
		t.Fatalf("unexpected mapping reference in command %q", mgmtCommands[2])
	}
	inlineBody1 := strings.TrimSpace(strings.SplitN(mgmtCommands[2], "<|", 2)[1])
	if lines := bytes.Count([]byte(inlineBody1), []byte("\n")) + 1; lines != 2 {
		t.Fatalf("unexpected line count in first batch %d", lines)
	}
	inlineBody2 := strings.TrimSpace(strings.SplitN(mgmtCommands[3], "<|", 2)[1])
	if lines := bytes.Count([]byte(inlineBody2), []byte("\n")) + 1; lines != 1 {
		t.Fatalf("unexpected line count in second batch %d", lines)
	}
}

func TestUploadFileToADX(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "rows.json")
	var rows []map[string]any
	for i := 0; i < 3; i++ {
		rows = append(rows, map[string]any{
			"DeviceName": "host" + strconv.Itoa(i+1),
			"Count":      i + 1,
		})
	}
	body, err := json.Marshal(rows)
	if err != nil {
		t.Fatalf("marshal rows: %v", err)
	}
	if err := os.WriteFile(filePath, body, 0o600); err != nil {
		t.Fatalf("write upload file: %v", err)
	}

	var tokenRequests int
	var mgmtRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/oauth2/token"):
			tokenRequests++
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"access_token":"adx-token"}`)
		case r.URL.Path == "/v1/rest/mgmt":
			mgmtRequests++
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"Tables":[]}`)
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := config{
		AuthMode:        "sp",
		ADXCluster:      server.URL,
		ADXDatabase:     "TestDB",
		ADXTable:        "DefenderEvents",
		ADXUploadFile:   filePath,
		ADXBatchSize:    2,
		ADXTenantID:     "tenant",
		ADXClientID:     "client",
		ADXClientSecret: "secret",
		ADXResource:     defaultADXResource,
		LoginBaseURL:    server.URL,
	}

	rowsUploaded, batchesUploaded, authMode, err := uploadFileToADX(context.Background(), server.Client(), cfg)
	if err != nil {
		t.Fatalf("uploadFileToADX returned error: %v", err)
	}
	if rowsUploaded != 3 {
		t.Fatalf("unexpected uploaded row count %d", rowsUploaded)
	}
	if batchesUploaded != 2 {
		t.Fatalf("unexpected uploaded batch count %d", batchesUploaded)
	}
	if authMode != "sp" {
		t.Fatalf("unexpected auth mode %q", authMode)
	}
	if tokenRequests != 1 {
		t.Fatalf("unexpected token request count %d", tokenRequests)
	}
	if mgmtRequests != 4 {
		t.Fatalf("unexpected management request count %d", mgmtRequests)
	}
}

func TestInspectADXMgmtResponseDetectsEmptyInlineIngest(t *testing.T) {
	body := []byte(`{
		"Tables": [{
			"TableName": "Table_0",
			"Columns": [{"ColumnName":"ExtentId","ColumnType":"String"}],
			"Rows": [["00000000-0000-0000-0000-000000000000"]]
		}]
	}`)

	err := inspectADXMgmtResponse(".ingest inline into table AlertEdges <| {}", body)
	if err == nil || !strings.Contains(err.Error(), "produced no extents") {
		t.Fatalf("expected empty ingest error, got %v", err)
	}
}

func TestInspectADXMgmtResponseAcceptsInlineIngestWithExtent(t *testing.T) {
	body := []byte(`{
		"Tables": [{
			"TableName": "Table_0",
			"Columns": [{"ColumnName":"ExtentId","ColumnType":"String"}],
			"Rows": [["11111111-1111-1111-1111-111111111111"]]
		}]
	}`)

	if err := inspectADXMgmtResponse(".ingest inline into table AlertNodes <| {}", body); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
