package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLoadDotEnv(t *testing.T) {
	t.Run("missing default env file is ignored", func(t *testing.T) {
		t.Chdir(t.TempDir())
		values, err := loadDotEnv(".env")
		if err != nil {
			t.Fatalf("loadDotEnv returned error: %v", err)
		}
		if len(values) != 0 {
			t.Fatalf("expected empty map, got %#v", values)
		}
	})

	t.Run("parses key values and quotes", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, ".env")
		content := strings.Join([]string{
			"# comment",
			"AZURE_TENANT_ID=tenant-id",
			"export AZURE_CLIENT_ID=\"client-id\"",
			"AZURE_CLIENT_SECRET='secret-value'",
			"",
		}, "\n")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("write env file: %v", err)
		}

		values, err := loadDotEnv(path)
		if err != nil {
			t.Fatalf("loadDotEnv returned error: %v", err)
		}
		if values["AZURE_TENANT_ID"] != "tenant-id" {
			t.Fatalf("unexpected tenant value %q", values["AZURE_TENANT_ID"])
		}
		if values["AZURE_CLIENT_ID"] != "client-id" {
			t.Fatalf("unexpected client id %q", values["AZURE_CLIENT_ID"])
		}
		if values["AZURE_CLIENT_SECRET"] != "secret-value" {
			t.Fatalf("unexpected secret %q", values["AZURE_CLIENT_SECRET"])
		}
	})
}

func TestDefaultEnvFile(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "default", args: nil, want: ".env"},
		{name: "space separated", args: []string{"--env-file", "custom.env"}, want: "custom.env"},
		{name: "equals syntax", args: []string{"--env-file=custom.env"}, want: "custom.env"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := defaultEnvFile(tt.args); got != tt.want {
				t.Fatalf("defaultEnvFile() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseFlagsSupportsInsecureSkipVerify(t *testing.T) {
	cfg, err := parseFlags([]string{
		"--query", "DeviceInfo | limit 1",
		"--output", "results.json",
		"--insecure-skip-verify",
	}, io.Discard)
	if err != nil {
		t.Fatalf("parseFlags returned error: %v", err)
	}
	if !cfg.InsecureSkipVerify {
		t.Fatalf("expected insecure skip verify to be enabled")
	}
}

func TestParseFlagsSupportsTableDumpDefaults(t *testing.T) {
	cfg, err := parseFlags([]string{
		"--dump-table", "DeviceInfo",
		"--output", "deviceinfo.json",
	}, io.Discard)
	if err != nil {
		t.Fatalf("parseFlags returned error: %v", err)
	}
	if cfg.DumpTable != "DeviceInfo" {
		t.Fatalf("unexpected dump table %q", cfg.DumpTable)
	}
	if cfg.DumpLookback != defaultDumpLookback {
		t.Fatalf("unexpected lookback %q", cfg.DumpLookback)
	}
	if cfg.DumpTimeColumn != "Timestamp" {
		t.Fatalf("unexpected time column %q", cfg.DumpTimeColumn)
	}
	if cfg.DumpRowLimit != defaultDumpRowLimit {
		t.Fatalf("unexpected row limit %d", cfg.DumpRowLimit)
	}
}

func TestParseFlagsRejectsUnsafeTableDumpValues(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "query conflict",
			args: []string{"--dump-table", "DeviceInfo", "--query", "DeviceInfo | limit 1"},
			want: "either -dump-table or -query/-query-file",
		},
		{
			name: "unsafe table",
			args: []string{"--dump-table", "DeviceInfo | take 1"},
			want: "invalid -dump-table",
		},
		{
			name: "unsafe lookback",
			args: []string{"--dump-table", "DeviceInfo", "--dump-lookback", "30d) | take 1"},
			want: "invalid -dump-lookback",
		},
		{
			name: "unsafe time column",
			args: []string{"--dump-table", "DeviceInfo", "--dump-time-column", "Timestamp | take 1"},
			want: "invalid -dump-time-column",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseFlags(tt.args, io.Discard)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected %q error, got %v", tt.want, err)
			}
		})
	}
}

func TestNewHTTPClient(t *testing.T) {
	t.Run("default transport keeps verification enabled", func(t *testing.T) {
		client := newHTTPClient(5*time.Second, false)
		if client.Timeout != 5*time.Second {
			t.Fatalf("unexpected timeout %s", client.Timeout)
		}
		if client.Transport != nil {
			t.Fatalf("expected nil transport when verification is enabled")
		}
	})

	t.Run("insecure mode disables certificate verification", func(t *testing.T) {
		client := newHTTPClient(5*time.Second, true)
		transport, ok := client.Transport.(*http.Transport)
		if !ok {
			t.Fatalf("expected *http.Transport, got %T", client.Transport)
		}
		if transport.TLSClientConfig == nil {
			t.Fatalf("expected TLS config")
		}
		if !transport.TLSClientConfig.InsecureSkipVerify {
			t.Fatalf("expected InsecureSkipVerify to be true")
		}
	})
}

func TestADXArtifactPaths(t *testing.T) {
	dataPath, schemaPath := adxArtifactPaths("/tmp/results.json")
	if dataPath != "/tmp/results.adx.json" {
		t.Fatalf("unexpected data path %q", dataPath)
	}
	if schemaPath != "/tmp/results.adx.kql" {
		t.Fatalf("unexpected schema path %q", schemaPath)
	}
}

func TestOpenGraphArtifactPath(t *testing.T) {
	path := openGraphArtifactPath("/tmp/results.json")
	if path != "/tmp/results.opengraph.json" {
		t.Fatalf("unexpected OpenGraph path %q", path)
	}
}

func TestOpenGraphIconArtifactPath(t *testing.T) {
	path := openGraphIconArtifactPath("/tmp/results.json")
	if path != "/tmp/results.opengraph.icons.json" {
		t.Fatalf("unexpected OpenGraph icon path %q", path)
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

func TestReadQuery(t *testing.T) {
	t.Run("inline query", func(t *testing.T) {
		query, err := readQuery("DeviceInfo | limit 10", "")
		if err != nil {
			t.Fatalf("readQuery returned error: %v", err)
		}
		if query != "DeviceInfo | limit 10" {
			t.Fatalf("unexpected query: %q", query)
		}
	})

	t.Run("query file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "query.kql")
		if err := os.WriteFile(path, []byte("DeviceInfo\n| limit 5\n"), 0o600); err != nil {
			t.Fatalf("write query file: %v", err)
		}

		query, err := readQuery("", path)
		if err != nil {
			t.Fatalf("readQuery returned error: %v", err)
		}
		if query != "DeviceInfo\n| limit 5" {
			t.Fatalf("unexpected query: %q", query)
		}
	})

	t.Run("rejects both", func(t *testing.T) {
		_, err := readQuery("a", "b")
		if err == nil || !strings.Contains(err.Error(), "either -query or -query-file") {
			t.Fatalf("expected mutual exclusion error, got %v", err)
		}
	})
}

func TestResolveAuthMode(t *testing.T) {
	tests := []struct {
		name string
		cfg  authConfig
		want string
	}{
		{
			name: "explicit azcli",
			cfg:  authConfig{AuthMode: "azcli"},
			want: "azcli",
		},
		{
			name: "auto prefers service principal",
			cfg: authConfig{
				AuthMode:     "auto",
				TenantID:     "tenant",
				ClientID:     "client",
				ClientSecret: "secret",
			},
			want: "sp",
		},
		{
			name: "auto falls back to azcli",
			cfg:  authConfig{AuthMode: "auto"},
			want: "azcli",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveAuthMode(tt.cfg); got != tt.want {
				t.Fatalf("resolveAuthMode() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestEnvOrDotEnv(t *testing.T) {
	t.Setenv("AZURE_CLIENT_ID", "from-env")
	got := envOrDotEnv("AZURE_CLIENT_ID", map[string]string{"AZURE_CLIENT_ID": "from-dotenv"})
	if got != "from-env" {
		t.Fatalf("envOrDotEnv() = %q, want %q", got, "from-env")
	}
}

func TestGetServicePrincipalToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method %s", r.Method)
		}
		if got := r.URL.Path; got != "/tenant-id/oauth2/token" {
			t.Fatalf("unexpected path %s", got)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		if got := r.PostForm.Get("resource"); got != defaultResource {
			t.Fatalf("unexpected resource %q", got)
		}
		if got := r.PostForm.Get("client_id"); got != "client-id" {
			t.Fatalf("unexpected client_id %q", got)
		}
		if got := r.PostForm.Get("client_secret"); got != "secret" {
			t.Fatalf("unexpected client_secret %q", got)
		}

		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"access_token":"token-value"}`)
	}))
	defer server.Close()

	cfg := config{
		AuthMode:     "sp",
		TenantID:     "tenant-id",
		ClientID:     "client-id",
		ClientSecret: "secret",
		Resource:     defaultResource,
		LoginBaseURL: server.URL,
	}

	token, err := getServicePrincipalToken(context.Background(), server.Client(), mdeAuthConfig(cfg))
	if err != nil {
		t.Fatalf("getServicePrincipalToken returned error: %v", err)
	}
	if token != "token-value" {
		t.Fatalf("unexpected token %q", token)
	}
}

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

func TestBuildTableDumpQueries(t *testing.T) {
	base := buildTableDumpBaseQuery("DeviceEvents", "Timestamp", "30d")
	if base != "DeviceEvents\n| where Timestamp >= ago(30d)" {
		t.Fatalf("unexpected base query %q", base)
	}
	if got := buildTableDumpCountQuery(base); got != "DeviceEvents\n| where Timestamp >= ago(30d)\n| count" {
		t.Fatalf("unexpected count query %q", got)
	}
	if got := buildTableDumpPartitionCountQuery(base, 4); got != "DeviceEvents\n| where Timestamp >= ago(30d)\n| summarize Count=count() by DumpPartition=hash(tostring(pack_all()), 4)" {
		t.Fatalf("unexpected partition count query %q", got)
	}
	if got := buildTableDumpPartitionQuery(base, 4, 2); got != "DeviceEvents\n| where Timestamp >= ago(30d)\n| where hash(tostring(pack_all()), 4) == 2" {
		t.Fatalf("unexpected partition query %q", got)
	}
}

func TestDumpTableWithoutPartitioning(t *testing.T) {
	var queries []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := readAdvancedQueryRequest(t, r)
		queries = append(queries, query)
		w.Header().Set("Content-Type", "application/json")

		switch query {
		case "DeviceInfo\n| where Timestamp >= ago(30d)\n| count":
			io.WriteString(w, `{"Schema":[{"Name":"Count","Type":"Int64"}],"Results":[{"Count":2}]}`)
		case "DeviceInfo\n| where Timestamp >= ago(30d)":
			io.WriteString(w, `{"Schema":[{"Name":"DeviceName","Type":"String"}],"Results":[{"DeviceName":"host1"},{"DeviceName":"host2"}]}`)
		default:
			t.Fatalf("unexpected query %q", query)
		}
	}))
	defer server.Close()

	cfg := config{
		Endpoint:        server.URL,
		DumpTable:       "DeviceInfo",
		DumpLookback:    "30d",
		DumpTimeColumn:  "Timestamp",
		DumpRowLimit:    defaultDumpRowLimit,
		DumpParallelism: 2,
		Output:          filepath.Join(t.TempDir(), "deviceinfo.json"),
	}

	output, err := dumpTable(context.Background(), server.Client(), cfg, "token-value", io.Discard)
	if err != nil {
		t.Fatalf("dumpTable returned error: %v", err)
	}
	if output.Rows != 2 {
		t.Fatalf("unexpected row count %d", output.Rows)
	}
	if output.Stats.TotalRows != 2 || output.Stats.Chunks != 1 || output.Stats.Partitions != 1 {
		t.Fatalf("unexpected stats %#v", output.Stats)
	}
	if len(queries) != 2 {
		t.Fatalf("unexpected query count %d", len(queries))
	}
	content, err := os.ReadFile(cfg.Output)
	if err != nil {
		t.Fatalf("read output file: %v", err)
	}
	var written queryResponse
	if err := json.Unmarshal(content, &written); err != nil {
		t.Fatalf("decode written output: %v", err)
	}
	if len(written.Results) != 2 {
		t.Fatalf("unexpected written row count %d", len(written.Results))
	}
}

func TestDumpTableWithHashPartitioning(t *testing.T) {
	var mu sync.Mutex
	seenChunkQueries := map[string]bool{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := readAdvancedQueryRequest(t, r)
		w.Header().Set("Content-Type", "application/json")

		switch {
		case query == "DeviceEvents\n| where Timestamp >= ago(7d)\n| count":
			io.WriteString(w, `{"Schema":[{"Name":"Count","Type":"Int64"}],"Results":[{"Count":60001}]}`)
		case query == "DeviceEvents\n| where Timestamp >= ago(7d)\n| summarize Count=count() by DumpPartition=hash(tostring(pack_all()), 3)":
			io.WriteString(w, `{"Schema":[{"Name":"DumpPartition","Type":"Int64"},{"Name":"Count","Type":"Int64"}],"Results":[{"DumpPartition":0,"Count":20000},{"DumpPartition":1,"Count":20001},{"DumpPartition":2,"Count":20000}]}`)
		case strings.Contains(query, "| where hash(tostring(pack_all()), 3) == 0"):
			mu.Lock()
			seenChunkQueries["0"] = true
			mu.Unlock()
			io.WriteString(w, `{"Schema":[{"Name":"EventId","Type":"String"}],"Results":[{"EventId":"partition-0"}]}`)
		case strings.Contains(query, "| where hash(tostring(pack_all()), 3) == 1"):
			mu.Lock()
			seenChunkQueries["1"] = true
			mu.Unlock()
			io.WriteString(w, `{"Schema":[{"Name":"EventId","Type":"String"}],"Results":[{"EventId":"partition-1"}]}`)
		case strings.Contains(query, "| where hash(tostring(pack_all()), 3) == 2"):
			mu.Lock()
			seenChunkQueries["2"] = true
			mu.Unlock()
			io.WriteString(w, `{"Schema":[{"Name":"EventId","Type":"String"}],"Results":[{"EventId":"partition-2"}]}`)
		default:
			t.Fatalf("unexpected query %q", query)
		}
	}))
	defer server.Close()

	cfg := config{
		Endpoint:        server.URL,
		DumpTable:       "DeviceEvents",
		DumpLookback:    "7d",
		DumpTimeColumn:  "Timestamp",
		DumpRowLimit:    defaultDumpRowLimit,
		DumpParallelism: 2,
		Output:          filepath.Join(t.TempDir(), "deviceevents.json"),
		ADXExport:       true,
	}

	var progress bytes.Buffer
	output, err := dumpTable(context.Background(), server.Client(), cfg, "token-value", &progress)
	if err != nil {
		t.Fatalf("dumpTable returned error: %v", err)
	}
	if output.Rows != 3 {
		t.Fatalf("unexpected row count %d", output.Rows)
	}
	if output.Stats.TotalRows != 60001 || output.Stats.Chunks != 3 || output.Stats.Partitions != 3 {
		t.Fatalf("unexpected stats %#v", output.Stats)
	}
	for _, partition := range []string{"0", "1", "2"} {
		if !seenChunkQueries[partition] {
			t.Fatalf("partition %s was not queried", partition)
		}
	}
	content, err := os.ReadFile(cfg.Output)
	if err != nil {
		t.Fatalf("read output file: %v", err)
	}
	var written queryResponse
	if err := json.Unmarshal(content, &written); err != nil {
		t.Fatalf("decode written output: %v", err)
	}
	if len(written.Results) != 3 {
		t.Fatalf("unexpected written row count %d", len(written.Results))
	}
	if output.ADXDataPath == "" || output.ADXSchemaPath == "" {
		t.Fatalf("expected ADX artifact paths, got %#v", output)
	}
	adxContent, err := os.ReadFile(output.ADXDataPath)
	if err != nil {
		t.Fatalf("read streamed ADX data file: %v", err)
	}
	if got := strings.Count(strings.TrimSpace(string(adxContent)), "\n") + 1; got != 3 {
		t.Fatalf("unexpected ADX row count %d", got)
	}
	schemaContent, err := os.ReadFile(output.ADXSchemaPath)
	if err != nil {
		t.Fatalf("read streamed ADX schema file: %v", err)
	}
	if !strings.Contains(string(schemaContent), "deviceevents.adx.json") {
		t.Fatalf("unexpected ADX schema content %s", string(schemaContent))
	}
	seenRows := map[string]bool{}
	for _, row := range written.Results {
		seenRows[fmt.Sprint(row["EventId"])] = true
	}
	for i := 0; i < 3; i++ {
		want := "partition-" + strconv.Itoa(i)
		if !seenRows[want] {
			t.Fatalf("missing row %q in %#v", want, written.Results)
		}
	}

	progressText := progress.String()
	for _, want := range []string{
		"counting rows in DeviceEvents over 7d",
		"found 60001 row(s) to dump",
		"counting rows across 3 hash partition(s)",
		"dumping 3 non-empty partition chunk(s)",
		"streaming results to",
		"completed partition",
		"completed partitioned dump with 3 row(s)",
	} {
		if !strings.Contains(progressText, want) {
			t.Fatalf("expected progress to contain %q, got:\n%s", want, progressText)
		}
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

func TestWriteJSONFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "results.json")

	err := writeJSONFile(path, []byte(`{"Results":[{"A":1}]}`))
	if err != nil {
		t.Fatalf("writeJSONFile returned error: %v", err)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read output file: %v", err)
	}
	if !strings.Contains(string(content), "\n  \"Results\"") {
		t.Fatalf("expected indented JSON, got %s", string(content))
	}
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

func TestWriteOpenGraphArtifactForAlertNodes(t *testing.T) {
	dir := t.TempDir()
	cfg := config{
		Output: filepath.Join(dir, "results.json"),
	}
	response := queryResponse{
		Schema: []queryColumn{
			{Name: "id", Type: "String"},
			{Name: "type", Type: "String"},
			{Name: "label", Type: "String"},
			{Name: "timestamp", Type: "DateTime"},
			{Name: "properties", Type: "Object"},
		},
		Results: []map[string]any{
			{
				"id":        "device-1",
				"type":      "Machine",
				"label":     "ws1.contoso.local",
				"timestamp": "2026-04-08T10:00:00Z",
				"properties": map[string]any{
					"accountName": "svc-backup",
					"rawData": map[string]any{
						"Severity": "High",
						"objectId": "abc-123",
					},
				},
			},
		},
	}

	path, iconPath, err := writeOpenGraphArtifact(cfg, response)
	if err != nil {
		t.Fatalf("writeOpenGraphArtifact returned error: %v", err)
	}
	if path != filepath.Join(dir, "results.opengraph.json") {
		t.Fatalf("unexpected OpenGraph output path %q", path)
	}
	if iconPath != filepath.Join(dir, "results.opengraph.icons.json") {
		t.Fatalf("unexpected OpenGraph icon path %q", iconPath)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read OpenGraph output: %v", err)
	}

	var payload openGraphPayload
	if err := json.Unmarshal(content, &payload); err != nil {
		t.Fatalf("decode OpenGraph output: %v", err)
	}
	if len(payload.Graph.Nodes) != 1 {
		t.Fatalf("unexpected node count %d", len(payload.Graph.Nodes))
	}
	if len(payload.Graph.Edges) != 0 {
		t.Fatalf("unexpected edge count %d", len(payload.Graph.Edges))
	}

	node := payload.Graph.Nodes[0]
	if node.ID != "device-1" {
		t.Fatalf("unexpected node id %q", node.ID)
	}
	if got := node.Kinds[0]; got != "Machine" {
		t.Fatalf("unexpected node kind %q", got)
	}
	if got := node.Properties["displayname"]; got != "ws1.contoso.local" {
		t.Fatalf("unexpected displayname %#v", got)
	}
	if got := node.Properties["accountname"]; got != "svc-backup" {
		t.Fatalf("unexpected flattened property %#v", got)
	}
	if got := node.Properties["rawdata_severity"]; got != "High" {
		t.Fatalf("unexpected nested property %#v", got)
	}
	if got := node.Properties["rawdata_source_objectid"]; got != "abc-123" {
		t.Fatalf("unexpected reserved property rename %#v", got)
	}

	iconContent, err := os.ReadFile(iconPath)
	if err != nil {
		t.Fatalf("read OpenGraph icon output: %v", err)
	}

	var iconPayload openGraphCustomNodePayload
	if err := json.Unmarshal(iconContent, &iconPayload); err != nil {
		t.Fatalf("decode OpenGraph icon output: %v", err)
	}
	if got := iconPayload.CustomTypes["Machine"].Icon.Name; got != "desktop" {
		t.Fatalf("unexpected machine icon %#v", got)
	}
}

func TestBuildOpenGraphPayloadForExposureGraphEdges(t *testing.T) {
	response := queryResponse{
		Schema: []queryColumn{
			{Name: "EdgeId", Type: "String"},
			{Name: "EdgeLabel", Type: "String"},
			{Name: "SourceNodeId", Type: "String"},
			{Name: "SourceNodeName", Type: "String"},
			{Name: "SourceNodeLabel", Type: "String"},
			{Name: "SourceNodeCategories", Type: "Object"},
			{Name: "TargetNodeId", Type: "String"},
			{Name: "TargetNodeName", Type: "String"},
			{Name: "TargetNodeLabel", Type: "String"},
			{Name: "TargetNodeCategories", Type: "Object"},
			{Name: "EdgeProperties", Type: "Object"},
		},
		Results: []map[string]any{
			{
				"EdgeId":               "edge-1",
				"EdgeLabel":            "has role on",
				"SourceNodeId":         "group-1",
				"SourceNodeName":       "Enterprise Admins",
				"SourceNodeLabel":      "group",
				"SourceNodeCategories": []any{"identity", "user_group"},
				"TargetNodeId":         "group-2",
				"TargetNodeName":       "Tier Zero",
				"TargetNodeLabel":      "group",
				"TargetNodeCategories": []any{"identity", "user_group"},
				"EdgeProperties": map[string]any{
					"rawData": map[string]any{
						"controlTypes": []any{"genericAll"},
					},
				},
			},
		},
	}

	payload, err := buildOpenGraphPayload(response)
	if err != nil {
		t.Fatalf("buildOpenGraphPayload returned error: %v", err)
	}
	if len(payload.Graph.Edges) != 1 {
		t.Fatalf("unexpected edge count %d", len(payload.Graph.Edges))
	}
	if len(payload.Graph.Nodes) != 2 {
		t.Fatalf("unexpected synthesized node count %d", len(payload.Graph.Nodes))
	}

	edge := payload.Graph.Edges[0]
	if edge.Kind != "has_role_on" {
		t.Fatalf("unexpected edge kind %q", edge.Kind)
	}
	if edge.Start.Value != "group-1" || edge.End.Value != "group-2" {
		t.Fatalf("unexpected edge refs %#v", edge)
	}
	if got := edge.Properties["rawdata_controltypes"].([]any)[0]; got != "genericAll" {
		t.Fatalf("unexpected flattened edge property %#v", edge.Properties["rawdata_controltypes"])
	}

	sourceNode := payload.Graph.Nodes[0]
	if sourceNode.ID != "group-1" {
		t.Fatalf("unexpected source node id %q", sourceNode.ID)
	}
	if got := sourceNode.Kinds[0]; got != "group" {
		t.Fatalf("unexpected source node kind %q", got)
	}
	if got := sourceNode.Properties["displayname"]; got != "Enterprise Admins" {
		t.Fatalf("unexpected source node name %#v", got)
	}
}

func TestBuildOpenGraphPayloadForMixedNodeAndEdgeRows(t *testing.T) {
	response := queryResponse{
		Results: []map[string]any{
			{
				"id":        "alert-1",
				"type":      "Alert",
				"label":     "Suspicious admin activity",
				"timestamp": "2026-04-08T10:00:00Z",
				"properties": map[string]any{
					"severity": "High",
				},
			},
			{
				"id":        "user-1",
				"type":      "User",
				"label":     "ballpit\\monkey-adm",
				"timestamp": "2026-04-08T10:00:00Z",
				"properties": map[string]any{
					"accountName": "monkey-adm",
				},
			},
			{
				"id":        "alert-1_alertimpacted_user-1",
				"sourceId":  "alert-1",
				"targetId":  "user-1",
				"type":      "AlertImpacted",
				"edgeType":  "AlertImpacted",
				"label":     "Impacted",
				"weight":    1.0,
				"timestamp": "2026-04-08T10:00:00Z",
				"properties": map[string]any{
					"relationship": "AlertImpacted",
				},
			},
		},
	}

	payload, err := buildOpenGraphPayload(response)
	if err != nil {
		t.Fatalf("buildOpenGraphPayload returned error: %v", err)
	}
	if len(payload.Graph.Nodes) != 2 {
		t.Fatalf("unexpected node count %d", len(payload.Graph.Nodes))
	}
	if len(payload.Graph.Edges) != 1 {
		t.Fatalf("unexpected edge count %d", len(payload.Graph.Edges))
	}
	if payload.Graph.Edges[0].Start.Value != "alert-1" || payload.Graph.Edges[0].End.Value != "user-1" {
		t.Fatalf("unexpected edge refs %#v", payload.Graph.Edges[0])
	}
}

func TestBuildOpenGraphPayloadRejectsUnsupportedShape(t *testing.T) {
	_, err := buildOpenGraphPayload(queryResponse{
		Schema: []queryColumn{
			{Name: "DeviceName", Type: "String"},
			{Name: "Timestamp", Type: "DateTime"},
		},
		Results: []map[string]any{
			{"DeviceName": "host1", "Timestamp": "2026-04-08T10:00:00Z"},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "supported OpenGraph node or edge shape") {
		t.Fatalf("expected unsupported shape error, got %v", err)
	}
}

func TestBuildOpenGraphCustomNodePayload(t *testing.T) {
	payload := openGraphPayload{
		Graph: openGraphGraph{
			Nodes: []openGraphNode{
				{ID: "1", Kinds: []string{"Alert"}},
				{ID: "2", Kinds: []string{"Machine"}},
				{ID: "3", Kinds: []string{"User"}},
				{ID: "4", Kinds: []string{"CustomThing"}},
			},
		},
	}

	iconPayload := buildOpenGraphCustomNodePayload(payload)
	if len(iconPayload.CustomTypes) != 4 {
		t.Fatalf("unexpected custom type count %d", len(iconPayload.CustomTypes))
	}
	if got := iconPayload.CustomTypes["Alert"].Icon.Name; got != "triangle-exclamation" {
		t.Fatalf("unexpected alert icon %#v", got)
	}
	if got := iconPayload.CustomTypes["Machine"].Icon.Name; got != "desktop" {
		t.Fatalf("unexpected machine icon %#v", got)
	}
	if got := iconPayload.CustomTypes["User"].Icon.Name; got != "user" {
		t.Fatalf("unexpected user icon %#v", got)
	}
	if got := iconPayload.CustomTypes["CustomThing"].Icon.Name; got != "circle-question" {
		t.Fatalf("unexpected fallback icon %#v", got)
	}
}

func TestUploadFileToBloodHound(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "graph.opengraph.json")
	if err := os.WriteFile(path, []byte(`{"graph":{"nodes":[],"edges":[]}}`), 0o600); err != nil {
		t.Fatalf("write graph file: %v", err)
	}

	var startCalls int
	var endCalls int
	var uploadCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/file-upload/start":
			startCalls++
			if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
				t.Fatalf("unexpected auth header %q", got)
			}
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"data":{"id":42}}`)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/file-upload/42":
			uploadCalls++
			if got := r.Header.Get("X-File-Upload-Name"); got != "graph.opengraph.json" {
				t.Fatalf("unexpected upload filename %q", got)
			}
			if got := r.Header.Get("Content-Type"); got != "application/json" {
				t.Fatalf("unexpected content type %q", got)
			}
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("read upload body: %v", err)
			}
			if string(body) != `{"graph":{"nodes":[],"edges":[]}}` {
				t.Fatalf("unexpected upload body %s", string(body))
			}
			w.WriteHeader(http.StatusAccepted)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/file-upload/42/end":
			endCalls++
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"data":{"id":42}}`)
		default:
			t.Fatalf("unexpected path %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := config{
		BloodHoundURL:   server.URL,
		BloodHoundToken: "test-token",
	}

	jobID, err := uploadFileToBloodHound(context.Background(), server.Client(), cfg, path)
	if err != nil {
		t.Fatalf("uploadFileToBloodHound returned error: %v", err)
	}
	if jobID != 42 {
		t.Fatalf("unexpected job id %d", jobID)
	}
	if startCalls != 1 || uploadCalls != 1 || endCalls != 1 {
		t.Fatalf("unexpected call counts start=%d upload=%d end=%d", startCalls, uploadCalls, endCalls)
	}
}

func TestUploadCustomNodesToBloodHound(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "graph.opengraph.icons.json")
	payload := openGraphCustomNodePayload{
		CustomTypes: map[string]openGraphCustomNodeConfig{
			"Machine": {Icon: openGraphCustomNodeIcon{Type: "font-awesome", Name: "desktop", Color: "#2563EB"}},
			"User":    {Icon: openGraphCustomNodeIcon{Type: "font-awesome", Name: "user", Color: "#16A34A"}},
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal icon payload: %v", err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write icon file: %v", err)
	}

	var createBody openGraphCustomNodePayload
	var updateBody bloodHoundCustomNodeUpdateRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/custom-nodes":
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"data":[{"kindName":"User","config":{"icon":{"type":"font-awesome","name":"user"}}}]}`)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/custom-nodes":
			if err := json.NewDecoder(r.Body).Decode(&createBody); err != nil {
				t.Fatalf("decode create body: %v", err)
			}
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"data":{}}`)
		case r.Method == http.MethodPut && r.URL.Path == "/api/v2/custom-nodes/User":
			if err := json.NewDecoder(r.Body).Decode(&updateBody); err != nil {
				t.Fatalf("decode update body: %v", err)
			}
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"data":{}}`)
		default:
			t.Fatalf("unexpected path %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	cfg := config{
		BloodHoundURL:   server.URL,
		BloodHoundToken: "test-token",
	}

	created, updated, err := uploadCustomNodesToBloodHound(context.Background(), server.Client(), cfg, path)
	if err != nil {
		t.Fatalf("uploadCustomNodesToBloodHound returned error: %v", err)
	}
	if created != 1 || updated != 1 {
		t.Fatalf("unexpected create/update counts %d/%d", created, updated)
	}
	if _, ok := createBody.CustomTypes["Machine"]; !ok {
		t.Fatalf("expected Machine in create payload %#v", createBody)
	}
	if updateBody.Config.Icon.Name != "user" {
		t.Fatalf("unexpected update payload %#v", updateBody)
	}
}

func TestAuthorizeBloodHoundRequestWithSignedAuth(t *testing.T) {
	cfg := config{
		BloodHoundTokenID:  "token-id",
		BloodHoundTokenKey: base64.StdEncoding.EncodeToString([]byte("super-secret-key")),
	}
	body := []byte(`{"graph":{"nodes":[],"edges":[]}}`)

	req, err := http.NewRequest(http.MethodPost, "https://bloodhound.example/api/v2/file-upload/42", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}

	if err := authorizeBloodHoundRequest(req, cfg, body); err != nil {
		t.Fatalf("authorizeBloodHoundRequest returned error: %v", err)
	}

	if got := req.Header.Get("Authorization"); got != "bhesignature token-id" {
		t.Fatalf("unexpected authorization header %q", got)
	}
	if req.Header.Get("RequestDate") == "" {
		t.Fatalf("expected request date header")
	}
	wantSig, err := buildBloodHoundRequestSignature(cfg.BloodHoundTokenKey, req.Header.Get("RequestDate"), http.MethodPost, "/api/v2/file-upload/42", body)
	if err != nil {
		t.Fatalf("buildBloodHoundRequestSignature returned error: %v", err)
	}
	if got := req.Header.Get("Signature"); got != wantSig {
		t.Fatalf("unexpected signature %q want %q", got, wantSig)
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
