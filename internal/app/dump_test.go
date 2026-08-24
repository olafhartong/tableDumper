package app

import (
	"bytes"
	"context"
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
)

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
