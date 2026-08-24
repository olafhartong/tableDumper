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
	"strings"
	"testing"
)

func TestPartitionableQueryRemovesTrailingSemicolons(t *testing.T) {
	query := "  let recent = DeviceEvents | where Timestamp > ago(1d);\nrecent | project DeviceId;;  "
	want := "let recent = DeviceEvents | where Timestamp > ago(1d);\nrecent | project DeviceId"
	if got := partitionableQuery(query); got != want {
		t.Fatalf("partitionableQuery() = %q, want %q", got, want)
	}
}

func TestDumpQueryWithHashPartitioning(t *testing.T) {
	baseQuery := "DeviceProcessEvents\n| project EventId"
	var chunkQueries []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := readAdvancedQueryRequest(t, r)
		w.Header().Set("Content-Type", "application/json")
		switch query {
		case baseQuery + "\n| count":
			io.WriteString(w, `{"Results":[{"Count":5}]}`)
		case baseQuery + "\n| summarize Count=count() by DumpPartition=hash(tostring(pack_all()), 2)":
			io.WriteString(w, `{"Results":[{"DumpPartition":0,"Count":2},{"DumpPartition":1,"Count":3}]}`)
		case baseQuery + "\n| where hash(tostring(pack_all()), 2) == 0":
			chunkQueries = append(chunkQueries, query)
			io.WriteString(w, `{"Schema":[{"Name":"EventId","Type":"String"}],"Results":[{"EventId":"event-0"},{"EventId":"event-2"}]}`)
		case baseQuery + "\n| where hash(tostring(pack_all()), 2) == 1":
			chunkQueries = append(chunkQueries, query)
			io.WriteString(w, `{"Schema":[{"Name":"EventId","Type":"String"}],"Results":[{"EventId":"event-1"},{"EventId":"event-3"},{"EventId":"event-4"}]}`)
		default:
			t.Fatalf("unexpected query %q", query)
		}
	}))
	defer server.Close()

	cfg := config{
		Endpoint:        server.URL,
		DumpRowLimit:    4,
		Output:          filepath.Join(t.TempDir(), "query-results.json"),
		DumpParallelism: 1,
	}
	var progress bytes.Buffer
	output, err := dumpQuery(context.Background(), server.Client(), cfg, "token-value", baseQuery+";", nil, &progress)
	if err != nil {
		t.Fatalf("dumpQuery returned error: %v", err)
	}
	if output.Rows != 5 || output.Stats.TotalRows != 5 || output.Stats.Chunks != 2 || output.Stats.Partitions != 2 {
		t.Fatalf("unexpected output %#v", output)
	}
	if len(chunkQueries) != 2 {
		t.Fatalf("unexpected chunk query count %d", len(chunkQueries))
	}

	body, err := os.ReadFile(cfg.Output)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	var response queryResponse
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("decode output: %v", err)
	}
	if len(response.Results) != 5 {
		t.Fatalf("unexpected result count %d: %s", len(response.Results), body)
	}
	seen := make(map[string]bool, len(response.Results))
	for _, row := range response.Results {
		seen[fmt.Sprint(row["EventId"])] = true
	}
	for i := 0; i < 5; i++ {
		if !seen[fmt.Sprintf("event-%d", i)] {
			t.Errorf("missing event-%d", i)
		}
	}
	for _, want := range []string{
		"counting rows returned by query",
		"query returns 5 row(s)",
		"calculating hash partitions",
		"dumping 2 non-empty partition chunk(s) sequentially",
		"completed partitioned query with 5 row(s)",
	} {
		if !strings.Contains(progress.String(), want) {
			t.Errorf("progress missing %q:\n%s", want, progress.String())
		}
	}
}

func TestDumpQueryFallsBackWhenSmallResultExceedsByteLimit(t *testing.T) {
	baseQuery := "DeviceEvents\n| project Payload"
	attemptedUnpartitioned := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := readAdvancedQueryRequest(t, r)
		w.Header().Set("Content-Type", "application/json")
		switch query {
		case baseQuery + "\n| count":
			io.WriteString(w, `{"Results":[{"Count":2}]}`)
		case baseQuery:
			attemptedUnpartitioned = true
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, `{"error":{"code":"BadRequest","message":"Query execution has exceeded the allowed result size. Optimize your query by limiting the amount of results and try again."}}`)
		case baseQuery + "\n| summarize Count=count() by DumpPartition=hash(tostring(pack_all()), 2)":
			io.WriteString(w, `{"Results":[{"DumpPartition":0,"Count":1},{"DumpPartition":1,"Count":1}]}`)
		case baseQuery + "\n| where hash(tostring(pack_all()), 2) == 0":
			io.WriteString(w, `{"Results":[{"Payload":"first"}]}`)
		case baseQuery + "\n| where hash(tostring(pack_all()), 2) == 1":
			io.WriteString(w, `{"Results":[{"Payload":"second"}]}`)
		default:
			t.Fatalf("unexpected query %q", query)
		}
	}))
	defer server.Close()

	cfg := config{
		Endpoint:     server.URL,
		DumpRowLimit: 10,
		Output:       filepath.Join(t.TempDir(), "wide-query-results.json"),
	}
	var progress bytes.Buffer
	output, err := dumpQuery(context.Background(), server.Client(), cfg, "token-value", baseQuery, nil, &progress)
	if err != nil {
		t.Fatalf("dumpQuery returned error: %v", err)
	}
	if !attemptedUnpartitioned {
		t.Fatal("unpartitioned query was not attempted")
	}
	if output.Rows != 2 || output.Stats.Chunks != 2 || output.Stats.Partitions != 2 {
		t.Fatalf("unexpected output %#v", output)
	}
	if !strings.Contains(progress.String(), "unpartitioned query exceeded the service result-size limit") {
		t.Fatalf("fallback was not reported in progress:\n%s", progress.String())
	}
}
