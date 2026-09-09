package app

import (
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

func TestPartitionKeyUsesOrderedScalarsAndExcludesBags(t *testing.T) {
	first, err := newQueryPartitionKey([]queryColumn{{"Timestamp", "DateTime"}, {"Payload", "Dynamic"}, {"EventId", "String"}, {"Count", "Int64"}})
	if err != nil {
		t.Fatal(err)
	}
	reordered, err := newQueryPartitionKey([]queryColumn{{"Count", "long"}, {"EventId", "String"}, {"Payload", "Dynamic"}, {"Timestamp", "DateTime"}})
	if err != nil {
		t.Fatal(err)
	}
	if first.expression != reordered.expression || len(first.columns) != 3 {
		t.Fatalf("key depends on schema order: %s versus %s", first.expression, reordered.expression)
	}
	if strings.Contains(first.expression, "Payload") || strings.Contains(first.expression, "pack_all") {
		t.Fatal("dynamic bag participates in partition key")
	}
	if !(strings.Index(first.expression, "Count") < strings.Index(first.expression, "EventId") && strings.Index(first.expression, "EventId") < strings.Index(first.expression, "Timestamp")) {
		t.Fatal("scalar columns are not in canonical order")
	}
	if err := first.validateSchema([]queryColumn{{"EventId", "String"}, {"Count", "long"}, {"Timestamp", "DateTime"}, {"Payload", "Dynamic"}}); err != nil {
		t.Fatal(err)
	}
	for _, schema := range [][]queryColumn{{{"EventId", "String"}}, {{"EventId", "Dynamic"}, {"Count", "Int64"}, {"Timestamp", "DateTime"}}} {
		if err := first.validateSchema(schema); err == nil {
			t.Fatal("changed key schema was accepted")
		}
	}
}

func TestPartitionKeyRejectsUnknownOrAmbiguousSchemas(t *testing.T) {
	for _, schema := range [][]queryColumn{nil, {{"Payload", "Dynamic"}}, {{"Value", "Unknown"}}, {{"Value", "String"}, {"Value", "Int64"}}, {{"", "String"}}} {
		if _, err := newQueryPartitionKey(schema); err == nil {
			t.Fatalf("unsafe schema accepted: %v", schema)
		}
	}
	key, err := newQueryPartitionKey([]queryColumn{{"odd\"column\\name] | take 1 //", "String"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(key.expression, `["odd\"column\\name] | take 1 //"]`) {
		t.Fatalf("column name not safely quoted: %s", key.expression)
	}
}

func TestPartitionCountsRequireCompleteUniqueInRangeBuckets(t *testing.T) {
	for _, counts := range [][]partitionCount{nil, {{0, 2}}, {{0, 2}, {0, 2}}, {{-1, 2}, {1, 2}}, {{0, 2}, {2, 2}}, {{0, -1}, {1, 5}}, {{0, 3}, {1, 2}}} {
		if err := validatePartitionCounts(counts, 2, 4); err == nil {
			t.Fatalf("invalid counts accepted: %v", counts)
		}
	}
	if err := validatePartitionCounts([]partitionCount{{1, 2}, {0, 2}}, 2, 4); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{`{"DumpPartition":0,"Count":0}`, `{"DumpPartition":0,"Count":-1}`, `{"DumpPartition":null,"Count":2}`} {
		var row map[string]any
		if err := json.Unmarshal([]byte(raw), &row); err != nil {
			t.Fatal(err)
		}
		if _, err := parsePartitionCountsResponse(queryResponse{Results: []map[string]any{row}}); err == nil {
			t.Fatal("malformed bucket accepted")
		}
	}
}

func TestPartitionFailurePreservesPublishedArtifacts(t *testing.T) {
	for _, failure := range []string{"missing rows", "extra rows", "changed key type", "missing key schema", "count mismatch", "dynamic only"} {
		t.Run(failure, func(t *testing.T) {
			dir := t.TempDir()
			output := filepath.Join(dir, "results.json")
			dataPath, schemaPath := adxArtifactPaths(output)
			for _, path := range []string{output, dataPath, schemaPath} {
				if err := os.WriteFile(path, []byte("previous complete artifact"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				query := readAdvancedQueryRequest(t, r)
				w.Header().Set("Content-Type", "application/json")
				switch {
				case strings.HasSuffix(query, "\n| count"):
					io.WriteString(w, `{"Results":[{"Count":4}]}`)
				case strings.HasSuffix(query, "\n| take 0"):
					typ := "String"
					if failure == "dynamic only" {
						typ = "Dynamic"
					}
					fmt.Fprintf(w, `{"Schema":[{"Name":"EventId","Type":%q}],"Results":[]}`, typ)
				case strings.Contains(query, "| summarize"):
					n := 2
					if failure == "count mismatch" {
						n = 1
					}
					fmt.Fprintf(w, `{"Results":[{"DumpPartition":0,"Count":2},{"DumpPartition":1,"Count":%d}]}`, n)
				case strings.HasSuffix(query, "== 0"):
					io.WriteString(w, `{"Schema":[{"Name":"EventId","Type":"String"}],"Results":[{"EventId":"a"},{"EventId":"b"}]}`)
				case strings.HasSuffix(query, "== 1"):
					rows := []map[string]any{{"EventId": "c"}, {"EventId": "d"}}
					schema := []queryColumn{{"EventId", "String"}}
					switch failure {
					case "missing rows":
						rows = rows[:1]
					case "extra rows":
						rows = append(rows, map[string]any{"EventId": "extra"})
					case "changed key type":
						schema[0].Type = "Dynamic"
					case "missing key schema":
						schema = nil
					}
					if err := json.NewEncoder(w).Encode(queryResponse{Schema: schema, Results: rows}); err != nil {
						t.Error(err)
					}
				default:
					t.Errorf("unexpected query %q", query)
					http.Error(w, "unexpected", 500)
				}
			}))
			defer server.Close()
			_, err := dumpQuery(context.Background(), server.Client(), config{Endpoint: server.URL, Output: output, DumpRowLimit: 3, ADXExport: true}, "token-value", "Events", nil, io.Discard)
			if err == nil {
				t.Fatal("incomplete/unsafe partitioning succeeded")
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 3 {
				t.Fatalf("temporary files left behind: %v", entries)
			}
			for _, path := range []string{output, dataPath, schemaPath} {
				body, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if string(body) != "previous complete artifact" {
					t.Fatalf("published artifact replaced on failure: %s", path)
				}
			}
		})
	}
}

func TestPartitionRetryReusesResolvedKey(t *testing.T) {
	schemas := 0
	downloads := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := readAdvancedQueryRequest(t, r)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(query, "\n| count"):
			io.WriteString(w, `{"Results":[{"Count":4}]}`)
		case strings.HasSuffix(query, "\n| take 0"):
			schemas++
			io.WriteString(w, `{"Schema":[{"Name":"EventId","Type":"String"},{"Name":"Bag","Type":"Dynamic"}],"Results":[]}`)
		case strings.Contains(query, "| summarize"):
			if !strings.Contains(query, `hash_sha256(tostring(pack_array(tostring(["EventId"]))))`) || strings.Contains(query, `["Bag"]`) {
				t.Errorf("wrong partition key: %s", query)
			}
			if strings.Contains(query, "% 2)") {
				io.WriteString(w, `{"Results":[{"DumpPartition":0,"Count":4}]}`)
			} else {
				io.WriteString(w, `{"Results":[{"DumpPartition":0,"Count":2},{"DumpPartition":1,"Count":2}]}`)
			}
		case strings.Contains(query, "| where"):
			downloads++
			if !strings.Contains(query, "% 4)") {
				t.Error("download used stale bucket count")
			}
			fmt.Fprintf(w, `{"Schema":[{"Name":"Bag","Type":"Dynamic"},{"Name":"EventId","Type":"String"}],"Results":[{"EventId":"%d-a","Bag":{"b":2,"a":1}},{"EventId":"%d-b","Bag":{"a":1,"b":2}}]}`, downloads, downloads)
		default:
			t.Errorf("unexpected query: %s", query)
			http.Error(w, "unexpected", 500)
		}
	}))
	defer server.Close()
	out, err := dumpQuery(context.Background(), server.Client(), config{Endpoint: server.URL, DumpRowLimit: 4, Output: filepath.Join(t.TempDir(), "results.json")}, "token-value", "Events", nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if schemas != 1 || downloads != 2 || out.Rows != 4 || out.Stats.Partitions != 4 {
		t.Fatalf("unexpected retry behavior: schemas=%d downloads=%d output=%v", schemas, downloads, out)
	}
}

func TestIndivisibleScalarKeysFailWithinBoundedRequests(t *testing.T) {
	counts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := readAdvancedQueryRequest(t, r)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(query, "\n| count"):
			io.WriteString(w, `{"Results":[{"Count":4}]}`)
		case strings.HasSuffix(query, "\n| take 0"):
			io.WriteString(w, `{"Schema":[{"Name":"SameKey","Type":"String"},{"Name":"Payload","Type":"Dynamic"}],"Results":[]}`)
		case strings.Contains(query, "| summarize"):
			counts++
			io.WriteString(w, `{"Results":[{"DumpPartition":0,"Count":4}]}`)
		default:
			t.Errorf("indivisible result must not be downloaded: %s", query)
			http.Error(w, "unexpected", 500)
		}
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "results.json")
	_, err := dumpQuery(context.Background(), server.Client(), config{Endpoint: server.URL, DumpRowLimit: 4, Output: path}, "token-value", "Events", nil, io.Discard)
	if err == nil || counts != 2 {
		t.Fatalf("expected bounded partition failure, got %v after %d counts", err, counts)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("indivisible query published a file")
	}
}
