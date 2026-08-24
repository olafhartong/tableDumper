package app

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type tableDumpStats struct {
	TotalRows  int
	Chunks     int
	Partitions int
}

type tableDumpOutput struct {
	Schema        []queryColumn
	Rows          int
	Stats         tableDumpStats
	Response      queryResponse
	ADXDataPath   string
	ADXSchemaPath string
}

type partitionCount struct {
	Partition int
	Rows      int
}

func dumpTable(ctx context.Context, httpClient *http.Client, cfg config, token string, pseudonyms *pseudonymizer, progress io.Writer) (tableDumpOutput, error) {
	baseQuery := buildTableDumpBaseQuery(cfg.DumpTable, cfg.DumpTimeColumn, cfg.DumpLookback)
	progressf(progress, "[-] counting rows in %s over %s...", cfg.DumpTable, cfg.DumpLookback)
	_, countResponse, err := runAdvancedQueryWithProgress(ctx, httpClient, cfg.Endpoint, token, buildTableDumpCountQuery(baseQuery), progress)
	if err != nil {
		return tableDumpOutput{}, fmt.Errorf("count rows in %s: %w", cfg.DumpTable, err)
	}

	totalRows, err := parseCountResponse(countResponse)
	if err != nil {
		return tableDumpOutput{}, fmt.Errorf("parse row count for %s: %w", cfg.DumpTable, err)
	}

	stats := tableDumpStats{TotalRows: totalRows}
	progressf(progress, "[i] found %d row(s) to dump from %s", totalRows, cfg.DumpTable)
	if totalRows < cfg.DumpRowLimit {
		progressf(progress, "[i] row count is below %d; dumping in a single query...", cfg.DumpRowLimit)
		_, response, err := runAdvancedQueryWithProgress(ctx, httpClient, cfg.Endpoint, token, baseQuery, progress)
		if err != nil {
			return tableDumpOutput{Stats: stats}, fmt.Errorf("dump %s: %w", cfg.DumpTable, err)
		}
		if pseudonyms != nil {
			response, err = pseudonyms.PseudonymizeResponse(ctx, response)
			if err != nil {
				return tableDumpOutput{Stats: stats}, err
			}
			if err := pseudonyms.Save(); err != nil {
				return tableDumpOutput{Stats: stats}, err
			}
		}
		body, err := marshalQueryResponse(response)
		if err != nil {
			return tableDumpOutput{Stats: stats}, err
		}
		if err := writeJSONFile(cfg.Output, body); err != nil {
			return tableDumpOutput{Stats: stats}, err
		}
		stats.Chunks = 1
		stats.Partitions = 1
		progressf(progress, "[i] completed single-query dump with %d row(s)", len(response.Results))
		output := tableDumpOutput{
			Schema:   response.Schema,
			Rows:     len(response.Results),
			Stats:    stats,
			Response: response,
		}
		if cfg.ADXExport {
			dataPath, schemaPath, err := writeADXArtifacts(cfg, response)
			if err != nil {
				return output, err
			}
			output.ADXDataPath = dataPath
			output.ADXSchemaPath = schemaPath
		}
		return output, nil
	}

	if cfg.OpenGraphExport {
		return tableDumpOutput{Stats: stats}, errors.New("opengraph export is not supported for partitioned table dumps because it requires loading all rows into memory")
	}

	progressf(progress, "[-] row count is at or above %d; calculating hash partitions...", cfg.DumpRowLimit)
	partitions, partitionCountValue, err := resolveDumpPartitions(ctx, httpClient, cfg, token, baseQuery, totalRows, progress)
	if err != nil {
		return tableDumpOutput{Stats: stats}, err
	}
	if len(partitions) == 0 {
		stats.Chunks = 0
		stats.Partitions = 0
		progressf(progress, "[-] no non-empty partitions found")
		if err := writeJSONFile(cfg.Output, []byte(`{"Schema":[],"Results":[]}`)); err != nil {
			return tableDumpOutput{Stats: stats}, err
		}
		return tableDumpOutput{Stats: stats}, nil
	}

	schema, rows, adxDataPath, adxSchemaPath, err := streamTableDumpPartitions(ctx, httpClient, cfg, token, baseQuery, partitions, partitionCountValue, pseudonyms, progress)
	if err != nil {
		return tableDumpOutput{Stats: stats}, err
	}
	stats.Chunks = len(partitions)
	stats.Partitions = partitionCountValue
	progressf(progress, "[i] completed partitioned dump with %d row(s)", rows)
	return tableDumpOutput{
		Schema:        schema,
		Rows:          rows,
		Stats:         stats,
		ADXDataPath:   adxDataPath,
		ADXSchemaPath: adxSchemaPath,
	}, nil
}

func resolveDumpPartitions(ctx context.Context, httpClient *http.Client, cfg config, token, baseQuery string, totalRows int, progress io.Writer) ([]partitionCount, int, error) {
	return resolveQueryPartitions(ctx, httpClient, cfg, token, baseQuery, totalRows, cfg.DumpTable, progress)
}

func resolveQueryPartitions(ctx context.Context, httpClient *http.Client, cfg config, token, baseQuery string, totalRows int, description string, progress io.Writer) ([]partitionCount, int, error) {
	return resolveQueryPartitionsStartingAt(ctx, httpClient, cfg, token, baseQuery, totalRows, 0, description, progress)
}

func resolveQueryPartitionsStartingAt(ctx context.Context, httpClient *http.Client, cfg config, token, baseQuery string, totalRows, minimumPartitions int, description string, progress io.Writer) ([]partitionCount, int, error) {
	partitionCountValue := (totalRows + cfg.DumpRowLimit - 1) / cfg.DumpRowLimit
	if partitionCountValue < 2 {
		partitionCountValue = 2
	}
	if partitionCountValue < minimumPartitions {
		partitionCountValue = minimumPartitions
	}

	for {
		if partitionCountValue > cfg.DumpRowLimit {
			return nil, 0, fmt.Errorf("unable to split %s into chunks below the service result-size limit after trying %d hash partitions", description, partitionCountValue)
		}
		progressf(progress, "[-] counting rows across %d hash partition(s)...", partitionCountValue)
		_, response, err := runAdvancedQueryWithProgress(ctx, httpClient, cfg.Endpoint, token, buildTableDumpPartitionCountQuery(baseQuery, partitionCountValue), progress)
		if err != nil {
			return nil, 0, fmt.Errorf("count %s hash partitions: %w", description, err)
		}
		partitions, err := parsePartitionCountsResponse(response)
		if err != nil {
			return nil, 0, fmt.Errorf("parse %s partition counts: %w", description, err)
		}
		sort.Slice(partitions, func(i, j int) bool {
			return partitions[i].Partition < partitions[j].Partition
		})
		maxRows := maxPartitionRows(partitions)
		progressf(progress, "[-] found %d non-empty partition(s); largest partition has %d row(s)", len(partitions), maxRows)
		if maxRows < cfg.DumpRowLimit {
			return partitions, partitionCountValue, nil
		}
		partitionCountValue *= 2
		progressf(progress, "[-] largest partition is still at or above %d row(s); retrying with %d partition(s)", cfg.DumpRowLimit, partitionCountValue)
		if partitionCountValue > cfg.DumpRowLimit {
			return nil, 0, fmt.Errorf("unable to split %s into chunks below %d rows after trying %d hash partitions", description, cfg.DumpRowLimit, partitionCountValue)
		}
	}
}

func streamTableDumpPartitions(ctx context.Context, httpClient *http.Client, cfg config, token, baseQuery string, partitions []partitionCount, partitionCountValue int, pseudonyms *pseudonymizer, progress io.Writer) ([]queryColumn, int, string, string, error) {
	return streamQueryPartitions(ctx, httpClient, cfg, token, baseQuery, partitions, partitionCountValue, pseudonyms, "dump "+cfg.DumpTable, progress)
}

func streamQueryPartitions(ctx context.Context, httpClient *http.Client, cfg config, token, baseQuery string, partitions []partitionCount, partitionCountValue int, pseudonyms *pseudonymizer, description string, progress io.Writer) ([]queryColumn, int, string, string, error) {
	var responseWriter *queryResponseStreamWriter
	var adxWriter *ndjsonStreamWriter
	var schema []queryColumn
	completed := 0
	progressf(progress, "[-] dumping %d non-empty partition chunk(s) sequentially", len(partitions))

	for _, partition := range partitions {
		query := buildTableDumpPartitionQuery(baseQuery, partitionCountValue, partition.Partition)
		_, response, err := runAdvancedQueryWithProgress(ctx, httpClient, cfg.Endpoint, token, query, progress)
		if err != nil {
			if responseWriter != nil {
				responseWriter.Abort()
			}
			if adxWriter != nil {
				adxWriter.Abort()
			}
			return nil, 0, "", "", fmt.Errorf("%s partition %d: %w", description, partition.Partition, err)
		}
		if len(response.Results) >= cfg.DumpRowLimit {
			if responseWriter != nil {
				responseWriter.Abort()
			}
			if adxWriter != nil {
				adxWriter.Abort()
			}
			return nil, 0, "", "", fmt.Errorf("partition %d returned %d rows, at or above the configured limit %d", partition.Partition, len(response.Results), cfg.DumpRowLimit)
		}
		if pseudonyms != nil {
			rows, err := pseudonyms.PseudonymizeRows(ctx, response.Results)
			if err != nil {
				if responseWriter != nil {
					responseWriter.Abort()
				}
				if adxWriter != nil {
					adxWriter.Abort()
				}
				return nil, 0, "", "", err
			}
			response.Results = rows
			if err := pseudonyms.Save(); err != nil {
				if responseWriter != nil {
					responseWriter.Abort()
				}
				if adxWriter != nil {
					adxWriter.Abort()
				}
				return nil, 0, "", "", err
			}
		}
		if responseWriter == nil {
			schema = response.Schema
			if len(schema) == 0 {
				schema = inferSchemaFromResults(response.Results)
			}
			var err error
			responseWriter, err = newQueryResponseStreamWriter(cfg.Output, schema)
			if err != nil {
				if adxWriter != nil {
					adxWriter.Abort()
				}
				return nil, 0, "", "", err
			}
			if cfg.ADXExport {
				dataPath, _ := adxArtifactPaths(cfg.Output)
				adxWriter, err = newNDJSONStreamWriter(dataPath)
				if err != nil {
					responseWriter.Abort()
					return nil, 0, "", "", err
				}
			}
			progressf(progress, "[i] streaming results to %s", cfg.Output)
		}
		completed++
		progressf(progress, "[i] completed partition %d (%d/%d): expected %d row(s), received %d row(s)", partition.Partition, completed, len(partitions), partition.Rows, len(response.Results))
		if err := responseWriter.WriteRows(response.Results); err != nil {
			responseWriter.Abort()
			if adxWriter != nil {
				adxWriter.Abort()
			}
			return nil, 0, "", "", err
		}
		if adxWriter != nil {
			if err := adxWriter.WriteRows(response.Results); err != nil {
				responseWriter.Abort()
				adxWriter.Abort()
				return nil, 0, "", "", err
			}
		}
	}

	if responseWriter == nil {
		var err error
		responseWriter, err = newQueryResponseStreamWriter(cfg.Output, nil)
		if err != nil {
			return nil, 0, "", "", err
		}
		schema = nil
	}
	if err := responseWriter.Close(); err != nil {
		if adxWriter != nil {
			adxWriter.Abort()
		}
		return nil, 0, "", "", err
	}
	if adxWriter == nil {
		return schema, responseWriter.RowCount(), "", "", nil
	}
	if err := adxWriter.Close(); err != nil {
		return nil, 0, "", "", err
	}

	_, schemaPath := adxArtifactPaths(cfg.Output)
	tableName, mappingName := resolveADXTableAndMapping(cfg, defaultADXTableName(cfg.Output))
	content, err := buildADXSchemaFile(schema, tableName, mappingName, filepath.Base(adxWriter.Path()))
	if err != nil {
		return nil, 0, "", "", err
	}
	if err := writeTextFile(schemaPath, content); err != nil {
		return nil, 0, "", "", err
	}
	return schema, responseWriter.RowCount(), adxWriter.Path(), schemaPath, nil
}

func progressf(progress io.Writer, format string, args ...any) {
	if progress == nil {
		return
	}
	fmt.Fprintf(progress, format+"\n", args...)
}

type queryResponseStreamWriter struct {
	path     string
	tempPath string
	file     *os.File
	writer   *bufio.Writer
	rowCount int
	closed   bool
}

func newQueryResponseStreamWriter(path string, schema []queryColumn) (*queryResponseStreamWriter, error) {
	file, tempPath, err := createTempFileForPath(path)
	if err != nil {
		return nil, err
	}

	writer := bufio.NewWriter(file)
	schemaBody, err := json.Marshal(schema)
	if err != nil {
		file.Close()
		os.Remove(tempPath)
		return nil, fmt.Errorf("encode streamed schema: %w", err)
	}
	if _, err := fmt.Fprintf(writer, "{\n  \"Schema\": %s,\n  \"Results\": [", schemaBody); err != nil {
		file.Close()
		os.Remove(tempPath)
		return nil, fmt.Errorf("write streamed response header: %w", err)
	}

	return &queryResponseStreamWriter{
		path:     path,
		tempPath: tempPath,
		file:     file,
		writer:   writer,
	}, nil
}

func (w *queryResponseStreamWriter) WriteRows(rows []map[string]any) error {
	for _, row := range rows {
		encoded, err := json.Marshal(row)
		if err != nil {
			return fmt.Errorf("encode streamed result row: %w", err)
		}
		if w.rowCount == 0 {
			if _, err := w.writer.WriteString("\n    "); err != nil {
				return fmt.Errorf("write streamed result row: %w", err)
			}
		} else {
			if _, err := w.writer.WriteString(",\n    "); err != nil {
				return fmt.Errorf("write streamed result row separator: %w", err)
			}
		}
		if _, err := w.writer.Write(encoded); err != nil {
			return fmt.Errorf("write streamed result row: %w", err)
		}
		w.rowCount++
	}
	return nil
}

func (w *queryResponseStreamWriter) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true

	if w.rowCount == 0 {
		if _, err := w.writer.WriteString("\n  ]\n}\n"); err != nil {
			w.Abort()
			return fmt.Errorf("write streamed response footer: %w", err)
		}
	} else {
		if _, err := w.writer.WriteString("\n  ]\n}\n"); err != nil {
			w.Abort()
			return fmt.Errorf("write streamed response footer: %w", err)
		}
	}
	if err := w.writer.Flush(); err != nil {
		w.Abort()
		return fmt.Errorf("flush streamed response: %w", err)
	}
	if err := w.file.Close(); err != nil {
		os.Remove(w.tempPath)
		return fmt.Errorf("close streamed response: %w", err)
	}
	if err := os.Rename(w.tempPath, w.path); err != nil {
		os.Remove(w.tempPath)
		return fmt.Errorf("replace output file %s: %w", w.path, err)
	}
	return nil
}

func (w *queryResponseStreamWriter) Abort() {
	if w == nil {
		return
	}
	if !w.closed {
		w.closed = true
		if w.file != nil {
			w.file.Close()
		}
	}
	if w.tempPath != "" {
		os.Remove(w.tempPath)
	}
}

func (w *queryResponseStreamWriter) RowCount() int {
	if w == nil {
		return 0
	}
	return w.rowCount
}

type ndjsonStreamWriter struct {
	path     string
	tempPath string
	file     *os.File
	writer   *bufio.Writer
	closed   bool
}

func newNDJSONStreamWriter(path string) (*ndjsonStreamWriter, error) {
	file, tempPath, err := createTempFileForPath(path)
	if err != nil {
		return nil, err
	}
	return &ndjsonStreamWriter{
		path:     path,
		tempPath: tempPath,
		file:     file,
		writer:   bufio.NewWriter(file),
	}, nil
}

func (w *ndjsonStreamWriter) WriteRows(rows []map[string]any) error {
	for _, row := range rows {
		encoded, err := json.Marshal(row)
		if err != nil {
			return fmt.Errorf("encode streamed ADX row: %w", err)
		}
		if _, err := w.writer.Write(encoded); err != nil {
			return fmt.Errorf("write streamed ADX row: %w", err)
		}
		if err := w.writer.WriteByte('\n'); err != nil {
			return fmt.Errorf("write streamed ADX row newline: %w", err)
		}
	}
	return nil
}

func (w *ndjsonStreamWriter) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true
	if err := w.writer.Flush(); err != nil {
		w.Abort()
		return fmt.Errorf("flush streamed ADX rows: %w", err)
	}
	if err := w.file.Close(); err != nil {
		os.Remove(w.tempPath)
		return fmt.Errorf("close streamed ADX rows: %w", err)
	}
	if err := os.Rename(w.tempPath, w.path); err != nil {
		os.Remove(w.tempPath)
		return fmt.Errorf("replace ADX data file %s: %w", w.path, err)
	}
	return nil
}

func (w *ndjsonStreamWriter) Abort() {
	if w == nil {
		return
	}
	if !w.closed {
		w.closed = true
		if w.file != nil {
			w.file.Close()
		}
	}
	if w.tempPath != "" {
		os.Remove(w.tempPath)
	}
}

func (w *ndjsonStreamWriter) Path() string {
	if w == nil {
		return ""
	}
	return w.path
}

func createTempFileForPath(path string) (*os.File, string, error) {
	dir := filepath.Dir(path)
	if dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, "", fmt.Errorf("create output directory %s: %w", dir, err)
		}
	}
	file, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return nil, "", fmt.Errorf("create temporary output file for %s: %w", path, err)
	}
	return file, file.Name(), nil
}

func buildTableDumpBaseQuery(tableName, timeColumn, lookback string) string {
	return fmt.Sprintf("%s\n| where %s >= ago(%s)", tableName, timeColumn, lookback)
}

func buildTableDumpCountQuery(baseQuery string) string {
	return baseQuery + "\n| count"
}

func buildTableDumpPartitionCountQuery(baseQuery string, partitions int) string {
	return fmt.Sprintf("%s\n| summarize Count=count() by DumpPartition=hash(tostring(pack_all()), %d)", baseQuery, partitions)
}

func buildTableDumpPartitionQuery(baseQuery string, partitions, partition int) string {
	return fmt.Sprintf("%s\n| where hash(tostring(pack_all()), %d) == %d", baseQuery, partitions, partition)
}

func parseCountResponse(response queryResponse) (int, error) {
	if len(response.Results) != 1 {
		return 0, fmt.Errorf("expected one count row, got %d", len(response.Results))
	}
	count, ok := lookupIntValue(response.Results[0], "Count", "count")
	if !ok {
		return 0, errors.New("count response did not include a Count column")
	}
	return count, nil
}

func parsePartitionCountsResponse(response queryResponse) ([]partitionCount, error) {
	partitions := make([]partitionCount, 0, len(response.Results))
	for i, row := range response.Results {
		partition, ok := lookupIntValue(row, "DumpPartition", "dumppartition")
		if !ok {
			return nil, fmt.Errorf("partition count row %d did not include DumpPartition", i+1)
		}
		rows, ok := lookupIntValue(row, "Count", "count")
		if !ok {
			return nil, fmt.Errorf("partition count row %d did not include Count", i+1)
		}
		if rows > 0 {
			partitions = append(partitions, partitionCount{Partition: partition, Rows: rows})
		}
	}
	return partitions, nil
}

func lookupIntValue(row map[string]any, names ...string) (int, bool) {
	for key, value := range row {
		for _, name := range names {
			if !strings.EqualFold(strings.TrimSpace(key), name) {
				continue
			}
			parsed, ok := intValue(value)
			if ok {
				return parsed, true
			}
		}
	}
	return 0, false
}

func intValue(value any) (int, bool) {
	switch typed := value.(type) {
	case int:
		return typed, true
	case int64:
		if typed > int64(int(^uint(0)>>1)) || typed < -int64(int(^uint(0)>>1))-1 {
			return 0, false
		}
		return int(typed), true
	case float64:
		if math.Trunc(typed) != typed {
			return 0, false
		}
		return int(typed), true
	case string:
		out, err := strconv.Atoi(strings.TrimSpace(typed))
		if err != nil {
			return 0, false
		}
		return out, true
	default:
		return 0, false
	}
}

func maxPartitionRows(partitions []partitionCount) int {
	maxRows := 0
	for _, partition := range partitions {
		if partition.Rows > maxRows {
			maxRows = partition.Rows
		}
	}
	return maxRows
}
