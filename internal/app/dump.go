package app

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
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

func dumpTable(ctx context.Context, source querySource, cfg config, pseudonyms *pseudonymizer, progress io.Writer) (tableDumpOutput, error) {
	cutoff := time.Now().UTC()
	baseQuery := buildTableDumpBaseQuery(cfg.DumpTable, cfg.DumpTimeColumn, cfg.DumpLookback, cutoff)
	source, err := withTableDumpTimespan(source, cfg, cutoff, progress)
	if err != nil {
		return tableDumpOutput{}, err
	}
	progressf(progress, "[-] counting rows in %s over %s...", cfg.DumpTable, cfg.DumpLookback)
	countResponse, err := source.RunQuery(ctx, buildTableDumpCountQuery(baseQuery), progress)
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
		response, err := source.RunQuery(ctx, baseQuery, progress)
		if err != nil {
			if !source.IsResultSizeExceeded(err) {
				return tableDumpOutput{Stats: stats}, fmt.Errorf("dump %s: %w", cfg.DumpTable, err)
			}
			progressf(progress, "[i] single-query dump exceeded the service result-size limit; retrying with hash partitions...")
			return dumpPartitionedQuery(ctx, source, cfg, baseQuery, totalRows, 2, stats, tableDumpCollection(cfg.DumpTable), pseudonyms, progress)
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

	progressf(progress, "[-] row count is at or above %d; calculating hash partitions...", cfg.DumpRowLimit)
	return dumpPartitionedQuery(ctx, source, cfg, baseQuery, totalRows, 0, stats, tableDumpCollection(cfg.DumpTable), pseudonyms, progress)
}

// withTableDumpTimespan gives sources with a service-side time range one that
// covers the fixed dump window. That range filters TimeGenerated, so it is not
// sent for another time column, where it could drop rows the query selects.
func withTableDumpTimespan(source querySource, cfg config, cutoff time.Time, progress io.Writer) (querySource, error) {
	windowed, ok := source.(timespanQuerySource)
	if !ok {
		return source, nil
	}
	if cfg.DumpTimeColumn != logAnalyticsTimeColumn {
		progressf(progress, "[i] not sending a service timespan because the dump filters on %s rather than %s", cfg.DumpTimeColumn, logAnalyticsTimeColumn)
		return source, nil
	}
	lookback, err := kqlTimespanDuration(cfg.DumpLookback)
	if err != nil {
		return nil, err
	}
	// The query filter stays authoritative. One second of padding keeps the
	// service's boundary handling from excluding rows at the window edges.
	end := cutoff.UTC().Truncate(time.Microsecond)
	return windowed.withTimespan(end.Add(-lookback-time.Second), end.Add(time.Second)), nil
}

func resolveQueryPartitionsStartingAt(ctx context.Context, source querySource, cfg config, baseQuery string, key queryPartitionKey, totalRows, minimumPartitions int, description string, progress io.Writer) ([]partitionCount, int, error) {
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
		response, err := source.RunQuery(ctx, buildTableDumpPartitionCountQuery(baseQuery, key.expression, partitionCountValue), progress)
		if err != nil {
			return nil, 0, fmt.Errorf("count %s hash partitions: %w", description, err)
		}
		partitions, err := parsePartitionCountsResponse(response)
		if err != nil {
			return nil, 0, fmt.Errorf("parse %s partition counts: %w", description, err)
		}
		if err := validatePartitionCounts(partitions, partitionCountValue, totalRows); err != nil {
			return nil, 0, err
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

func streamQueryPartitions(ctx context.Context, source querySource, cfg config, baseQuery string, key queryPartitionKey, partitions []partitionCount, partitionCountValue int, pseudonyms *pseudonymizer, description string, progress io.Writer) ([]queryColumn, int, string, string, error) {
	var responseWriter *queryResponseStreamWriter
	var adxWriter *ndjsonStreamWriter
	var schema []queryColumn
	// Abort every temporary artifact on any early return. Close/commit below
	// renames their temporary files, making this safe on successful completion.
	defer func() {
		if responseWriter != nil {
			responseWriter.Abort()
		}
		if adxWriter != nil {
			adxWriter.Abort()
		}
	}()
	completed := 0
	progressf(progress, "[-] dumping %d non-empty partition chunk(s) sequentially", len(partitions))

	for _, partition := range partitions {
		query := buildTableDumpPartitionQuery(baseQuery, key.expression, partitionCountValue, partition.Partition)
		response, err := source.RunQuery(ctx, query, progress)
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
		if len(response.Results) != partition.Rows {
			return nil, 0, "", "", fmt.Errorf("partition %d returned %d rows, expected %d; incomplete or changed results were not published", partition.Partition, len(response.Results), partition.Rows)
		}
		if err := key.validateSchema(response.Schema); err != nil {
			return nil, 0, "", "", err
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

func buildTableDumpBaseQuery(tableName, timeColumn, lookback string, cutoff time.Time) string {
	// Kusto datetime precision is 100 ns; use microseconds so Go's nanosecond
	// formatting never produces an unsupported nine-digit fractional second.
	end := cutoff.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano)
	return fmt.Sprintf("%s\n| where %s >= (datetime(%s) - %s) and %s < datetime(%s)", tableName, timeColumn, end, lookback, timeColumn, end)
}

func buildTableDumpCountQuery(baseQuery string) string {
	return baseQuery + "\n| count"
}

func buildTableDumpPartitionCountQuery(baseQuery, keyExpression string, partitions int) string {
	return fmt.Sprintf("%s\n| summarize Count=count() by DumpPartition=%s", baseQuery, partitionExpression(keyExpression, partitions))
}

func buildTableDumpPartitionQuery(baseQuery, keyExpression string, partitions, partition int) string {
	return fmt.Sprintf("%s\n| where %s == %d", baseQuery, partitionExpression(keyExpression, partitions), partition)
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
		if rows <= 0 {
			return nil, fmt.Errorf("partition count row %d contains a non-positive count", i+1)
		}
		partitions = append(partitions, partitionCount{Partition: partition, Rows: rows})
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
