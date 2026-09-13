package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

func dumpQuery(ctx context.Context, source querySource, cfg config, query string, pseudonyms *pseudonymizer, progress io.Writer) (tableDumpOutput, error) {
	baseQuery := partitionableQuery(query)
	progressf(progress, "[-] counting rows returned by query...")
	countResponse, err := source.RunQuery(ctx, buildTableDumpCountQuery(baseQuery), progress)
	if err != nil {
		return tableDumpOutput{}, fmt.Errorf("count query rows: %w", err)
	}

	totalRows, err := parseCountResponse(countResponse)
	if err != nil {
		return tableDumpOutput{}, fmt.Errorf("parse query row count: %w", err)
	}
	stats := tableDumpStats{TotalRows: totalRows}
	progressf(progress, "[i] query returns %d row(s)", totalRows)

	if totalRows < cfg.DumpRowLimit {
		progressf(progress, "[i] row count is below %d; running query without partitioning...", cfg.DumpRowLimit)
		response, err := source.RunQuery(ctx, baseQuery, progress)
		if err != nil {
			if !source.IsResultSizeExceeded(err) {
				return tableDumpOutput{Stats: stats}, err
			}
			progressf(progress, "[i] unpartitioned query exceeded the service result-size limit; retrying with hash partitions...")
			return dumpPartitionedQuery(ctx, source, cfg, baseQuery, totalRows, 2, stats, queryCollection, pseudonyms, progress)
		}
		if response, err = withEmptyResultSchema(ctx, source, baseQuery, response, progress); err != nil {
			return tableDumpOutput{Stats: stats}, err
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
	return dumpPartitionedQuery(ctx, source, cfg, baseQuery, totalRows, 0, stats, queryCollection, pseudonyms, progress)
}

// partitionedCollection names a free-form query or a table dump in the
// progress messages and errors of the shared partitioned collection.
type partitionedCollection struct {
	kind   string // "query" or "dump"
	plural string // "queries" or "table dumps"
	rows   string // what the partition counts describe
	chunks string // prefix of partition download errors
}

var queryCollection = partitionedCollection{kind: "query", plural: "queries", rows: "query results", chunks: "query"}

func tableDumpCollection(table string) partitionedCollection {
	return partitionedCollection{kind: "dump", plural: "table dumps", rows: table, chunks: "dump " + table}
}

// dumpPartitionedQuery collects baseQuery in hash partitions. When a partition
// still exceeds the service result-size limit, it retries with at least twice
// as many partitions.
func dumpPartitionedQuery(ctx context.Context, source querySource, cfg config, baseQuery string, totalRows, minimumPartitions int, stats tableDumpStats, collection partitionedCollection, pseudonyms *pseudonymizer, progress io.Writer) (tableDumpOutput, error) {
	if cfg.OpenGraphExport {
		return tableDumpOutput{Stats: stats}, fmt.Errorf("opengraph export is not supported for partitioned %s because it requires loading all rows into memory", collection.plural)
	}

	key, err := resolvePartitionKey(ctx, source, baseQuery, progress)
	if err != nil {
		return tableDumpOutput{Stats: stats}, err
	}
	for {
		partitions, partitionCountValue, err := resolveQueryPartitionsStartingAt(ctx, source, cfg, baseQuery, key, totalRows, minimumPartitions, collection.rows, progress)
		if err != nil {
			return tableDumpOutput{Stats: stats}, err
		}
		if len(partitions) == 0 {
			stats.Chunks = 0
			stats.Partitions = 0
			progressf(progress, "[-] no non-empty partitions found")
			return writeEmptyPartitionedResult(cfg, key, stats)
		}

		schema, rows, adxDataPath, adxSchemaPath, err := streamQueryPartitions(ctx, source, cfg, baseQuery, key, partitions, partitionCountValue, pseudonyms, collection.chunks, progress)
		if err == nil {
			stats.Chunks = len(partitions)
			stats.Partitions = partitionCountValue
			progressf(progress, "[i] completed partitioned %s with %d row(s)", collection.kind, rows)
			return tableDumpOutput{
				Schema:        schema,
				Rows:          rows,
				Stats:         stats,
				ADXDataPath:   adxDataPath,
				ADXSchemaPath: adxSchemaPath,
			}, nil
		}
		if !source.IsResultSizeExceeded(err) {
			return tableDumpOutput{Stats: stats}, err
		}
		if maxPartitionRows(partitions) <= 1 {
			return tableDumpOutput{Stats: stats}, fmt.Errorf("%s result contains an individual row that exceeds the service result-size limit: %w", collection.kind, err)
		}
		minimumPartitions = partitionCountValue * 2
		progressf(progress, "[i] a partition still exceeded the service result-size limit; retrying with at least %d hash partitions...", minimumPartitions)
	}
}

func isQueryResultSizeExceeded(err error) bool {
	var queryErr *advancedQueryError
	if !errors.As(err, &queryErr) || queryErr.StatusCode != http.StatusBadRequest {
		return false
	}
	body := strings.ToLower(queryErr.Body)
	return strings.Contains(body, "result size") && (strings.Contains(body, "exceed") || strings.Contains(body, "too large"))
}

func partitionableQuery(query string) string {
	query = strings.TrimSpace(query)
	for strings.HasSuffix(query, ";") {
		query = strings.TrimSpace(strings.TrimSuffix(query, ";"))
	}
	return query
}
