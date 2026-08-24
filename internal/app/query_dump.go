package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

func dumpQuery(ctx context.Context, httpClient *http.Client, cfg config, token, query string, pseudonyms *pseudonymizer, progress io.Writer) (tableDumpOutput, error) {
	baseQuery := partitionableQuery(query)
	progressf(progress, "[-] counting rows returned by query...")
	_, countResponse, err := runAdvancedQueryWithProgress(ctx, httpClient, cfg.Endpoint, token, buildTableDumpCountQuery(baseQuery), progress)
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
		_, response, err := runAdvancedQueryWithProgress(ctx, httpClient, cfg.Endpoint, token, baseQuery, progress)
		if err != nil {
			if !isQueryResultSizeExceeded(err) {
				return tableDumpOutput{Stats: stats}, err
			}
			progressf(progress, "[i] unpartitioned query exceeded the service result-size limit; retrying with hash partitions...")
			return dumpPartitionedQuery(ctx, httpClient, cfg, token, baseQuery, totalRows, 2, stats, pseudonyms, progress)
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
	return dumpPartitionedQuery(ctx, httpClient, cfg, token, baseQuery, totalRows, 0, stats, pseudonyms, progress)
}

func dumpPartitionedQuery(ctx context.Context, httpClient *http.Client, cfg config, token, baseQuery string, totalRows, minimumPartitions int, stats tableDumpStats, pseudonyms *pseudonymizer, progress io.Writer) (tableDumpOutput, error) {
	if cfg.OpenGraphExport {
		return tableDumpOutput{Stats: stats}, errors.New("opengraph export is not supported for partitioned queries because it requires loading all rows into memory")
	}

	for {
		partitions, partitionCountValue, err := resolveQueryPartitionsStartingAt(ctx, httpClient, cfg, token, baseQuery, totalRows, minimumPartitions, "query results", progress)
		if err != nil {
			return tableDumpOutput{Stats: stats}, err
		}
		if len(partitions) == 0 {
			stats.Chunks = 0
			stats.Partitions = 0
			if err := writeJSONFile(cfg.Output, []byte(`{"Schema":[],"Results":[]}`)); err != nil {
				return tableDumpOutput{Stats: stats}, err
			}
			return tableDumpOutput{Stats: stats}, nil
		}

		schema, rows, adxDataPath, adxSchemaPath, err := streamQueryPartitions(ctx, httpClient, cfg, token, baseQuery, partitions, partitionCountValue, pseudonyms, "query", progress)
		if err == nil {
			stats.Chunks = len(partitions)
			stats.Partitions = partitionCountValue
			progressf(progress, "[i] completed partitioned query with %d row(s)", rows)
			return tableDumpOutput{
				Schema:        schema,
				Rows:          rows,
				Stats:         stats,
				ADXDataPath:   adxDataPath,
				ADXSchemaPath: adxSchemaPath,
			}, nil
		}
		if !isQueryResultSizeExceeded(err) {
			return tableDumpOutput{Stats: stats}, err
		}
		if maxPartitionRows(partitions) <= 1 {
			return tableDumpOutput{Stats: stats}, fmt.Errorf("query result contains an individual row that exceeds the service result-size limit: %w", err)
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
