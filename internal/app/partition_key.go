package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

// A key is resolved once from the final result schema and reused by every
// count, retry, and download request. Dynamic bags never participate.
type queryPartitionKey struct {
	expression string
	columns    []queryColumn
}

func resolvePartitionKey(ctx context.Context, source querySource, baseQuery string, progress io.Writer) (queryPartitionKey, error) {
	progressf(progress, "[-] resolving scalar result columns for stable partition keys...")
	response, err := source.RunQuery(ctx, baseQuery+"\n| take 0", progress)
	if err != nil {
		return queryPartitionKey{}, fmt.Errorf("resolve partition schema: %w", err)
	}
	key, err := newQueryPartitionKey(response.Schema)
	if err != nil {
		return queryPartitionKey{}, err
	}
	progressf(progress, "[i] partition key uses %d scalar column(s); dynamic columns are excluded", len(key.columns))
	return key, nil
}

func newQueryPartitionKey(schema []queryColumn) (queryPartitionKey, error) {
	key := queryPartitionKey{}
	seen := make(map[string]bool)
	for _, column := range schema {
		if column.Name == "" || seen[column.Name] {
			return key, errors.New("partition schema contains an empty or duplicate column name")
		}
		seen[column.Name] = true
		column.Type = partitionScalarType(column.Type)
		if column.Type != "" {
			key.columns = append(key.columns, column)
		}
	}
	if len(key.columns) == 0 {
		return key, errors.New("cannot safely partition results without a known scalar column; project a stable scalar event key from dynamic data")
	}
	sort.Slice(key.columns, func(i, j int) bool { return key.columns[i].Name < key.columns[j].Name })
	expressions := make([]string, len(key.columns))
	for i, column := range key.columns {
		// Quoted identifiers prevent schema names from becoming KQL syntax.
		expressions[i] = "tostring([" + strconv.Quote(column.Name) + "])"
	}
	key.expression = "tostring(pack_array(" + strings.Join(expressions, ", ") + "))"
	return key, nil
}

func partitionScalarType(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "string":
		return "string"
	case "bool", "boolean":
		return "bool"
	case "int", "int32":
		return "int"
	case "long", "int64":
		return "long"
	case "real", "double":
		return "real"
	case "decimal":
		return "decimal"
	case "datetime":
		return "datetime"
	case "timespan":
		return "timespan"
	case "guid":
		return "guid"
	default:
		return ""
	}
}

func (key queryPartitionKey) validateSchema(schema []queryColumn) error {
	types := make(map[string]string, len(schema))
	for _, column := range schema {
		types[column.Name] = partitionScalarType(column.Type)
	}
	for _, column := range key.columns {
		if types[column.Name] != column.Type {
			return errors.New("partition key schema changed during collection; result was not published")
		}
	}
	return nil
}

func partitionExpression(keyExpression string, partitions int) string {
	// SHA-256 is stable across separate queries. Fifteen hex digits fit in a
	// positive signed long, so modulo always selects [0, partitions).
	return fmt.Sprintf("(tolong(strcat('0x', substring(hash_sha256(%s), 0, 15))) %% %d)", keyExpression, partitions)
}

func validatePartitionCounts(partitions []partitionCount, buckets, totalRows int) error {
	total := 0
	seen := make(map[int]bool, len(partitions))
	for _, partition := range partitions {
		if partition.Partition < 0 || partition.Partition >= buckets || seen[partition.Partition] || partition.Rows <= 0 || partition.Rows > totalRows-total {
			return errors.New("invalid or inconsistent partition counts; result was not published")
		}
		seen[partition.Partition] = true
		total += partition.Rows
	}
	if total != totalRows {
		return fmt.Errorf("partition counts total %d rows, expected %d; data changed or the service returned incomplete counts", total, totalRows)
	}
	return nil
}
