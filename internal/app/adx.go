package app

import (
	"bufio"
	"bytes"
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
	"strings"
	"time"
)

type adxMappingEntry struct {
	Column     string            `json:"column"`
	DataType   string            `json:"datatype"`
	Properties map[string]string `json:"Properties"`
}

type adxColumnDef struct {
	ColumnName  string
	SourceField string
	DataType    string
}

type ingestSource struct {
	Schema []queryColumn
	Rows   []map[string]any
}

type kustoMgmtResponse struct {
	Tables []kustoTable `json:"Tables"`
}

type kustoTable struct {
	TableName string             `json:"TableName"`
	Columns   []kustoTableColumn `json:"Columns"`
	Rows      [][]any            `json:"Rows"`
}

type kustoTableColumn struct {
	ColumnName string `json:"ColumnName"`
	ColumnType string `json:"ColumnType"`
}

func uploadFileToADX(ctx context.Context, httpClient *http.Client, cfg config) (int, int, string, error) {
	source, err := readIngestSource(cfg.ADXUploadFile)
	if err != nil {
		return 0, 0, "", err
	}

	schema := source.Schema
	if len(schema) == 0 {
		schema = inferSchemaFromResults(source.Rows)
	}
	if len(schema) == 0 {
		return 0, 0, "", errors.New("cannot upload an empty file without schema information")
	}

	token, authMode, err := acquireToken(ctx, httpClient, adxAuthConfig(cfg))
	if err != nil {
		return 0, 0, "", err
	}

	tableName, mappingName := resolveADXTableAndMapping(cfg, cfg.ADXTable)
	if err := ensureADXTableAndMapping(ctx, httpClient, cfg.ADXCluster, cfg.ADXDatabase, token, tableName, mappingName, schema); err != nil {
		return 0, 0, "", err
	}

	batchesUploaded, err := ingestRowsToADX(ctx, httpClient, cfg.ADXCluster, cfg.ADXDatabase, tableName, mappingName, token, source.Rows, cfg.ADXBatchSize)
	if err != nil {
		return 0, 0, "", err
	}

	return len(source.Rows), batchesUploaded, authMode, nil
}

func readIngestSource(path string) (ingestSource, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return ingestSource{}, fmt.Errorf("read ingest file %s: %w", path, err)
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return ingestSource{}, fmt.Errorf("ingest file %s is empty", path)
	}

	switch trimmed[0] {
	case '{':
		if response, err := parseQueryResponse(trimmed); err == nil && (response.Results != nil || response.Schema != nil) {
			return ingestSource{Schema: response.Schema, Rows: response.Results}, nil
		}

		var row map[string]any
		if err := json.Unmarshal(trimmed, &row); err == nil {
			return ingestSource{Rows: []map[string]any{row}}, nil
		}
		return readNDJSONSource(path, trimmed)
	case '[':
		var rows []map[string]any
		if err := json.Unmarshal(trimmed, &rows); err != nil {
			return ingestSource{}, fmt.Errorf("decode JSON array from %s: %w", path, err)
		}
		return ingestSource{Rows: rows}, nil
	default:
		return readNDJSONSource(path, trimmed)
	}
}

func lookupAny(payload map[string]any, keys ...string) any {
	for _, key := range keys {
		if value, ok := payload[key]; ok {
			return value
		}
	}
	return nil
}

func parseQueryColumns(value any) []queryColumn {
	items, ok := value.([]any)
	if !ok {
		return nil
	}

	columns := make([]queryColumn, 0, len(items))
	for _, item := range items {
		columnMap, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name, _ := lookupAny(columnMap, "Name", "name").(string)
		colType, _ := lookupAny(columnMap, "Type", "type").(string)
		if name == "" {
			continue
		}
		columns = append(columns, queryColumn{Name: name, Type: colType})
	}
	return columns
}

func parseQueryRows(value any) []map[string]any {
	items, ok := value.([]any)
	if !ok {
		return nil
	}

	rows := make([]map[string]any, 0, len(items))
	for _, item := range items {
		row, ok := item.(map[string]any)
		if !ok {
			continue
		}
		rows = append(rows, row)
	}
	return rows
}

func parseStringAnyMap(value any) map[string]any {
	result, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	return result
}

func readNDJSONSource(path string, body []byte) (ingestSource, error) {
	scanner := bufio.NewScanner(bytes.NewReader(body))
	maxTokenSize := len(body)
	if maxTokenSize < bufio.MaxScanTokenSize {
		maxTokenSize = bufio.MaxScanTokenSize
	}
	scanner.Buffer(make([]byte, 0, min(maxTokenSize, bufio.MaxScanTokenSize)), maxTokenSize)
	rows := make([]map[string]any, 0)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var row map[string]any
		if err := json.Unmarshal(line, &row); err != nil {
			return ingestSource{}, fmt.Errorf("decode NDJSON line %d from %s: %w", lineNo, path, err)
		}
		rows = append(rows, row)
	}
	if err := scanner.Err(); err != nil {
		return ingestSource{}, fmt.Errorf("read NDJSON from %s: %w", path, err)
	}
	return ingestSource{Rows: rows}, nil
}

func writeADXArtifacts(cfg config, response queryResponse) (string, string, error) {
	schema := response.Schema
	if len(schema) == 0 {
		schema = inferSchemaFromResults(response.Results)
	}
	if len(schema) == 0 {
		return "", "", errors.New("cannot generate ADX artifacts because the query response did not include schema information and returned no rows")
	}

	tableName, mappingName := resolveADXTableAndMapping(cfg, defaultADXTableName(cfg.Output))

	dataPath, schemaPath := adxArtifactPaths(cfg.Output)
	if err := writeNDJSONFile(dataPath, response.Results); err != nil {
		return "", "", err
	}

	content, err := buildADXSchemaFile(schema, tableName, mappingName, filepath.Base(dataPath))
	if err != nil {
		return "", "", err
	}
	if err := writeTextFile(schemaPath, content); err != nil {
		return "", "", err
	}

	return dataPath, schemaPath, nil
}

func writeNDJSONFile(path string, rows []map[string]any) error {
	var content bytes.Buffer
	for _, row := range rows {
		encoded, err := json.Marshal(row)
		if err != nil {
			return fmt.Errorf("encode ADX row: %w", err)
		}
		content.Write(encoded)
		content.WriteByte('\n')
	}
	return writeBytes(path, content.Bytes())
}

func adxArtifactPaths(outputPath string) (string, string) {
	ext := filepath.Ext(outputPath)
	base := strings.TrimSuffix(outputPath, ext)
	if base == "" {
		base = outputPath
	}
	return base + ".adx.json", base + ".adx.kql"
}

func resolveADXTableAndMapping(cfg config, fallbackTable string) (string, string) {
	tableName := cfg.ADXTable
	if tableName == "" {
		tableName = fallbackTable
	}
	mappingName := cfg.ADXMapping
	if mappingName == "" {
		mappingName = tableName + "_json"
	}
	return tableName, mappingName
}

func defaultADXTableName(outputPath string) string {
	ext := filepath.Ext(outputPath)
	base := filepath.Base(strings.TrimSuffix(outputPath, ext))
	if base == "" || base == "." || base == string(filepath.Separator) {
		base = "DefenderQueryResults"
	}
	base = sanitizeADXIdentifier(base)
	if base == "" {
		return "DefenderQueryResults"
	}
	return base
}

func sanitizeADXIdentifier(in string) string {
	var b strings.Builder
	for i, r := range in {
		switch {
		case r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			if i == 0 {
				b.WriteByte('_')
			}
			b.WriteRune(r)
		default:
			r = '_'
			if i == 0 && r >= '0' && r <= '9' {
				b.WriteByte('_')
			}
			b.WriteRune(r)
		}
	}
	return b.String()
}

func buildADXSchemaFile(schema []queryColumn, tableName, mappingName, dataFileName string) (string, error) {
	columnDefs, err := buildADXColumnDefs(schema)
	if err != nil {
		return "", err
	}

	mappingJSON, err := buildADXMappingJSON(columnDefs)
	if err != nil {
		return "", err
	}

	return strings.Join([]string{
		"// Run these commands in your target Azure Data Explorer database.",
		fmt.Sprintf("// Upload %s and ingest it as format=\"json\" using the mapping below.", dataFileName),
		fmt.Sprintf(".create table %s (%s)", tableName, buildADXColumnList(columnDefs)),
		fmt.Sprintf(".create-or-alter table %s ingestion json mapping \"%s\" '%s'", tableName, mappingName, escapeKustoString(string(mappingJSON))),
		"",
	}, "\n"), nil
}

func ensureADXTableAndMapping(ctx context.Context, httpClient *http.Client, cluster, database, token, tableName, mappingName string, schema []queryColumn) error {
	columnDefs, err := buildADXColumnDefs(schema)
	if err != nil {
		return err
	}

	mappingJSON, err := buildADXMappingJSON(columnDefs)
	if err != nil {
		return err
	}

	commands := []string{
		fmt.Sprintf(".create table %s (%s)", tableName, buildADXColumnList(columnDefs)),
		fmt.Sprintf(".create-or-alter table %s ingestion json mapping \"%s\" '%s'", tableName, mappingName, escapeKustoString(string(mappingJSON))),
	}

	for _, command := range commands {
		if err := runADXMgmtCommand(ctx, httpClient, cluster, database, token, command); err != nil {
			return err
		}
	}
	return nil
}

func runADXMgmtCommand(ctx context.Context, httpClient *http.Client, cluster, database, token, command string) error {
	body, err := json.Marshal(map[string]string{
		"db":  database,
		"csl": command,
	})
	if err != nil {
		return fmt.Errorf("encode ADX management command: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cluster+"/v1/rest/mgmt", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build ADX management request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("run ADX management command %q: %w", command, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read ADX management response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("ADX management command failed: %s: %s", resp.Status, strings.TrimSpace(string(respBody)))
	}

	if err := inspectADXMgmtResponse(command, respBody); err != nil {
		return err
	}
	return nil
}

func ingestRowsToADX(ctx context.Context, httpClient *http.Client, cluster, database, tableName, mappingName, token string, rows []map[string]any, batchSize int) (int, error) {
	if len(rows) == 0 {
		return 0, nil
	}

	batches := 0
	for start := 0; start < len(rows); start += batchSize {
		end := start + batchSize
		if end > len(rows) {
			end = len(rows)
		}
		if err := ingestBatchToADX(ctx, httpClient, cluster, database, tableName, mappingName, token, rows[start:end]); err != nil {
			return batches, err
		}
		batches++
	}
	return batches, nil
}

func ingestBatchToADX(ctx context.Context, httpClient *http.Client, cluster, database, tableName, mappingName, token string, rows []map[string]any) error {
	var body bytes.Buffer
	for _, row := range rows {
		encoded, err := json.Marshal(row)
		if err != nil {
			return fmt.Errorf("encode ADX ingest row: %w", err)
		}
		body.Write(encoded)
		body.WriteByte('\n')
	}

	command := fmt.Sprintf(".ingest inline into table %s with (format='json', ingestionMappingReference='%s') <|\n%s", tableName, escapeKustoString(mappingName), body.String())
	if err := runADXMgmtCommand(ctx, httpClient, cluster, database, token, command); err != nil {
		return fmt.Errorf("ADX inline ingest failed: %w", err)
	}
	return nil
}

func buildADXColumnDefs(schema []queryColumn) ([]adxColumnDef, error) {
	used := make(map[string]int)
	defs := make([]adxColumnDef, 0, len(schema))
	for _, column := range schema {
		if strings.TrimSpace(column.Name) == "" {
			return nil, errors.New("query schema included an empty column name")
		}
		baseName := sanitizeADXIdentifier(column.Name)
		if baseName == "" {
			baseName = "col"
		}
		columnName := baseName
		if count := used[columnName]; count > 0 {
			for {
				count++
				candidate := fmt.Sprintf("%s_%d", baseName, count)
				if _, exists := used[candidate]; !exists {
					columnName = candidate
					used[baseName] = count
					break
				}
			}
		}
		used[columnName] = 1
		defs = append(defs, adxColumnDef{
			ColumnName:  columnName,
			SourceField: column.Name,
			DataType:    defenderTypeToADXType(column.Type),
		})
	}
	return defs, nil
}

func buildADXColumnList(defs []adxColumnDef) string {
	columns := make([]string, 0, len(defs))
	for _, def := range defs {
		columns = append(columns, fmt.Sprintf("%s:%s", def.ColumnName, def.DataType))
	}
	return strings.Join(columns, ", ")
}

func buildADXMappingJSON(defs []adxColumnDef) ([]byte, error) {
	mapping := make([]adxMappingEntry, 0, len(defs))
	for _, def := range defs {
		mapping = append(mapping, adxMappingEntry{
			Column:   def.ColumnName,
			DataType: def.DataType,
			Properties: map[string]string{
				"Path": jsonPathForField(def.SourceField),
			},
		})
	}
	data, err := json.Marshal(mapping)
	if err != nil {
		return nil, fmt.Errorf("encode ADX mapping: %w", err)
	}
	return data, nil
}

func defenderTypeToADXType(in string) string {
	switch strings.ToLower(strings.TrimSpace(in)) {
	case "bool", "boolean":
		return "bool"
	case "date", "datetime":
		return "datetime"
	case "decimal":
		return "decimal"
	case "double", "float", "real":
		return "real"
	case "guid":
		return "guid"
	case "int", "int32", "integer":
		return "int"
	case "int64", "long":
		return "long"
	case "dynamic", "object", "array":
		return "dynamic"
	case "string":
		return "string"
	default:
		return "dynamic"
	}
}

func inferSchemaFromResults(results []map[string]any) []queryColumn {
	if len(results) == 0 {
		return nil
	}

	keys := make([]string, 0)
	typeByKey := make(map[string]string)
	for _, row := range results {
		for key, value := range row {
			if shouldSkipADXField(key) {
				continue
			}
			if _, ok := typeByKey[key]; !ok {
				keys = append(keys, key)
				typeByKey[key] = inferDefenderType(value)
				continue
			}
			typeByKey[key] = mergeDefenderTypes(typeByKey[key], inferDefenderType(value))
		}
	}

	sort.Strings(keys)
	schema := make([]queryColumn, 0, len(keys))
	for _, key := range keys {
		schema = append(schema, queryColumn{Name: key, Type: typeByKey[key]})
	}
	return schema
}

func shouldSkipADXField(key string) bool {
	return strings.HasSuffix(key, "@odata.type")
}

func inferDefenderType(value any) string {
	switch value.(type) {
	case bool:
		return "Boolean"
	case float64:
		number := value.(float64)
		if math.Trunc(number) == number {
			return "Int64"
		}
		return "Double"
	case string:
		if _, err := time.Parse(time.RFC3339, value.(string)); err == nil {
			return "DateTime"
		}
		return "String"
	case nil:
		return "Dynamic"
	case map[string]any, []any:
		return "Dynamic"
	default:
		return "Dynamic"
	}
}

func mergeDefenderTypes(left, right string) string {
	if left == right {
		return left
	}
	if left == "" {
		return right
	}
	if right == "" {
		return left
	}

	rank := map[string]int{
		"Boolean":  1,
		"Int64":    2,
		"Double":   3,
		"DateTime": 4,
		"String":   5,
		"Dynamic":  6,
	}
	if left == "Int64" && right == "Double" || left == "Double" && right == "Int64" {
		return "Double"
	}
	if rank[left] > rank[right] {
		return left
	}
	return right
}

func jsonPathForField(name string) string {
	if isSimpleJSONField(name) {
		return "$." + name
	}
	escaped := strings.ReplaceAll(name, `'`, `\'`)
	return "$['" + escaped + "']"
}

func isSimpleJSONField(name string) bool {
	if name == "" {
		return false
	}
	for i, r := range name {
		switch {
		case r == '_':
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case i > 0 && r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return true
}

func escapeKustoString(in string) string {
	return strings.ReplaceAll(in, `'`, `''`)
}

func inspectADXMgmtResponse(command string, body []byte) error {
	var resp kustoMgmtResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil
	}

	for _, table := range resp.Tables {
		if hasExceptionRows(table) {
			return fmt.Errorf("ADX management command returned exception rows: %s", compactJSON(body))
		}
	}

	if strings.HasPrefix(strings.TrimSpace(command), ".ingest inline") {
		ok, empty := inspectInlineIngestResult(resp)
		if ok && empty {
			return fmt.Errorf("ADX inline ingest produced no extents; the rows were accepted by HTTP but not ingested: %s", compactJSON(body))
		}
	}

	return nil
}

func hasExceptionRows(table kustoTable) bool {
	name := strings.ToLower(strings.TrimSpace(table.TableName))
	return strings.Contains(name, "exception") && len(table.Rows) > 0
}

func inspectInlineIngestResult(resp kustoMgmtResponse) (hasExtentColumn bool, allEmpty bool) {
	for _, table := range resp.Tables {
		idx := findColumnIndex(table.Columns, "ExtentId")
		if idx < 0 {
			continue
		}
		hasExtentColumn = true
		if len(table.Rows) == 0 {
			return true, true
		}
		allEmpty = true
		for _, row := range table.Rows {
			if idx >= len(row) {
				continue
			}
			if !isZeroExtentID(fmt.Sprint(row[idx])) {
				return true, false
			}
		}
		return true, allEmpty
	}
	return false, false
}

func findColumnIndex(columns []kustoTableColumn, name string) int {
	for i, column := range columns {
		if strings.EqualFold(strings.TrimSpace(column.ColumnName), name) {
			return i
		}
	}
	return -1
}

func isZeroExtentID(value string) bool {
	value = strings.TrimSpace(strings.ToLower(value))
	return value == "" || value == "00000000-0000-0000-0000-000000000000"
}

func compactJSON(body []byte) string {
	var buf bytes.Buffer
	if err := json.Compact(&buf, body); err != nil {
		return strings.TrimSpace(string(body))
	}
	return buf.String()
}
