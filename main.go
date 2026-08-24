package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultEndpoint     = "https://graph.microsoft.com/v1.0"
	defaultResource     = "https://graph.microsoft.com"
	defaultADXResource  = "https://api.kusto.windows.net"
	defaultLoginBaseURL = "https://login.microsoftonline.com"
	defaultOutputFile   = "results.json"
	defaultDumpLookback = "30d"
	defaultDumpRowLimit = 30000
)

type config struct {
	AuthMode                  string
	TenantID                  string
	ClientID                  string
	ClientSecret              string
	Query                     string
	QueryFile                 string
	DumpTable                 string
	DumpLookback              string
	DumpTimeColumn            string
	DumpRowLimit              int
	DumpParallelism           int
	Output                    string
	ADXExport                 bool
	OpenGraphExport           bool
	ADXCluster                string
	ADXDatabase               string
	ADXTable                  string
	ADXMapping                string
	ADXUploadFile             string
	ADXBatchSize              int
	ADXTenantID               string
	ADXClientID               string
	ADXClientSecret           string
	ADXResource               string
	BloodHoundURL             string
	BloodHoundToken           string
	BloodHoundTokenID         string
	BloodHoundTokenKey        string
	BloodHoundUploadGenerated bool
	BloodHoundUploadFile      string
	BloodHoundUploadIconsFile string
	Endpoint                  string
	Resource                  string
	LoginBaseURL              string
	InsecureSkipVerify        bool
	Timeout                   time.Duration
}

type authConfig struct {
	AuthMode     string
	TenantID     string
	ClientID     string
	ClientSecret string
	Resource     string
	LoginBaseURL string
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	Error       string `json:"error"`
	Description string `json:"error_description"`
}

type queryResponse struct {
	Schema  []queryColumn    `json:"Schema"`
	Results []map[string]any `json:"Results"`
	Stats   map[string]any   `json:"Stats"`
}

type queryColumn struct {
	Name string `json:"Name"`
	Type string `json:"Type"`
}

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

type dumpChunkResult struct {
	Partition    int
	ExpectedRows int
	Response     queryResponse
	Err          error
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

type openGraphPayload struct {
	Graph openGraphGraph `json:"graph"`
}

type openGraphGraph struct {
	Nodes []openGraphNode `json:"nodes"`
	Edges []openGraphEdge `json:"edges"`
}

type openGraphNode struct {
	ID         string         `json:"id"`
	Kinds      []string       `json:"kinds"`
	Properties map[string]any `json:"properties,omitempty"`
}

type openGraphEdge struct {
	Start      openGraphNodeReference `json:"start"`
	End        openGraphNodeReference `json:"end"`
	Kind       string                 `json:"kind"`
	Properties map[string]any         `json:"properties,omitempty"`
}

type openGraphNodeReference struct {
	MatchBy string `json:"match_by"`
	Value   string `json:"value"`
	Kind    string `json:"kind,omitempty"`
}

type openGraphCustomNodePayload struct {
	CustomTypes map[string]openGraphCustomNodeConfig `json:"custom_types"`
}

type openGraphCustomNodeConfig struct {
	Icon openGraphCustomNodeIcon `json:"icon"`
}

type openGraphCustomNodeIcon struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Color string `json:"color,omitempty"`
}

type bloodHoundFileUploadJobResponse struct {
	Data struct {
		ID int64 `json:"id"`
	} `json:"data"`
}

type bloodHoundCustomNodeListResponse struct {
	Data []bloodHoundCustomNode `json:"data"`
}

type bloodHoundCustomNode struct {
	KindName string                    `json:"kindName"`
	Config   openGraphCustomNodeConfig `json:"config"`
}

type bloodHoundCustomNodeUpdateRequest struct {
	Config openGraphCustomNodeConfig `json:"config"`
}

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	cfg, err := parseFlags(args, stderr)
	if err != nil {
		return err
	}

	httpClient := newHTTPClient(cfg.Timeout, cfg.InsecureSkipVerify)
	messages := make([]string, 0, 2)

	if hasQueryInput(cfg) {
		query, err := readQuery(cfg.Query, cfg.QueryFile)
		if err != nil {
			return err
		}

		token, authMode, err := acquireToken(ctx, httpClient, mdeAuthConfig(cfg))
		if err != nil {
			return err
		}

		body, response, err := runAdvancedQuery(ctx, httpClient, cfg.Endpoint, token, query)
		if err != nil {
			return err
		}

		if err := writeJSONFile(cfg.Output, body); err != nil {
			return err
		}

		rowCount := len(response.Results)
		message := fmt.Sprintf("wrote %d rows to %s using %s authentication", rowCount, cfg.Output, authMode)
		if cfg.ADXExport {
			dataPath, schemaPath, err := writeADXArtifacts(cfg, response)
			if err != nil {
				return err
			}
			message += fmt.Sprintf("\nadx data file: %s\nadx schema file: %s", dataPath, schemaPath)
		}
		if cfg.OpenGraphExport {
			openGraphPath, iconPath, err := writeOpenGraphArtifact(cfg, response)
			if err != nil {
				return err
			}
			message += fmt.Sprintf("\nopengraph file: %s", openGraphPath)
			if iconPath != "" {
				message += fmt.Sprintf("\nopengraph icon file: %s", iconPath)
			}
			if cfg.BloodHoundUploadGenerated {
				jobID, err := uploadFileToBloodHound(ctx, httpClient, cfg, openGraphPath)
				if err != nil {
					return err
				}
				message += fmt.Sprintf("\nbloodhound graph upload job: %d", jobID)
				if iconPath != "" {
					created, updated, err := uploadCustomNodesToBloodHound(ctx, httpClient, cfg, iconPath)
					if err != nil {
						return err
					}
					message += fmt.Sprintf("\nbloodhound icon upload: created %d, updated %d", created, updated)
				}
			}
		}
		messages = append(messages, message)
	}

	if cfg.DumpTable != "" {
		token, authMode, err := acquireToken(ctx, httpClient, mdeAuthConfig(cfg))
		if err != nil {
			return err
		}

		output, err := dumpTable(ctx, httpClient, cfg, token, stderr)
		if err != nil {
			return err
		}

		message := fmt.Sprintf("dumped %d rows from %s over %s to %s using %s authentication", output.Rows, cfg.DumpTable, cfg.DumpLookback, cfg.Output, authMode)
		if output.Stats.Chunks > 1 {
			message += fmt.Sprintf("\nprocessed %d chunk(s) across %d hash partition(s); initial matching row count was %d", output.Stats.Chunks, output.Stats.Partitions, output.Stats.TotalRows)
		}
		if output.ADXDataPath != "" {
			message += fmt.Sprintf("\nadx data file: %s\nadx schema file: %s", output.ADXDataPath, output.ADXSchemaPath)
		}
		if cfg.OpenGraphExport {
			openGraphPath, iconPath, err := writeOpenGraphArtifact(cfg, output.Response)
			if err != nil {
				return err
			}
			message += fmt.Sprintf("\nopengraph file: %s", openGraphPath)
			if iconPath != "" {
				message += fmt.Sprintf("\nopengraph icon file: %s", iconPath)
			}
		}
		messages = append(messages, message)
	}

	if cfg.ADXUploadFile != "" {
		rowsUploaded, batchesUploaded, authMode, err := uploadFileToADX(ctx, httpClient, cfg)
		if err != nil {
			return err
		}
		messages = append(messages, fmt.Sprintf("uploaded %d rows from %s to %s/%s in %d batch(es) using %s authentication", rowsUploaded, cfg.ADXUploadFile, cfg.ADXDatabase, cfg.ADXTable, batchesUploaded, authMode))
	}
	if cfg.BloodHoundUploadFile != "" {
		jobID, err := uploadFileToBloodHound(ctx, httpClient, cfg, cfg.BloodHoundUploadFile)
		if err != nil {
			return err
		}
		messages = append(messages, fmt.Sprintf("uploaded %s to BloodHound as file upload job %d", cfg.BloodHoundUploadFile, jobID))
	}
	if cfg.BloodHoundUploadIconsFile != "" {
		created, updated, err := uploadCustomNodesToBloodHound(ctx, httpClient, cfg, cfg.BloodHoundUploadIconsFile)
		if err != nil {
			return err
		}
		messages = append(messages, fmt.Sprintf("uploaded BloodHound custom node icons from %s (created %d, updated %d)", cfg.BloodHoundUploadIconsFile, created, updated))
	}

	if len(messages) == 0 {
		return errors.New("no action requested; provide -query or -query-file to run Defender query, -dump-table to dump a Defender table, -adx-upload-file to ingest data into ADX, or BloodHound upload flags to send OpenGraph artifacts")
	}

	fmt.Fprintln(stdout, strings.Join(messages, "\n"))
	return nil
}

func parseFlags(args []string, stderr io.Writer) (config, error) {
	cfg := config{}
	envFile := defaultEnvFile(args)
	dotenv, err := loadDotEnv(envFile)
	if err != nil {
		return cfg, err
	}

	fs := flag.NewFlagSet("tableDumper", flag.ContinueOnError)
	fs.SetOutput(stderr)

	fs.StringVar(&cfg.AuthMode, "auth", "auto", "Authentication mode: auto, sp, or azcli")
	fs.StringVar(&cfg.TenantID, "tenant-id", envOrDotEnv("AZURE_TENANT_ID", dotenv), "Microsoft Entra tenant ID")
	fs.StringVar(&cfg.ClientID, "client-id", envOrDotEnv("AZURE_CLIENT_ID", dotenv), "Service principal client ID")
	fs.StringVar(&cfg.ClientSecret, "client-secret", envOrDotEnv("AZURE_CLIENT_SECRET", dotenv), "Service principal client secret")
	fs.StringVar(&cfg.Query, "query", "", "KQL query string to run")
	fs.StringVar(&cfg.QueryFile, "query-file", "", "Path to a file containing the KQL query")
	fs.StringVar(&cfg.DumpTable, "dump-table", "", "Defender advanced hunting table name to dump")
	fs.StringVar(&cfg.DumpLookback, "dump-lookback", defaultDumpLookback, "Lookback timespan for -dump-table, for example 30d, 12h, or 90m")
	fs.StringVar(&cfg.DumpTimeColumn, "dump-time-column", "Timestamp", "Time column used for -dump-table lookback filtering")
	fs.IntVar(&cfg.DumpRowLimit, "dump-row-limit", defaultDumpRowLimit, "Maximum rows to request per table dump query before partitioning")
	fs.IntVar(&cfg.DumpParallelism, "dump-parallelism", 4, "Maximum number of table dump chunks to query in parallel")
	fs.StringVar(&cfg.Output, "output", defaultOutputFile, "Path to the JSON output file")
	fs.BoolVar(&cfg.ADXExport, "adx-export", false, "Also write Azure Data Explorer ingestion artifacts")
	fs.BoolVar(&cfg.OpenGraphExport, "opengraph-export", false, "Also write a BloodHound OpenGraph JSON payload")
	fs.StringVar(&cfg.ADXCluster, "adx-cluster", envOrDotEnvAny(dotenv, "ADX_CLUSTER"), "ADX cluster URI, for example https://<cluster>.<region>.kusto.windows.net")
	fs.StringVar(&cfg.ADXDatabase, "adx-database", envOrDotEnvAny(dotenv, "ADX_DATABASE"), "ADX database name")
	fs.StringVar(&cfg.ADXTable, "adx-table", "", "ADX table name to use in the generated schema file")
	fs.StringVar(&cfg.ADXMapping, "adx-mapping", "", "ADX ingestion mapping name to use in the generated schema file")
	fs.StringVar(&cfg.ADXUploadFile, "adx-upload-file", "", "Path to a JSON/NDJSON file to upload to ADX")
	fs.IntVar(&cfg.ADXBatchSize, "adx-batch-size", 500, "Number of rows to include in each ADX ingestion request")
	fs.StringVar(&cfg.ADXTenantID, "adx-tenant-id", envOrDotEnvAny(dotenv, "ADX_TENANT_ID"), "Microsoft Entra tenant ID to use for ADX")
	fs.StringVar(&cfg.ADXClientID, "adx-client-id", envOrDotEnvAny(dotenv, "ADX_CLIENT_ID"), "Service principal client ID to use for ADX")
	fs.StringVar(&cfg.ADXClientSecret, "adx-client-secret", envOrDotEnvAny(dotenv, "ADX_CLIENT_SECRET"), "Service principal client secret to use for ADX")
	fs.StringVar(&cfg.ADXResource, "adx-resource", envOrDotEnvAny(dotenv, "ADX_RESOURCE"), "OAuth resource/audience for ADX access tokens")
	fs.StringVar(&cfg.BloodHoundURL, "bloodhound-url", envOrDotEnvAny(dotenv, "BLOODHOUND_URL"), "BloodHound base URL")
	fs.StringVar(&cfg.BloodHoundToken, "bloodhound-token", envOrDotEnvAny(dotenv, "BLOODHOUND_TOKEN"), "BloodHound JWT bearer token")
	fs.StringVar(&cfg.BloodHoundTokenID, "bloodhound-token-id", envOrDotEnvAny(dotenv, "BLOODHOUND_TOKEN_ID"), "BloodHound API token ID for signed requests")
	fs.StringVar(&cfg.BloodHoundTokenKey, "bloodhound-token-key", envOrDotEnvAny(dotenv, "BLOODHOUND_TOKEN_KEY"), "BloodHound API token key for signed requests")
	fs.BoolVar(&cfg.BloodHoundUploadGenerated, "bloodhound-upload-generated", false, "After OpenGraph export, upload generated graph and icon files to BloodHound")
	fs.StringVar(&cfg.BloodHoundUploadFile, "bloodhound-upload-file", "", "Path to an OpenGraph JSON or ZIP file to upload to BloodHound")
	fs.StringVar(&cfg.BloodHoundUploadIconsFile, "bloodhound-upload-icons-file", "", "Path to a BloodHound custom node icon payload to upload")
	fs.StringVar(&cfg.Endpoint, "endpoint", defaultEndpoint, "Defender for Endpoint API base URL")
	fs.StringVar(&cfg.Resource, "resource", defaultResource, "OAuth resource/audience for the access token")
	fs.StringVar(&cfg.LoginBaseURL, "login-base-url", defaultLoginBaseURL, "Microsoft Entra login base URL")
	fs.BoolVar(&cfg.InsecureSkipVerify, "insecure-skip-verify", false, "Skip TLS certificate verification for HTTPS requests")
	fs.StringVar(&envFile, "env-file", envFile, "Path to a dotenv file to read for default credential values")
	fs.DurationVar(&cfg.Timeout, "timeout", 60*time.Second, "HTTP timeout")

	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: %s --query \"DeviceInfo | limit 10\" --output results.json [flags]\n\n", fs.Name())
		fmt.Fprintln(stderr, "Run a Defender for Endpoint advanced hunting query and save the JSON response.")
		fmt.Fprintln(stderr, "\nExamples:")
		fmt.Fprintf(stderr, "  %s --auth azcli --query \"DeviceInfo | limit 10\" --output results.json\n", fs.Name())
		fmt.Fprintf(stderr, "  %s --auth sp --tenant-id <tenant> --client-id <app> --client-secret <secret> --query-file query.kql --output results.json\n\n", fs.Name())
		fmt.Fprintln(stderr, "Flags:")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return cfg, err
	}

	cfg.AuthMode = strings.ToLower(strings.TrimSpace(cfg.AuthMode))
	switch cfg.AuthMode {
	case "auto", "sp", "azcli":
	default:
		return cfg, fmt.Errorf("unsupported -auth value %q; expected auto, sp, or azcli", cfg.AuthMode)
	}

	cfg.Endpoint = strings.TrimRight(strings.TrimSpace(cfg.Endpoint), "/")
	cfg.Resource = strings.TrimRight(strings.TrimSpace(cfg.Resource), "/")
	cfg.LoginBaseURL = strings.TrimRight(strings.TrimSpace(cfg.LoginBaseURL), "/")
	cfg.DumpTable = strings.TrimSpace(cfg.DumpTable)
	cfg.DumpLookback = strings.TrimSpace(cfg.DumpLookback)
	cfg.DumpTimeColumn = strings.TrimSpace(cfg.DumpTimeColumn)
	cfg.ADXCluster = strings.TrimRight(strings.TrimSpace(cfg.ADXCluster), "/")
	cfg.ADXDatabase = strings.TrimSpace(cfg.ADXDatabase)
	cfg.ADXUploadFile = strings.TrimSpace(cfg.ADXUploadFile)
	cfg.ADXResource = strings.TrimRight(strings.TrimSpace(cfg.ADXResource), "/")
	cfg.BloodHoundURL = strings.TrimRight(strings.TrimSpace(cfg.BloodHoundURL), "/")
	cfg.BloodHoundToken = strings.TrimSpace(cfg.BloodHoundToken)
	cfg.BloodHoundTokenID = strings.TrimSpace(cfg.BloodHoundTokenID)
	cfg.BloodHoundTokenKey = strings.TrimSpace(cfg.BloodHoundTokenKey)
	cfg.BloodHoundUploadFile = strings.TrimSpace(cfg.BloodHoundUploadFile)
	cfg.BloodHoundUploadIconsFile = strings.TrimSpace(cfg.BloodHoundUploadIconsFile)
	if cfg.ADXResource == "" {
		cfg.ADXResource = defaultADXResource
	}

	if cfg.Output == "" {
		return cfg, errors.New("output path must not be empty")
	}
	if cfg.Endpoint == "" {
		return cfg, errors.New("endpoint must not be empty")
	}
	if cfg.Resource == "" {
		return cfg, errors.New("resource must not be empty")
	}
	if cfg.LoginBaseURL == "" {
		return cfg, errors.New("login base URL must not be empty")
	}
	if cfg.ADXBatchSize <= 0 {
		return cfg, errors.New("adx batch size must be greater than zero")
	}
	if cfg.DumpRowLimit <= 0 {
		return cfg, errors.New("dump row limit must be greater than zero")
	}
	if cfg.DumpParallelism <= 0 {
		return cfg, errors.New("dump parallelism must be greater than zero")
	}
	if cfg.DumpTable != "" {
		if hasQueryInput(cfg) {
			return cfg, errors.New("provide either -dump-table or -query/-query-file, not both")
		}
		if !isSafeADXIdentifier(cfg.DumpTable) {
			return cfg, fmt.Errorf("invalid -dump-table value %q; use only letters, numbers, and underscores, starting with a letter or underscore", cfg.DumpTable)
		}
		if !isSafeADXIdentifier(cfg.DumpTimeColumn) {
			return cfg, fmt.Errorf("invalid -dump-time-column value %q; use only letters, numbers, and underscores, starting with a letter or underscore", cfg.DumpTimeColumn)
		}
		if !isSafeKQLTimespanLiteral(cfg.DumpLookback) {
			return cfg, fmt.Errorf("invalid -dump-lookback value %q; use a simple KQL timespan literal such as 30d, 12h, 90m, or 1.5h", cfg.DumpLookback)
		}
	}
	if cfg.ADXTable != "" && !isSafeADXIdentifier(cfg.ADXTable) {
		return cfg, fmt.Errorf("invalid -adx-table value %q; use only letters, numbers, and underscores, starting with a letter or underscore", cfg.ADXTable)
	}
	if cfg.ADXMapping != "" && !isSafeADXIdentifier(cfg.ADXMapping) {
		return cfg, fmt.Errorf("invalid -adx-mapping value %q; use only letters, numbers, and underscores, starting with a letter or underscore", cfg.ADXMapping)
	}
	if cfg.ADXUploadFile != "" {
		if cfg.ADXCluster == "" {
			return cfg, errors.New("adx upload requires -adx-cluster or ADX_CLUSTER")
		}
		if cfg.ADXDatabase == "" {
			return cfg, errors.New("adx upload requires -adx-database or ADX_DATABASE")
		}
		if cfg.ADXTable == "" {
			return cfg, errors.New("adx upload requires -adx-table")
		}
	}
	if cfg.BloodHoundUploadGenerated && !cfg.OpenGraphExport {
		return cfg, errors.New("bloodhound generated upload requires -opengraph-export")
	}
	if cfg.BloodHoundUploadGenerated && !hasQueryInput(cfg) {
		return cfg, errors.New("bloodhound generated upload requires -query or -query-file")
	}
	if cfg.BloodHoundUploadGenerated || cfg.BloodHoundUploadFile != "" || cfg.BloodHoundUploadIconsFile != "" {
		if cfg.BloodHoundURL == "" {
			return cfg, errors.New("bloodhound upload requires -bloodhound-url or BLOODHOUND_URL")
		}
		hasBearer := cfg.BloodHoundToken != ""
		hasSigned := cfg.BloodHoundTokenID != "" || cfg.BloodHoundTokenKey != ""
		if !hasBearer && !hasSigned {
			return cfg, errors.New("bloodhound upload requires either -bloodhound-token or the -bloodhound-token-id/-bloodhound-token-key pair")
		}
		if hasSigned && (cfg.BloodHoundTokenID == "" || cfg.BloodHoundTokenKey == "") {
			return cfg, errors.New("bloodhound signed requests require both -bloodhound-token-id and -bloodhound-token-key")
		}
	}

	return cfg, nil
}

func newHTTPClient(timeout time.Duration, insecureSkipVerify bool) *http.Client {
	client := &http.Client{Timeout: timeout}
	if !insecureSkipVerify {
		return client
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{}
	}
	transport.TLSClientConfig.InsecureSkipVerify = true
	client.Transport = transport
	return client
}

func defaultEnvFile(args []string) string {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--env-file" || arg == "-env-file":
			if i+1 < len(args) {
				return args[i+1]
			}
		case strings.HasPrefix(arg, "--env-file="):
			return strings.TrimPrefix(arg, "--env-file=")
		case strings.HasPrefix(arg, "-env-file="):
			return strings.TrimPrefix(arg, "-env-file=")
		}
	}
	return ".env"
}

func envOrDotEnv(key string, dotenv map[string]string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return dotenv[key]
}

func envOrDotEnvAny(dotenv map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := os.Getenv(key); value != "" {
			return value
		}
	}
	for _, key := range keys {
		if value := dotenv[key]; value != "" {
			return value
		}
	}
	return ""
}

func loadDotEnv(path string) (map[string]string, error) {
	values := make(map[string]string)
	if strings.TrimSpace(path) == "" {
		return values, nil
	}

	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && path == ".env" {
			return values, nil
		}
		return nil, fmt.Errorf("open env file %s: %w", path, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "export ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		}

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("parse env file %s:%d: expected KEY=VALUE", path, lineNo)
		}

		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" {
			return nil, fmt.Errorf("parse env file %s:%d: empty key", path, lineNo)
		}

		unquoted, err := unquoteDotEnvValue(value)
		if err != nil {
			return nil, fmt.Errorf("parse env file %s:%d: %w", path, lineNo, err)
		}
		values[key] = unquoted
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read env file %s: %w", path, err)
	}

	return values, nil
}

func unquoteDotEnvValue(value string) (string, error) {
	if len(value) >= 2 {
		if (value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'') {
			return value[1 : len(value)-1], nil
		}
		if value[0] == '"' || value[0] == '\'' {
			return "", errors.New("unterminated quoted value")
		}
	}
	return value, nil
}

func readQuery(inlineQuery, queryFile string) (string, error) {
	inlineQuery = strings.TrimSpace(inlineQuery)
	queryFile = strings.TrimSpace(queryFile)

	switch {
	case inlineQuery != "" && queryFile != "":
		return "", errors.New("provide either -query or -query-file, not both")
	case inlineQuery == "" && queryFile == "":
		return "", errors.New("provide a KQL query with -query or -query-file")
	case inlineQuery != "":
		return inlineQuery, nil
	default:
		content, err := os.ReadFile(queryFile)
		if err != nil {
			return "", fmt.Errorf("read query file %s: %w", queryFile, err)
		}
		query := strings.TrimSpace(string(content))
		if query == "" {
			return "", fmt.Errorf("query file %s is empty", queryFile)
		}
		return query, nil
	}
}

func hasQueryInput(cfg config) bool {
	return strings.TrimSpace(cfg.Query) != "" || strings.TrimSpace(cfg.QueryFile) != ""
}

func mdeAuthConfig(cfg config) authConfig {
	return authConfig{
		AuthMode:     cfg.AuthMode,
		TenantID:     cfg.TenantID,
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Resource:     cfg.Resource,
		LoginBaseURL: cfg.LoginBaseURL,
	}
}

func adxAuthConfig(cfg config) authConfig {
	return authConfig{
		AuthMode:     cfg.AuthMode,
		TenantID:     cfg.ADXTenantID,
		ClientID:     cfg.ADXClientID,
		ClientSecret: cfg.ADXClientSecret,
		Resource:     cfg.ADXResource,
		LoginBaseURL: cfg.LoginBaseURL,
	}
}

func acquireToken(ctx context.Context, httpClient *http.Client, cfg authConfig) (token string, authMode string, err error) {
	mode := resolveAuthMode(cfg)

	switch mode {
	case "sp":
		token, err = getServicePrincipalToken(ctx, httpClient, cfg)
	case "azcli":
		token, err = getAzureCLIToken(ctx, cfg)
	default:
		err = fmt.Errorf("internal error: unsupported auth mode %q", mode)
	}

	return token, mode, err
}

func resolveAuthMode(cfg authConfig) string {
	if cfg.AuthMode != "auto" {
		return cfg.AuthMode
	}
	if cfg.TenantID != "" && cfg.ClientID != "" && cfg.ClientSecret != "" {
		return "sp"
	}
	return "azcli"
}

func getServicePrincipalToken(ctx context.Context, httpClient *http.Client, cfg authConfig) (string, error) {
	if cfg.TenantID == "" || cfg.ClientID == "" || cfg.ClientSecret == "" {
		return "", errors.New("service principal auth requires tenant ID, client ID, and client secret")
	}

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", cfg.ClientID)
	form.Set("client_secret", cfg.ClientSecret)
	form.Set("resource", cfg.Resource)

	tokenURL := fmt.Sprintf("%s/%s/oauth2/token", cfg.LoginBaseURL, url.PathEscape(cfg.TenantID))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("request service principal token: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read token response: %w", err)
	}

	var tokenResp tokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("token request failed: %s: %s", resp.Status, strings.TrimSpace(compactError(tokenResp.Error, tokenResp.Description, body)))
	}
	if tokenResp.AccessToken == "" {
		return "", errors.New("token response did not contain an access token")
	}

	return tokenResp.AccessToken, nil
}

func getAzureCLIToken(ctx context.Context, cfg authConfig) (string, error) {
	args := []string{
		"account", "get-access-token",
		"--resource", cfg.Resource,
		"--output", "json",
	}
	if cfg.TenantID != "" {
		args = append(args, "--tenant", cfg.TenantID)
	}

	cmd := exec.CommandContext(ctx, "az", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("run Azure CLI token command: %w: %s", err, strings.TrimSpace(string(output)))
	}

	var tokenResp tokenResponse
	if err := json.Unmarshal(output, &tokenResp); err != nil {
		return "", fmt.Errorf("decode Azure CLI token response: %w", err)
	}
	if tokenResp.AccessToken == "" {
		return "", errors.New("Azure CLI did not return an access token; run 'az login' first")
	}

	return tokenResp.AccessToken, nil
}

func runAdvancedQuery(ctx context.Context, httpClient *http.Client, endpoint, token, query string) ([]byte, queryResponse, error) {
	requestBody, err := json.Marshal(map[string]string{"Query": query})
	if err != nil {
		return nil, queryResponse{}, fmt.Errorf("encode query request: %w", err)
	}

	url := endpoint + "/security/runHuntingQuery"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(requestBody))
	if err != nil {
		return nil, queryResponse{}, fmt.Errorf("build query request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, queryResponse{}, fmt.Errorf("run advanced query: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, queryResponse{}, fmt.Errorf("read query response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, queryResponse{}, fmt.Errorf("advanced query failed: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	parsed, err := parseQueryResponse(body)
	if err != nil {
		return nil, queryResponse{}, fmt.Errorf("decode query response: %w", err)
	}

	return body, parsed, nil
}

func dumpTable(ctx context.Context, httpClient *http.Client, cfg config, token string, progress io.Writer) (tableDumpOutput, error) {
	baseQuery := buildTableDumpBaseQuery(cfg.DumpTable, cfg.DumpTimeColumn, cfg.DumpLookback)
	progressf(progress, "counting rows in %s over %s...", cfg.DumpTable, cfg.DumpLookback)
	_, countResponse, err := runAdvancedQuery(ctx, httpClient, cfg.Endpoint, token, buildTableDumpCountQuery(baseQuery))
	if err != nil {
		return tableDumpOutput{}, fmt.Errorf("count rows in %s: %w", cfg.DumpTable, err)
	}

	totalRows, err := parseCountResponse(countResponse)
	if err != nil {
		return tableDumpOutput{}, fmt.Errorf("parse row count for %s: %w", cfg.DumpTable, err)
	}

	stats := tableDumpStats{TotalRows: totalRows}
	progressf(progress, "found %d row(s) to dump from %s", totalRows, cfg.DumpTable)
	if totalRows < cfg.DumpRowLimit {
		progressf(progress, "row count is below %d; dumping in a single query...", cfg.DumpRowLimit)
		_, response, err := runAdvancedQuery(ctx, httpClient, cfg.Endpoint, token, baseQuery)
		if err != nil {
			return tableDumpOutput{Stats: stats}, fmt.Errorf("dump %s: %w", cfg.DumpTable, err)
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
		progressf(progress, "completed single-query dump with %d row(s)", len(response.Results))
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

	progressf(progress, "row count is at or above %d; calculating hash partitions...", cfg.DumpRowLimit)
	partitions, partitionCountValue, err := resolveDumpPartitions(ctx, httpClient, cfg, token, baseQuery, totalRows, progress)
	if err != nil {
		return tableDumpOutput{Stats: stats}, err
	}
	if len(partitions) == 0 {
		stats.Chunks = 0
		stats.Partitions = 0
		progressf(progress, "no non-empty partitions found")
		if err := writeJSONFile(cfg.Output, []byte(`{"Schema":[],"Results":[]}`)); err != nil {
			return tableDumpOutput{Stats: stats}, err
		}
		return tableDumpOutput{Stats: stats}, nil
	}

	schema, rows, adxDataPath, adxSchemaPath, err := streamTableDumpPartitions(ctx, httpClient, cfg, token, baseQuery, partitions, partitionCountValue, progress)
	if err != nil {
		return tableDumpOutput{Stats: stats}, err
	}
	stats.Chunks = len(partitions)
	stats.Partitions = partitionCountValue
	progressf(progress, "completed partitioned dump with %d row(s)", rows)
	return tableDumpOutput{
		Schema:        schema,
		Rows:          rows,
		Stats:         stats,
		ADXDataPath:   adxDataPath,
		ADXSchemaPath: adxSchemaPath,
	}, nil
}

func resolveDumpPartitions(ctx context.Context, httpClient *http.Client, cfg config, token, baseQuery string, totalRows int, progress io.Writer) ([]partitionCount, int, error) {
	partitionCountValue := (totalRows + cfg.DumpRowLimit - 1) / cfg.DumpRowLimit
	if partitionCountValue < 2 {
		partitionCountValue = 2
	}

	for {
		progressf(progress, "counting rows across %d hash partition(s)...", partitionCountValue)
		_, response, err := runAdvancedQuery(ctx, httpClient, cfg.Endpoint, token, buildTableDumpPartitionCountQuery(baseQuery, partitionCountValue))
		if err != nil {
			return nil, 0, fmt.Errorf("count %s hash partitions: %w", cfg.DumpTable, err)
		}
		partitions, err := parsePartitionCountsResponse(response)
		if err != nil {
			return nil, 0, fmt.Errorf("parse %s partition counts: %w", cfg.DumpTable, err)
		}
		sort.Slice(partitions, func(i, j int) bool {
			return partitions[i].Partition < partitions[j].Partition
		})
		maxRows := maxPartitionRows(partitions)
		progressf(progress, "found %d non-empty partition(s); largest partition has %d row(s)", len(partitions), maxRows)
		if maxRows < cfg.DumpRowLimit {
			return partitions, partitionCountValue, nil
		}
		partitionCountValue *= 2
		progressf(progress, "largest partition is still at or above %d row(s); retrying with %d partition(s)", cfg.DumpRowLimit, partitionCountValue)
		if partitionCountValue > cfg.DumpRowLimit {
			return nil, 0, fmt.Errorf("unable to split %s into chunks below %d rows after trying %d hash partitions", cfg.DumpTable, cfg.DumpRowLimit, partitionCountValue)
		}
	}
}

func streamTableDumpPartitions(ctx context.Context, httpClient *http.Client, cfg config, token, baseQuery string, partitions []partitionCount, partitionCountValue int, progress io.Writer) ([]queryColumn, int, string, string, error) {
	results := make(chan dumpChunkResult, len(partitions))
	sem := make(chan struct{}, cfg.DumpParallelism)
	var wg sync.WaitGroup
	progressf(progress, "dumping %d non-empty partition chunk(s) with up to %d parallel request(s)", len(partitions), cfg.DumpParallelism)

	for _, partition := range partitions {
		partition := partition
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			query := buildTableDumpPartitionQuery(baseQuery, partitionCountValue, partition.Partition)
			_, response, err := runAdvancedQuery(ctx, httpClient, cfg.Endpoint, token, query)
			if err != nil {
				results <- dumpChunkResult{Partition: partition.Partition, ExpectedRows: partition.Rows, Err: fmt.Errorf("dump %s partition %d: %w", cfg.DumpTable, partition.Partition, err)}
				return
			}
			if len(response.Results) >= cfg.DumpRowLimit {
				results <- dumpChunkResult{Partition: partition.Partition, ExpectedRows: partition.Rows, Err: fmt.Errorf("partition %d returned %d rows, at or above the configured limit %d", partition.Partition, len(response.Results), cfg.DumpRowLimit)}
				return
			}
			results <- dumpChunkResult{Partition: partition.Partition, ExpectedRows: partition.Rows, Response: response}
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var responseWriter *queryResponseStreamWriter
	var adxWriter *ndjsonStreamWriter
	var schema []queryColumn
	completed := 0
	for result := range results {
		if result.Err != nil {
			if responseWriter != nil {
				responseWriter.Abort()
			}
			if adxWriter != nil {
				adxWriter.Abort()
			}
			return nil, 0, "", "", result.Err
		}
		if responseWriter == nil {
			schema = result.Response.Schema
			if len(schema) == 0 {
				schema = inferSchemaFromResults(result.Response.Results)
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
			progressf(progress, "streaming results to %s", cfg.Output)
		}
		completed++
		progressf(progress, "completed partition %d (%d/%d): expected %d row(s), received %d row(s)", result.Partition, completed, len(partitions), result.ExpectedRows, len(result.Response.Results))
		if err := responseWriter.WriteRows(result.Response.Results); err != nil {
			responseWriter.Abort()
			if adxWriter != nil {
				adxWriter.Abort()
			}
			return nil, 0, "", "", err
		}
		if adxWriter != nil {
			if err := adxWriter.WriteRows(result.Response.Results); err != nil {
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

func parseQueryResponse(body []byte) (queryResponse, error) {
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return queryResponse{}, err
	}

	return queryResponse{
		Schema:  parseQueryColumns(lookupAny(payload, "Schema", "schema")),
		Results: parseQueryRows(lookupAny(payload, "Results", "results")),
		Stats:   parseStringAnyMap(lookupAny(payload, "Stats", "stats")),
	}, nil
}

func marshalQueryResponse(response queryResponse) ([]byte, error) {
	payload := map[string]any{
		"Schema":  response.Schema,
		"Results": response.Results,
	}
	if response.Stats != nil {
		payload["Stats"] = response.Stats
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode query response: %w", err)
	}
	return body, nil
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

func writeOpenGraphArtifact(cfg config, response queryResponse) (string, string, error) {
	payload, err := buildOpenGraphPayload(response)
	if err != nil {
		return "", "", err
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", "", fmt.Errorf("encode OpenGraph payload: %w", err)
	}

	path := openGraphArtifactPath(cfg.Output)
	if err := writeJSONFile(path, body); err != nil {
		return "", "", err
	}

	iconPayload := buildOpenGraphCustomNodePayload(payload)
	if len(iconPayload.CustomTypes) == 0 {
		return path, "", nil
	}

	iconBody, err := json.Marshal(iconPayload)
	if err != nil {
		return "", "", fmt.Errorf("encode OpenGraph icon payload: %w", err)
	}

	iconPath := openGraphIconArtifactPath(cfg.Output)
	if err := writeJSONFile(iconPath, iconBody); err != nil {
		return "", "", err
	}

	return path, iconPath, nil
}

func writeJSONFile(path string, body []byte) error {
	pretty, err := indentJSON(body)
	if err != nil {
		return fmt.Errorf("format JSON output: %w", err)
	}

	dir := filepath.Dir(path)
	if dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("create output directory %s: %w", dir, err)
		}
	}

	if err := os.WriteFile(path, pretty, 0o600); err != nil {
		return fmt.Errorf("write output file %s: %w", path, err)
	}

	return nil
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

func writeTextFile(path, content string) error {
	return writeBytes(path, []byte(content))
}

func writeBytes(path string, body []byte) error {
	dir := filepath.Dir(path)
	if dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("create output directory %s: %w", dir, err)
		}
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		return fmt.Errorf("write output file %s: %w", path, err)
	}
	return nil
}

func adxArtifactPaths(outputPath string) (string, string) {
	ext := filepath.Ext(outputPath)
	base := strings.TrimSuffix(outputPath, ext)
	if base == "" {
		base = outputPath
	}
	return base + ".adx.json", base + ".adx.kql"
}

func openGraphArtifactPath(outputPath string) string {
	ext := filepath.Ext(outputPath)
	base := strings.TrimSuffix(outputPath, ext)
	if base == "" {
		base = outputPath
	}
	return base + ".opengraph.json"
}

func openGraphIconArtifactPath(outputPath string) string {
	ext := filepath.Ext(outputPath)
	base := strings.TrimSuffix(outputPath, ext)
	if base == "" {
		base = outputPath
	}
	return base + ".opengraph.icons.json"
}

func uploadFileToBloodHound(ctx context.Context, httpClient *http.Client, cfg config, path string) (int64, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("read BloodHound upload file %s: %w", path, err)
	}

	jobID, err := startBloodHoundFileUploadJob(ctx, httpClient, cfg)
	if err != nil {
		return 0, err
	}
	if err := sendBloodHoundFileUpload(ctx, httpClient, cfg, jobID, path, body); err != nil {
		return 0, err
	}
	if err := endBloodHoundFileUploadJob(ctx, httpClient, cfg, jobID); err != nil {
		return 0, err
	}
	return jobID, nil
}

func startBloodHoundFileUploadJob(ctx context.Context, httpClient *http.Client, cfg config) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.BloodHoundURL+"/api/v2/file-upload/start", nil)
	if err != nil {
		return 0, fmt.Errorf("build BloodHound file upload start request: %w", err)
	}
	if err := authorizeBloodHoundRequest(req, cfg, nil); err != nil {
		return 0, err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("start BloodHound file upload job: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("read BloodHound file upload start response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, fmt.Errorf("BloodHound file upload start failed: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	var parsed bloodHoundFileUploadJobResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return 0, fmt.Errorf("decode BloodHound file upload start response: %w", err)
	}
	if parsed.Data.ID == 0 {
		return 0, errors.New("BloodHound file upload start response did not contain a job id")
	}
	return parsed.Data.ID, nil
}

func sendBloodHoundFileUpload(ctx context.Context, httpClient *http.Client, cfg config, jobID int64, path string, body []byte) error {
	uploadURL := fmt.Sprintf("%s/api/v2/file-upload/%d", cfg.BloodHoundURL, jobID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uploadURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build BloodHound file upload request: %w", err)
	}
	if err := authorizeBloodHoundRequest(req, cfg, body); err != nil {
		return err
	}
	req.Header.Set("Content-Type", bloodHoundUploadContentType(path))
	req.Header.Set("X-File-Upload-Name", filepath.Base(path))

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("upload file %s to BloodHound: %w", path, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read BloodHound file upload response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("BloodHound file upload failed: %s: %s", resp.Status, strings.TrimSpace(string(respBody)))
	}
	return nil
}

func endBloodHoundFileUploadJob(ctx context.Context, httpClient *http.Client, cfg config, jobID int64) error {
	endURL := fmt.Sprintf("%s/api/v2/file-upload/%d/end", cfg.BloodHoundURL, jobID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endURL, nil)
	if err != nil {
		return fmt.Errorf("build BloodHound file upload end request: %w", err)
	}
	if err := authorizeBloodHoundRequest(req, cfg, nil); err != nil {
		return err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("end BloodHound file upload job %d: %w", jobID, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read BloodHound file upload end response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("BloodHound file upload end failed: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return nil
}

func uploadCustomNodesToBloodHound(ctx context.Context, httpClient *http.Client, cfg config, path string) (int, int, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, fmt.Errorf("read BloodHound icon file %s: %w", path, err)
	}

	var payload openGraphCustomNodePayload
	if err := json.Unmarshal(body, &payload); err != nil {
		return 0, 0, fmt.Errorf("decode BloodHound icon file %s: %w", path, err)
	}
	if len(payload.CustomTypes) == 0 {
		return 0, 0, errors.New("BloodHound icon file did not contain any custom_types")
	}

	existing, err := getBloodHoundCustomNodeKinds(ctx, httpClient, cfg)
	if err != nil {
		return 0, 0, err
	}

	toCreate := openGraphCustomNodePayload{CustomTypes: make(map[string]openGraphCustomNodeConfig)}
	toUpdate := make(map[string]openGraphCustomNodeConfig)
	for kind, config := range payload.CustomTypes {
		if existing[kind] {
			toUpdate[kind] = config
			continue
		}
		toCreate.CustomTypes[kind] = config
	}

	if len(toCreate.CustomTypes) > 0 {
		if err := createBloodHoundCustomNodes(ctx, httpClient, cfg, toCreate); err != nil {
			return 0, 0, err
		}
	}

	kinds := make([]string, 0, len(toUpdate))
	for kind := range toUpdate {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	for _, kind := range kinds {
		if err := updateBloodHoundCustomNode(ctx, httpClient, cfg, kind, toUpdate[kind]); err != nil {
			return 0, 0, err
		}
	}

	return len(toCreate.CustomTypes), len(toUpdate), nil
}

func getBloodHoundCustomNodeKinds(ctx context.Context, httpClient *http.Client, cfg config) (map[string]bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.BloodHoundURL+"/api/v2/custom-nodes", nil)
	if err != nil {
		return nil, fmt.Errorf("build BloodHound custom node list request: %w", err)
	}
	if err := authorizeBloodHoundRequest(req, cfg, nil); err != nil {
		return nil, err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("list BloodHound custom nodes: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read BloodHound custom node list response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("BloodHound custom node list failed: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	var parsed bloodHoundCustomNodeListResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("decode BloodHound custom node list response: %w", err)
	}

	result := make(map[string]bool, len(parsed.Data))
	for _, node := range parsed.Data {
		if strings.TrimSpace(node.KindName) != "" {
			result[node.KindName] = true
		}
	}
	return result, nil
}

func createBloodHoundCustomNodes(ctx context.Context, httpClient *http.Client, cfg config, payload openGraphCustomNodePayload) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode BloodHound custom node create payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.BloodHoundURL+"/api/v2/custom-nodes", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build BloodHound custom node create request: %w", err)
	}
	if err := authorizeBloodHoundRequest(req, cfg, body); err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("create BloodHound custom nodes: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read BloodHound custom node create response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("BloodHound custom node create failed: %s: %s", resp.Status, strings.TrimSpace(string(respBody)))
	}
	return nil
}

func updateBloodHoundCustomNode(ctx context.Context, httpClient *http.Client, cfg config, kind string, customConfig openGraphCustomNodeConfig) error {
	body, err := json.Marshal(bloodHoundCustomNodeUpdateRequest{Config: customConfig})
	if err != nil {
		return fmt.Errorf("encode BloodHound custom node update payload: %w", err)
	}

	updateURL := fmt.Sprintf("%s/api/v2/custom-nodes/%s", cfg.BloodHoundURL, url.PathEscape(kind))
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, updateURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build BloodHound custom node update request: %w", err)
	}
	if err := authorizeBloodHoundRequest(req, cfg, body); err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("update BloodHound custom node %s: %w", kind, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read BloodHound custom node update response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("BloodHound custom node update failed: %s: %s", resp.Status, strings.TrimSpace(string(respBody)))
	}
	return nil
}

func setBloodHoundAuthHeaders(req *http.Request, token string) {
	req.Header.Set("Accept", "application/json")
	if strings.TrimSpace(token) != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
}

func bloodHoundUploadContentType(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".zip":
		return "application/zip"
	default:
		return "application/json"
	}
}

func authorizeBloodHoundRequest(req *http.Request, cfg config, body []byte) error {
	setBloodHoundAuthHeaders(req, cfg.BloodHoundToken)
	if strings.TrimSpace(cfg.BloodHoundToken) != "" {
		return nil
	}
	if strings.TrimSpace(cfg.BloodHoundTokenID) == "" || strings.TrimSpace(cfg.BloodHoundTokenKey) == "" {
		return errors.New("missing BloodHound authentication credentials")
	}

	requestDate := time.Now().UTC().Format(time.RFC3339)
	signature, err := buildBloodHoundRequestSignature(cfg.BloodHoundTokenKey, requestDate, req.Method, req.URL.RequestURI(), body)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", fmt.Sprintf("bhesignature %s", cfg.BloodHoundTokenID))
	req.Header.Set("RequestDate", requestDate)
	req.Header.Set("Signature", signature)
	return nil
}

func buildBloodHoundRequestSignature(tokenKey, requestDate, method, requestURI string, body []byte) (string, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(tokenKey)
	if err != nil {
		return "", fmt.Errorf("decode BloodHound token key: %w", err)
	}

	operationKey := computeHMACSHA256(keyBytes, []byte(strings.ToUpper(method)+requestURI))
	dateKey := computeHMACSHA256(operationKey, []byte(requestDate))
	bodyKey := computeHMACSHA256(dateKey, body)
	return base64.StdEncoding.EncodeToString(bodyKey), nil
}

func computeHMACSHA256(key, payload []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	return mac.Sum(nil)
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

func isSafeADXIdentifier(in string) bool {
	if in == "" {
		return false
	}
	for i, r := range in {
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

func isSafeKQLTimespanLiteral(in string) bool {
	in = strings.TrimSpace(in)
	if in == "" {
		return false
	}

	unitStart := len(in)
	for i, r := range in {
		if (r < '0' || r > '9') && r != '.' {
			unitStart = i
			break
		}
	}
	if unitStart == 0 || unitStart == len(in) {
		return false
	}

	numberPart := in[:unitStart]
	unitPart := in[unitStart:]
	if !isSafeTimespanNumber(numberPart) {
		return false
	}

	switch unitPart {
	case "d", "h", "m", "s", "ms":
		return true
	default:
		return false
	}
}

func isSafeTimespanNumber(in string) bool {
	digits := 0
	dots := 0
	for _, r := range in {
		switch {
		case r >= '0' && r <= '9':
			digits++
		case r == '.':
			dots++
			if dots > 1 {
				return false
			}
		default:
			return false
		}
	}
	return digits > 0
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

func buildOpenGraphPayload(response queryResponse) (openGraphPayload, error) {
	payload := openGraphPayload{
		Graph: openGraphGraph{
			Nodes: make([]openGraphNode, 0),
			Edges: make([]openGraphEdge, 0),
		},
	}

	if len(response.Results) == 0 {
		return payload, nil
	}

	nodeIndex := make(map[string]int)
	for i, row := range response.Results {
		switch detectOpenGraphRowKind(row) {
		case "node":
			node, err := convertRowToOpenGraphNode(row)
			if err != nil {
				return openGraphPayload{}, fmt.Errorf("convert row %d to OpenGraph node: %w", i+1, err)
			}
			appendOrMergeOpenGraphNode(&payload, nodeIndex, node)
		case "edge":
			edge, err := convertRowToOpenGraphEdge(row)
			if err != nil {
				return openGraphPayload{}, fmt.Errorf("convert row %d to OpenGraph edge: %w", i+1, err)
			}
			payload.Graph.Edges = append(payload.Graph.Edges, edge)

			for _, node := range extractOpenGraphNodesFromEdgeRow(row) {
				appendOrMergeOpenGraphNode(&payload, nodeIndex, node)
			}
		default:
			return openGraphPayload{}, fmt.Errorf("row %d does not match a supported OpenGraph node or edge shape; expected node ids or source/target ids in the result set", i+1)
		}
	}

	return payload, nil
}

func buildOpenGraphCustomNodePayload(payload openGraphPayload) openGraphCustomNodePayload {
	customTypes := make(map[string]openGraphCustomNodeConfig)
	for _, node := range payload.Graph.Nodes {
		for _, kind := range node.Kinds {
			kind = strings.TrimSpace(kind)
			if kind == "" {
				continue
			}
			if _, ok := customTypes[kind]; ok {
				continue
			}
			customTypes[kind] = openGraphCustomNodeConfig{
				Icon: iconForOpenGraphKind(kind),
			}
		}
	}
	return openGraphCustomNodePayload{CustomTypes: customTypes}
}

func iconForOpenGraphKind(kind string) openGraphCustomNodeIcon {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "alert":
		return openGraphCustomNodeIcon{Type: "font-awesome", Name: "triangle-exclamation", Color: "#D97706"}
	case "user":
		return openGraphCustomNodeIcon{Type: "font-awesome", Name: "user", Color: "#16A34A"}
	case "machine", "computer":
		return openGraphCustomNodeIcon{Type: "font-awesome", Name: "desktop", Color: "#2563EB"}
	case "file":
		return openGraphCustomNodeIcon{Type: "font-awesome", Name: "file", Color: "#6B7280"}
	case "process":
		return openGraphCustomNodeIcon{Type: "font-awesome", Name: "gears", Color: "#7C3AED"}
	case "ip":
		return openGraphCustomNodeIcon{Type: "font-awesome", Name: "network-wired", Color: "#0891B2"}
	case "url":
		return openGraphCustomNodeIcon{Type: "font-awesome", Name: "link", Color: "#0284C7"}
	case "cloudresource":
		return openGraphCustomNodeIcon{Type: "font-awesome", Name: "cloud", Color: "#0F766E"}
	case "mailmessage":
		return openGraphCustomNodeIcon{Type: "font-awesome", Name: "envelope", Color: "#DC2626"}
	case "application":
		return openGraphCustomNodeIcon{Type: "font-awesome", Name: "window-maximize", Color: "#4F46E5"}
	case "group", "user_group":
		return openGraphCustomNodeIcon{Type: "font-awesome", Name: "users", Color: "#1D4ED8"}
	case "finding", "security_finding":
		return openGraphCustomNodeIcon{Type: "font-awesome", Name: "shield-halved", Color: "#B45309"}
	case "identity":
		return openGraphCustomNodeIcon{Type: "font-awesome", Name: "id-badge", Color: "#15803D"}
	default:
		return openGraphCustomNodeIcon{Type: "font-awesome", Name: "circle-question", Color: "#64748B"}
	}
}

func detectOpenGraphRowKind(row map[string]any) string {
	rowMap := normalizeRowMap(row)
	if hasNonEmptyFields(rowMap, "sourceid", "targetid") || hasNonEmptyFields(rowMap, "sourcenodeid", "targetnodeid") {
		return "edge"
	}
	if hasAnyNonEmptyField(rowMap, "id", "nodeid") {
		return "node"
	}
	return ""
}

func hasNonEmptyFields(row map[string]any, names ...string) bool {
	for _, name := range names {
		if stringValue(row[name]) == "" {
			return false
		}
	}
	return true
}

func hasAnyNonEmptyField(row map[string]any, names ...string) bool {
	for _, name := range names {
		if stringValue(row[name]) != "" {
			return true
		}
	}
	return false
}

func appendOrMergeOpenGraphNode(payload *openGraphPayload, nodeIndex map[string]int, node openGraphNode) {
	if idx, ok := nodeIndex[node.ID]; ok {
		payload.Graph.Nodes[idx] = mergeOpenGraphNodes(payload.Graph.Nodes[idx], node)
		return
	}
	nodeIndex[node.ID] = len(payload.Graph.Nodes)
	payload.Graph.Nodes = append(payload.Graph.Nodes, node)
}

func convertRowToOpenGraphNode(row map[string]any) (openGraphNode, error) {
	rowMap := normalizeRowMap(row)

	id := stringValue(rowMap["id"])
	if id == "" {
		id = stringValue(rowMap["nodeid"])
	}
	if id == "" {
		return openGraphNode{}, errors.New("missing node id")
	}

	properties := collectOpenGraphProperties(rowMap, map[string]struct{}{
		"id":             {},
		"nodeid":         {},
		"type":           {},
		"nodelabel":      {},
		"label":          {},
		"categories":     {},
		"properties":     {},
		"nodeproperties": {},
	})

	displayName := firstNonEmptyString(
		stringValue(rowMap["nodename"]),
		stringValue(rowMap["label"]),
		stringValue(rowMap["name"]),
	)
	if displayName != "" {
		setPropertyIfMissing(properties, "displayname", displayName)
		setPropertyIfMissing(properties, "name", displayName)
	}

	categories := primitiveStringSlice(rowMap["categories"])
	if len(categories) > 0 {
		setPropertyIfMissingArray(properties, "categories", categories)
	}

	return openGraphNode{
		ID:         id,
		Kinds:      buildOpenGraphKinds(firstNonEmptyString(stringValue(rowMap["type"]), stringValue(rowMap["nodelabel"])), rowMap["categories"]),
		Properties: properties,
	}, nil
}

func convertRowToOpenGraphEdge(row map[string]any) (openGraphEdge, error) {
	rowMap := normalizeRowMap(row)

	startID := firstNonEmptyString(stringValue(rowMap["sourceid"]), stringValue(rowMap["sourcenodeid"]))
	endID := firstNonEmptyString(stringValue(rowMap["targetid"]), stringValue(rowMap["targetnodeid"]))
	if startID == "" || endID == "" {
		return openGraphEdge{}, errors.New("missing source or target id")
	}

	rawKind := firstNonEmptyString(
		stringValue(rowMap["edgetype"]),
		edgeTypeValue(stringValue(rowMap["type"])),
		stringValue(rowMap["edgelabel"]),
		stringValue(rowMap["label"]),
	)
	kind := sanitizeOpenGraphKind(rawKind, "RELATED_TO")

	properties := collectOpenGraphProperties(rowMap, map[string]struct{}{
		"sourceid":             {},
		"targetid":             {},
		"sourcenodeid":         {},
		"targetnodeid":         {},
		"type":                 {},
		"edgetype":             {},
		"properties":           {},
		"edgeproperties":       {},
		"sourcenodename":       {},
		"sourcenodelabel":      {},
		"sourcenodecategories": {},
		"targetnodename":       {},
		"targetnodelabel":      {},
		"targetnodecategories": {},
	})

	return openGraphEdge{
		Start:      openGraphNodeReference{MatchBy: "id", Value: startID},
		End:        openGraphNodeReference{MatchBy: "id", Value: endID},
		Kind:       kind,
		Properties: properties,
	}, nil
}

func extractOpenGraphNodesFromEdgeRow(row map[string]any) []openGraphNode {
	rowMap := normalizeRowMap(row)
	nodes := make([]openGraphNode, 0, 2)

	if node := openGraphEdgeEndpointNode(
		stringValue(rowMap["sourcenodeid"]),
		stringValue(rowMap["sourcenodename"]),
		stringValue(rowMap["sourcenodelabel"]),
		rowMap["sourcenodecategories"],
	); node.ID != "" {
		nodes = append(nodes, node)
	}
	if node := openGraphEdgeEndpointNode(
		stringValue(rowMap["targetnodeid"]),
		stringValue(rowMap["targetnodename"]),
		stringValue(rowMap["targetnodelabel"]),
		rowMap["targetnodecategories"],
	); node.ID != "" {
		nodes = append(nodes, node)
	}

	return nodes
}

func openGraphEdgeEndpointNode(id, name, label string, categories any) openGraphNode {
	if id == "" {
		return openGraphNode{}
	}

	properties := map[string]any{}
	if name != "" {
		properties["displayname"] = name
		properties["name"] = name
	}
	if label != "" {
		properties["label"] = label
	}
	if categoryList := primitiveStringSlice(categories); len(categoryList) > 0 {
		properties["categories"] = categoryList
	}

	return openGraphNode{
		ID:         id,
		Kinds:      buildOpenGraphKinds(label, categories),
		Properties: properties,
	}
}

func mergeOpenGraphNodes(existing, incoming openGraphNode) openGraphNode {
	seenKinds := make(map[string]struct{}, len(existing.Kinds))
	for _, kind := range existing.Kinds {
		seenKinds[kind] = struct{}{}
	}
	for _, kind := range incoming.Kinds {
		if _, ok := seenKinds[kind]; ok {
			continue
		}
		existing.Kinds = append(existing.Kinds, kind)
		seenKinds[kind] = struct{}{}
	}

	if existing.Properties == nil {
		existing.Properties = map[string]any{}
	}
	for key, value := range incoming.Properties {
		if _, ok := existing.Properties[key]; !ok {
			existing.Properties[key] = value
		}
	}
	return existing
}

func collectOpenGraphProperties(row map[string]any, skip map[string]struct{}) map[string]any {
	properties := make(map[string]any)

	for _, key := range sortedRowKeys(row) {
		if shouldSkipOpenGraphField(key) {
			continue
		}
		if _, ok := skip[key]; ok {
			continue
		}
		flattenOpenGraphValue(properties, sanitizeOpenGraphPropertyName(key), row[key])
	}

	for _, embeddedKey := range []string{"properties", "nodeproperties", "edgeproperties"} {
		value, ok := row[embeddedKey]
		if !ok {
			continue
		}
		flattenOpenGraphValue(properties, "", value)
	}

	return properties
}

func sortedRowKeys(row map[string]any) []string {
	keys := make([]string, 0, len(row))
	for key := range row {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func normalizeRowMap(row map[string]any) map[string]any {
	normalized := make(map[string]any, len(row))
	for key, value := range row {
		normalized[normalizeRowKey(key)] = value
	}
	return normalized
}

func normalizeRowKey(key string) string {
	return strings.ToLower(strings.TrimSpace(key))
}

func edgeTypeValue(value string) string {
	if value == "" || strings.HasSuffix(value, "Edges") {
		return ""
	}
	return value
}

func buildOpenGraphKinds(primary string, categories any) []string {
	kinds := make([]string, 0, 3)
	seen := make(map[string]struct{})

	add := func(value string) {
		kind := sanitizeOpenGraphKind(value, "")
		if kind == "" {
			return
		}
		if _, ok := seen[kind]; ok {
			return
		}
		if len(kinds) >= 3 {
			return
		}
		seen[kind] = struct{}{}
		kinds = append(kinds, kind)
	}

	add(primary)
	for _, category := range primitiveStringSlice(categories) {
		add(category)
	}
	if len(kinds) == 0 {
		kinds = append(kinds, "ImportedNode")
	}
	return kinds
}

func sanitizeOpenGraphKind(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}

	var b strings.Builder
	lastUnderscore := false
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
			lastUnderscore = false
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
			lastUnderscore = false
		case r >= '0' && r <= '9':
			if b.Len() == 0 {
				b.WriteByte('_')
			}
			b.WriteRune(r)
			lastUnderscore = false
		default:
			if !lastUnderscore && b.Len() > 0 {
				b.WriteByte('_')
				lastUnderscore = true
			}
		}
	}

	kind := strings.Trim(b.String(), "_")
	if kind == "" {
		return fallback
	}
	if kind[0] >= '0' && kind[0] <= '9' {
		kind = "_" + kind
	}
	return kind
}

func sanitizeOpenGraphPropertyName(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return ""
	}

	var b strings.Builder
	lastUnderscore := false
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
			lastUnderscore = false
		case r >= '0' && r <= '9':
			b.WriteRune(r)
			lastUnderscore = false
		default:
			if !lastUnderscore && b.Len() > 0 {
				b.WriteByte('_')
				lastUnderscore = true
			}
		}
	}

	name := strings.Trim(b.String(), "_")
	if name == "objectid" {
		return "source_objectid"
	}
	return name
}

func shouldSkipOpenGraphField(key string) bool {
	return strings.HasSuffix(key, "@odata.type")
}

func flattenOpenGraphValue(properties map[string]any, prefix string, value any) {
	switch typed := value.(type) {
	case map[string]any:
		for _, key := range sortedRowKeys(typed) {
			if shouldSkipOpenGraphField(key) {
				continue
			}
			next := sanitizeOpenGraphPropertyName(key)
			if next == "" {
				continue
			}
			if prefix != "" {
				next = prefix + "_" + next
			}
			flattenOpenGraphValue(properties, next, typed[key])
		}
	case []any:
		if array, ok := normalizePrimitiveArray(typed); ok {
			setOpenGraphProperty(properties, prefix, array)
			return
		}
		setOpenGraphProperty(properties, prefix, compactJSONString(typed))
	case []string, []bool, []int, []int64, []float64, string, bool, float64, int, int64:
		setOpenGraphProperty(properties, prefix, typed)
	case nil:
		return
	default:
		setOpenGraphProperty(properties, prefix, compactJSONString(typed))
	}
}

func normalizePrimitiveArray(values []any) ([]any, bool) {
	if len(values) == 0 {
		return []any{}, true
	}

	group := ""
	normalized := make([]any, 0, len(values))
	for _, value := range values {
		current := primitiveValueGroup(value)
		if current == "" {
			return nil, false
		}
		if group == "" {
			group = current
		}
		if current != group {
			return nil, false
		}
		normalized = append(normalized, value)
	}
	return normalized, true
}

func primitiveValueGroup(value any) string {
	switch value.(type) {
	case string:
		return "string"
	case bool:
		return "bool"
	case float64, int, int64:
		return "number"
	default:
		return ""
	}
}

func compactJSONString(value any) string {
	body, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprintf("%v", value)
	}
	return string(body)
}

func setOpenGraphProperty(properties map[string]any, key string, value any) {
	key = sanitizeOpenGraphPropertyName(key)
	if key == "" {
		return
	}

	if existing, ok := properties[key]; ok {
		if fmt.Sprint(existing) == fmt.Sprint(value) {
			return
		}
		for i := 2; ; i++ {
			candidate := fmt.Sprintf("%s_%d", key, i)
			if _, exists := properties[candidate]; !exists {
				properties[candidate] = value
				return
			}
		}
	}

	properties[key] = value
}

func setPropertyIfMissing(properties map[string]any, key string, value string) {
	key = sanitizeOpenGraphPropertyName(key)
	if key == "" || value == "" {
		return
	}
	if _, ok := properties[key]; ok {
		return
	}
	properties[key] = value
}

func setPropertyIfMissingArray(properties map[string]any, key string, values []string) {
	key = sanitizeOpenGraphPropertyName(key)
	if key == "" || len(values) == 0 {
		return
	}
	if _, ok := properties[key]; ok {
		return
	}
	properties[key] = values
}

func stringValue(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(typed)
	default:
		return strings.TrimSpace(fmt.Sprint(typed))
	}
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func primitiveStringSlice(value any) []string {
	switch typed := value.(type) {
	case []string:
		return append([]string(nil), typed...)
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			text, ok := item.(string)
			if !ok || strings.TrimSpace(text) == "" {
				continue
			}
			out = append(out, strings.TrimSpace(text))
		}
		return out
	default:
		return nil
	}
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

func indentJSON(body []byte) ([]byte, error) {
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, body, "", "  "); err != nil {
		return nil, err
	}
	pretty.WriteByte('\n')
	return pretty.Bytes(), nil
}

func compactError(apiError, description string, fallback []byte) string {
	message := strings.TrimSpace(strings.Join([]string{apiError, description}, ": "))
	if message != "" {
		return message
	}
	return string(fallback)
}
