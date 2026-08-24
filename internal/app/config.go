package app

import (
	"bufio"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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
	ADXAuthMode               string
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
	Pseudonymize              bool
	PseudonymizeFilenames     bool
	PseudonymMap              string
	PseudonymFields           string
	PseudonymReplacementsFile string
	PseudonymMapRetention     string
	Endpoint                  string
	Resource                  string
	LoginBaseURL              string
	InsecureSkipVerify        bool
	Timeout                   time.Duration
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

	fs.StringVar(&cfg.AuthMode, "auth", "auto", "Authentication mode: auto, sp, azcli, or none")
	fs.StringVar(&cfg.TenantID, "tenant-id", envOrDotEnv("AZURE_TENANT_ID", dotenv), "Microsoft Entra tenant ID")
	fs.StringVar(&cfg.ClientID, "client-id", envOrDotEnv("AZURE_CLIENT_ID", dotenv), "Service principal client ID")
	fs.StringVar(&cfg.ClientSecret, "client-secret", envOrDotEnv("AZURE_CLIENT_SECRET", dotenv), "Service principal client secret")
	fs.StringVar(&cfg.Query, "query", "", "KQL query string to run")
	fs.StringVar(&cfg.QueryFile, "query-file", "", "Path to a file containing the KQL query")
	fs.StringVar(&cfg.DumpTable, "dump-table", "", "Defender advanced hunting table name to dump")
	fs.StringVar(&cfg.DumpLookback, "dump-lookback", defaultDumpLookback, "Lookback timespan for -dump-table, for example 30d, 12h, or 90m")
	fs.StringVar(&cfg.DumpTimeColumn, "dump-time-column", "Timestamp", "Time column used for -dump-table lookback filtering")
	fs.IntVar(&cfg.DumpRowLimit, "dump-row-limit", defaultDumpRowLimit, "Maximum rows per advanced hunting query chunk before partitioning")
	fs.IntVar(&cfg.DumpParallelism, "dump-parallelism", 1, "Deprecated compatibility flag; partition requests are always sequential")
	fs.StringVar(&cfg.Output, "output", defaultOutputFile, "Path to the JSON output file")
	fs.BoolVar(&cfg.ADXExport, "adx-export", false, "Also write Azure Data Explorer ingestion artifacts")
	fs.BoolVar(&cfg.OpenGraphExport, "opengraph-export", false, "Also write a BloodHound OpenGraph JSON payload")
	fs.StringVar(&cfg.ADXCluster, "adx-cluster", envOrDotEnvAny(dotenv, "ADX_CLUSTER"), "ADX cluster URI, for example https://<cluster>.<region>.kusto.windows.net")
	fs.StringVar(&cfg.ADXDatabase, "adx-database", envOrDotEnvAny(dotenv, "ADX_DATABASE"), "ADX database name")
	fs.StringVar(&cfg.ADXTable, "adx-table", "", "ADX table name to use in the generated schema file")
	fs.StringVar(&cfg.ADXMapping, "adx-mapping", "", "ADX ingestion mapping name to use in the generated schema file")
	fs.StringVar(&cfg.ADXUploadFile, "adx-upload-file", "", "Path to a JSON/NDJSON file to upload to ADX")
	fs.IntVar(&cfg.ADXBatchSize, "adx-batch-size", 500, "Number of rows to include in each ADX ingestion request")
	fs.StringVar(&cfg.ADXAuthMode, "adx-auth", envOrDotEnvAny(dotenv, "ADX_AUTH"), "Authentication mode override for ADX uploads: auto, sp, azcli, or none")
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
	fs.BoolVar(&cfg.Pseudonymize, "pseudonymize", false, "Pseudonymize identifiers with embedded NER before writing collected data")
	fs.BoolVar(&cfg.PseudonymizeFilenames, "pseudonymize-filenames", false, "Also pseudonymize linked filenames in file, path, and process command-line fields")
	fs.StringVar(&cfg.PseudonymMap, "pseudonym-map", "", "Path to a reusable pseudonym mapping file (a secure temporary file is created when omitted)")
	fs.StringVar(&cfg.PseudonymFields, "pseudonym-fields", envOrDotEnvAny(dotenv, "PSEUDONYM_FIELDS"), "Override the built-in table field allowlist; comma-separated with * and ? wildcards")
	fs.StringVar(&cfg.PseudonymReplacementsFile, "pseudonym-replacements-file", envOrDotEnvAny(dotenv, "PSEUDONYM_REPLACEMENTS_FILE"), "Path to a JSON file of literal word and phrase replacements")
	fs.StringVar(&cfg.PseudonymMapRetention, "pseudonym-map-retention", "keep", "Mapping file retention after collection: keep or delete")
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
	case "auto", "sp", "azcli", "none":
	default:
		return cfg, fmt.Errorf("unsupported -auth value %q; expected auto, sp, azcli, or none", cfg.AuthMode)
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
	cfg.ADXAuthMode = strings.ToLower(strings.TrimSpace(cfg.ADXAuthMode))
	cfg.ADXResource = strings.TrimRight(strings.TrimSpace(cfg.ADXResource), "/")
	cfg.BloodHoundURL = strings.TrimRight(strings.TrimSpace(cfg.BloodHoundURL), "/")
	cfg.BloodHoundToken = strings.TrimSpace(cfg.BloodHoundToken)
	cfg.BloodHoundTokenID = strings.TrimSpace(cfg.BloodHoundTokenID)
	cfg.BloodHoundTokenKey = strings.TrimSpace(cfg.BloodHoundTokenKey)
	cfg.BloodHoundUploadFile = strings.TrimSpace(cfg.BloodHoundUploadFile)
	cfg.BloodHoundUploadIconsFile = strings.TrimSpace(cfg.BloodHoundUploadIconsFile)
	cfg.PseudonymMap = strings.TrimSpace(cfg.PseudonymMap)
	cfg.PseudonymFields = strings.TrimSpace(cfg.PseudonymFields)
	cfg.PseudonymReplacementsFile = strings.TrimSpace(cfg.PseudonymReplacementsFile)
	cfg.PseudonymMapRetention = strings.ToLower(strings.TrimSpace(cfg.PseudonymMapRetention))
	if cfg.ADXResource == "" {
		cfg.ADXResource = defaultADXResource
	}
	if cfg.ADXAuthMode != "" {
		switch cfg.ADXAuthMode {
		case "auto", "sp", "azcli", "none":
		default:
			return cfg, fmt.Errorf("unsupported -adx-auth value %q; expected auto, sp, azcli, or none", cfg.ADXAuthMode)
		}
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
	if cfg.Pseudonymize && cfg.DumpTable == "" && !hasQueryInput(cfg) {
		return cfg, errors.New("pseudonymization requires -query, -query-file, or -dump-table")
	}
	if !cfg.Pseudonymize && cfg.PseudonymMap != "" {
		return cfg, errors.New("-pseudonym-map requires -pseudonymize")
	}
	if cfg.PseudonymizeFilenames && !cfg.Pseudonymize {
		return cfg, errors.New("-pseudonymize-filenames requires -pseudonymize")
	}
	if !cfg.Pseudonymize && cfg.PseudonymReplacementsFile != "" {
		return cfg, errors.New("-pseudonym-replacements-file requires -pseudonymize")
	}
	if cfg.PseudonymFields != "" {
		if _, err := newPseudonymFieldPolicy(cfg.PseudonymFields); err != nil {
			return cfg, fmt.Errorf("invalid -pseudonym-fields: %w", err)
		}
	}
	if cfg.PseudonymMap != "" && cfg.PseudonymReplacementsFile != "" && samePath(cfg.PseudonymMap, cfg.PseudonymReplacementsFile) {
		return cfg, errors.New("-pseudonym-map and -pseudonym-replacements-file must use different paths")
	}
	artifactPaths := []string{cfg.Output}
	if cfg.ADXExport {
		dataPath, schemaPath := adxArtifactPaths(cfg.Output)
		artifactPaths = append(artifactPaths, dataPath, schemaPath)
	}
	if cfg.OpenGraphExport {
		artifactPaths = append(artifactPaths, openGraphArtifactPath(cfg.Output), openGraphIconArtifactPath(cfg.Output))
	}
	for _, artifactPath := range artifactPaths {
		if cfg.PseudonymMap != "" && samePath(cfg.PseudonymMap, artifactPath) {
			return cfg, fmt.Errorf("-pseudonym-map must not use an output artifact path: %s", artifactPath)
		}
		if cfg.PseudonymReplacementsFile != "" && samePath(cfg.PseudonymReplacementsFile, artifactPath) {
			return cfg, fmt.Errorf("-pseudonym-replacements-file must not use an output artifact path: %s", artifactPath)
		}
	}
	switch cfg.PseudonymMapRetention {
	case "keep", "delete":
	default:
		return cfg, fmt.Errorf("unsupported -pseudonym-map-retention value %q; expected keep or delete", cfg.PseudonymMapRetention)
	}

	return cfg, nil
}

func samePath(left, right string) bool {
	leftPath, leftErr := filepath.Abs(filepath.Clean(left))
	rightPath, rightErr := filepath.Abs(filepath.Clean(right))
	if leftErr != nil || rightErr != nil {
		return filepath.Clean(left) == filepath.Clean(right)
	}
	return leftPath == rightPath
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
	authMode := cfg.ADXAuthMode
	if authMode == "" {
		authMode = cfg.AuthMode
	}
	return authConfig{
		AuthMode:     authMode,
		TenantID:     cfg.ADXTenantID,
		ClientID:     cfg.ADXClientID,
		ClientSecret: cfg.ADXClientSecret,
		Resource:     cfg.ADXResource,
		LoginBaseURL: cfg.LoginBaseURL,
	}
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
