package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"time"
)

const collectionManifestSchemaVersion = 1

// Table statuses. An empty table and a table this collection did not get must
// stay distinguishable: a reader treats an empty result as evidence.
const (
	manifestCaptured       = "captured"
	manifestCapturedEmpty  = "captured_empty"
	manifestNotCaptured    = "not_captured"
	manifestAbsentInSource = "absent_in_source"
)

type collectionManifest struct {
	SchemaVersion    int                      `json:"schema_version"`
	Tool             manifestTool             `json:"tool"`
	CreatedAt        time.Time                `json:"created_at"`
	UpdatedAt        time.Time                `json:"updated_at"`
	Pseudonymization manifestPseudonymization `json:"pseudonymization"`
	Tables           []manifestTable          `json:"tables"`
}

type manifestTool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type manifestPseudonymization struct {
	Enabled bool   `json:"enabled"`
	Mode    string `json:"mode,omitempty"`
	KeyID   string `json:"key_id,omitempty"`
}

type manifestTable struct {
	Source        string           `json:"source"`
	Name          string           `json:"name"`
	Status        string           `json:"status"`
	TimeColumn    string           `json:"time_column,omitempty"`
	Window        *manifestWindow  `json:"window,omitempty"`
	Query         string           `json:"query,omitempty"`
	Columns       []manifestColumn `json:"columns,omitempty"`
	RowCount      *int             `json:"row_count,omitempty"`
	Partitions    *int             `json:"partitions,omitempty"`
	File          string           `json:"file,omitempty"`
	SHA256        string           `json:"sha256,omitempty"`
	Bytes         *int64           `json:"bytes,omitempty"`
	ADXDataFile   string           `json:"adx_data_file,omitempty"`
	ADXDataSHA256 string           `json:"adx_data_sha256,omitempty"`
	Note          string           `json:"note,omitempty"`
}

type manifestWindow struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
	// IngestedBefore excludes rows ingested at or after it, so the recorded
	// counts describe one snapshot of the window.
	IngestedBefore time.Time `json:"ingested_before,omitzero"`
}

type manifestColumn struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// manifestRun describes the collection being recorded by one invocation.
type manifestRun struct {
	path             string
	pseudonymization manifestPseudonymization
}

// openManifestRun validates an existing manifest before any data is collected,
// so a corrupt file or a different pseudonymization setup fails immediately.
func openManifestRun(path string, pseudonyms *pseudonymizer) (*manifestRun, error) {
	run := &manifestRun{path: path}
	if pseudonyms != nil {
		run.pseudonymization = manifestPseudonymization{Enabled: true, Mode: "reversible", KeyID: pseudonyms.KeyID()}
		if pseudonyms.Irreversible() {
			run.pseudonymization.Mode = irreversiblePseudonymVaultMode
		}
	}
	if _, err := run.load(); err != nil {
		return nil, err
	}
	return run, nil
}

func (r *manifestRun) load() (*collectionManifest, error) {
	manifest, err := loadCollectionManifest(r.path)
	if err != nil || manifest == nil {
		return manifest, err
	}
	if manifest.Pseudonymization != r.pseudonymization {
		return nil, fmt.Errorf("manifest %s records a different pseudonymization setup (enabled, mode, or vault key_id); use one manifest per consistently pseudonymized collection", r.path)
	}
	return manifest, nil
}

// manifestResult is what a query or table dump produced, or the error that
// stopped it.
type manifestResult struct {
	source     querySource
	sourceName string
	table      string
	query      string
	// Table dumps record their fixed window; queries leave these empty.
	timeColumn string
	lookback   string
	cutoff     time.Time
	output     tableDumpOutput
	outputPath string
	err        error
}

// Record adds or replaces the entry for one table and returns the collection
// error unchanged, joined with any manifest error.
func (r *manifestRun) Record(result manifestResult) error {
	if r == nil {
		return result.err
	}
	entry, err := r.tableEntry(result)
	if err != nil && result.err == nil {
		// A result that cannot be described was not captured.
		result.err = err
		entry, err = r.tableEntry(result)
	}
	if err != nil {
		return errors.Join(result.err, err)
	}
	manifest, err := r.load()
	if err != nil {
		return errors.Join(result.err, err)
	}
	now := time.Now().UTC()
	if manifest == nil {
		manifest = &collectionManifest{CreatedAt: now, Pseudonymization: r.pseudonymization}
	}
	manifest.SchemaVersion = collectionManifestSchemaVersion
	manifest.Tool = manifestTool{Name: "tableDumper", Version: toolVersion()}
	manifest.UpdatedAt = now
	tables := manifest.Tables[:0]
	for _, table := range manifest.Tables {
		if table.Source != entry.Source || table.Name != entry.Name {
			tables = append(tables, table)
		}
	}
	manifest.Tables = append(tables, entry)
	if err := writeCollectionManifest(r.path, manifest); err != nil {
		return errors.Join(result.err, err)
	}
	return result.err
}

func (r *manifestRun) tableEntry(result manifestResult) (manifestTable, error) {
	entry := manifestTable{Source: result.sourceName, Name: result.table}
	if result.lookback != "" {
		lookback, err := kqlTimespanDuration(result.lookback)
		if err != nil {
			return entry, err
		}
		// Matches the query filter built by buildTableDumpBaseQuery.
		end := result.cutoff.UTC().Truncate(time.Microsecond)
		entry.TimeColumn, entry.Window = result.timeColumn, &manifestWindow{Start: end.Add(-lookback), End: end, IngestedBefore: end}
	}
	if !r.pseudonymization.Enabled {
		// Incident queries filter on real identifiers, so query text is only
		// recorded for collections that are not pseudonymized.
		entry.Query = result.query
	}
	if result.err != nil {
		if result.source != nil && result.source.IsTableNotFound(result.err, result.table) {
			entry.Status = manifestAbsentInSource
			entry.Note = "the table does not exist in the source"
		} else {
			entry.Status = manifestNotCaptured
			entry.Note = manifestFailureNote(result.err, r.pseudonymization.Enabled)
		}
		return entry, validateManifestTable(entry)
	}

	entry.Columns = manifestColumns(result.output.Schema)
	rows, partitions := result.output.Rows, result.output.Stats.Partitions
	entry.RowCount, entry.Partitions = &rows, &partitions
	entry.Status = manifestCaptured
	if rows == 0 {
		entry.Status = manifestCapturedEmpty
	}
	var err error
	if entry.File, entry.SHA256, entry.Bytes, err = r.describeFile(result.outputPath); err != nil {
		return entry, err
	}
	if result.output.ADXDataPath != "" {
		if entry.ADXDataFile, entry.ADXDataSHA256, _, err = r.describeFile(result.output.ADXDataPath); err != nil {
			return entry, err
		}
	}
	if err := validateManifestTable(entry); err != nil {
		return entry, fmt.Errorf("cannot record %s as %s in manifest %s: %w", entry.Name, entry.Status, r.path, err)
	}
	return entry, nil
}

// manifestFailureNote explains a failed collection. Service errors can echo
// query text, so pseudonymized collections record only the failure category.
func manifestFailureNote(err error, pseudonymized bool) string {
	if !pseudonymized {
		return err.Error()
	}
	var defenderErr *advancedQueryError
	var logAnalyticsErr *logAnalyticsQueryError
	var partialErr *logAnalyticsPartialResultError
	var capacityErr *pseudonymCapacityError
	var relationshipErr *pseudonymRelationshipError
	switch {
	case errors.As(err, &defenderErr):
		return fmt.Sprintf("query failed with HTTP %d; details omitted from a pseudonymized manifest", defenderErr.StatusCode)
	case errors.As(err, &logAnalyticsErr):
		return fmt.Sprintf("query failed with HTTP %d; details omitted from a pseudonymized manifest", logAnalyticsErr.StatusCode)
	case errors.As(err, &partialErr):
		return "the service returned an incomplete result, which was not used"
	case errors.As(err, &capacityErr):
		return capacityErr.Error()
	case errors.As(err, &relationshipErr):
		return relationshipErr.Error()
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return "the collection was interrupted or timed out"
	default:
		return "the collection failed before its result was published; details omitted from a pseudonymized manifest"
	}
}

func manifestColumns(schema []queryColumn) []manifestColumn {
	columns := make([]manifestColumn, len(schema))
	for i, column := range schema {
		columns[i] = manifestColumn{Name: column.Name, Type: defenderTypeToADXType(column.Type)}
	}
	return columns
}

// describeFile hashes a published file and returns its path relative to the
// manifest directory.
func (r *manifestRun) describeFile(path string) (string, string, *int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", "", nil, fmt.Errorf("hash %s for manifest: %w", path, err)
	}
	defer file.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	if err != nil {
		return "", "", nil, fmt.Errorf("hash %s for manifest: %w", path, err)
	}
	manifestDir, err := filepath.Abs(filepath.Dir(r.path))
	if err != nil {
		return "", "", nil, fmt.Errorf("resolve manifest directory: %w", err)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", "", nil, fmt.Errorf("resolve %s for manifest: %w", path, err)
	}
	relative, err := filepath.Rel(manifestDir, absolute)
	if err != nil {
		return "", "", nil, fmt.Errorf("make %s relative to manifest %s: %w", path, r.path, err)
	}
	return filepath.ToSlash(relative), hex.EncodeToString(hash.Sum(nil)), &size, nil
}

func loadCollectionManifest(path string) (*collectionManifest, error) {
	body, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read manifest %s: %w", path, err)
	}
	var manifest collectionManifest
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return nil, fmt.Errorf("decode manifest %s: %w", path, err)
	}
	if err := validateCollectionManifest(&manifest); err != nil {
		return nil, fmt.Errorf("invalid manifest %s: %w", path, err)
	}
	return &manifest, nil
}

func validateCollectionManifest(manifest *collectionManifest) error {
	if manifest.SchemaVersion != collectionManifestSchemaVersion {
		return fmt.Errorf("unsupported schema_version %d", manifest.SchemaVersion)
	}
	switch pseudonymization := manifest.Pseudonymization; {
	case !pseudonymization.Enabled && pseudonymization.Mode == "" && pseudonymization.KeyID == "":
	case pseudonymization.Enabled && (pseudonymization.Mode == "reversible" || pseudonymization.Mode == irreversiblePseudonymVaultMode) && len(pseudonymization.KeyID) == 16:
	default:
		return errors.New("pseudonymization must be disabled without mode or key_id, or enabled with a mode and a 16-character key_id")
	}
	seen := make(map[string]bool, len(manifest.Tables))
	for i, table := range manifest.Tables {
		if err := validateManifestTable(table); err != nil {
			return fmt.Errorf("table %d: %w", i+1, err)
		}
		if manifest.Pseudonymization.Enabled && table.Query != "" {
			return fmt.Errorf("table %d: a pseudonymized manifest must not record query text", i+1)
		}
		key := table.Source + "\x00" + table.Name
		if seen[key] {
			return fmt.Errorf("table %d: duplicate entry for %s table %s", i+1, table.Source, table.Name)
		}
		seen[key] = true
	}
	return nil
}

func validateManifestTable(table manifestTable) error {
	if table.Source != sourceDefender && table.Source != sourceLogAnalytics {
		return fmt.Errorf("unsupported source %q", table.Source)
	}
	if !isSafeADXIdentifier(table.Name) {
		return fmt.Errorf("invalid table name %q", table.Name)
	}
	if table.Window != nil && (table.Window.Start.IsZero() || !table.Window.Start.Before(table.Window.End)) {
		return errors.New("window start must be before its end")
	}
	if table.Window != nil && !table.Window.IngestedBefore.IsZero() && table.Window.IngestedBefore.Before(table.Window.End) {
		return errors.New("window ingested_before must not precede its end")
	}
	if (table.TimeColumn == "") != (table.Window == nil) {
		return errors.New("time_column and window must be recorded together")
	}
	materialized := table.Status == manifestCaptured || table.Status == manifestCapturedEmpty
	switch table.Status {
	case manifestCaptured:
		if table.RowCount == nil || *table.RowCount <= 0 {
			return errors.New("captured tables require row_count greater than zero")
		}
		if table.File == "" {
			return errors.New("captured tables require a file")
		}
	case manifestCapturedEmpty:
		if table.RowCount == nil || *table.RowCount != 0 {
			return errors.New("captured_empty tables require row_count 0")
		}
	case manifestNotCaptured:
		if table.Note == "" {
			return errors.New("not_captured tables require a note explaining why")
		}
	case manifestAbsentInSource:
	default:
		return fmt.Errorf("unsupported status %q", table.Status)
	}
	if materialized {
		if len(table.Columns) == 0 {
			return fmt.Errorf("%s tables require columns", table.Status)
		}
		names := make(map[string]bool, len(table.Columns))
		for _, column := range table.Columns {
			if column.Name == "" || names[column.Name] || column.Type == "" {
				return errors.New("columns require unique names and types")
			}
			names[column.Name] = true
		}
		if table.Partitions == nil || *table.Partitions < 0 {
			return fmt.Errorf("%s tables require partitions", table.Status)
		}
	} else if len(table.Columns) > 0 || table.RowCount != nil || table.Partitions != nil || table.File != "" || table.SHA256 != "" || table.Bytes != nil || table.ADXDataFile != "" || table.ADXDataSHA256 != "" {
		return fmt.Errorf("%s tables must not record columns, counts, or files", table.Status)
	}
	if (table.File == "") != (table.SHA256 == "") || (table.File == "") != (table.Bytes == nil) || (table.ADXDataFile == "") != (table.ADXDataSHA256 == "") {
		return errors.New("files require a sha256, and the main file requires bytes")
	}
	if table.ADXDataFile != "" && table.File == "" {
		return errors.New("adx_data_file requires file")
	}
	for _, path := range []string{table.File, table.ADXDataFile} {
		if path != "" && (filepath.IsAbs(path) || strings.HasPrefix(path, "/") || strings.Contains(path, `\`)) {
			return fmt.Errorf("file path %q must be relative to the manifest using forward slashes", path)
		}
	}
	for _, digest := range []string{table.SHA256, table.ADXDataSHA256} {
		if digest != "" && !isVaultKeyDigest(digest) {
			return fmt.Errorf("invalid sha256 %q", digest)
		}
	}
	if table.Bytes != nil && *table.Bytes < 0 {
		return errors.New("bytes must not be negative")
	}
	return nil
}

func writeCollectionManifest(path string, manifest *collectionManifest) error {
	sort.Slice(manifest.Tables, func(i, j int) bool {
		if manifest.Tables[i].Source != manifest.Tables[j].Source {
			return manifest.Tables[i].Source < manifest.Tables[j].Source
		}
		return manifest.Tables[i].Name < manifest.Tables[j].Name
	})
	if err := validateCollectionManifest(manifest); err != nil {
		return fmt.Errorf("refusing to write invalid manifest %s: %w", path, err)
	}
	body, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("encode manifest: %w", err)
	}
	return writeFileAtomically(path, append(body, '\n'))
}

// toolVersion reports the module version, or the VCS revision for local builds.
func toolVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	if info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	revision, modified := "", false
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			revision = setting.Value
		case "vcs.modified":
			modified = setting.Value == "true"
		}
	}
	if revision == "" {
		return "(devel)"
	}
	if len(revision) > 12 {
		revision = revision[:12]
	}
	if modified {
		revision += "-dirty"
	}
	return revision
}
