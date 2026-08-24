package app

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadDotEnv(t *testing.T) {
	t.Run("missing default env file is ignored", func(t *testing.T) {
		originalDirectory, err := os.Getwd()
		if err != nil {
			t.Fatalf("get working directory: %v", err)
		}
		if err := os.Chdir(t.TempDir()); err != nil {
			t.Fatalf("change working directory: %v", err)
		}
		t.Cleanup(func() {
			if err := os.Chdir(originalDirectory); err != nil {
				t.Errorf("restore working directory: %v", err)
			}
		})

		values, err := loadDotEnv(".env")
		if err != nil {
			t.Fatalf("loadDotEnv returned error: %v", err)
		}
		if len(values) != 0 {
			t.Fatalf("expected empty map, got %#v", values)
		}
	})

	t.Run("parses key values and quotes", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, ".env")
		content := strings.Join([]string{
			"# comment",
			"AZURE_TENANT_ID=tenant-id",
			"export AZURE_CLIENT_ID=\"client-id\"",
			"AZURE_CLIENT_SECRET='secret-value'",
			"",
		}, "\n")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("write env file: %v", err)
		}

		values, err := loadDotEnv(path)
		if err != nil {
			t.Fatalf("loadDotEnv returned error: %v", err)
		}
		if values["AZURE_TENANT_ID"] != "tenant-id" {
			t.Fatalf("unexpected tenant value %q", values["AZURE_TENANT_ID"])
		}
		if values["AZURE_CLIENT_ID"] != "client-id" {
			t.Fatalf("unexpected client id %q", values["AZURE_CLIENT_ID"])
		}
		if values["AZURE_CLIENT_SECRET"] != "secret-value" {
			t.Fatalf("unexpected secret %q", values["AZURE_CLIENT_SECRET"])
		}
	})
}

func TestDefaultEnvFile(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "default", args: nil, want: ".env"},
		{name: "space separated", args: []string{"--env-file", "custom.env"}, want: "custom.env"},
		{name: "equals syntax", args: []string{"--env-file=custom.env"}, want: "custom.env"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := defaultEnvFile(tt.args); got != tt.want {
				t.Fatalf("defaultEnvFile() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseFlagsSupportsInsecureSkipVerify(t *testing.T) {
	cfg, err := parseFlags([]string{
		"--query", "DeviceInfo | limit 1",
		"--output", "results.json",
		"--insecure-skip-verify",
	}, io.Discard)
	if err != nil {
		t.Fatalf("parseFlags returned error: %v", err)
	}
	if !cfg.InsecureSkipVerify {
		t.Fatalf("expected insecure skip verify to be enabled")
	}
}

func TestParseFlagsSupportsNoAuthentication(t *testing.T) {
	cfg, err := parseFlags([]string{
		"--auth", "azcli",
		"--adx-auth", "none",
		"--adx-cluster", "http://localhost:8080",
		"--adx-database", "TestDB",
		"--adx-table", "Events",
		"--adx-upload-file", "events.json",
	}, io.Discard)
	if err != nil {
		t.Fatalf("parseFlags returned error: %v", err)
	}
	if cfg.AuthMode != "azcli" || cfg.ADXAuthMode != "none" {
		t.Fatalf("unexpected authentication modes: Graph=%q ADX=%q", cfg.AuthMode, cfg.ADXAuthMode)
	}
}

func TestADXAuthConfigOverridesGeneralAuthentication(t *testing.T) {
	cfg := config{AuthMode: "azcli", ADXAuthMode: "none"}
	if got := adxAuthConfig(cfg).AuthMode; got != "none" {
		t.Fatalf("expected ADX authentication override, got %q", got)
	}

	cfg.ADXAuthMode = ""
	if got := adxAuthConfig(cfg).AuthMode; got != "azcli" {
		t.Fatalf("expected general authentication fallback, got %q", got)
	}
}

func TestParseFlagsSupportsTableDumpDefaults(t *testing.T) {
	cfg, err := parseFlags([]string{
		"--dump-table", "DeviceInfo",
		"--output", "deviceinfo.json",
	}, io.Discard)
	if err != nil {
		t.Fatalf("parseFlags returned error: %v", err)
	}
	if cfg.DumpTable != "DeviceInfo" {
		t.Fatalf("unexpected dump table %q", cfg.DumpTable)
	}
	if cfg.DumpLookback != defaultDumpLookback {
		t.Fatalf("unexpected lookback %q", cfg.DumpLookback)
	}
	if cfg.DumpTimeColumn != "Timestamp" {
		t.Fatalf("unexpected time column %q", cfg.DumpTimeColumn)
	}
	if cfg.DumpRowLimit != defaultDumpRowLimit {
		t.Fatalf("unexpected row limit %d", cfg.DumpRowLimit)
	}
	if cfg.DumpParallelism != 1 {
		t.Fatalf("unexpected deprecated dump parallelism %d", cfg.DumpParallelism)
	}
	if cfg.PseudonymMapRetention != "keep" {
		t.Fatalf("unexpected pseudonym map retention default %q", cfg.PseudonymMapRetention)
	}
}

func TestParseFlagsAcceptsDeprecatedDumpParallelism(t *testing.T) {
	cfg, err := parseFlags([]string{"--dump-table", "DeviceInfo", "--dump-parallelism", "6"}, io.Discard)
	if err != nil {
		t.Fatalf("parseFlags returned error: %v", err)
	}
	if cfg.DumpParallelism != 6 {
		t.Fatalf("unexpected deprecated dump parallelism %d", cfg.DumpParallelism)
	}
}

func TestParseFlagsSupportsPseudonymization(t *testing.T) {
	cfg, err := parseFlags([]string{
		"--query", "DeviceInfo | limit 1",
		"--pseudonymize",
		"--pseudonymize-filenames",
		"--pseudonym-map", "/tmp/pseudonyms.json",
		"--pseudonym-fields", "AccountName,*FileName,*FolderPath",
		"--pseudonym-replacements-file", "/tmp/replacements.json",
		"--pseudonym-map-retention", "keep",
	}, io.Discard)
	if err != nil {
		t.Fatalf("parseFlags returned error: %v", err)
	}
	if !cfg.Pseudonymize || !cfg.PseudonymizeFilenames || cfg.PseudonymMap != "/tmp/pseudonyms.json" || cfg.PseudonymFields != "AccountName,*FileName,*FolderPath" || cfg.PseudonymReplacementsFile != "/tmp/replacements.json" || cfg.PseudonymMapRetention != "keep" {
		t.Fatalf("unexpected pseudonymization config: %#v", cfg)
	}
}

func TestParseFlagsLeavesFilenamePseudonymizationDisabledByDefault(t *testing.T) {
	cfg, err := parseFlags([]string{"--query", "DeviceInfo | limit 1", "--pseudonymize"}, io.Discard)
	if err != nil {
		t.Fatalf("parseFlags returned error: %v", err)
	}
	if cfg.PseudonymizeFilenames {
		t.Fatal("filename pseudonymization was enabled by default")
	}
}

func TestParseFlagsRejectsFilenamePseudonymizationWithoutPseudonymization(t *testing.T) {
	_, err := parseFlags([]string{"--query", "DeviceInfo | limit 1", "--pseudonymize-filenames"}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "requires -pseudonymize") {
		t.Fatalf("expected filename pseudonymization validation error, got %v", err)
	}
}

func TestParseFlagsRejectsInvalidPseudonymFieldPolicy(t *testing.T) {
	_, err := parseFlags([]string{
		"--query", "DeviceInfo | limit 1",
		"--pseudonymize",
		"--pseudonym-fields", "AccountName,,FileName",
	}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "pseudonym-fields") {
		t.Fatalf("expected pseudonym field validation error, got %v", err)
	}
}

func TestParseFlagsRejectsPseudonymMapWithoutPseudonymization(t *testing.T) {
	_, err := parseFlags([]string{
		"--query", "DeviceInfo | limit 1",
		"--pseudonym-map", "/tmp/pseudonyms.json",
	}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "requires -pseudonymize") {
		t.Fatalf("expected pseudonym map validation error, got %v", err)
	}
}

func TestParseFlagsRejectsPseudonymMapAtOutputPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "results.json")
	_, err := parseFlags([]string{
		"--query", "DeviceInfo | limit 1",
		"--output", path,
		"--pseudonymize",
		"--pseudonym-map", path,
	}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "must not use an output artifact path") {
		t.Fatalf("expected pseudonym map path validation error, got %v", err)
	}
}

func TestParseFlagsRejectsReplacementFileWithoutPseudonymization(t *testing.T) {
	_, err := parseFlags([]string{
		"--query", "DeviceInfo | limit 1",
		"--pseudonym-replacements-file", "/tmp/replacements.json",
	}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "requires -pseudonymize") {
		t.Fatalf("expected replacement file validation error, got %v", err)
	}
}

func TestParseFlagsRejectsReplacementFilePathCollisions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "results.json")
	_, err := parseFlags([]string{
		"--query", "DeviceInfo | limit 1",
		"--output", path,
		"--pseudonymize",
		"--pseudonym-replacements-file", path,
	}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "must not use an output artifact path") {
		t.Fatalf("expected replacement file path validation error, got %v", err)
	}

	_, err = parseFlags([]string{
		"--query", "DeviceInfo | limit 1",
		"--pseudonymize",
		"--pseudonym-map", path,
		"--pseudonym-replacements-file", path,
	}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "must use different paths") {
		t.Fatalf("expected pseudonym config path collision error, got %v", err)
	}
}

func TestParseFlagsRejectsUnsafeTableDumpValues(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "query conflict",
			args: []string{"--dump-table", "DeviceInfo", "--query", "DeviceInfo | limit 1"},
			want: "either -dump-table or -query/-query-file",
		},
		{
			name: "unsafe table",
			args: []string{"--dump-table", "DeviceInfo | take 1"},
			want: "invalid -dump-table",
		},
		{
			name: "unsafe lookback",
			args: []string{"--dump-table", "DeviceInfo", "--dump-lookback", "30d) | take 1"},
			want: "invalid -dump-lookback",
		},
		{
			name: "unsafe time column",
			args: []string{"--dump-table", "DeviceInfo", "--dump-time-column", "Timestamp | take 1"},
			want: "invalid -dump-time-column",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseFlags(tt.args, io.Discard)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected %q error, got %v", tt.want, err)
			}
		})
	}
}

func TestNewHTTPClient(t *testing.T) {
	t.Run("default transport keeps verification enabled", func(t *testing.T) {
		client := newHTTPClient(5*time.Second, false)
		if client.Timeout != 5*time.Second {
			t.Fatalf("unexpected timeout %s", client.Timeout)
		}
		if client.Transport != nil {
			t.Fatalf("expected nil transport when verification is enabled")
		}
	})

	t.Run("insecure mode disables certificate verification", func(t *testing.T) {
		client := newHTTPClient(5*time.Second, true)
		transport, ok := client.Transport.(*http.Transport)
		if !ok {
			t.Fatalf("expected *http.Transport, got %T", client.Transport)
		}
		if transport.TLSClientConfig == nil {
			t.Fatalf("expected TLS config")
		}
		if !transport.TLSClientConfig.InsecureSkipVerify {
			t.Fatalf("expected InsecureSkipVerify to be true")
		}
	})
}

func TestReadQuery(t *testing.T) {
	t.Run("inline query", func(t *testing.T) {
		query, err := readQuery("DeviceInfo | limit 10", "")
		if err != nil {
			t.Fatalf("readQuery returned error: %v", err)
		}
		if query != "DeviceInfo | limit 10" {
			t.Fatalf("unexpected query: %q", query)
		}
	})

	t.Run("query file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "query.kql")
		if err := os.WriteFile(path, []byte("DeviceInfo\n| limit 5\n"), 0o600); err != nil {
			t.Fatalf("write query file: %v", err)
		}

		query, err := readQuery("", path)
		if err != nil {
			t.Fatalf("readQuery returned error: %v", err)
		}
		if query != "DeviceInfo\n| limit 5" {
			t.Fatalf("unexpected query: %q", query)
		}
	})

	t.Run("rejects both", func(t *testing.T) {
		_, err := readQuery("a", "b")
		if err == nil || !strings.Contains(err.Error(), "either -query or -query-file") {
			t.Fatalf("expected mutual exclusion error, got %v", err)
		}
	})
}

func TestEnvOrDotEnv(t *testing.T) {
	t.Setenv("AZURE_CLIENT_ID", "from-env")
	got := envOrDotEnv("AZURE_CLIENT_ID", map[string]string{"AZURE_CLIENT_ID": "from-dotenv"})
	if got != "from-env" {
		t.Fatalf("envOrDotEnv() = %q, want %q", got, "from-env")
	}
}
