package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteJSONFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "results.json")

	err := writeJSONFile(path, []byte(`{"Results":[{"A":1}]}`))
	if err != nil {
		t.Fatalf("writeJSONFile returned error: %v", err)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read output file: %v", err)
	}
	if !strings.Contains(string(content), "\n  \"Results\"") {
		t.Fatalf("expected indented JSON, got %s", string(content))
	}
}
