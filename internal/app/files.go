package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

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

// writeFileAtomically replaces path with an owner-only file through a synced
// temporary file, so readers never observe a partial write.
func writeFileAtomically(path string, body []byte) error {
	file, tempPath, err := createTempFileForPath(path)
	if err != nil {
		return err
	}
	cleanup := func() {
		file.Close()
		os.Remove(tempPath)
	}
	if err := file.Chmod(0o600); err != nil {
		cleanup()
		return fmt.Errorf("secure temporary file for %s: %w", path, err)
	}
	if _, err := file.Write(body); err != nil {
		cleanup()
		return fmt.Errorf("write temporary file for %s: %w", path, err)
	}
	if err := file.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("sync temporary file for %s: %w", path, err)
	}
	if err := file.Close(); err != nil {
		os.Remove(tempPath)
		return fmt.Errorf("close temporary file for %s: %w", path, err)
	}
	if err := os.Rename(tempPath, path); err != nil {
		os.Remove(tempPath)
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return nil
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
