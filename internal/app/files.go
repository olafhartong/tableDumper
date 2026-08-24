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
