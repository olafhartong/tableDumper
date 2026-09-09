package app

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestLinkedFilenamesRedactEntireOriginalPath(t *testing.T) {
	for _, tc := range []struct{ name, prefix, path string }{
		{"windows", "", `C:\Users\Alice\SecretProject\report.exe`},
		{"posix", "", `/home/Alice/SecretProject/report.exe`},
		{"initiating", "InitiatingProcess", `C:\Users\Alice\SecretProject\report.exe`},
		{"parent", "InitiatingProcessParent", `/Users/Alice/SecretProject/report.exe`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			p, err := newPseudonymizer(filepath.Join(dir, "vault.json"))
			if err != nil {
				t.Fatal(err)
			}
			configureAllPseudonymFields(t, p)
			p.ConfigureFilenamePseudonymization(true)
			rulePath := filepath.Join(dir, "words.json")
			writeReplacementConfig(t, rulePath, `{"replacements":[{"find":"SecretProject","replace":"PublicProject"}]}`)
			rules, err := loadWordReplacementSet(rulePath)
			if err != nil {
				t.Fatal(err)
			}
			if err := p.ConfigureWordReplacements(rules); err != nil {
				t.Fatal(err)
			}
			row := map[string]any{"AccountName": "Alice", tc.prefix + "FileName": "report.exe", tc.prefix + "FolderPath": tc.path, tc.prefix + "FilePath": tc.path, tc.prefix + "FullPath": tc.path}
			rows := []map[string]any{row, {"Nested": []any{row}}}
			out, err := p.PseudonymizeRows(context.Background(), rows)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := json.Marshal(out)
			for _, secret := range []string{"Alice", "SecretProject", "report.exe"} {
				if strings.Contains(string(body), secret) {
					t.Fatalf("original %s survived: %s", secret, body)
				}
			}
			filename := out[0][tc.prefix+"FileName"].(string)
			for _, field := range []string{"FolderPath", "FilePath", "FullPath"} {
				got := out[0][tc.prefix+field].(string)
				if pathLastComponent(got) != filename || !strings.Contains(got, out[0]["AccountName"].(string)) || !strings.Contains(got, "PublicProject") {
					t.Fatalf("path relationships lost: %s", got)
				}
			}
			if err := p.Save(); err != nil {
				t.Fatal(err)
			}
			reloaded, err := newPseudonymizer(p.Path())
			if err != nil {
				t.Fatal(err)
			}
			configureAllPseudonymFields(t, reloaded)
			reloaded.ConfigureFilenamePseudonymization(true)
			if err := reloaded.ConfigureWordReplacements(rules); err != nil {
				t.Fatal(err)
			}
			again, err := reloaded.PseudonymizeRows(context.Background(), rows)
			if err != nil {
				t.Fatal(err)
			}
			againBody, _ := json.Marshal(again)
			if string(body) != string(againBody) {
				t.Fatal("path mappings changed after reload")
			}
		})
	}
}

func TestPathBearingFilenameRedactsUserAndPreservesLinkedBasename(t *testing.T) {
	p, err := newPseudonymizer(filepath.Join(t.TempDir(), "vault.json"))
	if err != nil {
		t.Fatal(err)
	}
	configureAllPseudonymFields(t, p)
	p.ConfigureFilenamePseudonymization(true)
	out, err := p.PseudonymizeRows(context.Background(), []map[string]any{{"AccountName": "Alice", "FileName": `C:\Users\Alice\report.exe`, "FolderPath": `C:\Users\Alice\report`}})
	if err != nil {
		t.Fatal(err)
	}
	filename := out[0]["FileName"].(string)
	folder := out[0]["FolderPath"].(string)
	if strings.Contains(filename+folder, "Alice") || strings.TrimSuffix(filename, ".exe") != folder {
		t.Fatalf("linked path was not safely transformed: %v", out)
	}
}
