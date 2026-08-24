package app

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLiteralWordReplacementsOverrideDetectionAndAreTracked(t *testing.T) {
	directory := t.TempDir()
	replacementsPath := filepath.Join(directory, "replacements.json")
	writeReplacementConfig(t, replacementsPath, `{
  "replacements": [
    {"find": "ACME+Ops", "replace": "Northbridge Labs"}
  ]
}`)
	replacements, err := loadWordReplacementSet(replacementsPath)
	if err != nil {
		t.Fatalf("loadWordReplacementSet returned error: %v", err)
	}

	vaultPath := filepath.Join(directory, "mappings.json")
	pseudonyms, err := newPseudonymizer(vaultPath)
	if err != nil {
		t.Fatalf("newPseudonymizer returned error: %v", err)
	}
	configureAllPseudonymFields(t, pseudonyms)
	if err := pseudonyms.ConfigureWordReplacements(replacements); err != nil {
		t.Fatalf("ConfigureWordReplacements returned error: %v", err)
	}

	converted, err := pseudonyms.pseudonymizeString(context.Background(), "Message", "ACME+Ops contacted alice@example.com")
	if err != nil {
		t.Fatalf("pseudonymizeString returned error: %v", err)
	}
	if !strings.Contains(converted, "Northbridge Labs") {
		t.Fatalf("configured literal replacement was not applied: %q", converted)
	}
	if strings.Contains(converted, "alice@example.com") {
		t.Fatalf("non-configured identifier was not pseudonymized: %q", converted)
	}
	if err := pseudonyms.Save(); err != nil {
		t.Fatalf("Save returned error: %v", err)
	}

	body, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatalf("read mapping vault: %v", err)
	}
	var vault pseudonymVault
	if err := json.Unmarshal(body, &vault); err != nil {
		t.Fatalf("decode mapping vault: %v", err)
	}
	found := false
	for _, mapping := range vault.Mappings {
		if mapping.EntityType == string(entityConfigured) && mapping.Original == "ACME+Ops" && mapping.Pseudonym == "Northbridge Labs" {
			found = true
		}
	}
	if !found {
		t.Fatalf("configured replacement was not tracked in mapping vault: %#v", vault.Mappings)
	}
}

func TestLiteralWordReplacementMatchingOptions(t *testing.T) {
	t.Run("case insensitive whole words by default", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "replacements.json")
		writeReplacementConfig(t, path, `{"replacements":[{"find":["Contoso","Fabrikam"],"replace":"Northwind"}]}`)
		set, err := loadWordReplacementSet(path)
		if err != nil {
			t.Fatalf("loadWordReplacementSet returned error: %v", err)
		}
		if set.Len() != 2 {
			t.Fatalf("Len = %d, want 2 aliases", set.Len())
		}
		entities := set.Recognize("CONTOSO precontosopost Contoso and Fabrikam")
		if len(entities) != 3 {
			t.Fatalf("Recognize returned %d matches, want 3", len(entities))
		}
	})

	t.Run("case sensitive and substring matching", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "replacements.json")
		writeReplacementConfig(t, path, `{
  "case_sensitive": true,
  "whole_words": false,
  "replacements": [{"find":"cat","replace":"dog"}]
}`)
		set, err := loadWordReplacementSet(path)
		if err != nil {
			t.Fatalf("loadWordReplacementSet returned error: %v", err)
		}
		entities := set.Recognize("Cat concatenate cat")
		if len(entities) != 2 {
			t.Fatalf("Recognize returned %d matches, want 2", len(entities))
		}
	})
}

func TestFindListMapsAliasesToOneReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replacements.json")
	writeReplacementConfig(t, path, `{
  "replacements": [{
    "find": ["Contoso Ltd", "Contoso", "Fabrikam"],
    "replace": "Northbridge Group"
  }]
}`)
	set, err := loadWordReplacementSet(path)
	if err != nil {
		t.Fatalf("loadWordReplacementSet returned error: %v", err)
	}
	pseudonyms, err := newPseudonymizer(filepath.Join(t.TempDir(), "mappings.json"))
	if err != nil {
		t.Fatalf("newPseudonymizer returned error: %v", err)
	}
	value := "Contoso Ltd acquired Fabrikam; CONTOSO approved the deal."
	got := pseudonyms.replaceEntities(value, set.Recognize(value))
	want := "Northbridge Group acquired Northbridge Group; Northbridge Group approved the deal."
	if got != want {
		t.Fatalf("replaceEntities = %q, want %q", got, want)
	}
}

func TestLongestConfiguredReplacementWins(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replacements.json")
	writeReplacementConfig(t, path, `{
  "replacements": [
    {"find":"Project","replace":"Program"},
    {"find":"Project Falcon","replace":"Project Aurora"}
  ]
}`)
	set, err := loadWordReplacementSet(path)
	if err != nil {
		t.Fatalf("loadWordReplacementSet returned error: %v", err)
	}
	pseudonyms, err := newPseudonymizer(filepath.Join(t.TempDir(), "mappings.json"))
	if err != nil {
		t.Fatalf("newPseudonymizer returned error: %v", err)
	}
	if got := pseudonyms.replaceEntities("Project Falcon", set.Recognize("Project Falcon")); got != "Project Aurora" {
		t.Fatalf("replaceEntities = %q, want Project Aurora", got)
	}
}

func TestConfiguredReplacementConflictWithExistingVault(t *testing.T) {
	directory := t.TempDir()
	vaultPath := filepath.Join(directory, "mappings.json")
	pseudonyms, err := newPseudonymizer(vaultPath)
	if err != nil {
		t.Fatalf("newPseudonymizer returned error: %v", err)
	}
	pseudonyms.configuredReplacement("Contoso", "Northwind")
	if err := pseudonyms.Save(); err != nil {
		t.Fatalf("Save returned error: %v", err)
	}

	configPath := filepath.Join(directory, "replacements.json")
	writeReplacementConfig(t, configPath, `{"replacements":[{"find":"Contoso","replace":"Tailspin"}]}`)
	set, err := loadWordReplacementSet(configPath)
	if err != nil {
		t.Fatalf("loadWordReplacementSet returned error: %v", err)
	}
	reloaded, err := newPseudonymizer(vaultPath)
	if err != nil {
		t.Fatalf("reload pseudonymizer: %v", err)
	}
	if err := reloaded.ConfigureWordReplacements(set); err == nil || !strings.Contains(err.Error(), "conflicts") {
		t.Fatalf("expected replacement conflict, got %v", err)
	}
}

func TestLoadWordReplacementSetRejectsInvalidConfig(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "empty list", body: `{"replacements":[]}`},
		{name: "empty find list", body: `{"replacements":[{"find":[],"replace":"A"}]}`},
		{name: "empty find alias", body: `{"replacements":[{"find":["Contoso",""],"replace":"A"}]}`},
		{name: "empty value", body: `{"replacements":[{"find":"Contoso","replace":""}]}`},
		{name: "duplicate", body: `{"replacements":[{"find":"Contoso","replace":"A"},{"find":"CONTOSO","replace":"B"}]}`},
		{name: "wrong find type", body: `{"replacements":[{"find":42,"replace":"A"}]}`},
		{name: "unknown property", body: `{"regex":true,"replacements":[{"find":"Contoso","replace":"A"}]}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "replacements.json")
			writeReplacementConfig(t, path, tt.body)
			if _, err := loadWordReplacementSet(path); err == nil {
				t.Fatal("loadWordReplacementSet unexpectedly succeeded")
			}
		})
	}
}

func writeReplacementConfig(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write replacement config: %v", err)
	}
}
