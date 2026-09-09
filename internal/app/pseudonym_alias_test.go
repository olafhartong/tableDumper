package app

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestDeviceAliasesSurviveVaultRoundTrip(t *testing.T) {
	for _, row := range []map[string]any{
		{"DeviceName": "pc.corp.test", "DeviceFqdn": "pc.corp.test"},
		{"DeviceName": "pc.corp.test", "DeviceFqdn": "alias.corp.test"},
		{"DeviceName": "PC", "DeviceFqdn": "alias.corp.test", "DeviceDnsDomain": "CORP"},
	} {
		p, err := newPseudonymizer(filepath.Join(t.TempDir(), "vault.json"))
		if err != nil {
			t.Fatal(err)
		}
		configureAllPseudonymFields(t, p)
		rows := []map[string]any{row}
		out, err := p.PseudonymizeRows(context.Background(), rows)
		if err != nil {
			t.Fatal(err)
		}
		want, _ := json.Marshal(out)
		for round := 0; round < 3; round++ {
			if err := p.Save(); err != nil {
				t.Fatal(err)
			}
			p, err = newPseudonymizer(p.Path())
			if err != nil {
				t.Fatalf("round %d: %v", round, err)
			}
			configureAllPseudonymFields(t, p)
			out, err = p.PseudonymizeRows(context.Background(), rows)
			if err != nil {
				t.Fatal(err)
			}
			got, _ := json.Marshal(out)
			if string(got) != string(want) {
				t.Fatal("alias values changed")
			}
		}
	}
}

func TestLegacyExactFQDNAliasLoadsInEitherOrder(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		p, err := newPseudonymizer(filepath.Join(t.TempDir(), "vault.json"))
		if err != nil {
			t.Fatal(err)
		}
		mappings := []pseudonymMapping{
			{EntityType: "hostname", Original: "PC.corp.test", Pseudonym: "ws-1234.example.internal"},
			{EntityType: "domain", Original: "pc.corp.test", Pseudonym: "ws-1234.example.internal"},
		}
		if reverse {
			mappings[0], mappings[1] = mappings[1], mappings[0]
		}
		writeAliasTestVault(t, p.Path(), mappings)
		if _, err := newPseudonymizer(p.Path()); err != nil {
			t.Fatal(err)
		}
	}
}

func TestVaultRejectsUnrelatedOrMalformedAliases(t *testing.T) {
	cases := map[string][]pseudonymMapping{
		"unrelated":          {{EntityType: "hostname", Original: "pc.corp.test", Pseudonym: "ws-1234.example.internal"}, {EntityType: "domain", Original: "unrelated.test", Pseudonym: "ws-1234.example.internal"}},
		"dangling":           {{EntityType: "hostname", Original: "pc", Pseudonym: "ws-1234", AliasOf: "missing"}},
		"different value":    {{EntityType: "hostname", Original: "pc", Pseudonym: "ws-1234"}, {EntityType: "domain", Original: "pc.corp.test", Pseudonym: "different.internal", AliasOf: entityKey(entityHostname, "pc")}},
		"incompatible kinds": {{EntityType: "identifier", Original: "id", Pseudonym: "same"}, {EntityType: "hostname", Original: "pc", Pseudonym: "same", AliasOf: entityKey(entityIdentifier, "id")}},
		"cycle":              {{EntityType: "hostname", Original: "pc", Pseudonym: "same", AliasOf: entityKey(entityDomain, "pc")}, {EntityType: "domain", Original: "pc", Pseudonym: "same", AliasOf: entityKey(entityHostname, "pc")}},
	}
	for name, mappings := range cases {
		t.Run(name, func(t *testing.T) {
			p, err := newPseudonymizer(filepath.Join(t.TempDir(), "vault.json"))
			if err != nil {
				t.Fatal(err)
			}
			writeAliasTestVault(t, p.Path(), mappings)
			if _, err := newPseudonymizer(p.Path()); err == nil {
				t.Fatal("invalid alias accepted")
			}
		})
	}
}

func writeAliasTestVault(t *testing.T, path string, mappings []pseudonymMapping) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var vault pseudonymVault
	if err := json.Unmarshal(body, &vault); err != nil {
		t.Fatal(err)
	}
	vault.Mappings = mappings
	body, err = json.Marshal(vault)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
}
