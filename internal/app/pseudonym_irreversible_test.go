package app

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var irreversibleTestOriginals = []string{
	"jdoe", "j.doe@contoso.com", "contoso", "FIN-LAPTOP-042", "corp.contoso.com",
	"bob.vance@fabrikam.com", "bob.vance", "fabrikam", "2f1a6c0e-4b7d-4e59-9a51-3c1d2b8e7f60",
	"rg-finance-prod", "vm-payroll-01", "Project Falcon",
}

func irreversibleTestRows() []map[string]any {
	return []map[string]any{{
		"Timestamp":                   "2026-09-01T10:15:00Z",
		"AccountName":                 "jdoe",
		"AccountDomain":               "CONTOSO",
		"AccountUpn":                  "j.doe@contoso.com",
		"InitiatingProcessAccountUpn": "j.doe@contoso.com",
		"DeviceName":                  "FIN-LAPTOP-042.corp.contoso.com",
		"RecipientEmailAddress":       "bob.vance@fabrikam.com",
		"FolderPath":                  `C:\Users\jdoe\Documents\Project Falcon\budget.xlsx`,
		"ResourceId":                  "/subscriptions/2f1a6c0e-4b7d-4e59-9a51-3c1d2b8e7f60/resourceGroups/rg-finance-prod/providers/Microsoft.Compute/virtualMachines/vm-payroll-01",
	}}
}

func TestIrreversibleRunStoresNoOriginalValuesAndStaysLinkedAcrossRuns(t *testing.T) {
	directory := t.TempDir()
	vaultPath := filepath.Join(directory, "collection.pseudonyms.json")
	replacementsPath := filepath.Join(directory, "replacements.json")
	writeReplacementConfig(t, replacementsPath, `{"replacements":[{"find":"Project Falcon","replace":"Project Aurora"}]}`)

	var rows []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]string
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode query request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(payload["Query"], "\n| count") {
			fmt.Fprintf(w, `{"Results":[{"Count":%d}]}`, len(rows))
			return
		}
		json.NewEncoder(w).Encode(queryResponse{Results: rows})
	}))
	defer server.Close()

	run := func(output string, irreversible bool) map[string]any {
		t.Helper()
		args := []string{
			"--env-file", "", "--auth", "none", "--endpoint", server.URL,
			"--query", "DeviceEvents | take 1", "--output", output,
			"--pseudonymize", "--pseudonym-map", vaultPath, "--pseudonym-replacements-file", replacementsPath,
		}
		if irreversible {
			args = append(args, "--pseudonym-map-irreversible")
		}
		if err := Run(context.Background(), args, nil, io.Discard, io.Discard); err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
		body, err := os.ReadFile(output)
		if err != nil {
			t.Fatal(err)
		}
		var response queryResponse
		if err := json.Unmarshal(body, &response); err != nil || len(response.Results) != 1 {
			t.Fatalf("unexpected output %s: %v", body, err)
		}
		return response.Results[0]
	}

	rows = irreversibleTestRows()
	first := run(filepath.Join(directory, "first.json"), true)
	vault := assertIrreversibleVaultFile(t, vaultPath)
	hasAlias := false
	for _, mapping := range vault.Mappings {
		hasAlias = hasAlias || mapping.AliasOf != ""
	}
	if !hasAlias {
		t.Fatal("irreversible vault did not record linked aliases")
	}
	if !strings.Contains(first["FolderPath"].(string), "Project Aurora") {
		t.Fatalf("configured replacement was not applied: %v", first["FolderPath"])
	}

	// The second run omits the flag and sees each identity and device through a
	// different alias, which must resolve to the first run's pseudonyms.
	rows = []map[string]any{{
		"AccountUpn":  "J.Doe@contoso.com",
		"DeviceName":  "fin-laptop-042",
		"FolderPath":  `C:\Users\JDOE\Desktop\project falcon`,
		"SenderEmail": "bob.vance@fabrikam.com",
	}}
	second := run(filepath.Join(directory, "second.json"), false)
	if second["AccountUpn"] != first["AccountUpn"] {
		t.Fatalf("linked identity changed across runs: %v != %v", second["AccountUpn"], first["AccountUpn"])
	}
	firstHost, _ := splitHostname(first["DeviceName"].(string))
	if second["DeviceName"] != firstHost {
		t.Fatalf("linked device changed across runs: %v != %v", second["DeviceName"], firstHost)
	}
	username, _, _ := splitEmail(first["AccountUpn"].(string))
	if want := `C:\Users\` + username + `\Desktop\Project Aurora`; second["FolderPath"] != want {
		t.Fatalf("path identity or configured replacement changed: %v != %v", second["FolderPath"], want)
	}
	if second["SenderEmail"] != first["RecipientEmailAddress"] {
		t.Fatalf("email changed across runs: %v != %v", second["SenderEmail"], first["RecipientEmailAddress"])
	}
	assertIrreversibleVaultFile(t, vaultPath)
}

func assertIrreversibleVaultFile(t *testing.T, path string) pseudonymVault {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lower := strings.ToLower(string(body))
	for _, original := range irreversibleTestOriginals {
		if strings.Contains(lower, strings.ToLower(original)) {
			t.Fatalf("irreversible vault contains original value %q:\n%s", original, body)
		}
	}
	var vault pseudonymVault
	if err := json.Unmarshal(body, &vault); err != nil {
		t.Fatal(err)
	}
	if vault.Version != irreversiblePseudonymVaultVersion || vault.Mode != irreversiblePseudonymVaultMode || len(vault.KeyID) != 16 || len(vault.Mappings) == 0 {
		t.Fatalf("unexpected irreversible vault header: version=%d mode=%q key_id=%q mappings=%d", vault.Version, vault.Mode, vault.KeyID, len(vault.Mappings))
	}
	for _, mapping := range vault.Mappings {
		if mapping.Original != "" || !isVaultKeyDigest(mapping.OriginalHMAC) {
			t.Fatalf("irreversible mapping stores an original or lacks original_hmac: %#v", mapping)
		}
	}
	if !bytes.Contains(body, []byte(`"original_hmac"`)) || bytes.Contains(body, []byte(`"original":`)) {
		t.Fatalf("unexpected mapping fields in irreversible vault:\n%s", body)
	}
	return vault
}

func TestIrreversibleAndReversibleVaultsProduceIdenticalPseudonyms(t *testing.T) {
	directory := t.TempDir()
	replacementsPath := filepath.Join(directory, "replacements.json")
	writeReplacementConfig(t, replacementsPath, `{"replacements":[{"find":"Project Falcon","replace":"Project Aurora"}]}`)
	replacements, err := loadWordReplacementSet(replacementsPath)
	if err != nil {
		t.Fatal(err)
	}
	outputs := make(map[bool][2]string)
	for _, irreversible := range []bool{false, true} {
		path := filepath.Join(directory, fmt.Sprintf("vault-%t.json", irreversible))
		var runs [2]string
		for round := range runs {
			p, err := openPseudonymizer(path, irreversible)
			if err != nil {
				t.Fatal(err)
			}
			if round == 0 {
				p.seed = bytes.Repeat([]byte{7}, 32)
			}
			configureAllPseudonymFields(t, p)
			if err := p.ConfigureWordReplacements(replacements); err != nil {
				t.Fatal(err)
			}
			out, err := p.PseudonymizeRows(context.Background(), irreversibleTestRows())
			if err != nil {
				t.Fatal(err)
			}
			if err := p.Save(); err != nil {
				t.Fatal(err)
			}
			body, _ := json.Marshal(out)
			runs[round] = string(body)
		}
		if runs[0] != runs[1] {
			t.Fatalf("irreversible=%t output changed after reload:\n%s\n%s", irreversible, runs[0], runs[1])
		}
		outputs[irreversible] = runs
	}
	if outputs[false][0] != outputs[true][0] {
		t.Fatalf("vault mode changed pseudonyms:\nreversible:   %s\nirreversible: %s", outputs[false][0], outputs[true][0])
	}
	for _, original := range irreversibleTestOriginals {
		if strings.Contains(strings.ToLower(outputs[true][0]), strings.ToLower(original)) {
			t.Fatalf("pseudonymized output contains %q: %s", original, outputs[true][0])
		}
	}

	reversible, err := newPseudonymizer(filepath.Join(directory, "vault-false.json"))
	if err != nil {
		t.Fatal(err)
	}
	irreversible, err := newPseudonymizer(filepath.Join(directory, "vault-true.json"))
	if err != nil {
		t.Fatal(err)
	}
	if reversible.MappingCount() != irreversible.MappingCount() || reversible.KeyID() != irreversible.KeyID() {
		t.Fatalf("vault modes differ: mappings %d/%d key_id %s/%s", reversible.MappingCount(), irreversible.MappingCount(), reversible.KeyID(), irreversible.KeyID())
	}
}

func TestIrreversibleVaultModeIsPropertyOfTheFile(t *testing.T) {
	directory := t.TempDir()
	reversiblePath := filepath.Join(directory, "reversible.json")
	if _, err := newPseudonymizer(reversiblePath); err != nil {
		t.Fatal(err)
	}
	if _, err := openPseudonymizer(reversiblePath, true); err == nil || !strings.Contains(err.Error(), "reversible") {
		t.Fatalf("irreversible flag with a reversible vault was accepted: %v", err)
	}
	if p, err := newPseudonymizer(reversiblePath); err != nil || p.Irreversible() {
		t.Fatalf("rejected conversion changed the reversible vault: %v", err)
	}

	irreversiblePath := filepath.Join(directory, "irreversible.json")
	p, err := openPseudonymizer(irreversiblePath, true)
	if err != nil {
		t.Fatal(err)
	}
	p.replacement(entityUsername, "jdoe")
	if err := p.Save(); err != nil {
		t.Fatal(err)
	}
	reopened, err := newPseudonymizer(irreversiblePath)
	if err != nil {
		t.Fatal(err)
	}
	if !reopened.Irreversible() {
		t.Fatal("irreversible vault became reversible when reopened without the flag")
	}
	reopened.replacement(entityUsername, "second.user")
	if err := reopened.Save(); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(irreversiblePath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, []byte("jdoe")) || bytes.Contains(body, []byte("second.user")) || !bytes.Contains(body, []byte(`"mode": "irreversible"`)) {
		t.Fatalf("reopened irreversible vault stored originals or lost its mode:\n%s", body)
	}
}

func TestIrreversibleVaultDetectsConflicts(t *testing.T) {
	t.Run("relationship", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "vault.json")
		p, err := openPseudonymizer(path, true)
		if err != nil {
			t.Fatal(err)
		}
		configureAllPseudonymFields(t, p)
		if _, err := p.PseudonymizeRows(context.Background(), []map[string]any{{"DeviceName": "one.corp.test"}, {"DeviceName": "two.corp.test"}}); err != nil {
			t.Fatal(err)
		}
		if err := p.Save(); err != nil {
			t.Fatal(err)
		}
		before, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		p, err = newPseudonymizer(path)
		if err != nil {
			t.Fatal(err)
		}
		configureAllPseudonymFields(t, p)
		out, err := p.PseudonymizeRows(context.Background(), []map[string]any{{"DeviceName": "one.corp.test", "DeviceFqdn": "two.corp.test"}})
		var conflict *pseudonymRelationshipError
		if out != nil || !errors.As(err, &conflict) {
			t.Fatalf("wanted relationship conflict, got %v, %v", out, err)
		}
		if !errors.As(p.Save(), &conflict) {
			t.Fatal("conflicted irreversible mappings were saved")
		}
		if after, _ := os.ReadFile(path); string(after) != string(before) {
			t.Fatal("irreversible vault changed after conflict")
		}
	})

	t.Run("configured replacement", func(t *testing.T) {
		directory := t.TempDir()
		path := filepath.Join(directory, "vault.json")
		p, err := openPseudonymizer(path, true)
		if err != nil {
			t.Fatal(err)
		}
		p.configuredReplacement("Contoso", "Northwind")
		if err := p.Save(); err != nil {
			t.Fatal(err)
		}
		configPath := filepath.Join(directory, "replacements.json")
		writeReplacementConfig(t, configPath, `{"replacements":[{"find":"CONTOSO","replace":"Tailspin"}]}`)
		set, err := loadWordReplacementSet(configPath)
		if err != nil {
			t.Fatal(err)
		}
		reloaded, err := newPseudonymizer(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := reloaded.ConfigureWordReplacements(set); err == nil || !strings.Contains(err.Error(), "conflicts") {
			t.Fatalf("expected replacement conflict, got %v", err)
		}
		writeReplacementConfig(t, configPath, `{"replacements":[{"find":"contoso","replace":"Northwind"}]}`)
		if set, err = loadWordReplacementSet(configPath); err != nil {
			t.Fatal(err)
		}
		if err := reloaded.ConfigureWordReplacements(set); err != nil {
			t.Fatalf("matching replacement rejected: %v", err)
		}
	})
}

func TestIrreversibleVaultRejectsTamperedEntries(t *testing.T) {
	validHMAC := strings.Repeat("ab", sha256.Size)
	otherHMAC := strings.Repeat("cd", sha256.Size)
	cases := map[string]func(*pseudonymVault){
		"stored original":   func(v *pseudonymVault) { v.Mappings[0].Original = "jdoe" },
		"missing hmac":      func(v *pseudonymVault) { v.Mappings[0].OriginalHMAC = "" },
		"malformed hmac":    func(v *pseudonymVault) { v.Mappings[0].OriginalHMAC = "jdoe" },
		"key id mismatch":   func(v *pseudonymVault) { v.KeyID = "0000000000000000" },
		"mode without bump": func(v *pseudonymVault) { v.Version = pseudonymVaultVersion },
		"bump without mode": func(v *pseudonymVault) { v.Mode = "" },
		"unknown mode":      func(v *pseudonymVault) { v.Mode = "hashed" },
		"dangling alias":    func(v *pseudonymVault) { v.Mappings[0].AliasOf = "hostname\x00" + otherHMAC },
		"unrelated collision": func(v *pseudonymVault) {
			v.Mappings = append(v.Mappings, pseudonymMapping{EntityType: "domain", OriginalHMAC: otherHMAC, Pseudonym: v.Mappings[0].Pseudonym})
		},
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "vault.json")
			if _, err := openPseudonymizer(path, true); err != nil {
				t.Fatal(err)
			}
			body, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var vault pseudonymVault
			if err := json.Unmarshal(body, &vault); err != nil {
				t.Fatal(err)
			}
			vault.Mappings = []pseudonymMapping{{EntityType: "hostname", OriginalHMAC: validHMAC, Pseudonym: "ws-1234"}}
			tamper(&vault)
			if body, err = json.Marshal(vault); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, body, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := newPseudonymizer(path); err == nil {
				t.Fatal("tampered irreversible vault accepted")
			}
		})
	}

	path := filepath.Join(t.TempDir(), "reversible.json")
	p, err := newPseudonymizer(path)
	if err != nil {
		t.Fatal(err)
	}
	writeAliasTestVault(t, p.Path(), []pseudonymMapping{{EntityType: "hostname", Original: "pc", OriginalHMAC: validHMAC, Pseudonym: "ws-1234"}})
	if _, err := newPseudonymizer(path); err == nil {
		t.Fatal("reversible vault accepted original_hmac")
	}
}

func TestLegacyAliasFallbackIgnoresMappingsWithoutOriginals(t *testing.T) {
	host := pseudonymMapping{EntityType: "hostname", OriginalHMAC: strings.Repeat("ab", sha256.Size), Pseudonym: "ws-1234.example.internal"}
	domain := pseudonymMapping{EntityType: "domain", OriginalHMAC: strings.Repeat("ab", sha256.Size), Pseudonym: "ws-1234.example.internal"}
	if linkedMappingsMaySharePseudonym("hostname\x00"+host.OriginalHMAC, host, "domain\x00"+domain.OriginalHMAC, domain) {
		t.Fatal("mappings without originals matched the legacy exact-FQDN fallback")
	}
}

func TestVaultKeyIDIdentifiesSeedWithoutRevealingIt(t *testing.T) {
	p, err := newPseudonymizer(filepath.Join(t.TempDir(), "vault.json"))
	if err != nil {
		t.Fatal(err)
	}
	p.seed = bytes.Repeat([]byte{9}, 32)
	mac := hmac.New(sha256.New, p.seed)
	mac.Write([]byte("tabledumper-key-id-v1"))
	if want := hex.EncodeToString(mac.Sum(nil))[:16]; p.KeyID() != want {
		t.Fatalf("KeyID() = %q, want %q", p.KeyID(), want)
	}
	if err := p.Save(); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(p.Path())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte(`"key_id": "`+p.KeyID()+`"`)) {
		t.Fatalf("vault does not record key_id:\n%s", body)
	}
	p.seed = bytes.Repeat([]byte{10}, 32)
	if p.KeyID() == hex.EncodeToString(mac.Sum(nil))[:16] {
		t.Fatal("different seeds share a key_id")
	}
}
