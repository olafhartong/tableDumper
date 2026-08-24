package app

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPseudonymizeRowsUsesRealisticStableEntities(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mappings.json")
	pseudonyms, err := newPseudonymizer(path)
	if err != nil {
		t.Fatalf("newPseudonymizer returned error: %v", err)
	}
	configureAllPseudonymFields(t, pseudonyms)

	rows := []map[string]any{{
		"AccountDisplayName": "Marie Curie",
		"AccountUpn":         "marie.curie@contoso.com",
		"AccountName":        `CONTOSO\marie.curie`,
		"AccountSid":         "S-1-5-21-111111111-222222222-333333333-1001",
		"DeviceName":         "DC-CONTOSO-01.corp.contoso.com",
		"DeviceId":           "9e32d7f1-a53d-4c3f-9b3e-0bda9995b305",
		"RemoteIP":           "8.8.8.8",
		"Message":            "Marie Curie signed in to Contoso Research from 8.8.8.8.",
	}}

	converted, err := pseudonyms.PseudonymizeRows(context.Background(), rows)
	if err != nil {
		t.Fatalf("PseudonymizeRows returned error: %v", err)
	}
	if err := pseudonyms.Save(); err != nil {
		t.Fatalf("Save returned error: %v", err)
	}

	name := converted[0]["AccountDisplayName"].(string)
	if name == "Marie Curie" || !strings.Contains(name, " ") {
		t.Fatalf("expected a realistic replacement name, got %q", name)
	}
	if message := converted[0]["Message"].(string); strings.Contains(message, "Marie Curie") || !strings.Contains(message, name) {
		t.Fatalf("expected the same person replacement in free text, got %q", message)
	}
	email := converted[0]["AccountUpn"].(string)
	if email == "marie.curie@contoso.com" || !strings.Contains(email, "@") {
		t.Fatalf("unexpected email replacement %q", email)
	} else if local, _, _ := strings.Cut(email, "@"); local != usernameFromDisplayName(name) {
		t.Fatalf("email local part %q is inconsistent with replacement name %q", local, name)
	}
	if host := converted[0]["DeviceName"].(string); !strings.HasPrefix(host, "dc-") {
		t.Fatalf("expected hostname role to be preserved, got %q", host)
	} else if !strings.Contains(host, ".") {
		t.Fatalf("expected FQDN structure to be preserved, got %q", host)
	} else if _, emailDomain, _ := strings.Cut(email, "@"); !strings.HasSuffix(host, "."+emailDomain) {
		t.Fatalf("FQDN %q does not preserve its relationship to email domain %q", host, emailDomain)
	}
	if account := converted[0]["AccountName"].(string); !strings.Contains(account, `\`) || strings.Contains(account, "CONTOSO") {
		t.Fatalf("expected DOMAIN\\user structure with pseudonyms, got %q", account)
	}
	if ip := converted[0]["RemoteIP"].(string); ip == "8.8.8.8" {
		t.Fatalf("expected IP to be replaced")
	}
	if id := converted[0]["DeviceId"].(string); id == rows[0]["DeviceId"] || !guidPattern.MatchString(id) {
		t.Fatalf("expected a format-preserving GUID, got %q", id)
	}

	body, err := json.Marshal(converted)
	if err != nil {
		t.Fatalf("marshal pseudonymized rows: %v", err)
	}
	for _, original := range []string{"Marie Curie", "marie.curie@contoso.com", "CONTOSO", "DC-CONTOSO-01", "8.8.8.8", "9e32d7f1-a53d-4c3f-9b3e-0bda9995b305"} {
		if strings.Contains(string(body), original) {
			t.Fatalf("pseudonymized output still contains %q: %s", original, body)
		}
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat mapping file: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mapping file permissions = %o, want 600", got)
	}

	reloaded, err := newPseudonymizer(path)
	if err != nil {
		t.Fatalf("reload pseudonymizer: %v", err)
	}
	configureAllPseudonymFields(t, reloaded)
	again, err := reloaded.PseudonymizeRows(context.Background(), rows)
	if err != nil {
		t.Fatalf("PseudonymizeRows after reload returned error: %v", err)
	}
	againBody, _ := json.Marshal(again)
	if string(againBody) != string(body) {
		t.Fatalf("pseudonyms changed after reload:\nfirst: %s\nagain: %s", body, againBody)
	}
}

func TestPseudonymVaultDropsEmptyLegacyMappingsAndRemainsReusable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mappings.json")
	pseudonyms, err := newPseudonymizer(path)
	if err != nil {
		t.Fatalf("newPseudonymizer returned error: %v", err)
	}
	wantUsername := pseudonyms.replacement(entityUsername, "alice")
	pseudonyms.mu.Lock()
	pseudonyms.mappings[entityKey(entityDomain, "")] = pseudonymMapping{
		EntityType: string(entityDomain),
		Original:   "",
		Pseudonym:  "legacy-empty.internal",
	}
	pseudonyms.mu.Unlock()
	if err := pseudonyms.Save(); err != nil {
		t.Fatalf("Save returned error: %v", err)
	}

	reloaded, err := newPseudonymizer(path)
	if err != nil {
		t.Fatalf("reload vault containing an empty legacy mapping: %v", err)
	}
	if got := reloaded.DiscardedMappingCount(); got != 1 {
		t.Fatalf("DiscardedMappingCount() = %d, want 1", got)
	}
	if got := reloaded.replacement(entityUsername, "alice"); got != wantUsername {
		t.Fatalf("valid mapping changed during cleanup: got %q, want %q", got, wantUsername)
	}
	if got := reloaded.MappingCount(); got != 1 {
		t.Fatalf("MappingCount() after cleanup = %d, want 1", got)
	}

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read cleaned vault: %v", err)
	}
	var vault pseudonymVault
	if err := json.Unmarshal(body, &vault); err != nil {
		t.Fatalf("decode cleaned vault: %v", err)
	}
	for _, mapping := range vault.Mappings {
		if strings.TrimSpace(mapping.Original) == "" || strings.TrimSpace(mapping.Pseudonym) == "" {
			t.Fatalf("cleaned vault still contains unusable mapping: %#v", mapping)
		}
	}

	again, err := newPseudonymizer(path)
	if err != nil {
		t.Fatalf("reload cleaned vault: %v", err)
	}
	if again.DiscardedMappingCount() != 0 || again.replacement(entityUsername, "alice") != wantUsername {
		t.Fatalf("cleaned vault was not stably reusable")
	}
}

func TestPseudonymizerDoesNotCreateEmptyMappings(t *testing.T) {
	pseudonyms, err := newPseudonymizer(filepath.Join(t.TempDir(), "mappings.json"))
	if err != nil {
		t.Fatalf("newPseudonymizer returned error: %v", err)
	}
	before := pseudonyms.MappingCount()
	if got := pseudonyms.replacement(entityDomain, ""); got != "" {
		t.Fatalf("replacement for an empty value = %q, want empty", got)
	}
	if got := pseudonyms.replacement(entityUsername, "   "); got != "   " {
		t.Fatalf("replacement for whitespace = %q, want original whitespace", got)
	}
	if got := pseudonyms.MappingCount(); got != before {
		t.Fatalf("empty replacements added mappings: before=%d after=%d", before, got)
	}
}

func TestPseudonymVaultReportsInvalidEntryDetails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mappings.json")
	_, err := newPseudonymizer(path)
	if err != nil {
		t.Fatalf("newPseudonymizer returned error: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read vault: %v", err)
	}
	var vault pseudonymVault
	if err := json.Unmarshal(body, &vault); err != nil {
		t.Fatalf("decode vault: %v", err)
	}
	vault.Mappings = append(vault.Mappings, pseudonymMapping{EntityType: "mystery", Original: "alice", Pseudonym: "masked"})
	body, err = json.Marshal(vault)
	if err != nil {
		t.Fatalf("encode invalid vault: %v", err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write invalid vault: %v", err)
	}

	_, err = newPseudonymizer(path)
	if err == nil || !strings.Contains(err.Error(), "entry 1") || !strings.Contains(err.Error(), `unsupported entity_type "mystery"`) {
		t.Fatalf("invalid vault error lacks entry details: %v", err)
	}
}

func TestPseudonymizeRowsRecursesIntoNestedJSON(t *testing.T) {
	pseudonyms, err := newPseudonymizer(filepath.Join(t.TempDir(), "mappings.json"))
	if err != nil {
		t.Fatalf("newPseudonymizer returned error: %v", err)
	}
	configureAllPseudonymFields(t, pseudonyms)
	rows := []map[string]any{{
		"AdditionalFields": `{"OwnerDisplayName":"Ada Lovelace","OwnerEmail":"ada@example.org","SourceIP":"10.1.2.3","CommandLine":"C:\\Users\\ada\\tool.exe CONTOSO\\ada"}`,
	}}

	converted, err := pseudonyms.PseudonymizeRows(context.Background(), rows)
	if err != nil {
		t.Fatalf("PseudonymizeRows returned error: %v", err)
	}
	nested := converted[0]["AdditionalFields"].(string)
	for _, original := range []string{"Ada Lovelace", "ada@example.org", "10.1.2.3", `\ada\`} {
		if strings.Contains(nested, original) {
			t.Fatalf("nested JSON still contains %q: %s", original, nested)
		}
	}
}

func TestPseudonymizeRowsReplacesUsernamesInFolderPathsConsistently(t *testing.T) {
	pseudonyms, err := newPseudonymizer(filepath.Join(t.TempDir(), "mappings.json"))
	if err != nil {
		t.Fatalf("newPseudonymizer returned error: %v", err)
	}
	rows := []map[string]any{{
		"AccountName":                 "USERNAME",
		"AccountUpn":                  "USERNAME@contoso.example",
		"FolderPath":                  `/Users/USERNAME/Library/Application Support/tool`,
		"InitiatingProcessFolderPath": `C:\Users\USERNAME\AppData\Local\tool.exe`,
		"ParentProcessFolderPath":     `/home/USERNAME/.config/tool`,
		"MixedSeparatorFolderPath":    `C:\Users/USERNAME/AppData/Local/tool.exe`,
	}}

	converted, err := pseudonyms.PseudonymizeRows(context.Background(), rows)
	if err != nil {
		t.Fatalf("PseudonymizeRows returned error: %v", err)
	}
	username := converted[0]["AccountName"].(string)
	if username == "USERNAME" {
		t.Fatal("AccountName was not pseudonymized")
	}
	upn := converted[0]["AccountUpn"].(string)
	if local, _, ok := strings.Cut(upn, "@"); !ok || local != username {
		t.Fatalf("UPN %q does not use account pseudonym %q", upn, username)
	}

	wantPaths := map[string]string{
		"FolderPath":                  `/Users/` + username + `/Library/Application Support/tool`,
		"InitiatingProcessFolderPath": `C:\Users\` + username + `\AppData\Local\tool.exe`,
		"ParentProcessFolderPath":     `/home/` + username + `/.config/tool`,
		"MixedSeparatorFolderPath":    `C:\Users/` + username + `/AppData/Local/tool.exe`,
	}
	for field, want := range wantPaths {
		if got := converted[0][field]; got != want {
			t.Fatalf("%s = %q, want %q", field, got, want)
		}
	}
}

func TestPseudonymizeRowsLinksSecurityEventAccountFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mappings.json")
	pseudonyms, err := newPseudonymizer(path)
	if err != nil {
		t.Fatalf("newPseudonymizer returned error: %v", err)
	}
	policy, err := newPseudonymFieldPolicy(defaultPseudonymFieldsForTable("DeviceProcessEvents"))
	if err != nil {
		t.Fatalf("create DeviceProcessEvents policy: %v", err)
	}
	if err := pseudonyms.ConfigureFieldPolicy(policy); err != nil {
		t.Fatalf("ConfigureFieldPolicy returned error: %v", err)
	}

	rows := []map[string]any{{
		"AccountDomain":                  "CONTOSO",
		"AccountName":                    "legacy-logon",
		"AccountUpn":                     "alice.vanpelt@corp.contoso.com",
		"InitiatingProcessAccountDomain": "CONTOSO",
		"InitiatingProcessAccountName":   "legacy-logon",
		"InitiatingProcessAccountUpn":    "alice.vanpelt@corp.contoso.com",
	}}
	converted, err := pseudonyms.PseudonymizeRows(context.Background(), rows)
	if err != nil {
		t.Fatalf("PseudonymizeRows returned error: %v", err)
	}

	account := converted[0]["AccountName"].(string)
	local, domain, ok := splitEmail(converted[0]["AccountUpn"].(string))
	if !ok || account != local {
		t.Fatalf("AccountName %q and AccountUpn local part %q do not represent one identity", account, local)
	}
	if got := converted[0]["AccountDomain"]; got != domain {
		t.Fatalf("AccountDomain %q does not match AccountUpn domain %q", got, domain)
	}
	if converted[0]["InitiatingProcessAccountName"] != account || converted[0]["InitiatingProcessAccountDomain"] != domain || converted[0]["InitiatingProcessAccountUpn"] != converted[0]["AccountUpn"] {
		t.Fatalf("initiating-process identity is not linked to account identity: %#v", converted[0])
	}

	if err := pseudonyms.Save(); err != nil {
		t.Fatalf("Save returned error: %v", err)
	}
	reloaded, err := newPseudonymizer(path)
	if err != nil {
		t.Fatalf("reload pseudonymizer: %v", err)
	}
	if err := reloaded.ConfigureFieldPolicy(policy); err != nil {
		t.Fatalf("ConfigureFieldPolicy after reload: %v", err)
	}
	again, err := reloaded.PseudonymizeRows(context.Background(), rows)
	if err != nil {
		t.Fatalf("PseudonymizeRows after reload returned error: %v", err)
	}
	firstBody, _ := json.Marshal(converted)
	againBody, _ := json.Marshal(again)
	if string(firstBody) != string(againBody) {
		t.Fatalf("linked identity changed after vault reload:\nfirst: %s\nagain: %s", firstBody, againBody)
	}
}

func TestPseudonymizeRowsRepairsExistingInconsistentIdentityMappings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mappings.json")
	pseudonyms, err := newPseudonymizer(path)
	if err != nil {
		t.Fatalf("newPseudonymizer returned error: %v", err)
	}
	policy, err := newPseudonymFieldPolicy(defaultPseudonymFieldsForTable("DeviceProcessEvents"))
	if err != nil {
		t.Fatalf("create DeviceProcessEvents policy: %v", err)
	}
	if err := pseudonyms.ConfigureFieldPolicy(policy); err != nil {
		t.Fatalf("ConfigureFieldPolicy returned error: %v", err)
	}

	// Simulate a vault created by the old value-only implementation.
	accountName := pseudonyms.replacement(entityUsername, "legacy-logon")
	accountDomain := pseudonyms.replacement(entityDomain, "CONTOSO")
	accountUPN := pseudonyms.replacement(entityEmail, "alice.vanpelt@corp.contoso.com")
	local, domain, ok := splitEmail(accountUPN)
	if !ok || (accountName == local && accountDomain == domain) {
		t.Fatalf("test setup did not create inconsistent legacy mappings: %q, %q, %q", accountName, accountDomain, accountUPN)
	}
	if err := pseudonyms.Save(); err != nil {
		t.Fatalf("save legacy mappings: %v", err)
	}

	rows := []map[string]any{{
		"AccountDomain":                  "CONTOSO",
		"AccountName":                    "legacy-logon",
		"AccountUpn":                     "alice.vanpelt@corp.contoso.com",
		"InitiatingProcessAccountDomain": "CONTOSO",
		"InitiatingProcessAccountName":   "legacy-logon",
		"InitiatingProcessAccountUpn":    "alice.vanpelt@corp.contoso.com",
	}}
	converted, err := pseudonyms.PseudonymizeRows(context.Background(), rows)
	if err != nil {
		t.Fatalf("PseudonymizeRows returned error: %v", err)
	}
	assertLinkedAccountFamily(t, converted[0], "")
	assertLinkedAccountFamily(t, converted[0], "InitiatingProcess")
	if converted[0]["AccountName"] != converted[0]["InitiatingProcessAccountName"] || converted[0]["AccountUpn"] != converted[0]["InitiatingProcessAccountUpn"] || converted[0]["AccountDomain"] != converted[0]["InitiatingProcessAccountDomain"] {
		t.Fatalf("identical source identities did not resolve to one identity set: %#v", converted[0])
	}

	if err := pseudonyms.Save(); err != nil {
		t.Fatalf("save repaired mappings: %v", err)
	}
	reloaded, err := newPseudonymizer(path)
	if err != nil {
		t.Fatalf("reload repaired mappings: %v", err)
	}
	if err := reloaded.ConfigureFieldPolicy(policy); err != nil {
		t.Fatalf("ConfigureFieldPolicy after reload: %v", err)
	}
	again, err := reloaded.PseudonymizeRows(context.Background(), rows)
	if err != nil {
		t.Fatalf("PseudonymizeRows after reload returned error: %v", err)
	}
	firstBody, _ := json.Marshal(converted)
	againBody, _ := json.Marshal(again)
	if string(firstBody) != string(againBody) {
		t.Fatalf("repaired identity changed after vault reload:\nfirst: %s\nagain: %s", firstBody, againBody)
	}
}

func TestPseudonymizeRowsKeepsDifferentAccountFamiliesInternallyCoherent(t *testing.T) {
	pseudonyms, err := newPseudonymizer(filepath.Join(t.TempDir(), "mappings.json"))
	if err != nil {
		t.Fatalf("newPseudonymizer returned error: %v", err)
	}
	rows := []map[string]any{{
		"AccountDomain":                  "CONTOSO",
		"AccountName":                    "interactive-logon",
		"AccountUpn":                     "alice@contoso.com",
		"InitiatingProcessAccountDomain": "FABRIKAM",
		"InitiatingProcessAccountName":   "service-logon",
		"InitiatingProcessAccountUpn":    "svc-agent@fabrikam.net",
	}}
	converted, err := pseudonyms.PseudonymizeRows(context.Background(), rows)
	if err != nil {
		t.Fatalf("PseudonymizeRows returned error: %v", err)
	}
	assertLinkedAccountFamily(t, converted[0], "")
	assertLinkedAccountFamily(t, converted[0], "InitiatingProcess")
	if converted[0]["AccountName"] == converted[0]["InitiatingProcessAccountName"] || converted[0]["AccountUpn"] == converted[0]["InitiatingProcessAccountUpn"] {
		t.Fatalf("different source identities were incorrectly merged: %#v", converted[0])
	}
}

func TestPseudonymizeRowsSynthesizesMissingUPNWithinIdentityFamily(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mappings.json")
	pseudonyms, err := newPseudonymizer(path)
	if err != nil {
		t.Fatalf("newPseudonymizer returned error: %v", err)
	}
	rows := []map[string]any{{
		"AccountDomain":                  "NT SERVICE",
		"AccountName":                    "SqlServerExtension",
		"AccountUpn":                     "",
		"InitiatingProcessAccountDomain": "NT SERVICE",
		"InitiatingProcessAccountName":   "SqlServerExtension",
		"InitiatingProcessAccountUpn":    "",
	}}
	converted, err := pseudonyms.PseudonymizeRows(context.Background(), rows)
	if err != nil {
		t.Fatalf("PseudonymizeRows returned error: %v", err)
	}
	assertLinkedAccountFamily(t, converted[0], "")
	assertLinkedAccountFamily(t, converted[0], "InitiatingProcess")
	if converted[0]["AccountUpn"] == "" || converted[0]["AccountUpn"] != converted[0]["InitiatingProcessAccountUpn"] {
		t.Fatalf("missing UPNs were not synthesized as one shared identity: %#v", converted[0])
	}

	if err := pseudonyms.Save(); err != nil {
		t.Fatalf("Save returned error: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read mapping vault: %v", err)
	}
	var vault pseudonymVault
	if err := json.Unmarshal(body, &vault); err != nil {
		t.Fatalf("decode mapping vault: %v", err)
	}
	for _, mapping := range vault.Mappings {
		if strings.TrimSpace(mapping.Original) == "" {
			t.Fatalf("synthesizing a missing identity component created a global empty mapping: %#v", mapping)
		}
	}

	reloaded, err := newPseudonymizer(path)
	if err != nil {
		t.Fatalf("reload mapping vault: %v", err)
	}
	again, err := reloaded.PseudonymizeRows(context.Background(), rows)
	if err != nil {
		t.Fatalf("PseudonymizeRows after reload returned error: %v", err)
	}
	firstBody, _ := json.Marshal(converted)
	againBody, _ := json.Marshal(again)
	if string(firstBody) != string(againBody) {
		t.Fatalf("synthesized identity changed after vault reload:\nfirst: %s\nagain: %s", firstBody, againBody)
	}
}

func TestPseudonymizeRowsSynthesizesSeparateMissingUPNsForDifferentIdentities(t *testing.T) {
	pseudonyms, err := newPseudonymizer(filepath.Join(t.TempDir(), "mappings.json"))
	if err != nil {
		t.Fatalf("newPseudonymizer returned error: %v", err)
	}
	rows := []map[string]any{{
		"AccountDomain":                  "CONTOSO",
		"AccountName":                    "interactive-logon",
		"AccountUpn":                     "",
		"InitiatingProcessAccountDomain": "CONTOSO",
		"InitiatingProcessAccountName":   "service-logon",
		"InitiatingProcessAccountUpn":    "",
	}}
	converted, err := pseudonyms.PseudonymizeRows(context.Background(), rows)
	if err != nil {
		t.Fatalf("PseudonymizeRows returned error: %v", err)
	}
	assertLinkedAccountFamily(t, converted[0], "")
	assertLinkedAccountFamily(t, converted[0], "InitiatingProcess")
	if converted[0]["AccountName"] == converted[0]["InitiatingProcessAccountName"] || converted[0]["AccountUpn"] == converted[0]["InitiatingProcessAccountUpn"] {
		t.Fatalf("different identities with missing UPNs were incorrectly merged: %#v", converted[0])
	}
	if converted[0]["AccountDomain"] != converted[0]["InitiatingProcessAccountDomain"] {
		t.Fatalf("shared source domain did not keep one pseudonymous domain: %#v", converted[0])
	}
}

func assertLinkedAccountFamily(t *testing.T, row map[string]any, prefix string) {
	t.Helper()
	accountName := row[prefix+"AccountName"].(string)
	local, domain, ok := splitEmail(row[prefix+"AccountUpn"].(string))
	if !ok || accountName != local || row[prefix+"AccountDomain"] != domain {
		t.Fatalf("%sAccount identity family is inconsistent: name=%q, UPN=%q, domain=%q", prefix, accountName, row[prefix+"AccountUpn"], row[prefix+"AccountDomain"])
	}
}

func TestPseudonymizeRowsLinksEmailAddressAndDomainFields(t *testing.T) {
	pseudonyms, err := newPseudonymizer(filepath.Join(t.TempDir(), "mappings.json"))
	if err != nil {
		t.Fatalf("newPseudonymizer returned error: %v", err)
	}
	policy, err := newPseudonymFieldPolicy(defaultPseudonymFieldsForTable("EmailEvents"))
	if err != nil {
		t.Fatalf("create EmailEvents policy: %v", err)
	}
	if err := pseudonyms.ConfigureFieldPolicy(policy); err != nil {
		t.Fatalf("ConfigureFieldPolicy returned error: %v", err)
	}
	rows := []map[string]any{{
		"SenderFromAddress":     "alice@corp.contoso.com",
		"SenderFromDomain":      "CONTOSO",
		"SenderMailFromAddress": "bounce-4711@mail.contoso.com",
		"SenderMailFromDomain":  "mail.contoso.com",
	}}
	converted, err := pseudonyms.PseudonymizeRows(context.Background(), rows)
	if err != nil {
		t.Fatalf("PseudonymizeRows returned error: %v", err)
	}
	_, fromDomain, ok := splitEmail(converted[0]["SenderFromAddress"].(string))
	if !ok || converted[0]["SenderFromDomain"] != fromDomain {
		t.Fatalf("sender From address/domain relationship was not preserved: %#v", converted[0])
	}
	_, mailFromDomain, ok := splitEmail(converted[0]["SenderMailFromAddress"].(string))
	if !ok || converted[0]["SenderMailFromDomain"] != mailFromDomain {
		t.Fatalf("sender MailFrom address/domain relationship was not preserved: %#v", converted[0])
	}
}

func TestPseudonymizeRowsLinksDeviceHostAndDomainFields(t *testing.T) {
	pseudonyms, err := newPseudonymizer(filepath.Join(t.TempDir(), "mappings.json"))
	if err != nil {
		t.Fatalf("newPseudonymizer returned error: %v", err)
	}
	configureAllPseudonymFields(t, pseudonyms)
	rows := []map[string]any{{
		"DeviceName":      "WS-0042",
		"DeviceFqdn":      "asset-9.corp.contoso.com",
		"DeviceDnsDomain": "CORP",
	}}
	converted, err := pseudonyms.PseudonymizeRows(context.Background(), rows)
	if err != nil {
		t.Fatalf("PseudonymizeRows returned error: %v", err)
	}
	host := converted[0]["DeviceName"].(string)
	fqdnHost, fqdnDomain := splitHostname(converted[0]["DeviceFqdn"].(string))
	if host != fqdnHost || converted[0]["DeviceDnsDomain"] != fqdnDomain {
		t.Fatalf("device host/domain relationship was not preserved: %#v", converted[0])
	}
}

func TestPseudonymizeRowsLinksDeviceFQDNToPrimaryAccountDomain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mappings.json")
	pseudonyms, err := newPseudonymizer(path)
	if err != nil {
		t.Fatalf("newPseudonymizer returned error: %v", err)
	}
	// Simulate independent legacy mappings for the account and device domains.
	pseudonyms.replacement(entityDomain, "CONTOSO")
	pseudonyms.replacement(entityHostname, "host-42.corp.contoso.com")
	if err := pseudonyms.Save(); err != nil {
		t.Fatalf("Save returned error: %v", err)
	}

	rows := []map[string]any{{
		"AccountDomain":                  "CONTOSO",
		"AccountName":                    "alice",
		"AccountUpn":                     "",
		"InitiatingProcessAccountDomain": "FABRIKAM",
		"InitiatingProcessAccountName":   "service-agent",
		"InitiatingProcessAccountUpn":    "",
		"DeviceName":                     "host-42.corp.contoso.com",
	}}
	converted, err := pseudonyms.PseudonymizeRows(context.Background(), rows)
	if err != nil {
		t.Fatalf("PseudonymizeRows returned error: %v", err)
	}
	_, deviceDomain := splitHostname(converted[0]["DeviceName"].(string))
	if deviceDomain == "" || converted[0]["AccountDomain"] != deviceDomain {
		t.Fatalf("DeviceName domain does not match primary AccountDomain: %#v", converted[0])
	}
	if converted[0]["InitiatingProcessAccountDomain"] == deviceDomain {
		t.Fatalf("DeviceName incorrectly used the secondary initiating-process domain: %#v", converted[0])
	}

	if err := pseudonyms.Save(); err != nil {
		t.Fatalf("save reconciled mappings: %v", err)
	}
	reloaded, err := newPseudonymizer(path)
	if err != nil {
		t.Fatalf("reload mappings: %v", err)
	}
	again, err := reloaded.PseudonymizeRows(context.Background(), rows)
	if err != nil {
		t.Fatalf("PseudonymizeRows after reload returned error: %v", err)
	}
	firstBody, _ := json.Marshal(converted)
	againBody, _ := json.Marshal(again)
	if string(firstBody) != string(againBody) {
		t.Fatalf("account/device domain relationship changed after reload:\nfirst: %s\nagain: %s", firstBody, againBody)
	}
}

func TestPseudonymizeRowsLeavesFilenamesUnchangedByDefault(t *testing.T) {
	pseudonyms, err := newPseudonymizer(filepath.Join(t.TempDir(), "mappings.json"))
	if err != nil {
		t.Fatalf("newPseudonymizer returned error: %v", err)
	}
	configureAllPseudonymFields(t, pseudonyms)

	rows := []map[string]any{{
		"FileName":                        "oscfg.exe",
		"FolderPath":                      `C:\ProgramData\GuestConfig\bin\oscfg.exe`,
		"ProcessCommandLine":              `"oscfg.exe" exec resource`,
		"InitiatingProcessFileName":       "gc_worker.exe",
		"InitiatingProcessFolderPath":     `C:\Program Files\AzureConnectedMachineAgent\GC\gc_worker.exe`,
		"InitiatingProcessCommandLine":    `"gc_worker.exe" -a AzureWindowsBaseline`,
		"InitiatingProcessParentFileName": "parent-agent.exe",
	}}

	converted, err := pseudonyms.PseudonymizeRows(context.Background(), rows)
	if err != nil {
		t.Fatalf("PseudonymizeRows returned error: %v", err)
	}

	for field, original := range rows[0] {
		if converted[0][field] != original {
			t.Errorf("%s changed by default from %q to %q", field, original, converted[0][field])
		}
	}
}

func TestPseudonymizeRowsLinksFilenamesAcrossPathsAndCommandLinesWhenEnabled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mappings.json")
	pseudonyms, err := newPseudonymizer(path)
	if err != nil {
		t.Fatalf("newPseudonymizer returned error: %v", err)
	}
	configureAllPseudonymFields(t, pseudonyms)
	pseudonyms.ConfigureFilenamePseudonymization(true)

	rows := []map[string]any{{
		"FileName":                           "oscfg.exe",
		"FolderPath":                         `C:\ProgramData\GuestConfig\Configuration\bin\oscfg.exe`,
		"ProcessCommandLine":                 `"oscfg.exe" exec oscfg myoscfg.exe oscfg.exe.config`,
		"InitiatingProcessFileName":          "gc_worker.exe",
		"InitiatingProcessFolderPath":        `C:\Program Files\AzureConnectedMachineAgent\GC\gc_worker.exe`,
		"InitiatingProcessCommandLine":       `"gc_worker.exe" -a gc_worker --keep gc_worker.exe.config`,
		"InitiatingProcessParentFileName":    "parent-agent.exe",
		"InitiatingProcessParentFolderPath":  `C:\Program Files\Company\parent-agent.exe`,
		"InitiatingProcessParentCommandLine": `parent-agent.exe --service parent-agent`,
	}, {
		"FileName":                     "shared.exe",
		"FolderPath":                   `C:\Tools\shared.exe`,
		"ProcessCommandLine":           `shared.exe run`,
		"InitiatingProcessFileName":    "shared.exe",
		"InitiatingProcessFolderPath":  `C:\Services\shared.exe`,
		"InitiatingProcessCommandLine": `shared run`,
	}}

	converted, err := pseudonyms.PseudonymizeRows(context.Background(), rows)
	if err != nil {
		t.Fatalf("PseudonymizeRows returned error: %v", err)
	}
	mainFilename := converted[0]["FileName"].(string)
	if mainFilename == "oscfg.exe" || !strings.HasPrefix(mainFilename, "file-") || !strings.HasSuffix(mainFilename, ".exe") {
		t.Fatalf("unexpected main filename replacement %q", mainFilename)
	}
	if got := converted[0]["FolderPath"].(string); !strings.HasSuffix(got, `\`+mainFilename) {
		t.Fatalf("FolderPath %q does not end in linked filename %q", got, mainFilename)
	}
	mainBase := strings.TrimSuffix(mainFilename, ".exe")
	wantMainCommand := `"` + mainFilename + `" exec ` + mainBase + ` myoscfg.exe oscfg.exe.config`
	if got := converted[0]["ProcessCommandLine"].(string); got != wantMainCommand {
		t.Fatalf("ProcessCommandLine = %q, want %q", got, wantMainCommand)
	}

	initiatingFilename := converted[0]["InitiatingProcessFileName"].(string)
	if initiatingFilename == "gc_worker.exe" || initiatingFilename == mainFilename {
		t.Fatalf("unexpected initiating filename replacement %q", initiatingFilename)
	}
	if got := converted[0]["InitiatingProcessFolderPath"].(string); !strings.HasSuffix(got, `\`+initiatingFilename) {
		t.Fatalf("InitiatingProcessFolderPath %q does not end in linked filename %q", got, initiatingFilename)
	}
	initiatingBase := strings.TrimSuffix(initiatingFilename, ".exe")
	wantInitiatingCommand := `"` + initiatingFilename + `" -a ` + initiatingBase + ` --keep gc_worker.exe.config`
	if got := converted[0]["InitiatingProcessCommandLine"].(string); got != wantInitiatingCommand {
		t.Fatalf("InitiatingProcessCommandLine = %q, want %q", got, wantInitiatingCommand)
	}

	parentFilename := converted[0]["InitiatingProcessParentFileName"].(string)
	if got := converted[0]["InitiatingProcessParentFolderPath"].(string); !strings.HasSuffix(got, `\`+parentFilename) {
		t.Fatalf("InitiatingProcessParentFolderPath %q does not end in linked filename %q", got, parentFilename)
	}
	parentBase := strings.TrimSuffix(parentFilename, ".exe")
	if got, want := converted[0]["InitiatingProcessParentCommandLine"].(string), parentFilename+" --service "+parentBase; got != want {
		t.Fatalf("InitiatingProcessParentCommandLine = %q, want %q", got, want)
	}

	if converted[1]["FileName"] != converted[1]["InitiatingProcessFileName"] {
		t.Fatalf("the same source filename received different process-family replacements: %q and %q", converted[1]["FileName"], converted[1]["InitiatingProcessFileName"])
	}

	if err := pseudonyms.Save(); err != nil {
		t.Fatalf("Save returned error: %v", err)
	}
	reloaded, err := newPseudonymizer(path)
	if err != nil {
		t.Fatalf("reload pseudonymizer: %v", err)
	}
	configureAllPseudonymFields(t, reloaded)
	reloaded.ConfigureFilenamePseudonymization(true)
	again, err := reloaded.PseudonymizeRows(context.Background(), rows)
	if err != nil {
		t.Fatalf("PseudonymizeRows after reload returned error: %v", err)
	}
	firstBody, _ := json.Marshal(converted)
	againBody, _ := json.Marshal(again)
	if string(firstBody) != string(againBody) {
		t.Fatalf("linked filenames changed after reload:\nfirst: %s\nagain: %s", firstBody, againBody)
	}
}

func TestPseudonymizeRowsPreservesGraphRelationshipsAndLabelContext(t *testing.T) {
	pseudonyms, err := newPseudonymizer(filepath.Join(t.TempDir(), "mappings.json"))
	if err != nil {
		t.Fatalf("newPseudonymizer returned error: %v", err)
	}
	configureAllPseudonymFields(t, pseudonyms)
	rows := []map[string]any{
		{"id": "device-123", "type": "Machine", "label": "CONTOSO-DC-01", "DeviceName": "CONTOSO-DC-01"},
		{"sourceId": "device-123", "targetId": "user-456", "type": "AuthenticatedTo"},
	}

	converted, err := pseudonyms.PseudonymizeRows(context.Background(), rows)
	if err != nil {
		t.Fatalf("PseudonymizeRows returned error: %v", err)
	}
	if converted[0]["id"] == "device-123" {
		t.Fatalf("node identifier was not pseudonymized")
	}
	if converted[0]["id"] != converted[1]["sourceId"] {
		t.Fatalf("edge source %q no longer matches node id %q", converted[1]["sourceId"], converted[0]["id"])
	}
	if converted[0]["label"] != converted[0]["DeviceName"] {
		t.Fatalf("machine label %q does not match device pseudonym %q", converted[0]["label"], converted[0]["DeviceName"])
	}
}

func TestEntityKindForFieldAvoidsEmailMetadataFalsePositives(t *testing.T) {
	tests := []struct {
		field string
		want  entityKind
	}{
		{field: "RecipientEmailAddress", want: entityEmail},
		{field: "SenderFromAddress", want: entityEmail},
		{field: "SenderMailFromAddress", want: entityEmail},
		{field: "AccountUpn", want: entityEmail},
		{field: "EmailSubject", want: ""},
		{field: "EmailDirection", want: ""},
		{field: "EmailClusterId", want: entityIdentifier},
		{field: "OrganizationId", want: entityIdentifier},
	}
	for _, tt := range tests {
		t.Run(tt.field, func(t *testing.T) {
			if got := entityKindForField(tt.field); got != tt.want {
				t.Fatalf("entityKindForField(%q) = %q, want %q", tt.field, got, tt.want)
			}
		})
	}
}

func TestPhoneRecognitionRejectsDatesAndSoftwareVersions(t *testing.T) {
	value := "Versions 10.8831.19045.6466 and 10.0.22631.4751 shipped on 2026-06-23 and 24-07-2026; call +31 (0)20 123-4567."
	entities := recognizePatternEntities(value)
	phones := make([]string, 0)
	for _, entity := range entities {
		if entity.Kind == entityPhone {
			phones = append(phones, entity.Text)
		}
	}
	if len(phones) != 1 || !strings.Contains(phones[0], "20 123-4567") {
		t.Fatalf("recognized phone entities = %#v, want only the formatted phone number", phones)
	}
	for _, falsePositive := range []string{"10.8831.19045.6466", "10.0.22631.4751", "2026-06-23", "24-07-2026"} {
		if isLikelyPhoneNumber(falsePositive) {
			t.Fatalf("isLikelyPhoneNumber(%q) = true", falsePositive)
		}
	}
}

func TestPseudonymizeRowsPreservesDatesAndSoftwareVersions(t *testing.T) {
	pseudonyms, err := newPseudonymizer(filepath.Join(t.TempDir(), "mappings.json"))
	if err != nil {
		t.Fatalf("newPseudonymizer returned error: %v", err)
	}
	configureAllPseudonymFields(t, pseudonyms)
	rows := []map[string]any{{
		"OSVersion":   "10.8831.19045.6466",
		"ReleaseDate": "2026-07-24",
		"Message":     "Released 10.8831.19045.6466 on 2026-07-24. Call +31 (0)20 123-4567 for support.",
	}}

	converted, err := pseudonyms.PseudonymizeRows(context.Background(), rows)
	if err != nil {
		t.Fatalf("PseudonymizeRows returned error: %v", err)
	}
	if got := converted[0]["OSVersion"]; got != rows[0]["OSVersion"] {
		t.Fatalf("OSVersion = %q, want unchanged %q", got, rows[0]["OSVersion"])
	}
	if got := converted[0]["ReleaseDate"]; got != rows[0]["ReleaseDate"] {
		t.Fatalf("ReleaseDate = %q, want unchanged %q", got, rows[0]["ReleaseDate"])
	}
	message := converted[0]["Message"].(string)
	if !strings.Contains(message, "10.8831.19045.6466") || !strings.Contains(message, "2026-07-24") {
		t.Fatalf("version or date changed in message: %q", message)
	}
	if strings.Contains(message, "20 123-4567") {
		t.Fatalf("actual phone number was not pseudonymized: %q", message)
	}
}

func TestFinalizePseudonymMapRetention(t *testing.T) {
	t.Run("keep", func(t *testing.T) {
		pseudonyms, err := newPseudonymizer(filepath.Join(t.TempDir(), "mappings.json"))
		if err != nil {
			t.Fatalf("newPseudonymizer returned error: %v", err)
		}
		kept, err := finalizePseudonymMap(pseudonyms, "keep")
		if err != nil || !kept {
			t.Fatalf("finalizePseudonymMap() = %v, %v; want kept", kept, err)
		}
		if _, err := os.Stat(pseudonyms.Path()); err != nil {
			t.Fatalf("kept mapping file is missing: %v", err)
		}
	})

	t.Run("delete", func(t *testing.T) {
		pseudonyms, err := newPseudonymizer(filepath.Join(t.TempDir(), "mappings.json"))
		if err != nil {
			t.Fatalf("newPseudonymizer returned error: %v", err)
		}
		kept, err := finalizePseudonymMap(pseudonyms, "delete")
		if err != nil || kept {
			t.Fatalf("finalizePseudonymMap() = %v, %v; want deleted", kept, err)
		}
		if _, err := os.Stat(pseudonyms.Path()); !os.IsNotExist(err) {
			t.Fatalf("mapping file still exists after delete: %v", err)
		}
	})
}

func configureAllPseudonymFields(t *testing.T, pseudonyms *pseudonymizer) {
	t.Helper()
	policy, err := newPseudonymFieldPolicy("*")
	if err != nil {
		t.Fatalf("newPseudonymFieldPolicy returned error: %v", err)
	}
	if err := pseudonyms.ConfigureFieldPolicy(policy); err != nil {
		t.Fatalf("ConfigureFieldPolicy returned error: %v", err)
	}
}
