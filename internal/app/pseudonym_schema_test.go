package app

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func schemaTestPseudonymizer(t *testing.T, table string, irreversible bool) *pseudonymizer {
	t.Helper()
	p, err := openPseudonymizer(filepath.Join(t.TempDir(), "vault.json"), irreversible)
	if err != nil {
		t.Fatal(err)
	}
	schemaTestPolicy(t, p, table)
	return p
}

func schemaTestPolicy(t *testing.T, p *pseudonymizer, table string) {
	t.Helper()
	policy, err := newPseudonymFieldPolicy(defaultPseudonymFieldsForTable(table))
	if err != nil {
		t.Fatal(err)
	}
	if err := p.ConfigureFieldPolicy(policy); err != nil {
		t.Fatal(err)
	}
}

func schemaTestRoundTrip(t *testing.T, p *pseudonymizer, table string, rows []map[string]any) []map[string]any {
	t.Helper()
	out, err := p.PseudonymizeRows(context.Background(), rows)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Save(); err != nil {
		t.Fatal(err)
	}
	reloaded, err := newPseudonymizer(p.Path())
	if err != nil {
		t.Fatal(err)
	}
	schemaTestPolicy(t, reloaded, table)
	reloaded.ConfigureFilenamePseudonymization(p.filenamesEnabled())
	again, err := reloaded.PseudonymizeRows(context.Background(), rows)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(out, again) {
		t.Fatalf("values changed after reload:\n%#v\n%#v", out, again)
	}
	if p.Irreversible() {
		body, err := os.ReadFile(p.Path())
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(body), `"original":`) {
			t.Fatal("irreversible vault contains originals")
		}
	}
	return out
}

func TestFullSchemaPolicyAdditions(t *testing.T) {
	for table, fields := range map[string][]string{
		"IdentityInfo":        {"AccountDisplayName", "GivenName", "Surname", "Address", "Phone", "Manager", "CompanyName", "EmployeeId", "DistinguishedName", "SipProxyAddress", "OtherMailAddresses"},
		"IdentityAccountInfo": {"DisplayName", "AccountId", "AccountUpn", "EmailAddress"},
		"IdentityLogonEvents": {"AccountDisplayName", "TargetAccountDisplayName"},
		"EmailEvents":         {"SenderDisplayName", "To", "Cc", "DistributionList"},
		"EmailAttachmentInfo": {"SenderDisplayName"},
		"MessageEvents":       {"SenderDisplayName"},
		"AIAgentsInfo":        {"OwnerAccountUpns"},
		"ASimEmailEventLogs":  {"EmailFromAddress", "EmailReplyToAddress", "EmailToRecipients", "EmailCCRecipients", "EmailBCCRecipients"},
		"BehaviorAnalytics":   {"ActorName", "ActorPrincipalName", "TargetName", "TargetPrincipalName"},
		"SigninLogs":          {"AlternateSignInName", "UserDisplayName"},
		"CloudDnsEvents":      {"DnsQuery", "ProcessName"},
		"ASimDnsActivityLogs": {"DnsQuery"},
		"DeviceFileEvents":    {"FileOriginUrl", "FileOriginReferrerUrl"},
		"EmailUrlInfo":        {"Url"}, "UrlClickEvents": {"Url", "UrlChain"},
		"CloudKeyVaultEvents": {"RequestUri"}, "CommonSecurityLog": {"RequestURL", "ProcessName"},
	} {
		p, err := newPseudonymFieldPolicy(defaultPseudonymFieldsForTable(table))
		if err != nil {
			t.Fatal(err)
		}
		for _, field := range fields {
			if !p.Matches(field) {
				t.Errorf("%s.%s is not selected", table, field)
			}
		}
		for _, field := range []string{"ActivityDisplayName", "ResourceDisplayName", "AccountIdType", "UsernameType", "UrlLocation", "UrlCount", "RequestUriLength", "ActorScope", "RemoteIP", "AccountSid", "DeviceId", "ProcessCommandLine"} {
			if p.Matches(field) {
				t.Errorf("metadata %s.%s is selected", table, field)
			}
		}
	}
	for _, field := range []string{"DisplayName", "AccountId", "Address", "Phone", "To", "Cc", "Url"} {
		p, _ := newPseudonymFieldPolicy(defaultPseudonymFieldsForTable("UnknownTable"))
		if p.Matches(field) {
			t.Errorf("ambiguous fallback selects %s", field)
		}
	}
}

func TestFullSchemaIdentityComponentsStayLinked(t *testing.T) {
	for _, irreversible := range []bool{false, true} {
		p := schemaTestPseudonymizer(t, "IdentityInfo", irreversible)
		rows := []map[string]any{{
			"AccountName": "asmith", "AccountDisplayName": "Alice Smith", "GivenName": "Alice", "Surname": "Smith",
			"AccountUpn": "alice.smith@contoso.com", "EmailAddress": "alice@contoso.com",
			"OtherMailAddresses": []any{"alias@contoso.com", "another@fabrikam.com"},
			"DistinguishedName":  `CN=Smith\, Alice,OU=Finance,DC=contoso,DC=com`,
			"SipProxyAddress":    "sip:alice@contoso.com", "Phone": "+31 20 123 4567",
			"Address": "1 Secret Street", "Manager": "Bob Jones", "CompanyName": "Contoso", "EmployeeId": "EMP-123",
			"AccountSid": "S-1-5-21-123-456-789-1000", "TenantId": "tenant-123",
		}}
		out := schemaTestRoundTrip(t, p, "IdentityInfo", rows)[0]
		if out["AccountDisplayName"] != out["GivenName"].(string)+" "+out["Surname"].(string) {
			t.Fatalf("name components disagree: %#v", out)
		}
		for _, email := range append([]string{out["AccountUpn"].(string), out["EmailAddress"].(string)}, mailboxEmails(out["OtherMailAddresses"])...) {
			local, _, _ := splitEmail(email)
			if local != out["AccountName"] {
				t.Fatalf("alias %q is not linked to %q", email, out["AccountName"])
			}
		}
		if out["SipProxyAddress"] != "sip:"+out["EmailAddress"].(string) {
			t.Fatalf("SIP alias disagrees: %#v", out)
		}
		if !strings.Contains(out["DistinguishedName"].(string), "CN="+out["AccountDisplayName"].(string)) {
			t.Fatalf("DN common name is not linked: %v", out["DistinguishedName"])
		}
		for _, field := range []string{"Phone", "Address", "Manager", "CompanyName", "EmployeeId"} {
			if out[field] == rows[0][field] {
				t.Errorf("%s unchanged", field)
			}
		}
		for _, field := range []string{"AccountSid", "TenantId"} {
			if out[field] != rows[0][field] {
				t.Errorf("%s changed", field)
			}
		}
		if out["Manager"] == out["AccountDisplayName"] {
			t.Fatal("manager was merged into account")
		}
	}
}

func TestFullSchemaRecipientCollectionsKeepDistinctIdentities(t *testing.T) {
	for _, irreversible := range []bool{false, true} {
		p := schemaTestPseudonymizer(t, "EmailEvents", irreversible)
		rows := []map[string]any{{
			"SenderFromAddress": "alice@contoso.com", "SenderDisplayName": "Alice Smith",
			"RecipientEmailAddress": "bob@contoso.com",
			"To":                    []any{"alice@contoso.com", "bob@contoso.com", map[string]any{"Address": "carol@contoso.com", "Name": "Carol Jones", "Count": 3}, `"Carol Jones" <carol@contoso.com>`},
			"Cc":                    `["bob@contoso.com", {"EmailAddress":"carol@contoso.com","DisplayName":"Carol Jones","Count":3}]`,
			"DistributionList":      "Engineering",
		}}
		out := schemaTestRoundTrip(t, p, "EmailEvents", rows)[0]
		to := out["To"].([]any)
		if to[0] != out["SenderFromAddress"] || to[1] != out["RecipientEmailAddress"] || to[0] == to[1] {
			t.Fatalf("recipients merged or unlinked: %#v", out)
		}
		carol := to[2].(map[string]any)
		local, _, _ := splitEmail(carol["Address"].(string))
		if local != usernameFromDisplayName(carol["Name"].(string)) || carol["Count"] != 3 {
			t.Fatalf("mailbox object corrupted: %#v", carol)
		}
		if got, want := to[3], `"`+carol["Name"].(string)+`" <`+carol["Address"].(string)+`>`; got != want {
			t.Fatalf("mailbox display form = %q, want %q", got, want)
		}
		var cc []any
		if err := json.Unmarshal([]byte(out["Cc"].(string)), &cc); err != nil {
			t.Fatal(err)
		}
		if cc[0] != to[1] || cc[1].(map[string]any)["EmailAddress"] != carol["Address"] {
			t.Fatalf("CC addresses disagree: %#v", out)
		}
		local, _, _ = splitEmail(out["SenderFromAddress"].(string))
		if local != usernameFromDisplayName(out["SenderDisplayName"].(string)) {
			t.Fatal("sender display name disagrees")
		}
	}
}

func TestFullSchemaAccountIdsAndAlternateLogins(t *testing.T) {
	p := schemaTestPseudonymizer(t, "CloudAppEvents", false)
	rows := []map[string]any{
		{"AccountId": "alice@contoso.com", "AccountDisplayName": "Alice Smith"},
		{"AccountId": "bsmith", "AccountDisplayName": "Bob Smith"},
		{"AccountId": "80110e3c-3ec4-4567-b06d-7d47a72562f5"},
	}
	out := schemaTestRoundTrip(t, p, "CloudAppEvents", rows)
	local, _, _ := splitEmail(out[0]["AccountId"].(string))
	if local != usernameFromDisplayName(out[0]["AccountDisplayName"].(string)) {
		t.Fatal("UPN AccountId is not linked")
	}
	if out[1]["AccountId"] != usernameFromDisplayName(out[1]["AccountDisplayName"].(string)) {
		t.Fatal("SAM AccountId is not linked")
	}
	if !isExactGUID(out[2]["AccountId"].(string)) || out[2]["AccountId"] == rows[2]["AccountId"] {
		t.Fatal("GUID AccountId was not pseudonymized as an identifier")
	}
	p = schemaTestPseudonymizer(t, "SigninLogs", false)
	out = schemaTestRoundTrip(t, p, "SigninLogs", []map[string]any{{"UserPrincipalName": "alice@contoso.com", "UserDisplayName": "Alice Smith", "AlternateSignInName": "asmith"}})
	local, _, _ = splitEmail(out[0]["UserPrincipalName"].(string))
	if local != out[0]["AlternateSignInName"] {
		t.Fatal("alternate sign-in name is not linked")
	}
}

func TestFullSchemaURLsDNSAndProcessNames(t *testing.T) {
	p := schemaTestPseudonymizer(t, "DeviceFileEvents", false)
	url := "https://portal.contoso.com/path/original.txt?id=80110e3c-3ec4-4567-b06d-7d47a72562f5"
	out := schemaTestRoundTrip(t, p, "DeviceFileEvents", []map[string]any{{"FileOriginUrl": url, "FileOriginReferrerUrl": url, "UrlDomain": "portal.contoso.com", "RemoteIP": "10.1.2.3"}})[0]
	if out["FileOriginUrl"] != out["FileOriginReferrerUrl"] || !strings.Contains(out["FileOriginUrl"].(string), out["UrlDomain"].(string)) {
		t.Fatal("URL fields disagree")
	}
	if strings.Contains(out["FileOriginUrl"].(string), "portal.contoso.com") || !strings.HasSuffix(out["FileOriginUrl"].(string), "/path/original.txt?id=80110e3c-3ec4-4567-b06d-7d47a72562f5") {
		t.Fatalf("URL structure changed: %v", out)
	}
	p = schemaTestPseudonymizer(t, "CloudDnsEvents", false)
	p.ConfigureFilenamePseudonymization(true)
	out = schemaTestRoundTrip(t, p, "CloudDnsEvents", []map[string]any{{"DnsQuery": "portal.contoso.com", "ProcessName": "secret.exe", "ProcessCommandLine": "secret.exe --query portal.contoso.com"}})[0]
	if out["DnsQuery"] == "portal.contoso.com" || out["ProcessName"] == "secret.exe" || !strings.HasPrefix(out["ProcessCommandLine"].(string), out["ProcessName"].(string)+" ") {
		t.Fatalf("DNS/process fields not linked: %#v", out)
	}
}

func TestFullSchemaActorNamesAndGraphNames(t *testing.T) {
	p := schemaTestPseudonymizer(t, "OktaSystemLogs", false)
	out := schemaTestRoundTrip(t, p, "OktaSystemLogs", []map[string]any{{"ActorUsername": "asmith", "ActorDisplayName": "Alice Smith"}})[0]
	if out["ActorUsername"] != usernameFromDisplayName(out["ActorDisplayName"].(string)) {
		t.Fatalf("actor fields disagree: %#v", out)
	}
	p = schemaTestPseudonymizer(t, "ExposureGraphNodes", false)
	rows := []map[string]any{{"NodeId": "node-1", "NodeLabel": "User", "NodeName": "Alice Smith", "Type": "ExposureGraphNodes"}}
	out = schemaTestRoundTrip(t, p, "ExposureGraphNodes", rows)[0]
	if out["NodeId"] != "node-1" || out["NodeName"] == "Alice Smith" {
		t.Fatalf("node identity not protected: %#v", out)
	}
	schemaTestPolicy(t, p, "ExposureGraphEdges")
	edges := schemaTestRoundTrip(t, p, "ExposureGraphEdges", []map[string]any{{"SourceNodeId": "node-1", "SourceNodeLabel": "User", "SourceNodeName": "Alice Smith", "TargetNodeId": "node-2", "TargetNodeLabel": "Device", "TargetNodeName": "pc-123"}})[0]
	if edges["SourceNodeName"] != out["NodeName"] || edges["SourceNodeId"] != out["NodeId"] || edges["TargetNodeName"] == "pc-123" {
		t.Fatalf("graph names not linked: %#v", edges)
	}
}

func TestFullSchemaPartialNamesDoNotMergeAccounts(t *testing.T) {
	p := schemaTestPseudonymizer(t, "IdentityInfo", false)
	rows := []map[string]any{{"AccountName": "alice.one", "GivenName": "Alice"}, {"AccountName": "alice.two", "GivenName": "Alice"}}
	out := schemaTestRoundTrip(t, p, "IdentityInfo", rows)
	if out[0]["AccountName"] == out[1]["AccountName"] {
		t.Fatal("accounts with the same given name merged")
	}
	for _, row := range out {
		if row["GivenName"] != strings.Fields(displayNameFromUsername(row["AccountName"].(string)))[0] {
			t.Fatalf("partial name not linked: %#v", row)
		}
	}
}

func TestFullSchemaDirectoryEscapesAndExplicitScope(t *testing.T) {
	p := schemaTestPseudonymizer(t, "IdentityInfo", false)
	rows := []map[string]any{
		{"AccountName": "asmith", "DistinguishedName": `CN=Smith\2C Alice+UID=asmith,OU=People,DC=contoso,DC=com`},
		{"AccountName": "asmith", "DistinguishedName": `CN=Smith\, Alice+UID=asmith,OU=People,DC=contoso,DC=com`},
		{"DistinguishedName": `CN=Alice,OU=bad\`},
	}
	out := schemaTestRoundTrip(t, p, "IdentityInfo", rows)
	if out[0]["DistinguishedName"] != out[1]["DistinguishedName"] || !strings.Contains(out[0]["DistinguishedName"].(string), "+UID="+out[0]["AccountName"].(string)) {
		t.Fatalf("DN escape/UID aliases disagree: %#v", out)
	}
	if !strings.HasPrefix(out[2]["DistinguishedName"].(string), "id-") {
		t.Fatal("invalid DN did not receive opaque replacement")
	}
	policy, err := newPseudonymFieldPolicy("Phone")
	if err != nil {
		t.Fatal(err)
	}
	if err := p.ConfigureFieldPolicy(policy); err != nil {
		t.Fatal(err)
	}
	row := map[string]any{"AccountDisplayName": "Alice Smith", "GivenName": "Alice", "OtherMailAddresses": []any{"alice@contoso.com"}, "Phone": "+31 20 123 4567"}
	out, err = p.PseudonymizeRows(context.Background(), []map[string]any{row})
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"AccountDisplayName", "GivenName", "OtherMailAddresses"} {
		if !reflect.DeepEqual(out[0][field], row[field]) {
			t.Fatalf("explicit override changed %s", field)
		}
	}
	if out[0]["Phone"] == row["Phone"] {
		t.Fatal("selected phone unchanged")
	}
}
