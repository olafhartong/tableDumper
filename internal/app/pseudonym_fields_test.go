package app

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultPseudonymFieldPolicyUsesAnAllowlist(t *testing.T) {
	policy, err := newPseudonymFieldPolicy(defaultPseudonymFieldsForTable("DeviceProcessEvents"))
	if err != nil {
		t.Fatalf("newPseudonymFieldPolicy returned error: %v", err)
	}
	for _, field := range []string{
		"AccountName", "InitiatingProcessAccountName", "AccountUpn", "FileName",
		"InitiatingProcessFileName", "DomainName", "AccountDomain", "DeviceName",
		"ComputerName", "InitiatingProcessFolderPath", "AzureResourceId",
	} {
		if !policy.Matches(field) {
			t.Errorf("default policy does not match %q", field)
		}
	}
	for _, field := range []string{
		"NamedPipeName", "Timestamp", "UnixTimestamp", "OSVersion", "ProcessCommandLine",
		"Message", "RemoteIP", "AccountSid", "DeviceId", "ReportId",
	} {
		if policy.Matches(field) {
			t.Errorf("default policy unexpectedly matches %q", field)
		}
	}
}

func TestBuiltInPseudonymPoliciesAreTableSpecific(t *testing.T) {
	processPolicy, err := newPseudonymFieldPolicy(defaultPseudonymFieldsForTable("DeviceProcessEvents"))
	if err != nil {
		t.Fatalf("create DeviceProcessEvents policy: %v", err)
	}
	deviceInfoPolicy, err := newPseudonymFieldPolicy(defaultPseudonymFieldsForTable("DeviceInfo"))
	if err != nil {
		t.Fatalf("create DeviceInfo policy: %v", err)
	}
	emailPolicy, err := newPseudonymFieldPolicy(defaultPseudonymFieldsForTable("EmailEvents"))
	if err != nil {
		t.Fatalf("create EmailEvents policy: %v", err)
	}

	if !processPolicy.Matches("InitiatingProcessFileName") || !processPolicy.Matches("InitiatingProcessAccountName") {
		t.Fatal("DeviceProcessEvents policy is missing process identity fields")
	}
	if !deviceInfoPolicy.Matches("DeviceName") || deviceInfoPolicy.Matches("FileName") || deviceInfoPolicy.Matches("AccountName") {
		t.Fatal("DeviceInfo policy is not limited to device/domain/resource fields")
	}
	if !emailPolicy.Matches("SenderFromAddress") || !emailPolicy.Matches("SenderMailFromAddress") || !emailPolicy.Matches("SenderFromDomain") || emailPolicy.Matches("AccountName") || emailPolicy.Matches("NamedPipeName") {
		t.Fatal("EmailEvents policy is not limited to domain fields")
	}
}

func TestSchemaDerivedFieldNamesAreCoveredConservatively(t *testing.T) {
	policy, err := newPseudonymFieldPolicy(defaultPseudonymFieldsForTable("ASimProcessEventLogs"))
	if err != nil {
		t.Fatalf("create schema-derived policy: %v", err)
	}
	for _, field := range []string{
		"UserPrincipal", "HomeDirectory", "ProfilePath", "FilePath", "SrcFileDirectory",
		"TargetProcessFileInternalName", "DstDvcFqdn", "Computer", "ResourceGroup",
		"AccountName_s", "File_FileName_s", "WorkspaceResourceGroup",
		"ActingProcessName", "ParentProcessName",
	} {
		if !policy.Matches(field) {
			t.Errorf("schema-derived policy does not match %q", field)
		}
	}
	for _, field := range []string{
		"NamedPipeName", "UnixTimestamp", "OSVersion", "DvcScopeId", "UsernameType",
		"ProcessCommandLine", "FileHash", "ActorScope",
	} {
		if policy.Matches(field) {
			t.Errorf("schema-derived policy unexpectedly matches %q", field)
		}
	}
}

func TestAmbiguousSchemaFieldsRemainTableScoped(t *testing.T) {
	tests := []struct {
		table string
		field string
		want  bool
	}{
		{table: "DnsAuditEvents", field: "Name", want: true},
		{table: "AppMetrics", field: "Name", want: false},
		{table: "OfficeActivity", field: "UserId", want: true},
		{table: "AppRequests", field: "UserId", want: false},
		{table: "SecurityEvent", field: "TargetAccount", want: true},
		{table: "AWSVPCFlow", field: "AccountId", want: false},
		{table: "AlertEvidence", field: "RemoteUrl", want: true},
		{table: "AppRequests", field: "RemoteUrl", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.table+"/"+tt.field, func(t *testing.T) {
			policy, err := newPseudonymFieldPolicy(defaultPseudonymFieldsForTable(tt.table))
			if err != nil {
				t.Fatalf("create %s policy: %v", tt.table, err)
			}
			if got := policy.Matches(tt.field); got != tt.want {
				t.Fatalf("policy.Matches(%q) = %v, want %v", tt.field, got, tt.want)
			}
		})
	}
}

func TestPseudonymFieldPolicySupportsExactNamesAndWildcards(t *testing.T) {
	policy, err := newPseudonymFieldPolicy(" Account_Name, FileName_s, InitiatingProcess*Name, *FolderPath ")
	if err != nil {
		t.Fatalf("newPseudonymFieldPolicy returned error: %v", err)
	}
	for _, field := range []string{"AccountName", "FileName_s", "InitiatingProcessFileName", "InitiatingProcessAccountName", "FolderPath"} {
		if !policy.Matches(field) {
			t.Errorf("policy does not match %q", field)
		}
	}
	if policy.Matches("NamedPipeName") {
		t.Fatal("policy unexpectedly matches NamedPipeName")
	}
}

func TestPseudonymFieldPolicyRejectsAmbiguousPatterns(t *testing.T) {
	for _, value := range []string{"", "AccountName,,FileName", "Account[Name"} {
		if _, err := newPseudonymFieldPolicy(value); err == nil {
			t.Errorf("newPseudonymFieldPolicy(%q) unexpectedly succeeded", value)
		}
	}
}

func TestDefaultFieldScopeLeavesUnselectedDataUntouched(t *testing.T) {
	pseudonyms, err := newPseudonymizer(filepath.Join(t.TempDir(), "mappings.json"))
	if err != nil {
		t.Fatalf("newPseudonymizer returned error: %v", err)
	}
	pseudonyms.ConfigureFilenamePseudonymization(true)
	rows := []map[string]any{{
		"AccountName":                 "alice",
		"FileName":                    "confidential-report.docx",
		"DomainName":                  "corp.contoso.com",
		"DeviceName":                  "CONTOSO-WS-42",
		"InitiatingProcessFolderPath": `C:\Users\alice\Documents`,
		"NamedPipeName":               `\Device\NamedPipe\Winsock2\CatalogChangeListener-123-0`,
		"UnixTimestamp":               "1712345678",
		"Timestamp":                   "2026-07-24",
		"OSVersion":                   "10.8831.19045.6466",
		"ProcessCommandLine":          `tool.exe --pipe \.\pipe\contoso.com --user alice`,
		"AdditionalFields":            `{"AccountName":"nested-alice","FileName":"nested-secret.txt"}`,
		"RemoteIP":                    "10.2.3.4",
		"DeviceId":                    "80110e3c-3ec4-4567-b06d-7d47a72562f5",
	}}

	converted, err := pseudonyms.PseudonymizeRows(context.Background(), rows)
	if err != nil {
		t.Fatalf("PseudonymizeRows returned error: %v", err)
	}
	for _, field := range []string{"NamedPipeName", "UnixTimestamp", "Timestamp", "OSVersion", "AdditionalFields", "RemoteIP", "DeviceId"} {
		if converted[0][field] != rows[0][field] {
			t.Errorf("unselected %s changed from %q to %q", field, rows[0][field], converted[0][field])
		}
	}
	if got, want := converted[0]["ProcessCommandLine"], `tool.exe --pipe \.\pipe\contoso.com --user ***`; got != want {
		t.Errorf("ProcessCommandLine = %q, want credential-masked %q", got, want)
	}
	for _, field := range []string{"AccountName", "FileName", "DomainName", "DeviceName"} {
		if converted[0][field] == rows[0][field] {
			t.Errorf("selected %s was not pseudonymized", field)
		}
	}
	if got := converted[0]["FileName"].(string); !strings.HasSuffix(got, ".docx") {
		t.Errorf("filename extension was not preserved: %q", got)
	}
	username := converted[0]["AccountName"].(string)
	if got := converted[0]["InitiatingProcessFolderPath"].(string); !strings.Contains(got, `\Users\`+username+`\`) {
		t.Errorf("folder path %q does not use account pseudonym %q", got, username)
	}
}

func TestSchemaDerivedFieldsArePseudonymized(t *testing.T) {
	pseudonyms, err := newPseudonymizer(filepath.Join(t.TempDir(), "mappings.json"))
	if err != nil {
		t.Fatalf("newPseudonymizer returned error: %v", err)
	}
	policy, err := newPseudonymFieldPolicy(defaultPseudonymFieldsForTable("SecurityEvent"))
	if err != nil {
		t.Fatalf("create SecurityEvent policy: %v", err)
	}
	if err := pseudonyms.ConfigureFieldPolicy(policy); err != nil {
		t.Fatalf("ConfigureFieldPolicy returned error: %v", err)
	}
	pseudonyms.ConfigureFilenamePseudonymization(true)
	rows := []map[string]any{{
		"AccountName":        "alice",
		"UserPrincipal":      "alice@example.com",
		"HomeDirectory":      `C:\Users\alice`,
		"FilePath":           `C:\Users\alice\Documents\quarterly-plan.docx`,
		"Computer":           "workstation-42",
		"ResourceGroup":      "production-payroll",
		"File_FileName_s":    "customer-list.csv",
		"NamedPipeName":      `\Device\NamedPipe\Winsock2\CatalogChangeListener-123-0`,
		"UnixTimestamp":      "1712345678",
		"ProcessCommandLine": `tool.exe --input customer-list.csv`,
	}}

	converted, err := pseudonyms.PseudonymizeRows(context.Background(), rows)
	if err != nil {
		t.Fatalf("PseudonymizeRows returned error: %v", err)
	}
	for _, field := range []string{"AccountName", "UserPrincipal", "HomeDirectory", "FilePath", "Computer", "ResourceGroup", "File_FileName_s"} {
		if converted[0][field] == rows[0][field] {
			t.Errorf("schema-derived field %s was not pseudonymized", field)
		}
	}
	for _, field := range []string{"NamedPipeName", "UnixTimestamp", "ProcessCommandLine"} {
		if converted[0][field] != rows[0][field] {
			t.Errorf("out-of-scope field %s changed", field)
		}
	}
	if got := converted[0]["FilePath"].(string); !strings.HasSuffix(got, ".docx") || strings.Contains(got, "quarterly-plan") {
		t.Errorf("file path was not structurally pseudonymized: %q", got)
	}
}

func TestSchemaDomainFieldsOnlyChangeDomainData(t *testing.T) {
	pseudonyms, err := newPseudonymizer(filepath.Join(t.TempDir(), "mappings.json"))
	if err != nil {
		t.Fatalf("newPseudonymizer returned error: %v", err)
	}
	policy, err := newPseudonymFieldPolicy(defaultPseudonymFieldsForTable("AlertEvidence"))
	if err != nil {
		t.Fatalf("create AlertEvidence policy: %v", err)
	}
	if err := pseudonyms.ConfigureFieldPolicy(policy); err != nil {
		t.Fatalf("ConfigureFieldPolicy returned error: %v", err)
	}
	resourceID := "80110e3c-3ec4-4567-b06d-7d47a72562f5"
	originalURL := "https://portal.example.com/resources/" + resourceID + "?version=10.8831.19045.6466"
	rows := []map[string]any{{
		"RemoteUrl": originalURL,
		"RemoteIP":  "10.2.3.4",
	}}

	converted, err := pseudonyms.PseudonymizeRows(context.Background(), rows)
	if err != nil {
		t.Fatalf("PseudonymizeRows returned error: %v", err)
	}
	url := converted[0]["RemoteUrl"].(string)
	if url == originalURL || strings.Contains(url, "portal.example.com") {
		t.Fatalf("RemoteUrl domain was not pseudonymized: %q", url)
	}
	if !strings.Contains(url, resourceID) || !strings.Contains(url, "10.8831.19045.6466") {
		t.Fatalf("RemoteUrl non-domain data changed: %q", url)
	}
	if converted[0]["RemoteIP"] != rows[0]["RemoteIP"] {
		t.Fatalf("unselected RemoteIP changed to %q", converted[0]["RemoteIP"])
	}
}

func TestSchemaHostnameFieldLeavesIPAddressUntouched(t *testing.T) {
	pseudonyms, err := newPseudonymizer(filepath.Join(t.TempDir(), "mappings.json"))
	if err != nil {
		t.Fatalf("newPseudonymizer returned error: %v", err)
	}
	policy, err := newPseudonymFieldPolicy(defaultPseudonymFieldsForTable("SentinelAlibabaCloudWAFLogs"))
	if err != nil {
		t.Fatalf("create WAF policy: %v", err)
	}
	if err := pseudonyms.ConfigureFieldPolicy(policy); err != nil {
		t.Fatalf("ConfigureFieldPolicy returned error: %v", err)
	}
	rows := []map[string]any{{"Host": "10.2.3.4", "MatchedHost": "origin.example.com"}}

	converted, err := pseudonyms.PseudonymizeRows(context.Background(), rows)
	if err != nil {
		t.Fatalf("PseudonymizeRows returned error: %v", err)
	}
	if converted[0]["Host"] != rows[0]["Host"] {
		t.Fatalf("IP-valued Host changed to %q", converted[0]["Host"])
	}
	if converted[0]["MatchedHost"] == rows[0]["MatchedHost"] {
		t.Fatal("domain-valued MatchedHost was not pseudonymized")
	}
}

func TestExplicitFieldScopeOverridesDefaults(t *testing.T) {
	pseudonyms, err := newPseudonymizer(filepath.Join(t.TempDir(), "mappings.json"))
	if err != nil {
		t.Fatalf("newPseudonymizer returned error: %v", err)
	}
	policy, err := newPseudonymFieldPolicy("AccountName,FileName")
	if err != nil {
		t.Fatalf("newPseudonymFieldPolicy returned error: %v", err)
	}
	if err := pseudonyms.ConfigureFieldPolicy(policy); err != nil {
		t.Fatalf("ConfigureFieldPolicy returned error: %v", err)
	}
	pseudonyms.ConfigureFilenamePseudonymization(true)
	rows := []map[string]any{{"AccountName": "alice", "FileName": "secret.txt", "DeviceName": "host-01"}}
	converted, err := pseudonyms.PseudonymizeRows(context.Background(), rows)
	if err != nil {
		t.Fatalf("PseudonymizeRows returned error: %v", err)
	}
	if converted[0]["AccountName"] == "alice" || converted[0]["FileName"] == "secret.txt" {
		t.Fatal("explicitly selected fields were not pseudonymized")
	}
	if converted[0]["DeviceName"] != "host-01" {
		t.Fatalf("unselected DeviceName changed to %q", converted[0]["DeviceName"])
	}
}
