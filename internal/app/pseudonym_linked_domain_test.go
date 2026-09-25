package app

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestLinkedIdentityDomainsDoNotConflictAcrossRows(t *testing.T) {
	tests := []struct {
		name  string
		table string
		rows  []map[string]any
		check func(t *testing.T, converted []map[string]any)
	}{
		{
			name:  "composite accounts share their domain",
			table: "SecurityEvent",
			rows: []map[string]any{
				{"Account": `CONTOSO\alice`},
				{"Account": `CONTOSO\bob`},
			},
			check: func(t *testing.T, converted []map[string]any) {
				assertSameCompositeDomain(t, converted[0]["Account"], converted[1]["Account"])
			},
		},
		{
			name:  "composite service accounts share their domain",
			table: "OfficeActivity",
			rows: []map[string]any{
				{"UserId": `NT AUTHORITY\SYSTEM (Microsoft.Exchange.ServiceHost)`},
				{"UserId": `NT AUTHORITY\SYSTEM (Microsoft.Exchange.AdminApi)`},
			},
			check: func(t *testing.T, converted []map[string]any) {
				assertSameCompositeDomain(t, converted[0]["UserId"], converted[1]["UserId"])
			},
		},
		{
			name:  "local account domain later seen with an already mapped UPN domain",
			table: "DeviceProcessEvents",
			rows: []map[string]any{
				{"DeviceName": "laptop-7", "AccountDomain": "laptop-7", "AccountName": "admin", "AccountUpn": ""},
				{"DeviceName": "srv-1", "AccountDomain": "contoso", "AccountName": "bob", "AccountUpn": "bob@contoso.com"},
				{"DeviceName": "laptop-7", "AccountDomain": "laptop-7", "AccountName": "alice", "AccountUpn": "alice@contoso.com"},
			},
			check: func(t *testing.T, converted []map[string]any) {
				if converted[2]["AccountDomain"] != converted[0]["AccountDomain"] || converted[2]["DeviceName"] != converted[0]["DeviceName"] {
					t.Fatalf("local account domain changed between rows: %#v, %#v", converted[0], converted[2])
				}
				_, bobDomain, _ := splitEmail(converted[1]["AccountUpn"].(string))
				local, aliceDomain, ok := splitEmail(converted[2]["AccountUpn"].(string))
				if !ok || aliceDomain != bobDomain {
					t.Fatalf("UPN domain %q does not match the established UPN domain %q", converted[2]["AccountUpn"], bobDomain)
				}
				if local != converted[2]["AccountName"] {
					t.Fatalf("AccountName %q and AccountUpn local part %q do not represent one identity", converted[2]["AccountName"], local)
				}
				assertLinkedAccountFamily(t, converted[1], "")
			},
		},
		{
			name:  "composite account domain later seen with a separate domain field",
			table: "SecurityEvent",
			rows: []map[string]any{
				{"Account": `CONTOSO\alice`},
				{"TargetAccount": `CONTOSO\bob`, "TargetDomainName": "CONTOSO", "TargetUserName": "bob"},
			},
			check: func(t *testing.T, converted []map[string]any) {
				assertSameCompositeDomain(t, converted[0]["Account"], converted[1]["TargetAccount"])
				if domain, _, _ := splitWindowsAccount(converted[0]["Account"].(string)); converted[1]["TargetDomainName"] != domain {
					t.Fatalf("TargetDomainName %q does not match composite domain %q", converted[1]["TargetDomainName"], domain)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "mappings.json")
			policy, err := newPseudonymFieldPolicy(defaultPseudonymFieldsForTable(tt.table))
			if err != nil {
				t.Fatalf("create %s policy: %v", tt.table, err)
			}
			run := func() []map[string]any {
				t.Helper()
				pseudonyms, err := newPseudonymizer(path)
				if err != nil {
					t.Fatalf("newPseudonymizer returned error: %v", err)
				}
				if err := pseudonyms.ConfigureFieldPolicy(policy); err != nil {
					t.Fatalf("ConfigureFieldPolicy returned error: %v", err)
				}
				converted, err := pseudonyms.PseudonymizeRows(context.Background(), tt.rows)
				if err != nil {
					t.Fatalf("PseudonymizeRows returned error: %v", err)
				}
				if err := pseudonyms.Save(); err != nil {
					t.Fatalf("Save returned error: %v", err)
				}
				return converted
			}

			converted := run()
			tt.check(t, converted)
			again := run()
			firstBody, _ := json.Marshal(converted)
			againBody, _ := json.Marshal(again)
			if string(firstBody) != string(againBody) {
				t.Fatalf("linked identity changed after vault reload:\nfirst: %s\nagain: %s", firstBody, againBody)
			}
		})
	}
}

func assertSameCompositeDomain(t *testing.T, first, second any) {
	t.Helper()
	firstDomain, firstUser, ok := splitWindowsAccount(first.(string))
	if !ok {
		t.Fatalf("%q is not a composite account", first)
	}
	secondDomain, secondUser, ok := splitWindowsAccount(second.(string))
	if !ok {
		t.Fatalf("%q is not a composite account", second)
	}
	if firstDomain != secondDomain {
		t.Fatalf("composite accounts %q and %q do not share one domain", first, second)
	}
	if strings.EqualFold(firstUser, secondUser) {
		t.Fatalf("different users %q and %q were merged", first, second)
	}
}
