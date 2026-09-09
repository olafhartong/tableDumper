package app

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
)

func TestDevicePseudonymsStayStableAcrossAccountOrderAndReload(t *testing.T) {
	var expectedHost string
	for _, reverse := range []bool{false, true} {
		p, err := newPseudonymizer(filepath.Join(t.TempDir(), "vault.json"))
		if err != nil {
			t.Fatal(err)
		}
		p.seed = bytes.Repeat([]byte{17}, 32)
		configureAllPseudonymFields(t, p)
		domains := []string{"CONTOSO", "FABRIKAM", "CONTOSO"}
		if reverse {
			domains = []string{"FABRIKAM", "CONTOSO", "FABRIKAM"}
		}
		for _, domain := range domains {
			out, err := p.PseudonymizeRows(context.Background(), []map[string]any{{"AccountName": "alice", "AccountDomain": domain, "DeviceName": "pc.corp.test", "DeviceFqdn": "pc.corp.test"}})
			if err != nil {
				t.Fatal(err)
			}
			host := out[0]["DeviceName"].(string)
			if expectedHost == "" {
				expectedHost = host
			}
			if host != expectedHost || out[0]["DeviceFqdn"] != expectedHost {
				t.Fatalf("device changed with account/order: %v", out)
			}
			if err := p.Save(); err != nil {
				t.Fatal(err)
			}
			p, err = newPseudonymizer(p.Path())
			if err != nil {
				t.Fatal(err)
			}
			configureAllPseudonymFields(t, p)
		}
	}
}

func TestLaterContradictoryDeviceAliasPreservesEarlierMappings(t *testing.T) {
	p, err := newPseudonymizer(filepath.Join(t.TempDir(), "vault.json"))
	if err != nil {
		t.Fatal(err)
	}
	configureAllPseudonymFields(t, p)
	first, err := p.PseudonymizeRows(context.Background(), []map[string]any{{"DeviceName": "one.corp.test"}, {"DeviceName": "two.corp.test"}})
	if err != nil {
		t.Fatal(err)
	}
	before := make(map[string]pseudonymMapping)
	for k, v := range p.mappings {
		before[k] = v
	}
	out, err := p.PseudonymizeRows(context.Background(), []map[string]any{{"DeviceName": "one.corp.test", "DeviceFqdn": "two.corp.test"}})
	if err == nil || out != nil {
		t.Fatalf("contradictory aliases should stop output: %v %v", out, err)
	}
	for k, v := range before {
		if p.mappings[k] != v {
			t.Fatal("existing device mapping was overwritten")
		}
	}
	if p.mappings[entityKey(entityHostname, "one.corp.test")].Pseudonym != first[0]["DeviceName"] || p.mappings[entityKey(entityHostname, "two.corp.test")].Pseudonym != first[1]["DeviceName"] {
		t.Fatal("earlier emitted values invalidated")
	}
}
