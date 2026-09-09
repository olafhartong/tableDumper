package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestPseudonymPoolsExpandPastFriendlyNameCapacity(t *testing.T) {
	p, err := newPseudonymizer(filepath.Join(t.TempDir(), "vault.json"))
	if err != nil {
		t.Fatal(err)
	}
	p.seed = bytes.Repeat([]byte{42}, 32)
	cases := []struct {
		kind   entityKind
		count  int
		prefix string
	}{{entityUsername, 3000, "user"}, {entityPerson, 1200, "person"}, {entityHostname, 10050, "host"}, {entityDomain, 6000, "domain"}}
	samples := make(map[string]string)
	for _, tc := range cases {
		seen := make(map[string]bool)
		for i := 0; i < tc.count; i++ {
			original := fmt.Sprintf("%s-%d", tc.prefix, i)
			got := p.replacement(tc.kind, original)
			if got == "" || seen[got] {
				t.Fatalf("%s allocation %d failed or duplicated: %v", tc.kind, i, p.transformationError)
			}
			seen[got] = true
			if i%1000 == 0 {
				samples[entityKey(tc.kind, original)] = got
			}
		}
	}
	if err := p.Save(); err != nil {
		t.Fatal(err)
	}
	reloaded, err := newPseudonymizer(p.Path())
	if err != nil {
		t.Fatal(err)
	}
	for key, want := range samples {
		if got := reloaded.mappings[key].Pseudonym; got != want {
			t.Fatalf("saved mapping changed: %q != %q", got, want)
		}
	}
}

func TestPublicIPv4ExhaustionFailsWithoutPublishingMappings(t *testing.T) {
	p, err := newPseudonymizer(filepath.Join(t.TempDir(), "vault.json"))
	if err != nil {
		t.Fatal(err)
	}
	configureAllPseudonymFields(t, p)
	seen := make(map[string]bool)
	for i := 0; i < 762; i++ {
		original := fmt.Sprintf("11.%d.%d.%d", i/65536, (i/256)%256, i%256)
		got := p.replacement(entityIPAddress, original)
		address, err := netip.ParseAddr(got)
		if err != nil || !address.Is4() || seen[got] {
			t.Fatalf("invalid or duplicate IPv4 at %d: %s", i, got)
		}
		seen[got] = true
	}
	if err := p.Save(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(p.Path())
	if err != nil {
		t.Fatal(err)
	}
	out, err := p.PseudonymizeRows(context.Background(), []map[string]any{{"RemoteIP": "12.1.2.3"}})
	var exhausted *pseudonymCapacityError
	if out != nil || !errors.As(err, &exhausted) {
		t.Fatalf("expected explicit capacity error without output, got %v, %v", out, err)
	}
	if !errors.As(p.Save(), &exhausted) {
		t.Fatal("failed generation must not be saved")
	}
	after, err := os.ReadFile(p.Path())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("failed allocation modified the saved vault")
	}
}

func TestCompositePseudonymCollisionIsBounded(t *testing.T) {
	p, err := newPseudonymizer(filepath.Join(t.TempDir(), "vault.json"))
	if err != nil {
		t.Fatal(err)
	}
	candidate := p.replacement(entityUsername, "alice") + "@" + p.replacement(entityDomain, "example.test")
	p.configuredReplacement("configured-alias", candidate)
	if got := p.replacement(entityEmail, "alice@example.test"); got != "" {
		t.Fatalf("expected collision failure, got %s", got)
	}
	var exhausted *pseudonymCapacityError
	if !errors.As(p.Save(), &exhausted) {
		t.Fatal("composite collision was not reported")
	}
}
