package app

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testSubscriptionID = "80110e3c-3ec4-4567-b06d-7d47a72562f5"

func TestPseudonymizeAzureResourceIDsPreservesHierarchyAndRelationships(t *testing.T) {
	vaultPath := filepath.Join(t.TempDir(), "mappings.json")
	pseudonyms, err := newPseudonymizer(vaultPath)
	if err != nil {
		t.Fatalf("newPseudonymizer returned error: %v", err)
	}
	first := "/subscriptions/" + testSubscriptionID + "/resourceGroups/lab2-on-premises-vms/providers/Microsoft.HybridCompute/machines/ad-connect"
	second := "/subscriptions/" + testSubscriptionID + "/resourceGroups/lab2-on-premises-vms/providers/Microsoft.HybridCompute/machines/adcs"
	rows := []map[string]any{{
		"AzureResourceId":   first,
		"SubscriptionId":    testSubscriptionID,
		"ResourceGroupName": "lab2-on-premises-vms",
	}, {"AzureResourceId": second}}

	converted, err := pseudonyms.PseudonymizeRows(context.Background(), rows)
	if err != nil {
		t.Fatalf("PseudonymizeRows returned error: %v", err)
	}
	firstParts := strings.Split(converted[0]["AzureResourceId"].(string), "/")
	secondParts := strings.Split(converted[1]["AzureResourceId"].(string), "/")
	if len(firstParts) != 9 || len(secondParts) != 9 {
		t.Fatalf("unexpected resource ID structure: %#v and %#v", firstParts, secondParts)
	}
	if firstParts[2] == testSubscriptionID || firstParts[2] != secondParts[2] || !isExactGUID(firstParts[2]) {
		t.Fatalf("subscription relationship was not preserved: %q and %q", firstParts[2], secondParts[2])
	}
	if firstParts[4] == "lab2-on-premises-vms" || firstParts[4] != secondParts[4] || !strings.HasPrefix(firstParts[4], "rg-") {
		t.Fatalf("resource group relationship was not preserved: %q and %q", firstParts[4], secondParts[4])
	}
	if converted[0]["SubscriptionId"] != firstParts[2] || converted[0]["ResourceGroupName"] != firstParts[4] {
		t.Fatalf("standalone scope fields do not match the resource ID: subscription=%q resourceGroup=%q", converted[0]["SubscriptionId"], converted[0]["ResourceGroupName"])
	}
	if firstParts[5] != "providers" || firstParts[6] != "Microsoft.HybridCompute" || firstParts[7] != "machines" {
		t.Fatalf("provider/type hierarchy changed: %#v", firstParts)
	}
	if firstParts[8] == "ad-connect" || secondParts[8] == "adcs" || firstParts[8] == secondParts[8] {
		t.Fatalf("resource names were not independently pseudonymized: %q and %q", firstParts[8], secondParts[8])
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
	foundStructuredMapping := false
	for _, mapping := range vault.Mappings {
		if mapping.EntityType == string(entityAzureResourceID) && mapping.Original == first && strings.HasPrefix(mapping.Pseudonym, "/subscriptions/") {
			foundStructuredMapping = true
		}
	}
	if !foundStructuredMapping {
		t.Fatalf("structured Azure Resource ID mapping not found: %#v", vault.Mappings)
	}
}

func TestPseudonymizeAzureResourceIDHandlesNestedResourcesAndFreeText(t *testing.T) {
	pseudonyms, err := newPseudonymizer(filepath.Join(t.TempDir(), "mappings.json"))
	if err != nil {
		t.Fatalf("newPseudonymizer returned error: %v", err)
	}
	configureAllPseudonymFields(t, pseudonyms)
	resourceID := "/subscriptions/" + testSubscriptionID + "/resourceGroups/network-prod/providers/Microsoft.Network/virtualNetworks/core-vnet/subnets/default"
	message := "Changed " + resourceID + "."

	converted, err := pseudonyms.pseudonymizeString(context.Background(), "Message", message)
	if err != nil {
		t.Fatalf("pseudonymizeString returned error: %v", err)
	}
	for _, original := range []string{testSubscriptionID, "network-prod", "core-vnet", "/subnets/default"} {
		if strings.Contains(converted, original) {
			t.Fatalf("free-text Azure Resource ID still contains %q: %q", original, converted)
		}
	}
	if !strings.Contains(converted, "/providers/Microsoft.Network/virtualNetworks/") || !strings.Contains(converted, "/subnets/") || !strings.HasSuffix(converted, ".") {
		t.Fatalf("resource hierarchy or surrounding punctuation changed: %q", converted)
	}
}

func TestParseAzureResourceIDRejectsUnstructuredIdentifiers(t *testing.T) {
	for _, value := range []string{
		"2f93c996-af24-41ff-a522-d0c508425f52",
		"/subscriptions/not-a-guid/resourceGroups/example/providers/Microsoft.Compute/virtualMachines/vm1",
		"/subscriptions/" + testSubscriptionID + "/resourceGroups/example/providers/Microsoft.Compute/virtualMachines",
	} {
		if _, ok := parseAzureResourceID(value); ok {
			t.Fatalf("parseAzureResourceID(%q) unexpectedly succeeded", value)
		}
	}
}

func TestPseudonymizeAzureResourceGroupID(t *testing.T) {
	pseudonyms, err := newPseudonymizer(filepath.Join(t.TempDir(), "mappings.json"))
	if err != nil {
		t.Fatalf("newPseudonymizer returned error: %v", err)
	}
	original := "/subscriptions/" + testSubscriptionID + "/resourceGroups/lab2-on-premises-vms"
	converted, ok := pseudonyms.pseudonymizeAzureResourceID(original)
	if !ok {
		t.Fatal("pseudonymizeAzureResourceID did not recognize a resource-group ID")
	}
	if strings.Contains(converted, testSubscriptionID) || strings.Contains(converted, "lab2-on-premises-vms") || !strings.Contains(converted, "/resourceGroups/rg-") {
		t.Fatalf("resource-group ID was not structurally pseudonymized: %q", converted)
	}
}
