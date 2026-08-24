package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenGraphArtifactPath(t *testing.T) {
	path := openGraphArtifactPath("/tmp/results.json")
	if path != "/tmp/results.opengraph.json" {
		t.Fatalf("unexpected OpenGraph path %q", path)
	}
}

func TestOpenGraphIconArtifactPath(t *testing.T) {
	path := openGraphIconArtifactPath("/tmp/results.json")
	if path != "/tmp/results.opengraph.icons.json" {
		t.Fatalf("unexpected OpenGraph icon path %q", path)
	}
}

func TestWriteOpenGraphArtifactForAlertNodes(t *testing.T) {
	dir := t.TempDir()
	cfg := config{
		Output: filepath.Join(dir, "results.json"),
	}
	response := queryResponse{
		Schema: []queryColumn{
			{Name: "id", Type: "String"},
			{Name: "type", Type: "String"},
			{Name: "label", Type: "String"},
			{Name: "timestamp", Type: "DateTime"},
			{Name: "properties", Type: "Object"},
		},
		Results: []map[string]any{
			{
				"id":        "device-1",
				"type":      "Machine",
				"label":     "ws1.contoso.local",
				"timestamp": "2026-04-08T10:00:00Z",
				"properties": map[string]any{
					"accountName": "svc-backup",
					"rawData": map[string]any{
						"Severity": "High",
						"objectId": "abc-123",
					},
				},
			},
		},
	}

	path, iconPath, err := writeOpenGraphArtifact(cfg, response)
	if err != nil {
		t.Fatalf("writeOpenGraphArtifact returned error: %v", err)
	}
	if path != filepath.Join(dir, "results.opengraph.json") {
		t.Fatalf("unexpected OpenGraph output path %q", path)
	}
	if iconPath != filepath.Join(dir, "results.opengraph.icons.json") {
		t.Fatalf("unexpected OpenGraph icon path %q", iconPath)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read OpenGraph output: %v", err)
	}

	var payload openGraphPayload
	if err := json.Unmarshal(content, &payload); err != nil {
		t.Fatalf("decode OpenGraph output: %v", err)
	}
	if len(payload.Graph.Nodes) != 1 {
		t.Fatalf("unexpected node count %d", len(payload.Graph.Nodes))
	}
	if len(payload.Graph.Edges) != 0 {
		t.Fatalf("unexpected edge count %d", len(payload.Graph.Edges))
	}

	node := payload.Graph.Nodes[0]
	if node.ID != "device-1" {
		t.Fatalf("unexpected node id %q", node.ID)
	}
	if got := node.Kinds[0]; got != "Machine" {
		t.Fatalf("unexpected node kind %q", got)
	}
	if got := node.Properties["displayname"]; got != "ws1.contoso.local" {
		t.Fatalf("unexpected displayname %#v", got)
	}
	if got := node.Properties["accountname"]; got != "svc-backup" {
		t.Fatalf("unexpected flattened property %#v", got)
	}
	if got := node.Properties["rawdata_severity"]; got != "High" {
		t.Fatalf("unexpected nested property %#v", got)
	}
	if got := node.Properties["rawdata_source_objectid"]; got != "abc-123" {
		t.Fatalf("unexpected reserved property rename %#v", got)
	}

	iconContent, err := os.ReadFile(iconPath)
	if err != nil {
		t.Fatalf("read OpenGraph icon output: %v", err)
	}

	var iconPayload openGraphCustomNodePayload
	if err := json.Unmarshal(iconContent, &iconPayload); err != nil {
		t.Fatalf("decode OpenGraph icon output: %v", err)
	}
	if got := iconPayload.CustomTypes["Machine"].Icon.Name; got != "desktop" {
		t.Fatalf("unexpected machine icon %#v", got)
	}
}

func TestBuildOpenGraphPayloadForExposureGraphEdges(t *testing.T) {
	response := queryResponse{
		Schema: []queryColumn{
			{Name: "EdgeId", Type: "String"},
			{Name: "EdgeLabel", Type: "String"},
			{Name: "SourceNodeId", Type: "String"},
			{Name: "SourceNodeName", Type: "String"},
			{Name: "SourceNodeLabel", Type: "String"},
			{Name: "SourceNodeCategories", Type: "Object"},
			{Name: "TargetNodeId", Type: "String"},
			{Name: "TargetNodeName", Type: "String"},
			{Name: "TargetNodeLabel", Type: "String"},
			{Name: "TargetNodeCategories", Type: "Object"},
			{Name: "EdgeProperties", Type: "Object"},
		},
		Results: []map[string]any{
			{
				"EdgeId":               "edge-1",
				"EdgeLabel":            "has role on",
				"SourceNodeId":         "group-1",
				"SourceNodeName":       "Enterprise Admins",
				"SourceNodeLabel":      "group",
				"SourceNodeCategories": []any{"identity", "user_group"},
				"TargetNodeId":         "group-2",
				"TargetNodeName":       "Tier Zero",
				"TargetNodeLabel":      "group",
				"TargetNodeCategories": []any{"identity", "user_group"},
				"EdgeProperties": map[string]any{
					"rawData": map[string]any{
						"controlTypes": []any{"genericAll"},
					},
				},
			},
		},
	}

	payload, err := buildOpenGraphPayload(response)
	if err != nil {
		t.Fatalf("buildOpenGraphPayload returned error: %v", err)
	}
	if len(payload.Graph.Edges) != 1 {
		t.Fatalf("unexpected edge count %d", len(payload.Graph.Edges))
	}
	if len(payload.Graph.Nodes) != 2 {
		t.Fatalf("unexpected synthesized node count %d", len(payload.Graph.Nodes))
	}

	edge := payload.Graph.Edges[0]
	if edge.Kind != "has_role_on" {
		t.Fatalf("unexpected edge kind %q", edge.Kind)
	}
	if edge.Start.Value != "group-1" || edge.End.Value != "group-2" {
		t.Fatalf("unexpected edge refs %#v", edge)
	}
	if got := edge.Properties["rawdata_controltypes"].([]any)[0]; got != "genericAll" {
		t.Fatalf("unexpected flattened edge property %#v", edge.Properties["rawdata_controltypes"])
	}

	sourceNode := payload.Graph.Nodes[0]
	if sourceNode.ID != "group-1" {
		t.Fatalf("unexpected source node id %q", sourceNode.ID)
	}
	if got := sourceNode.Kinds[0]; got != "group" {
		t.Fatalf("unexpected source node kind %q", got)
	}
	if got := sourceNode.Properties["displayname"]; got != "Enterprise Admins" {
		t.Fatalf("unexpected source node name %#v", got)
	}
}

func TestBuildOpenGraphPayloadForMixedNodeAndEdgeRows(t *testing.T) {
	response := queryResponse{
		Results: []map[string]any{
			{
				"id":        "alert-1",
				"type":      "Alert",
				"label":     "Suspicious admin activity",
				"timestamp": "2026-04-08T10:00:00Z",
				"properties": map[string]any{
					"severity": "High",
				},
			},
			{
				"id":        "user-1",
				"type":      "User",
				"label":     "ballpit\\monkey-adm",
				"timestamp": "2026-04-08T10:00:00Z",
				"properties": map[string]any{
					"accountName": "monkey-adm",
				},
			},
			{
				"id":        "alert-1_alertimpacted_user-1",
				"sourceId":  "alert-1",
				"targetId":  "user-1",
				"type":      "AlertImpacted",
				"edgeType":  "AlertImpacted",
				"label":     "Impacted",
				"weight":    1.0,
				"timestamp": "2026-04-08T10:00:00Z",
				"properties": map[string]any{
					"relationship": "AlertImpacted",
				},
			},
		},
	}

	payload, err := buildOpenGraphPayload(response)
	if err != nil {
		t.Fatalf("buildOpenGraphPayload returned error: %v", err)
	}
	if len(payload.Graph.Nodes) != 2 {
		t.Fatalf("unexpected node count %d", len(payload.Graph.Nodes))
	}
	if len(payload.Graph.Edges) != 1 {
		t.Fatalf("unexpected edge count %d", len(payload.Graph.Edges))
	}
	if payload.Graph.Edges[0].Start.Value != "alert-1" || payload.Graph.Edges[0].End.Value != "user-1" {
		t.Fatalf("unexpected edge refs %#v", payload.Graph.Edges[0])
	}
}

func TestBuildOpenGraphPayloadRejectsUnsupportedShape(t *testing.T) {
	_, err := buildOpenGraphPayload(queryResponse{
		Schema: []queryColumn{
			{Name: "DeviceName", Type: "String"},
			{Name: "Timestamp", Type: "DateTime"},
		},
		Results: []map[string]any{
			{"DeviceName": "host1", "Timestamp": "2026-04-08T10:00:00Z"},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "supported OpenGraph node or edge shape") {
		t.Fatalf("expected unsupported shape error, got %v", err)
	}
}

func TestBuildOpenGraphCustomNodePayload(t *testing.T) {
	payload := openGraphPayload{
		Graph: openGraphGraph{
			Nodes: []openGraphNode{
				{ID: "1", Kinds: []string{"Alert"}},
				{ID: "2", Kinds: []string{"Machine"}},
				{ID: "3", Kinds: []string{"User"}},
				{ID: "4", Kinds: []string{"CustomThing"}},
			},
		},
	}

	iconPayload := buildOpenGraphCustomNodePayload(payload)
	if len(iconPayload.CustomTypes) != 4 {
		t.Fatalf("unexpected custom type count %d", len(iconPayload.CustomTypes))
	}
	if got := iconPayload.CustomTypes["Alert"].Icon.Name; got != "triangle-exclamation" {
		t.Fatalf("unexpected alert icon %#v", got)
	}
	if got := iconPayload.CustomTypes["Machine"].Icon.Name; got != "desktop" {
		t.Fatalf("unexpected machine icon %#v", got)
	}
	if got := iconPayload.CustomTypes["User"].Icon.Name; got != "user" {
		t.Fatalf("unexpected user icon %#v", got)
	}
	if got := iconPayload.CustomTypes["CustomThing"].Icon.Name; got != "circle-question" {
		t.Fatalf("unexpected fallback icon %#v", got)
	}
}
