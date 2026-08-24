package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

type openGraphPayload struct {
	Graph openGraphGraph `json:"graph"`
}

type openGraphGraph struct {
	Nodes []openGraphNode `json:"nodes"`
	Edges []openGraphEdge `json:"edges"`
}

type openGraphNode struct {
	ID         string         `json:"id"`
	Kinds      []string       `json:"kinds"`
	Properties map[string]any `json:"properties,omitempty"`
}

type openGraphEdge struct {
	Start      openGraphNodeReference `json:"start"`
	End        openGraphNodeReference `json:"end"`
	Kind       string                 `json:"kind"`
	Properties map[string]any         `json:"properties,omitempty"`
}

type openGraphNodeReference struct {
	MatchBy string `json:"match_by"`
	Value   string `json:"value"`
	Kind    string `json:"kind,omitempty"`
}

type openGraphCustomNodePayload struct {
	CustomTypes map[string]openGraphCustomNodeConfig `json:"custom_types"`
}

type openGraphCustomNodeConfig struct {
	Icon openGraphCustomNodeIcon `json:"icon"`
}

type openGraphCustomNodeIcon struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Color string `json:"color,omitempty"`
}

func writeOpenGraphArtifact(cfg config, response queryResponse) (string, string, error) {
	payload, err := buildOpenGraphPayload(response)
	if err != nil {
		return "", "", err
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", "", fmt.Errorf("encode OpenGraph payload: %w", err)
	}

	path := openGraphArtifactPath(cfg.Output)
	if err := writeJSONFile(path, body); err != nil {
		return "", "", err
	}

	iconPayload := buildOpenGraphCustomNodePayload(payload)
	if len(iconPayload.CustomTypes) == 0 {
		return path, "", nil
	}

	iconBody, err := json.Marshal(iconPayload)
	if err != nil {
		return "", "", fmt.Errorf("encode OpenGraph icon payload: %w", err)
	}

	iconPath := openGraphIconArtifactPath(cfg.Output)
	if err := writeJSONFile(iconPath, iconBody); err != nil {
		return "", "", err
	}

	return path, iconPath, nil
}

func openGraphArtifactPath(outputPath string) string {
	ext := filepath.Ext(outputPath)
	base := strings.TrimSuffix(outputPath, ext)
	if base == "" {
		base = outputPath
	}
	return base + ".opengraph.json"
}

func openGraphIconArtifactPath(outputPath string) string {
	ext := filepath.Ext(outputPath)
	base := strings.TrimSuffix(outputPath, ext)
	if base == "" {
		base = outputPath
	}
	return base + ".opengraph.icons.json"
}

func buildOpenGraphPayload(response queryResponse) (openGraphPayload, error) {
	payload := openGraphPayload{
		Graph: openGraphGraph{
			Nodes: make([]openGraphNode, 0),
			Edges: make([]openGraphEdge, 0),
		},
	}

	if len(response.Results) == 0 {
		return payload, nil
	}

	nodeIndex := make(map[string]int)
	for i, row := range response.Results {
		switch detectOpenGraphRowKind(row) {
		case "node":
			node, err := convertRowToOpenGraphNode(row)
			if err != nil {
				return openGraphPayload{}, fmt.Errorf("convert row %d to OpenGraph node: %w", i+1, err)
			}
			appendOrMergeOpenGraphNode(&payload, nodeIndex, node)
		case "edge":
			edge, err := convertRowToOpenGraphEdge(row)
			if err != nil {
				return openGraphPayload{}, fmt.Errorf("convert row %d to OpenGraph edge: %w", i+1, err)
			}
			payload.Graph.Edges = append(payload.Graph.Edges, edge)

			for _, node := range extractOpenGraphNodesFromEdgeRow(row) {
				appendOrMergeOpenGraphNode(&payload, nodeIndex, node)
			}
		default:
			return openGraphPayload{}, fmt.Errorf("row %d does not match a supported OpenGraph node or edge shape; expected node ids or source/target ids in the result set", i+1)
		}
	}

	return payload, nil
}

func buildOpenGraphCustomNodePayload(payload openGraphPayload) openGraphCustomNodePayload {
	customTypes := make(map[string]openGraphCustomNodeConfig)
	for _, node := range payload.Graph.Nodes {
		for _, kind := range node.Kinds {
			kind = strings.TrimSpace(kind)
			if kind == "" {
				continue
			}
			if _, ok := customTypes[kind]; ok {
				continue
			}
			customTypes[kind] = openGraphCustomNodeConfig{
				Icon: iconForOpenGraphKind(kind),
			}
		}
	}
	return openGraphCustomNodePayload{CustomTypes: customTypes}
}

func iconForOpenGraphKind(kind string) openGraphCustomNodeIcon {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "alert":
		return openGraphCustomNodeIcon{Type: "font-awesome", Name: "triangle-exclamation", Color: "#D97706"}
	case "user":
		return openGraphCustomNodeIcon{Type: "font-awesome", Name: "user", Color: "#16A34A"}
	case "machine", "computer":
		return openGraphCustomNodeIcon{Type: "font-awesome", Name: "desktop", Color: "#2563EB"}
	case "file":
		return openGraphCustomNodeIcon{Type: "font-awesome", Name: "file", Color: "#6B7280"}
	case "process":
		return openGraphCustomNodeIcon{Type: "font-awesome", Name: "gears", Color: "#7C3AED"}
	case "ip":
		return openGraphCustomNodeIcon{Type: "font-awesome", Name: "network-wired", Color: "#0891B2"}
	case "url":
		return openGraphCustomNodeIcon{Type: "font-awesome", Name: "link", Color: "#0284C7"}
	case "cloudresource":
		return openGraphCustomNodeIcon{Type: "font-awesome", Name: "cloud", Color: "#0F766E"}
	case "mailmessage":
		return openGraphCustomNodeIcon{Type: "font-awesome", Name: "envelope", Color: "#DC2626"}
	case "application":
		return openGraphCustomNodeIcon{Type: "font-awesome", Name: "window-maximize", Color: "#4F46E5"}
	case "group", "user_group":
		return openGraphCustomNodeIcon{Type: "font-awesome", Name: "users", Color: "#1D4ED8"}
	case "finding", "security_finding":
		return openGraphCustomNodeIcon{Type: "font-awesome", Name: "shield-halved", Color: "#B45309"}
	case "identity":
		return openGraphCustomNodeIcon{Type: "font-awesome", Name: "id-badge", Color: "#15803D"}
	default:
		return openGraphCustomNodeIcon{Type: "font-awesome", Name: "circle-question", Color: "#64748B"}
	}
}

func detectOpenGraphRowKind(row map[string]any) string {
	rowMap := normalizeRowMap(row)
	if hasNonEmptyFields(rowMap, "sourceid", "targetid") || hasNonEmptyFields(rowMap, "sourcenodeid", "targetnodeid") {
		return "edge"
	}
	if hasAnyNonEmptyField(rowMap, "id", "nodeid") {
		return "node"
	}
	return ""
}

func hasNonEmptyFields(row map[string]any, names ...string) bool {
	for _, name := range names {
		if stringValue(row[name]) == "" {
			return false
		}
	}
	return true
}

func hasAnyNonEmptyField(row map[string]any, names ...string) bool {
	for _, name := range names {
		if stringValue(row[name]) != "" {
			return true
		}
	}
	return false
}

func appendOrMergeOpenGraphNode(payload *openGraphPayload, nodeIndex map[string]int, node openGraphNode) {
	if idx, ok := nodeIndex[node.ID]; ok {
		payload.Graph.Nodes[idx] = mergeOpenGraphNodes(payload.Graph.Nodes[idx], node)
		return
	}
	nodeIndex[node.ID] = len(payload.Graph.Nodes)
	payload.Graph.Nodes = append(payload.Graph.Nodes, node)
}

func convertRowToOpenGraphNode(row map[string]any) (openGraphNode, error) {
	rowMap := normalizeRowMap(row)

	id := stringValue(rowMap["id"])
	if id == "" {
		id = stringValue(rowMap["nodeid"])
	}
	if id == "" {
		return openGraphNode{}, errors.New("missing node id")
	}

	properties := collectOpenGraphProperties(rowMap, map[string]struct{}{
		"id":             {},
		"nodeid":         {},
		"type":           {},
		"nodelabel":      {},
		"label":          {},
		"categories":     {},
		"properties":     {},
		"nodeproperties": {},
	})

	displayName := firstNonEmptyString(
		stringValue(rowMap["nodename"]),
		stringValue(rowMap["label"]),
		stringValue(rowMap["name"]),
	)
	if displayName != "" {
		setPropertyIfMissing(properties, "displayname", displayName)
		setPropertyIfMissing(properties, "name", displayName)
	}

	categories := primitiveStringSlice(rowMap["categories"])
	if len(categories) > 0 {
		setPropertyIfMissingArray(properties, "categories", categories)
	}

	return openGraphNode{
		ID:         id,
		Kinds:      buildOpenGraphKinds(firstNonEmptyString(stringValue(rowMap["type"]), stringValue(rowMap["nodelabel"])), rowMap["categories"]),
		Properties: properties,
	}, nil
}

func convertRowToOpenGraphEdge(row map[string]any) (openGraphEdge, error) {
	rowMap := normalizeRowMap(row)

	startID := firstNonEmptyString(stringValue(rowMap["sourceid"]), stringValue(rowMap["sourcenodeid"]))
	endID := firstNonEmptyString(stringValue(rowMap["targetid"]), stringValue(rowMap["targetnodeid"]))
	if startID == "" || endID == "" {
		return openGraphEdge{}, errors.New("missing source or target id")
	}

	rawKind := firstNonEmptyString(
		stringValue(rowMap["edgetype"]),
		edgeTypeValue(stringValue(rowMap["type"])),
		stringValue(rowMap["edgelabel"]),
		stringValue(rowMap["label"]),
	)
	kind := sanitizeOpenGraphKind(rawKind, "RELATED_TO")

	properties := collectOpenGraphProperties(rowMap, map[string]struct{}{
		"sourceid":             {},
		"targetid":             {},
		"sourcenodeid":         {},
		"targetnodeid":         {},
		"type":                 {},
		"edgetype":             {},
		"properties":           {},
		"edgeproperties":       {},
		"sourcenodename":       {},
		"sourcenodelabel":      {},
		"sourcenodecategories": {},
		"targetnodename":       {},
		"targetnodelabel":      {},
		"targetnodecategories": {},
	})

	return openGraphEdge{
		Start:      openGraphNodeReference{MatchBy: "id", Value: startID},
		End:        openGraphNodeReference{MatchBy: "id", Value: endID},
		Kind:       kind,
		Properties: properties,
	}, nil
}

func extractOpenGraphNodesFromEdgeRow(row map[string]any) []openGraphNode {
	rowMap := normalizeRowMap(row)
	nodes := make([]openGraphNode, 0, 2)

	if node := openGraphEdgeEndpointNode(
		stringValue(rowMap["sourcenodeid"]),
		stringValue(rowMap["sourcenodename"]),
		stringValue(rowMap["sourcenodelabel"]),
		rowMap["sourcenodecategories"],
	); node.ID != "" {
		nodes = append(nodes, node)
	}
	if node := openGraphEdgeEndpointNode(
		stringValue(rowMap["targetnodeid"]),
		stringValue(rowMap["targetnodename"]),
		stringValue(rowMap["targetnodelabel"]),
		rowMap["targetnodecategories"],
	); node.ID != "" {
		nodes = append(nodes, node)
	}

	return nodes
}

func openGraphEdgeEndpointNode(id, name, label string, categories any) openGraphNode {
	if id == "" {
		return openGraphNode{}
	}

	properties := map[string]any{}
	if name != "" {
		properties["displayname"] = name
		properties["name"] = name
	}
	if label != "" {
		properties["label"] = label
	}
	if categoryList := primitiveStringSlice(categories); len(categoryList) > 0 {
		properties["categories"] = categoryList
	}

	return openGraphNode{
		ID:         id,
		Kinds:      buildOpenGraphKinds(label, categories),
		Properties: properties,
	}
}

func mergeOpenGraphNodes(existing, incoming openGraphNode) openGraphNode {
	seenKinds := make(map[string]struct{}, len(existing.Kinds))
	for _, kind := range existing.Kinds {
		seenKinds[kind] = struct{}{}
	}
	for _, kind := range incoming.Kinds {
		if _, ok := seenKinds[kind]; ok {
			continue
		}
		existing.Kinds = append(existing.Kinds, kind)
		seenKinds[kind] = struct{}{}
	}

	if existing.Properties == nil {
		existing.Properties = map[string]any{}
	}
	for key, value := range incoming.Properties {
		if _, ok := existing.Properties[key]; !ok {
			existing.Properties[key] = value
		}
	}
	return existing
}

func collectOpenGraphProperties(row map[string]any, skip map[string]struct{}) map[string]any {
	properties := make(map[string]any)

	for _, key := range sortedRowKeys(row) {
		if shouldSkipOpenGraphField(key) {
			continue
		}
		if _, ok := skip[key]; ok {
			continue
		}
		flattenOpenGraphValue(properties, sanitizeOpenGraphPropertyName(key), row[key])
	}

	for _, embeddedKey := range []string{"properties", "nodeproperties", "edgeproperties"} {
		value, ok := row[embeddedKey]
		if !ok {
			continue
		}
		flattenOpenGraphValue(properties, "", value)
	}

	return properties
}

func sortedRowKeys(row map[string]any) []string {
	keys := make([]string, 0, len(row))
	for key := range row {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func normalizeRowMap(row map[string]any) map[string]any {
	normalized := make(map[string]any, len(row))
	for key, value := range row {
		normalized[normalizeRowKey(key)] = value
	}
	return normalized
}

func normalizeRowKey(key string) string {
	return strings.ToLower(strings.TrimSpace(key))
}

func edgeTypeValue(value string) string {
	if value == "" || strings.HasSuffix(value, "Edges") {
		return ""
	}
	return value
}

func buildOpenGraphKinds(primary string, categories any) []string {
	kinds := make([]string, 0, 3)
	seen := make(map[string]struct{})

	add := func(value string) {
		kind := sanitizeOpenGraphKind(value, "")
		if kind == "" {
			return
		}
		if _, ok := seen[kind]; ok {
			return
		}
		if len(kinds) >= 3 {
			return
		}
		seen[kind] = struct{}{}
		kinds = append(kinds, kind)
	}

	add(primary)
	for _, category := range primitiveStringSlice(categories) {
		add(category)
	}
	if len(kinds) == 0 {
		kinds = append(kinds, "ImportedNode")
	}
	return kinds
}

func sanitizeOpenGraphKind(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}

	var b strings.Builder
	lastUnderscore := false
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
			lastUnderscore = false
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
			lastUnderscore = false
		case r >= '0' && r <= '9':
			if b.Len() == 0 {
				b.WriteByte('_')
			}
			b.WriteRune(r)
			lastUnderscore = false
		default:
			if !lastUnderscore && b.Len() > 0 {
				b.WriteByte('_')
				lastUnderscore = true
			}
		}
	}

	kind := strings.Trim(b.String(), "_")
	if kind == "" {
		return fallback
	}
	if kind[0] >= '0' && kind[0] <= '9' {
		kind = "_" + kind
	}
	return kind
}

func sanitizeOpenGraphPropertyName(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return ""
	}

	var b strings.Builder
	lastUnderscore := false
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
			lastUnderscore = false
		case r >= '0' && r <= '9':
			b.WriteRune(r)
			lastUnderscore = false
		default:
			if !lastUnderscore && b.Len() > 0 {
				b.WriteByte('_')
				lastUnderscore = true
			}
		}
	}

	name := strings.Trim(b.String(), "_")
	if name == "objectid" {
		return "source_objectid"
	}
	return name
}

func shouldSkipOpenGraphField(key string) bool {
	return strings.HasSuffix(key, "@odata.type")
}

func flattenOpenGraphValue(properties map[string]any, prefix string, value any) {
	switch typed := value.(type) {
	case map[string]any:
		for _, key := range sortedRowKeys(typed) {
			if shouldSkipOpenGraphField(key) {
				continue
			}
			next := sanitizeOpenGraphPropertyName(key)
			if next == "" {
				continue
			}
			if prefix != "" {
				next = prefix + "_" + next
			}
			flattenOpenGraphValue(properties, next, typed[key])
		}
	case []any:
		if array, ok := normalizePrimitiveArray(typed); ok {
			setOpenGraphProperty(properties, prefix, array)
			return
		}
		setOpenGraphProperty(properties, prefix, compactJSONString(typed))
	case []string, []bool, []int, []int64, []float64, string, bool, float64, int, int64:
		setOpenGraphProperty(properties, prefix, typed)
	case nil:
		return
	default:
		setOpenGraphProperty(properties, prefix, compactJSONString(typed))
	}
}

func normalizePrimitiveArray(values []any) ([]any, bool) {
	if len(values) == 0 {
		return []any{}, true
	}

	group := ""
	normalized := make([]any, 0, len(values))
	for _, value := range values {
		current := primitiveValueGroup(value)
		if current == "" {
			return nil, false
		}
		if group == "" {
			group = current
		}
		if current != group {
			return nil, false
		}
		normalized = append(normalized, value)
	}
	return normalized, true
}

func primitiveValueGroup(value any) string {
	switch value.(type) {
	case string:
		return "string"
	case bool:
		return "bool"
	case float64, int, int64:
		return "number"
	default:
		return ""
	}
}

func compactJSONString(value any) string {
	body, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprintf("%v", value)
	}
	return string(body)
}

func setOpenGraphProperty(properties map[string]any, key string, value any) {
	key = sanitizeOpenGraphPropertyName(key)
	if key == "" {
		return
	}

	if existing, ok := properties[key]; ok {
		if fmt.Sprint(existing) == fmt.Sprint(value) {
			return
		}
		for i := 2; ; i++ {
			candidate := fmt.Sprintf("%s_%d", key, i)
			if _, exists := properties[candidate]; !exists {
				properties[candidate] = value
				return
			}
		}
	}

	properties[key] = value
}

func setPropertyIfMissing(properties map[string]any, key string, value string) {
	key = sanitizeOpenGraphPropertyName(key)
	if key == "" || value == "" {
		return
	}
	if _, ok := properties[key]; ok {
		return
	}
	properties[key] = value
}

func setPropertyIfMissingArray(properties map[string]any, key string, values []string) {
	key = sanitizeOpenGraphPropertyName(key)
	if key == "" || len(values) == 0 {
		return
	}
	if _, ok := properties[key]; ok {
		return
	}
	properties[key] = values
}

func stringValue(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(typed)
	default:
		return strings.TrimSpace(fmt.Sprint(typed))
	}
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func primitiveStringSlice(value any) []string {
	switch typed := value.(type) {
	case []string:
		return append([]string(nil), typed...)
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			text, ok := item.(string)
			if !ok || strings.TrimSpace(text) == "" {
				continue
			}
			out = append(out, strings.TrimSpace(text))
		}
		return out
	default:
		return nil
	}
}
