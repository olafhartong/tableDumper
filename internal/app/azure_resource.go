package app

import (
	"regexp"
	"strings"
)

const azureResourceIDPriority = 200

var azureResourceIDCandidatePattern = regexp.MustCompile(`(?i)/subscriptions/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/[^\s"'<>]+`)

type azureResourceNamePart struct {
	typeIndex int
	nameIndex int
}

type azureResourceIDParts struct {
	segments           []string
	subscriptionIndex  int
	resourceGroupIndex int
	resourceNames      []azureResourceNamePart
}

func parseAzureResourceID(value string) (azureResourceIDParts, bool) {
	segments := strings.Split(value, "/")
	if len(segments) < 3 || segments[0] != "" || !strings.EqualFold(segments[1], "subscriptions") || !isExactGUID(segments[2]) {
		return azureResourceIDParts{}, false
	}

	parts := azureResourceIDParts{
		segments:           append([]string(nil), segments...),
		subscriptionIndex:  2,
		resourceGroupIndex: -1,
	}
	index := 3
	if index == len(segments) {
		return parts, true
	}
	if index < len(segments) && strings.EqualFold(segments[index], "resourceGroups") {
		if index+1 >= len(segments) || segments[index+1] == "" {
			return azureResourceIDParts{}, false
		}
		parts.resourceGroupIndex = index + 1
		index += 2
	}
	if index == len(segments) {
		return parts, true
	}
	if index+3 >= len(segments) || !strings.EqualFold(segments[index], "providers") || segments[index+1] == "" {
		return azureResourceIDParts{}, false
	}
	index += 2

	for index < len(segments) {
		if strings.EqualFold(segments[index], "providers") {
			if index+3 >= len(segments) || segments[index+1] == "" {
				return azureResourceIDParts{}, false
			}
			index += 2
			continue
		}
		if index+1 >= len(segments) || segments[index] == "" || segments[index+1] == "" {
			return azureResourceIDParts{}, false
		}
		parts.resourceNames = append(parts.resourceNames, azureResourceNamePart{typeIndex: index, nameIndex: index + 1})
		index += 2
	}
	return parts, true
}

func isExactGUID(value string) bool {
	indices := guidPattern.FindStringIndex(value)
	return len(indices) == 2 && indices[0] == 0 && indices[1] == len(value)
}

func recognizeAzureResourceIDEntities(value string) []recognizedEntity {
	entities := make([]recognizedEntity, 0)
	for _, indices := range azureResourceIDCandidatePattern.FindAllStringIndex(value, -1) {
		candidate := strings.TrimRight(value[indices[0]:indices[1]], ".,;:)]}")
		if candidate == "" {
			continue
		}
		if _, ok := parseAzureResourceID(candidate); !ok {
			continue
		}
		entities = append(entities, recognizedEntity{
			Start:    indices[0],
			End:      indices[0] + len(candidate),
			Kind:     entityAzureResourceID,
			Text:     candidate,
			Priority: azureResourceIDPriority,
		})
	}
	return entities
}

func (p *pseudonymizer) pseudonymizeAzureResourceID(value string) (string, bool) {
	parts, ok := parseAzureResourceID(value)
	if !ok {
		return "", false
	}
	if existing, ok := p.existingReplacement(entityAzureResourceID, value); ok {
		return existing, true
	}

	parts.segments[parts.subscriptionIndex] = p.replacement(entityIdentifier, parts.segments[parts.subscriptionIndex])
	if parts.resourceGroupIndex >= 0 {
		parts.segments[parts.resourceGroupIndex] = p.replacement(entityAzureResourceGroup, parts.segments[parts.resourceGroupIndex])
	}
	for _, resource := range parts.resourceNames {
		kind := azureResourceNameKind(parts.segments[resource.typeIndex], parts.segments[resource.nameIndex])
		parts.segments[resource.nameIndex] = p.replacement(kind, parts.segments[resource.nameIndex])
	}

	pseudonym := strings.Join(parts.segments, "/")
	return p.recordStructuralReplacement(entityAzureResourceID, value, pseudonym), true
}

func azureResourceNameKind(resourceType, resourceName string) entityKind {
	if isExactGUID(resourceName) {
		return entityIdentifier
	}
	switch strings.ToLower(resourceType) {
	case "machine", "machines", "virtualmachine", "virtualmachines", "computer", "computers", "device", "devices", "host", "hosts", "server", "servers":
		return entityHostname
	default:
		return entityAzureResourceName
	}
}

func (p *pseudonymizer) existingReplacement(kind entityKind, original string) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	mapping, ok := p.mappings[entityKey(kind, original)]
	return mapping.Pseudonym, ok
}

func (p *pseudonymizer) recordStructuralReplacement(kind entityKind, original, pseudonym string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	key := entityKey(kind, original)
	if mapping, ok := p.mappings[key]; ok {
		return mapping.Pseudonym
	}
	p.mappings[key] = pseudonymMapping{EntityType: string(kind), Original: original, Pseudonym: pseudonym}
	if _, exists := p.used[strings.ToLower(pseudonym)]; !exists {
		p.used[strings.ToLower(pseudonym)] = key
	}
	return pseudonym
}
