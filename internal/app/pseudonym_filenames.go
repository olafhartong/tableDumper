package app

import "strings"

type linkedFilenameProfile struct {
	filenames   []linkedFilenameValue
	paths       []linkedFilenameValue
	commandLine []linkedFilenameValue
}

type linkedFilenameValue struct {
	field string
	value string
}

func (p *pseudonymizer) linkedFilenameOverrides(row map[string]any) map[string]string {
	if !p.filenamesEnabled() {
		return nil
	}

	profiles := make(map[string]*linkedFilenameProfile)
	for _, field := range sortedMapKeys(row) {
		value, ok := row[field].(string)
		if !ok || strings.TrimSpace(value) == "" {
			continue
		}
		family, role, ok := linkedFilenameField(field)
		if !ok {
			continue
		}
		profile := profiles[family]
		if profile == nil {
			profile = &linkedFilenameProfile{}
			profiles[family] = profile
		}
		entry := linkedFilenameValue{field: field, value: value}
		switch role {
		case "filename":
			if p.shouldPseudonymizeField(field) {
				profile.filenames = append(profile.filenames, entry)
			}
		case "path":
			if p.shouldPseudonymizeField(field) {
				profile.paths = append(profile.paths, entry)
			}
		case "commandline":
			profile.commandLine = append(profile.commandLine, entry)
		}
	}

	overrides := make(map[string]string)
	for _, profile := range profiles {
		if len(profile.filenames) == 0 {
			continue
		}
		original := pathLastComponent(profile.filenames[0].value)
		if original == "" {
			continue
		}
		replacement := p.replacement(entityFilename, original)
		for _, entry := range profile.filenames {
			overrides[entry.field], _ = p.pseudonymizeLinkedPathFilename(entry.field, entry.value, original, replacement, true)
		}
		for _, entry := range profile.paths {
			if converted, changed := p.pseudonymizeLinkedPathFilename(entry.field, entry.value, original, replacement, false); changed {
				overrides[entry.field] = converted
			}
		}
		for _, entry := range profile.commandLine {
			// Mask while the original executable is available for command-specific
			// options such as mysql -pPASSWORD, then link executable references.
			masked := maskSensitiveCommandLine(entry.value, row)
			if converted, changed := replaceRelatedCommandFilename(masked, original, replacement); changed || masked != entry.value {
				overrides[entry.field] = converted
			}
		}
	}
	return overrides
}

func linkedFilenameField(field string) (string, string, bool) {
	name := normalizeFieldName(field)
	for _, suffix := range []struct {
		value string
		role  string
	}{
		{"commandline", "commandline"},
		{"folderpath", "path"},
		{"filepath", "path"},
		{"fullpath", "path"},
		{"filename", "filename"},
	} {
		if !strings.HasSuffix(name, suffix.value) {
			continue
		}
		family := strings.TrimSuffix(name, suffix.value)
		if family == "" || family == "process" {
			family = "process"
		}
		return family, suffix.role, true
	}
	return "", "", false
}

func pathLastComponent(value string) string {
	_, start, end := pathLastComponentRange(value)
	if start == end {
		return ""
	}
	return value[start:end]
}

func pathLastComponentRange(value string) (bool, int, int) {
	end := len(value)
	for end > 0 && isPathSeparator(value[end-1]) {
		end--
	}
	start := end
	for start > 0 && !isPathSeparator(value[start-1]) {
		start--
	}
	return start > 0, start, end
}

// Plan the linked basename and the other path edits against the same original
// string, so no override skips path redaction or reprocesses a generated token.
func (p *pseudonymizer) pseudonymizeLinkedPathFilename(field, value, original, replacement string, replacePlain bool) (string, bool) {
	_, start, end := pathLastComponentRange(value)
	component := value[start:end]
	linked := ""
	for _, variant := range filenameReplacementVariants(original, replacement) {
		if strings.EqualFold(component, variant.original) {
			linked = variant.replacement
			break
		}
	}
	if linked == "" && replacePlain && !strings.ContainsAny(value, `/\`) {
		linked = replacement
	}
	var entities []recognizedEntity
	if linked != "" && start < end {
		entities = append(entities, recognizedEntity{Start: start, End: end, Kind: entityFilename, Text: component, Replacement: linked, Priority: 1})
	}
	return p.pseudonymizePathWithEntities(field, value, entities), len(entities) > 0
}

type filenameReplacementVariant struct {
	original    string
	replacement string
}

func filenameReplacementVariants(original, replacement string) []filenameReplacementVariant {
	variants := []filenameReplacementVariant{{original: original, replacement: replacement}}
	if strings.EqualFold(filenameExtension(original), ".exe") {
		variants = append(variants, filenameReplacementVariant{
			original:    original[:len(original)-4],
			replacement: strings.TrimSuffix(replacement, filenameExtension(replacement)),
		})
	}
	return variants
}

func filenameExtension(value string) string {
	component := pathLastComponent(value)
	index := strings.LastIndexByte(component, '.')
	if index <= 0 {
		return ""
	}
	return component[index:]
}

func replaceRelatedCommandFilename(value, original, replacement string) (string, bool) {
	changed := false
	for _, variant := range filenameReplacementVariants(original, replacement) {
		if variant.original == "" {
			continue
		}
		var builder strings.Builder
		last := 0
		for index := 0; index+len(variant.original) <= len(value); {
			end := index + len(variant.original)
			if strings.EqualFold(value[index:end], variant.original) && filenameTokenBoundary(value, index, end) {
				builder.WriteString(value[last:index])
				builder.WriteString(variant.replacement)
				last = end
				index = end
				changed = true
				continue
			}
			index++
		}
		if last > 0 {
			builder.WriteString(value[last:])
			value = builder.String()
		}
	}
	return value, changed
}

func filenameTokenBoundary(value string, start, end int) bool {
	return (start == 0 || !isFilenameTokenByte(value[start-1])) &&
		(end == len(value) || !isFilenameTokenByte(value[end]))
}

func isFilenameTokenByte(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' ||
		value >= '0' && value <= '9' || value == '_' || value == '-' || value == '.'
}
