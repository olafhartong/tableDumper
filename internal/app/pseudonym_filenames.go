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
			overrides[entry.field] = replaceRelatedPathFilename(entry.value, original, replacement, true)
		}
		for _, entry := range profile.paths {
			if converted, changed := replaceRelatedPathFilenameIfPresent(entry.value, original, replacement); changed {
				overrides[entry.field] = converted
			}
		}
		for _, entry := range profile.commandLine {
			if converted, changed := replaceRelatedCommandFilename(entry.value, original, replacement); changed {
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

func replaceRelatedPathFilename(value, original, replacement string, replacePlain bool) string {
	converted, changed := replaceRelatedPathFilenameIfPresent(value, original, replacement)
	if changed {
		return converted
	}
	if replacePlain && !strings.ContainsAny(value, `/\`) {
		return replacement
	}
	return value
}

func replaceRelatedPathFilenameIfPresent(value, original, replacement string) (string, bool) {
	_, start, end := pathLastComponentRange(value)
	if start == end {
		return value, false
	}
	component := value[start:end]
	for _, variant := range filenameReplacementVariants(original, replacement) {
		if strings.EqualFold(component, variant.original) {
			return value[:start] + variant.replacement + value[end:], true
		}
	}
	return value, false
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
