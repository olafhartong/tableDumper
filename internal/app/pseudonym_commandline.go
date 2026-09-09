package app

import (
	"regexp"
	"sort"
	"strings"
)

var (
	sensitiveCommandKeyPattern = strings.Join([]string{
		`user`, `username`, `user[-_]?name`, `user[-_]?id`, `uid`, `login`, `login[-_]?name`,
		`password`, `passwd`, `pass`, `pwd`, `credential`, `credentials`,
		`api[-_]?key`, `apikey`, `access[-_]?key`, `secret[-_]?key`, `subscription[-_]?key`,
		`token`, `access[-_]?token`, `auth[-_]?token`, `bearer[-_]?token`, `oauth2[-_]?bearer`, `refresh[-_]?token`, `sas[-_]?token`,
		`github[-_]?token`, `personal[-_]?access[-_]?token`, `pat`,
		`app[-_]?id`, `appid`, `application[-_]?id`, `client[-_]?id`, `tenant[-_]?id`,
		`app[-_]?secret`, `appsecret`, `application[-_]?secret`, `client[-_]?secret`, `client[-_]?key`,
		`azure[-_]?client[-_]?id`, `azure[-_]?client[-_]?secret`, `azure[-_]?tenant[-_]?id`,
		`arm[-_]?client[-_]?id`, `arm[-_]?client[-_]?secret`, `arm[-_]?tenant[-_]?id`,
		`aws[-_]?access[-_]?key[-_]?id`, `aws[-_]?secret[-_]?access[-_]?key`, `aws[-_]?session[-_]?token`,
		`account[-_]?key`, `shared[-_]?access[-_]?key`, `shared[-_]?access[-_]?signature`,
		`sig`, `signature`,
	}, `|`)

	sensitiveSeparatedArgumentPattern = regexp.MustCompile(
		`(?i)(?:^|[\s])(?:--?|/)(?:` + sensitiveCommandKeyPattern + `)[\t ]+`,
	)
	sensitiveShortArgumentPattern         = regexp.MustCompile(`(?i)(?:^|[\s])-(?:u|p)[\t ]+`)
	sensitiveShortAssignedArgumentPattern = regexp.MustCompile(`(?i)(?:^|[\s])-(?:u|p)[\t ]*[:=][\t ]*`)
	sensitiveAssignedArgumentPattern      = regexp.MustCompile(
		`(?i)(?:^|[\s;&|?"'])(?:(?:--?|/)?(?:` + sensitiveCommandKeyPattern + `))[\t ]*[:=][\t ]*`,
	)
	sensitiveConnectionStringPattern = regexp.MustCompile(
		`(?i)(?:^|[;\s"'])(?:user[\t ]*id|username|uid|password|pwd|client[\t ]*id|client[\t ]*secret|app[\t ]*id|app[\t ]*secret|account[\t ]*key|shared[\t ]*access[\t ]*(?:key|signature))[\t ]*=[\t ]*`,
	)
	sensitiveJSONPropertyPattern = regexp.MustCompile(
		`(?i)(?:\\?["'])(?:` + sensitiveCommandKeyPattern + `)(?:\\?["'])[\t ]*:[\t ]*`,
	)
	sensitiveAttachedArgumentPattern = regexp.MustCompile(`(?:^|[\s])-[upU]`)
	mysqlCommandPattern              = regexp.MustCompile(`(?i)(?:^|[\s"'/\\])(?:mysql|mysqldump|mysqlsh|mariadb|mariadb-dump)(?:\.exe)?(?:[\s"']|$)`)
	curlCommandPattern               = regexp.MustCompile(`(?i)(?:^|[\s"'/\\])curl(?:\.exe)?(?:[\s"']|$)`)
	sensitiveAuthorizationPattern    = regexp.MustCompile(`(?i)(?:authorization[\t ]*[:=][\t ]*(?:\\?["'])?(?:bearer|basic)[\t ]+)`)
	sensitiveAPIHeaderPattern        = regexp.MustCompile(`(?i)(?:x-api-key|api-key|subscription-key)[\t ]*:[\t ]*`)
	urlUserInfoPattern               = regexp.MustCompile(`(?i)[a-z][a-z0-9+.-]*://([^/@\s]+)@`)
	jwtPattern                       = regexp.MustCompile(`\b(eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,})\b`)
	awsAccessKeyPattern              = regexp.MustCompile(`\b((?:AKIA|ASIA)[A-Z0-9]{16})\b`)
)

func sensitiveCommandLineOverrides(row map[string]any, existing map[string]string) map[string]string {
	overrides := make(map[string]string)
	for _, field := range sortedMapKeys(row) {
		if !strings.HasSuffix(normalizeFieldName(field), "commandline") {
			continue
		}
		value, ok := row[field].(string)
		if !ok || value == "" {
			continue
		}
		if replacement, ok := existing[field]; ok {
			value = replacement
		}
		masked := maskSensitiveCommandLine(value, row)
		if masked != value {
			overrides[field] = masked
		}
	}
	return overrides
}

func maskSensitiveCommandLine(value string, row map[string]any) string {
	value = maskCommandArgumentValues(value)
	for _, pattern := range []*regexp.Regexp{
		urlUserInfoPattern,
		jwtPattern,
		awsAccessKeyPattern,
	} {
		value = replaceCapturedCommandValues(value, pattern)
	}

	value = emailPattern.ReplaceAllString(value, "***")
	value = replaceRegexCapture(value, userHomePathPattern, 1, "***")
	return maskKnownCommandLineIdentities(value, row)
}

func replaceCapturedCommandValues(value string, pattern *regexp.Regexp) string {
	return replaceRegexCaptureFunc(value, pattern, 1, maskedCommandValue)
}

// Prefix detection identifies credentials; a scanner consumes their entire
// value, including escaped quotes and adjacent quoted/unquoted token fragments.
// All spans refer to the original command, avoiding offsets into edited text.
func maskCommandArgumentValues(value string) string {
	type span struct{ start, end int }
	var spans []span
	for _, pattern := range []*regexp.Regexp{
		sensitiveSeparatedArgumentPattern, sensitiveShortArgumentPattern,
		sensitiveShortAssignedArgumentPattern, sensitiveAssignedArgumentPattern,
		sensitiveConnectionStringPattern, sensitiveJSONPropertyPattern,
		sensitiveAuthorizationPattern, sensitiveAPIHeaderPattern,
	} {
		for _, match := range pattern.FindAllStringIndex(value, -1) {
			start := match[1]
			end := commandSecretEnd(value, start, pattern == sensitiveJSONPropertyPattern)
			if end > start {
				spans = append(spans, span{start, end})
			}
		}
	}
	// Attached short options are command-specific: for example MySQL's -P is
	// a port and unrelated programs may use -path or -port as ordinary options.
	mysql, curl := mysqlCommandPattern.MatchString(value), curlCommandPattern.MatchString(value)
	for _, match := range sensitiveAttachedArgumentPattern.FindAllStringIndex(value, -1) {
		start := match[1]
		option := value[start-1]
		if !(mysql && (option == 'u' || option == 'p') || curl && (option == 'u' || option == 'U')) || start == len(value) || strings.ContainsRune(" \t\r\n:=", rune(value[start])) {
			continue
		}
		end := commandSecretEnd(value, start, false)
		if end > start {
			spans = append(spans, span{start, end})
		}
	}
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].start == spans[j].start {
			return spans[i].end > spans[j].end
		}
		return spans[i].start < spans[j].start
	})
	var merged []span
	for _, s := range spans {
		if len(merged) > 0 && s.start < merged[len(merged)-1].end {
			if s.end > merged[len(merged)-1].end {
				merged[len(merged)-1].end = s.end
			}
		} else {
			merged = append(merged, s)
		}
	}
	var out strings.Builder
	last := 0
	for _, s := range merged {
		out.WriteString(value[last:s.start])
		out.WriteString(maskedCommandValue(value[s.start:s.end]))
		last = s.end
	}
	out.WriteString(value[last:])
	return out.String()
}

func commandSecretEnd(value string, start int, jsonProperty bool) int {
	if jsonProperty && start+1 < len(value) && value[start] == '\\' && isCommandQuote(value[start+1]) {
		// Escaped JSON delimiters use one backslash. An internal escaped quote
		// has more backslashes and must not end the value.
		quote := value[start+1]
		for i := start + 2; i < len(value); i++ {
			if value[i] != '\\' {
				continue
			}
			j := i
			for j < len(value) && value[j] == '\\' {
				j++
			}
			if j < len(value) && value[j] == quote && j-i == 1 {
				return j + 1
			}
			i = j
		}
		return len(value)
	}
	outer := commandQuoteContext(value[:start])
	var quote byte
	for i := start; i < len(value); i++ {
		ch := value[i]
		if (ch == '\\' || ch == '`') && i+1 < len(value) {
			i++
			continue
		}
		if quote != 0 {
			if ch == quote {
				if i+1 < len(value) && value[i+1] == quote {
					i++
					continue
				}
				quote = 0
				if jsonProperty {
					return i + 1
				}
			}
			continue
		}
		if strings.ContainsRune(" \t\r\n;&|", rune(ch)) || jsonProperty && strings.ContainsRune(",}", rune(ch)) {
			return i
		}
		if isCommandQuote(ch) {
			if outer == ch {
				return i
			}
			quote = ch
		}
	}
	return len(value)
}

func commandQuoteContext(prefix string) byte {
	var quote byte
	for i := 0; i < len(prefix); i++ {
		ch := prefix[i]
		if (ch == '\\' || ch == '`') && i+1 < len(prefix) {
			i++
			continue
		}
		if quote != 0 {
			if ch == quote {
				quote = 0
			}
		} else if isCommandQuote(ch) {
			quote = ch
		}
	}
	return quote
}

func isCommandQuote(ch byte) bool { return ch == '"' || ch == '\'' }

func maskedCommandValue(value string) string {
	if len(value) >= 4 && value[0] == '\\' && (value[1] == '"' || value[1] == '\'') && value[len(value)-2] == '\\' && value[len(value)-1] == value[1] {
		return value[:2] + "***" + value[len(value)-2:]
	}
	if len(value) >= 2 {
		if value[0] == '"' && value[len(value)-1] == '"' || value[0] == '\'' && value[len(value)-1] == '\'' {
			return value[:1] + "***" + value[len(value)-1:]
		}
	}
	return "***"
}

func replaceRegexCapture(value string, pattern *regexp.Regexp, group int, replacement string) string {
	return replaceRegexCaptureFunc(value, pattern, group, func(string) string { return replacement })
}

func replaceRegexCaptureFunc(value string, pattern *regexp.Regexp, group int, replacement func(string) string) string {
	matches := pattern.FindAllStringSubmatchIndex(value, -1)
	if len(matches) == 0 {
		return value
	}
	var builder strings.Builder
	last := 0
	for _, match := range matches {
		capture := group * 2
		if capture+1 >= len(match) || match[capture] < last {
			continue
		}
		start, end := match[capture], match[capture+1]
		builder.WriteString(value[last:start])
		builder.WriteString(replacement(value[start:end]))
		last = end
	}
	if last == 0 {
		return value
	}
	builder.WriteString(value[last:])
	return builder.String()
}

func maskKnownCommandLineIdentities(value string, row map[string]any) string {
	identities := make(map[string]string)
	for _, field := range sortedMapKeys(row) {
		text, ok := row[field].(string)
		if !ok || strings.TrimSpace(text) == "" {
			continue
		}
		_, kind, linked := linkedIdentityField(field)
		if !linked || kind != entityUsername && kind != entityEmail {
			continue
		}
		addSensitiveIdentity(identities, text)
		if local, _, ok := splitEmail(text); ok {
			addSensitiveIdentity(identities, local)
		}
		if _, username, ok := splitWindowsAccount(text); ok {
			addSensitiveIdentity(identities, username)
		}
	}

	ordered := make([]string, 0, len(identities))
	for identity := range identities {
		ordered = append(ordered, identity)
	}
	sort.Slice(ordered, func(i, j int) bool {
		if len(ordered[i]) == len(ordered[j]) {
			return ordered[i] < ordered[j]
		}
		return len(ordered[i]) > len(ordered[j])
	})
	for _, identity := range ordered {
		value, _ = replaceSensitiveIdentity(value, identity)
	}
	return value
}

func addSensitiveIdentity(identities map[string]string, value string) {
	value = strings.TrimSpace(value)
	if value != "" {
		identities[strings.ToLower(value)] = value
	}
}

func replaceSensitiveIdentity(value, identity string) (string, bool) {
	changed := false
	var builder strings.Builder
	last := 0
	for index := 0; index+len(identity) <= len(value); {
		end := index + len(identity)
		if strings.EqualFold(value[index:end], identity) && identityTokenBoundary(value, index, end) {
			builder.WriteString(value[last:index])
			builder.WriteString("***")
			last = end
			index = end
			changed = true
			continue
		}
		index++
	}
	if !changed {
		return value, false
	}
	builder.WriteString(value[last:])
	return builder.String(), true
}

func identityTokenBoundary(value string, start, end int) bool {
	return (start == 0 || !isIdentityTokenByte(value[start-1])) &&
		(end == len(value) || !isIdentityTokenByte(value[end]))
}

func isIdentityTokenByte(value byte) bool {
	return isFilenameTokenByte(value) || value == '@'
}
