package app

import (
	"regexp"
	"sort"
	"strings"
)

const sensitiveCommandValuePattern = `("[^"]*"|'[^']*'|[^\s;&|"']+)`

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
		`(?i)(?:^|[\s])(?:--?|/)(?:` + sensitiveCommandKeyPattern + `)[\t ]+` + sensitiveCommandValuePattern,
	)
	sensitiveShortArgumentPattern = regexp.MustCompile(
		`(?i)(?:^|[\s])-(?:u|p)[\t ]+` + sensitiveCommandValuePattern,
	)
	sensitiveShortAssignedArgumentPattern = regexp.MustCompile(
		`(?i)(?:^|[\s])-(?:u|p)[\t ]*[:=][\t ]*` + sensitiveCommandValuePattern,
	)
	sensitiveAssignedArgumentPattern = regexp.MustCompile(
		`(?i)(?:^|[\s;&|?])(?:(?:--?|/)?(?:` + sensitiveCommandKeyPattern + `))[\t ]*[:=][\t ]*` + sensitiveCommandValuePattern,
	)
	sensitiveConnectionStringPattern = regexp.MustCompile(
		`(?i)(?:^|[;\s])(?:user[\t ]*id|username|uid|password|pwd|client[\t ]*id|client[\t ]*secret|app[\t ]*id|app[\t ]*secret|account[\t ]*key|shared[\t ]*access[\t ]*(?:key|signature))[\t ]*=[\t ]*` + sensitiveCommandValuePattern,
	)
	sensitiveJSONPropertyPattern = regexp.MustCompile(
		`(?i)(?:\\?["'])(?:` + sensitiveCommandKeyPattern + `)(?:\\?["'])[\t ]*:[\t ]*(\\?"[^"]*\\?"|\\?'[^']*\\?')`,
	)
	sensitiveAuthorizationPattern = regexp.MustCompile(`(?i)(?:authorization[\t ]*[:=][\t ]*(?:\\?["'])?(?:bearer|basic)[\t ]+)([^"'\s;,]+)`)
	sensitiveAPIHeaderPattern     = regexp.MustCompile(`(?i)(?:x-api-key|api-key|subscription-key)[\t ]*:[\t ]*([^"'\s;,]+)`)
	urlUserInfoPattern            = regexp.MustCompile(`(?i)[a-z][a-z0-9+.-]*://([^/@\s]+)@`)
	jwtPattern                    = regexp.MustCompile(`\b(eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,})\b`)
	awsAccessKeyPattern           = regexp.MustCompile(`\b((?:AKIA|ASIA)[A-Z0-9]{16})\b`)
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
	for _, pattern := range []*regexp.Regexp{
		sensitiveSeparatedArgumentPattern,
		sensitiveShortArgumentPattern,
		sensitiveShortAssignedArgumentPattern,
		sensitiveAssignedArgumentPattern,
		sensitiveConnectionStringPattern,
		sensitiveJSONPropertyPattern,
		sensitiveAuthorizationPattern,
		sensitiveAPIHeaderPattern,
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
