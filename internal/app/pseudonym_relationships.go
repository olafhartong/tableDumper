package app

import (
	"sort"
	"strings"
)

// Identity fields in security schemas commonly describe one account using
// several identifiers: a SAM account name, UPN, display name, and domain. The
// source strings need not be textual aliases of each other, so value-only
// pseudonymization cannot preserve that relationship. These profiles use the
// semantic field prefix (Account, InitiatingProcessAccount, SenderFrom, etc.)
// to link the values before the row is transformed.
type linkedIdentityProfile struct {
	key       string
	fields    []linkedIdentityFieldValue
	people    []string
	usernames []string
	emails    []string
	domains   []string
}

type linkedIdentityFieldValue struct {
	field string
	kind  entityKind
	value string
}

type linkedIdentityReplacement struct {
	person   string
	username string
	domain   string
}

type linkedDeviceValue struct {
	value       string
	mappingKind entityKind
	host        string
	domain      string
}

type linkedDeviceProfile struct {
	hosts   []linkedDeviceValue
	domains []string
}

func (p *pseudonymizer) primeEntityRelationships(row map[string]any) map[string]string {
	overrides := p.primeLinkedIdentities(row)
	p.primeLinkedDevices(row, preferredDeviceDomain(row, overrides))
	return overrides
}

func preferredDeviceDomain(row map[string]any, identityOverrides map[string]string) string {
	for _, wanted := range []string{"accountdomain", "initiatingprocessaccountdomain"} {
		for _, field := range sortedMapKeys(row) {
			if normalizeFieldName(field) == wanted {
				return strings.TrimSpace(identityOverrides[field])
			}
		}
	}
	return ""
}

func (p *pseudonymizer) primeLinkedIdentities(row map[string]any) map[string]string {
	profiles := make(map[string]*linkedIdentityProfile)
	for _, field := range sortedMapKeys(row) {
		if !p.shouldPseudonymizeField(field) {
			continue
		}
		value, ok := row[field].(string)
		if !ok {
			continue
		}
		group, kind, ok := linkedIdentityField(field)
		if !ok {
			continue
		}
		profile := profiles[group]
		if profile == nil {
			profile = &linkedIdentityProfile{key: group}
			profiles[group] = profile
		}
		profile.fields = append(profile.fields, linkedIdentityFieldValue{field: field, kind: kind, value: value})
		if strings.TrimSpace(value) == "" {
			continue
		}
		switch kind {
		case entityPerson:
			profile.people = append(profile.people, value)
		case entityUsername:
			profile.usernames = append(profile.usernames, value)
		case entityEmail:
			if local, domain, ok := splitEmail(value); ok {
				profile.emails = append(profile.emails, value)
				profile.usernames = append(profile.usernames, local)
				profile.domains = append(profile.domains, domain)
			}
		case entityDomain:
			profile.domains = append(profile.domains, value)
		}
	}

	groups := make([]string, 0, len(profiles))
	for group := range profiles {
		groups = append(groups, group)
	}
	sort.Strings(groups)

	p.mu.Lock()
	defer p.mu.Unlock()
	overrides := make(map[string]string)
	for _, group := range groups {
		profile := profiles[group]
		if !profileHasIdentityField(profile) {
			continue
		}
		replacement := p.linkIdentityProfileLocked(profile)
		for _, field := range profile.fields {
			switch field.kind {
			case entityPerson:
				overrides[field.field] = replacement.person
			case entityEmail:
				overrides[field.field] = replacement.username + "@" + replacement.domain
			case entityDomain:
				overrides[field.field] = replacement.domain
			case entityUsername:
				if _, _, composite := splitWindowsAccount(field.value); composite {
					overrides[field.field] = replacement.domain + `\` + replacement.username
				} else {
					overrides[field.field] = replacement.username
				}
			}
		}
	}
	return overrides
}

func profileHasIdentityField(profile *linkedIdentityProfile) bool {
	for _, field := range profile.fields {
		if field.kind == entityPerson || field.kind == entityUsername || field.kind == entityEmail {
			return true
		}
	}
	return false
}

func (p *pseudonymizer) linkIdentityProfileLocked(profile *linkedIdentityProfile) linkedIdentityReplacement {
	profile.people = uniqueSortedStrings(profile.people)
	profile.usernames = uniqueSortedStrings(profile.usernames)
	profile.emails = uniqueSortedStrings(profile.emails)
	profile.domains = uniqueSortedStrings(profile.domains)

	fakeUsername := p.existingLinkedUsernameLocked(profile)
	if fakeUsername == "" {
		source := firstUsernameComponent(profile.usernames)
		if source == "" && len(profile.people) > 0 {
			source = identityAlias(profile.people[0])
		}
		if source == "" {
			source = linkedIdentityFallbackSource(profile)
		}
		fakeUsername = p.replacementLocked(entityUsername, source)
	}

	fakeDomain := p.existingLinkedDomainLocked(profile)
	if fakeDomain == "" && len(profile.domains) > 0 {
		// The sorted first value is a deterministic canonical domain for every
		// alias observed in this semantic field family.
		fakeDomain = p.replacementLocked(entityDomain, profile.domains[0])
	}
	if fakeDomain == "" {
		fakeDomain = p.replacementLocked(entityDomain, "linked-identity-domain:"+linkedIdentityFallbackSource(profile))
	}

	for _, original := range profile.usernames {
		if domain, username, ok := splitWindowsAccount(original); ok {
			p.forceLinkedReplacementLocked(entityUsername, username, fakeUsername)
			if fakeDomain != "" {
				p.forceLinkedReplacementLocked(entityDomain, domain, fakeDomain)
				p.forceLinkedReplacementLocked(entityUsername, original, fakeDomain+`\`+fakeUsername)
			} else {
				p.forceLinkedReplacementLocked(entityUsername, original, p.replacementLocked(entityDomain, domain)+`\`+fakeUsername)
			}
			continue
		}
		p.forceLinkedReplacementLocked(entityUsername, original, fakeUsername)
	}
	for _, original := range profile.domains {
		if fakeDomain != "" {
			p.forceLinkedReplacementLocked(entityDomain, original, fakeDomain)
		}
	}
	for _, original := range profile.emails {
		local, domain, ok := splitEmail(original)
		if !ok {
			continue
		}
		p.forceLinkedReplacementLocked(entityUsername, local, fakeUsername)
		domainReplacement := fakeDomain
		if domainReplacement == "" {
			domainReplacement = p.replacementLocked(entityDomain, domain)
		}
		p.forceLinkedReplacementLocked(entityDomain, domain, domainReplacement)
		p.forceLinkedReplacementLocked(entityEmail, original, fakeUsername+"@"+domainReplacement)
	}
	fakePerson := displayNameFromUsername(fakeUsername)
	for _, original := range profile.people {
		p.forceLinkedReplacementLocked(entityPerson, original, fakePerson)
	}
	return linkedIdentityReplacement{person: fakePerson, username: fakeUsername, domain: fakeDomain}
}

func linkedIdentityFallbackSource(profile *linkedIdentityProfile) string {
	for _, values := range [][]string{profile.usernames, profile.people, profile.domains, profile.emails} {
		if len(values) > 0 {
			return profile.key + ":" + values[0]
		}
	}
	return profile.key + ":missing"
}

func (p *pseudonymizer) existingLinkedUsernameLocked(profile *linkedIdentityProfile) string {
	for _, original := range profile.usernames {
		if mapping, ok := p.mappings[entityKey(entityUsername, original)]; ok {
			candidate := mapping.Pseudonym
			if _, username, composite := splitWindowsAccount(candidate); composite {
				candidate = username
			}
			if candidate != "" {
				return candidate
			}
		}
		if _, username, composite := splitWindowsAccount(original); composite {
			if mapping, ok := p.mappings[entityKey(entityUsername, username)]; ok {
				return mapping.Pseudonym
			}
		}
	}
	for _, original := range profile.emails {
		if mapping, ok := p.mappings[entityKey(entityEmail, original)]; ok {
			if local, _, ok := splitEmail(mapping.Pseudonym); ok {
				return local
			}
		}
	}
	for _, original := range profile.people {
		if mapping, ok := p.mappings[entityKey(entityPerson, original)]; ok {
			return usernameFromDisplayName(mapping.Pseudonym)
		}
	}
	return ""
}

func (p *pseudonymizer) existingLinkedDomainLocked(profile *linkedIdentityProfile) string {
	for _, original := range profile.domains {
		if mapping, ok := p.mappings[entityKey(entityDomain, original)]; ok {
			return mapping.Pseudonym
		}
	}
	for _, original := range profile.emails {
		if mapping, ok := p.mappings[entityKey(entityEmail, original)]; ok {
			if _, domain, ok := splitEmail(mapping.Pseudonym); ok {
				return domain
			}
		}
	}
	return ""
}

func linkedIdentityField(field string) (string, entityKind, bool) {
	name := normalizeFieldName(field)
	kind := entityKindForField(field)
	switch kind {
	case entityPerson:
		switch {
		case strings.HasSuffix(name, "accountdisplayname"):
			return strings.TrimSuffix(name, "accountdisplayname") + "account", kind, true
		case strings.HasSuffix(name, "userdisplayname"):
			return strings.TrimSuffix(name, "userdisplayname") + "user", kind, true
		case name == "senderdisplayname", strings.HasSuffix(name, "senderfromdisplayname"):
			return "senderfrom", kind, true
		case strings.HasSuffix(name, "recipientdisplayname"):
			return strings.TrimSuffix(name, "recipientdisplayname") + "recipient", kind, true
		case strings.HasSuffix(name, "displayname"):
			return strings.TrimSuffix(name, "displayname"), kind, true
		default:
			return name, kind, true
		}
	case entityUsername:
		for _, suffix := range []struct{ suffix, replacement string }{
			{"accountname", "account"}, {"username", "user"}, {"useraccount", "user"},
			{"loginname", "user"}, {"actorprincipalname", "actor"},
		} {
			if strings.HasSuffix(name, suffix.suffix) {
				return strings.TrimSuffix(name, suffix.suffix) + suffix.replacement, kind, true
			}
		}
		return name, kind, true
	case entityEmail:
		for _, suffix := range []struct{ suffix, replacement string }{
			{"userprincipalname", "user"}, {"userprincipal", "user"},
			{"emailaddress", ""}, {"mailaddress", ""}, {"mailaddresses", ""},
			{"email", ""}, {"upn", ""}, {"address", ""},
		} {
			if strings.HasSuffix(name, suffix.suffix) {
				group := strings.TrimSuffix(name, suffix.suffix) + suffix.replacement
				if group == "sender" {
					group = "senderfrom"
				}
				return group, kind, true
			}
		}
	case entityDomain:
		for _, suffix := range []struct{ suffix, replacement string }{
			{"accountdomain", "account"}, {"userdomain", "user"}, {"domain", ""},
		} {
			if strings.HasSuffix(name, suffix.suffix) {
				return strings.TrimSuffix(name, suffix.suffix) + suffix.replacement, kind, true
			}
		}
	}
	return "", "", false
}

func (p *pseudonymizer) primeLinkedDevices(row map[string]any, preferredDomain string) {
	profiles := make(map[string]*linkedDeviceProfile)
	for _, field := range sortedMapKeys(row) {
		if !p.shouldPseudonymizeField(field) {
			continue
		}
		value, ok := row[field].(string)
		if !ok || strings.TrimSpace(value) == "" {
			continue
		}
		group, component, mappingKind, ok := linkedDeviceField(field)
		if !ok {
			continue
		}
		profile := profiles[group]
		if profile == nil {
			profile = &linkedDeviceProfile{}
			profiles[group] = profile
		}
		if component == entityDomain {
			profile.domains = append(profile.domains, value)
			continue
		}
		host, domain := splitHostname(value)
		profile.hosts = append(profile.hosts, linkedDeviceValue{value: value, mappingKind: mappingKind, host: host, domain: domain})
		if domain != "" {
			profile.domains = append(profile.domains, domain)
		}
	}

	groups := make([]string, 0, len(profiles))
	for group := range profiles {
		groups = append(groups, group)
	}
	sort.Strings(groups)
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, group := range groups {
		p.linkDeviceProfileLocked(profiles[group], preferredDomain)
	}
}

func (p *pseudonymizer) linkDeviceProfileLocked(profile *linkedDeviceProfile, preferredDomain string) {
	if len(profile.hosts) == 0 {
		return
	}
	profile.domains = uniqueSortedStrings(profile.domains)
	fakeHost := ""
	for _, host := range profile.hosts {
		if mapping, ok := p.mappings[entityKey(host.mappingKind, host.value)]; ok {
			fakeHost, _ = splitHostname(mapping.Pseudonym)
			break
		}
		if mapping, ok := p.mappings[entityKey(entityHostname, host.host)]; ok {
			fakeHost = mapping.Pseudonym
			break
		}
	}
	if fakeHost == "" {
		fakeHost = p.replacementLocked(entityHostname, profile.hosts[0].host)
	}
	fakeDomain := strings.TrimSpace(preferredDomain)
	if fakeDomain == "" {
		for _, domain := range profile.domains {
			if mapping, ok := p.mappings[entityKey(entityDomain, domain)]; ok {
				fakeDomain = mapping.Pseudonym
				break
			}
		}
	}
	if fakeDomain == "" && len(profile.domains) > 0 {
		fakeDomain = p.replacementLocked(entityDomain, profile.domains[0])
	}
	for _, host := range profile.hosts {
		p.forceLinkedReplacementLocked(entityHostname, host.host, fakeHost)
		candidate := fakeHost
		if host.domain != "" && fakeDomain != "" {
			candidate += "." + fakeDomain
		}
		p.forceLinkedReplacementLocked(host.mappingKind, host.value, candidate)
	}
	for _, domain := range profile.domains {
		if fakeDomain != "" {
			p.forceLinkedReplacementLocked(entityDomain, domain, fakeDomain)
		}
	}
}

func linkedDeviceField(field string) (string, entityKind, entityKind, bool) {
	name := normalizeFieldName(field)
	kind := entityKindForField(field)
	deviceMarker := strings.Contains(name, "device") || strings.Contains(name, "computer") || strings.Contains(name, "machine") || strings.Contains(name, "workstation") || strings.Contains(name, "hostname") || strings.Contains(name, "dvc")
	if !deviceMarker {
		return "", "", "", false
	}
	if strings.HasSuffix(name, "fqdn") {
		return strings.TrimSuffix(name, "fqdn"), entityHostname, kind, true
	}
	if kind == entityHostname {
		for _, suffix := range []struct{ suffix, replacement string }{
			{"devicename", "device"}, {"computername", "computer"}, {"machinename", "machine"},
			{"workstationname", "workstation"}, {"hostname", "host"},
		} {
			if strings.HasSuffix(name, suffix.suffix) {
				return strings.TrimSuffix(name, suffix.suffix) + suffix.replacement, entityHostname, kind, true
			}
		}
		return name, entityHostname, kind, true
	}
	if kind == entityDomain {
		for _, suffix := range []string{"dnsdomain", "domain"} {
			if strings.HasSuffix(name, suffix) {
				return strings.TrimSuffix(name, suffix), entityDomain, kind, true
			}
		}
	}
	return "", "", "", false
}

func (p *pseudonymizer) forceLinkedReplacementLocked(kind entityKind, original, candidate string) string {
	if strings.TrimSpace(original) == "" || strings.TrimSpace(candidate) == "" {
		return original
	}
	key := entityKey(kind, original)
	if mapping, ok := p.mappings[key]; ok && mapping.Pseudonym == candidate {
		return candidate
	} else if ok {
		p.releaseUsedPseudonymLocked(key, mapping.Pseudonym)
	}
	p.mappings[key] = pseudonymMapping{EntityType: string(kind), Original: original, Pseudonym: candidate}
	if _, exists := p.used[strings.ToLower(candidate)]; !exists {
		p.used[strings.ToLower(candidate)] = key
	}
	return candidate
}

func (p *pseudonymizer) releaseUsedPseudonymLocked(key, pseudonym string) {
	usedKey := strings.ToLower(pseudonym)
	if p.used[usedKey] != key {
		return
	}
	delete(p.used, usedKey)
	for otherKey, mapping := range p.mappings {
		if otherKey != key && strings.EqualFold(mapping.Pseudonym, pseudonym) {
			p.used[usedKey] = otherKey
			return
		}
	}
}

func linkedAliasesMaySharePseudonym(kind entityKind, originalKey string) bool {
	separator := strings.IndexByte(originalKey, 0)
	if separator < 0 || entityKind(originalKey[:separator]) != kind {
		return false
	}
	switch kind {
	case entityPerson, entityUsername, entityEmail, entityDomain, entityHostname:
		return true
	default:
		return false
	}
}

func sortedMapKeys(row map[string]any) []string {
	keys := make([]string, 0, len(row))
	for key := range row {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func uniqueSortedStrings(values []string) []string {
	seen := make(map[string]string, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, exists := seen[key]; !exists {
			seen[key] = value
		}
	}
	keys := make([]string, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		out = append(out, seen[key])
	}
	return out
}

func firstUsernameComponent(values []string) string {
	for _, value := range values {
		if _, username, ok := splitWindowsAccount(value); ok {
			return username
		}
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func splitWindowsAccount(value string) (string, string, bool) {
	domain, username, ok := strings.Cut(strings.TrimSpace(value), `\`)
	return domain, username, ok && domain != "" && username != "" && !strings.Contains(username, `\`)
}

func splitEmail(value string) (string, string, bool) {
	local, domain, ok := strings.Cut(strings.TrimSpace(value), "@")
	return local, domain, ok && local != "" && domain != "" && !strings.Contains(domain, "@")
}

func splitHostname(value string) (string, string) {
	host, domain, ok := strings.Cut(strings.TrimSuffix(strings.TrimSpace(value), "."), ".")
	if !ok || host == "" || !domainPattern.MatchString(domain) {
		return strings.TrimSpace(value), ""
	}
	return host, domain
}
