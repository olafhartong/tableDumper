package app

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/mail"
	"strings"
)

func isMailboxCollectionField(field string) bool {
	name := normalizeFieldName(field)
	return strings.HasSuffix(name, "mailaddresses") || strings.HasSuffix(name, "accountupns") ||
		name == "to" || name == "cc" || name == "bcc" || name == "distributionlist" ||
		name == "emailtorecipients" || name == "emailccrecipients" || name == "emailbccrecipients" ||
		name == "sipproxyaddress"
}

func mailboxEmails(value any) []string {
	switch v := value.(type) {
	case string:
		return emailPattern.FindAllString(v, -1)
	case []any:
		var out []string
		for _, child := range v {
			out = append(out, mailboxEmails(child)...)
		}
		return out
	case []string:
		var out []string
		for _, child := range v {
			out = append(out, mailboxEmails(child)...)
		}
		return out
	case map[string]any:
		var out []string
		for _, key := range sortedMapKeys(v) {
			out = append(out, mailboxEmails(v[key])...)
		}
		return out
	}
	return nil
}

// A selected mailbox container carries selection into its scalar members, but
// does not turn unrelated metadata (counts, types, IDs) into identity fields.
func (p *pseudonymizer) pseudonymizeMailboxCollection(ctx context.Context, value any) (any, error) {
	switch v := value.(type) {
	case string:
		if decoded, ok := decodeJSONObject(v); ok {
			converted, err := p.pseudonymizeMailboxCollection(ctx, decoded)
			if err != nil {
				return nil, err
			}
			body, err := json.Marshal(converted)
			return string(body), err
		}
		// Parse display-name forms before replacing spans. Each mailbox has
		// its own profile; multiple recipients must never become aliases.
		entities := p.wordReplacements.Recognize(v)
		if addresses, err := mail.ParseAddressList(v); err == nil {
			for _, address := range addresses {
				if address.Name == "" {
					continue
				}
				p.linkMailbox(address.Address, address.Name)
				for start := 0; start < len(v); {
					i := strings.Index(v[start:], address.Name)
					if i < 0 {
						break
					}
					i += start
					entities = append(entities, recognizedEntity{Start: i, End: i + len(address.Name), Kind: entityPerson, Text: address.Name})
					start = i + len(address.Name)
				}
			}
		}
		entities = appendPatternEntities(entities, v, emailPattern, entityEmail, nil)
		if len(entities) == 0 && strings.TrimSpace(v) != "" && !strings.Contains(v, "@") && !strings.Contains(v, ":") {
			// Distribution lists can be names instead of SMTP addresses.
			return p.replacement(entityUsername, v), nil
		}
		return p.replaceEntities(v, entities), nil
	case []any:
		out := make([]any, len(v))
		for i, child := range v {
			converted, err := p.pseudonymizeMailboxCollection(ctx, child)
			if err != nil {
				return nil, err
			}
			out[i] = converted
		}
		return out, nil
	case []string:
		out := make([]string, len(v))
		for i, child := range v {
			converted, err := p.pseudonymizeMailboxCollection(ctx, child)
			if err != nil {
				return nil, err
			}
			out[i] = converted.(string)
		}
		return out, nil
	case map[string]any:
		address := firstMapString(v, "EmailAddress", "Address", "Email", "Upn")
		name := firstMapString(v, "DisplayName", "Name")
		if isExactEmail(address) && name != "" {
			p.linkMailbox(address, name)
		}
		out := make(map[string]any, len(v))
		for _, key := range sortedMapKeys(v) {
			child := v[key]
			switch normalizeFieldName(key) {
			case "address", "emailaddress", "email", "upn", "recipients", "to", "cc", "bcc":
				converted, err := p.pseudonymizeMailboxCollection(ctx, child)
				if err != nil {
					return nil, err
				}
				out[key] = converted
			case "displayname", "name":
				if text, ok := child.(string); ok && isExactEmail(address) {
					out[key] = p.replacement(entityPerson, text)
				} else {
					out[key] = child
				}
			default:
				converted, err := p.pseudonymizeValue(ctx, key, child)
				if err != nil {
					return nil, err
				}
				out[key] = converted
			}
		}
		return out, nil
	default:
		return value, nil
	}
}

func (p *pseudonymizer) linkMailbox(email, name string) {
	local, domain, ok := splitEmail(email)
	if !ok {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.linkIdentityProfileLocked(&linkedIdentityProfile{
		key: "mailbox", people: []string{name}, usernames: []string{local},
		emails: []string{email}, domains: []string{domain},
	})
}

type distinguishedNamePart struct{ attribute, value, separator string }

func isDistinguishedNameField(field string) bool {
	return normalizeFieldName(field) == "distinguishedname"
}

// Split only on unescaped RDN delimiters and decode LDAP escaped bytes, so
// CN=Doe\, Alice and CN=Doe\2C Alice describe the same person.
func parseDistinguishedName(value string) ([]distinguishedNamePart, bool) {
	var parts []distinguishedNamePart
	start := 0
	separator := ""
	for i := 0; i <= len(value); i++ {
		if i < len(value) && value[i] == '\\' {
			if i+1 >= len(value) {
				return nil, false
			}
			i++
			continue
		}
		if i < len(value) && value[i] != ',' && value[i] != '+' {
			continue
		}
		attribute, encoded, ok := strings.Cut(value[start:i], "=")
		attribute = strings.TrimSpace(attribute)
		if !ok || attribute == "" {
			return nil, false
		}
		var decoded strings.Builder
		encoded = strings.TrimSpace(encoded)
		for j := 0; j < len(encoded); j++ {
			if encoded[j] == '\\' {
				j++
				if j >= len(encoded) {
					return nil, false
				}
				if j+1 < len(encoded) {
					if b, err := hex.DecodeString(encoded[j : j+2]); err == nil {
						decoded.Write(b)
						j++
						continue
					}
				}
			}
			decoded.WriteByte(encoded[j])
		}
		parts = append(parts, distinguishedNamePart{attribute, decoded.String(), separator})
		if i < len(value) {
			separator = value[i : i+1]
		}
		start = i + 1
	}
	return parts, len(parts) > 0
}

func distinguishedNameIdentity(parts []distinguishedNamePart) (string, string) {
	name := ""
	var domain []string
	for _, part := range parts {
		switch strings.ToLower(part.attribute) {
		case "cn":
			if name == "" {
				name = part.value
			}
		case "dc":
			domain = append(domain, part.value)
		}
	}
	return name, strings.Join(domain, ".")
}

func (p *pseudonymizer) pseudonymizeDistinguishedName(value string) string {
	if strings.TrimSpace(value) == "" {
		return value
	}
	parts, ok := parseDistinguishedName(value)
	if !ok {
		return p.replacement(entityIdentifier, value)
	}
	_, domain := distinguishedNameIdentity(parts)
	var out strings.Builder
	domainWritten := false
	for _, part := range parts {
		kind := entityIdentifier
		switch strings.ToLower(part.attribute) {
		case "cn":
			kind = entityPerson
		case "ou", "o":
			kind = entityOrganization
		case "uid":
			kind = entityUsername
		case "dc":
			if !domainWritten {
				for i, label := range strings.Split(p.replacement(entityDomain, domain), ".") {
					if i == 0 {
						out.WriteString(part.separator)
					} else {
						out.WriteByte(',')
					}
					out.WriteString(part.attribute + "=" + label)
				}
				domainWritten = true
			}
			continue
		}
		out.WriteString(part.separator)
		out.WriteString(part.attribute + "=" + p.replacement(kind, part.value))
	}
	return out.String()
}
