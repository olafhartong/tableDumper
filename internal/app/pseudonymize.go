package app

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/jdkato/prose/v3"
)

const pseudonymVaultVersion = 1

type entityKind string

const (
	entityPerson             entityKind = "person"
	entityOrganization       entityKind = "organization"
	entityUsername           entityKind = "username"
	entityEmail              entityKind = "email"
	entityDomain             entityKind = "domain"
	entityHostname           entityKind = "hostname"
	entityIPAddress          entityKind = "ip_address"
	entityMACAddress         entityKind = "mac_address"
	entitySID                entityKind = "sid"
	entityIdentifier         entityKind = "identifier"
	entityPhone              entityKind = "phone"
	entityAddress            entityKind = "address"
	entityFilename           entityKind = "filename"
	entityConfigured         entityKind = "configured_word"
	entityAzureResourceID    entityKind = "azure_resource_id"
	entityAzureResourceGroup entityKind = "azure_resource_group"
	entityAzureResourceName  entityKind = "azure_resource_name"
)

type pseudonymMapping struct {
	EntityType string `json:"entity_type"`
	Original   string `json:"original"`
	Pseudonym  string `json:"pseudonym"`
}

type pseudonymVault struct {
	Version   int                `json:"version"`
	Seed      string             `json:"seed"`
	CreatedAt time.Time          `json:"created_at"`
	UpdatedAt time.Time          `json:"updated_at"`
	Mappings  []pseudonymMapping `json:"mappings"`
}

type pseudonymizer struct {
	mu                    sync.Mutex
	path                  string
	seed                  []byte
	createdAt             time.Time
	mappings              map[string]pseudonymMapping
	used                  map[string]string
	textCache             map[string]string
	fieldPolicy           *pseudonymFieldPolicy
	wordReplacements      *wordReplacementSet
	pseudonymizeFilenames bool
	initialSize           int
	discardedMappings     int
}

type recognizedEntity struct {
	Start       int
	End         int
	Kind        entityKind
	Text        string
	Replacement string
	Priority    int
}

var (
	emailPattern          = regexp.MustCompile(`(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b`)
	ipv4Pattern           = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
	ipv6Pattern           = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{0,4}\b`)
	sidPattern            = regexp.MustCompile(`(?i)\bS-[0-9]+(?:-[0-9]+){2,15}\b`)
	guidPattern           = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
	macPattern            = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b`)
	phonePattern          = regexp.MustCompile(`\b\+?[0-9][0-9 .()\-]{6,}[0-9]\b`)
	numericDatePattern    = regexp.MustCompile(`^(?:[0-9]{4}-[0-9]{1,2}-[0-9]{1,2}|[0-9]{1,2}-[0-9]{1,2}-[0-9]{4})$`)
	numericVersionPattern = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){2,}$`)
	domainPattern         = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b`)
	userHomePathPattern   = regexp.MustCompile(`(?i)[/\\](?:home|users)[/\\]([^/\\\s]+)`)
	windowsAccountPattern = regexp.MustCompile(`(?i)\b([a-z0-9_.-]{2,})\\([a-z0-9_.@$-]+)\b`)
)

var personFirstNames = []string{
	"Amara", "Anika", "Ari", "Camille", "Daniel", "Elena", "Emilia", "Felix",
	"Hana", "Hugo", "Imani", "Ines", "Jonas", "Julian", "Kaito", "Layla",
	"Leonie", "Liam", "Lucia", "Mara", "Mateo", "Maya", "Milan", "Nadia",
	"Naomi", "Noah", "Nora", "Omar", "Ravi", "Sofia", "Tariq", "Yara",
}

var personLastNames = []string{
	"Andersen", "Bakker", "Bennett", "Costa", "De Vries", "Dubois", "Fischer", "Garcia",
	"Haddad", "Ibrahim", "Jansen", "Johansson", "Kaya", "Kowalski", "Laurent", "Martens",
	"Meijer", "Mendoza", "Moreau", "Nakamura", "Novak", "Okafor", "Petrov", "Rahman",
	"Rossi", "Santos", "Schmidt", "Silva", "Singh", "Smit", "Tanaka", "Visser",
}

var organizationAdjectives = []string{
	"Alder", "Alpine", "Amber", "Amicable", "Arcadian", "Astral", "Atlas", "Audacious",
	"Balanced", "Blue", "Bold", "Bright", "Brisk", "Candid", "Careful", "Cedar",
	"Celestial", "Clear", "Clever", "Clockwork", "Coastal", "Concord", "Copper", "Cosmic",
	"Curious", "Dapper", "Daring", "Daylight", "Earnest", "Electric", "Elegant", "Evergreen",
	"Fabled", "Friendly", "Golden", "Grand", "Harbor", "Hidden", "Honest", "Horizon",
	"Ingenious", "Ivory", "Juniper", "Kindred", "Linden", "Lively", "Lucid", "Lunar",
	"Meridian", "Mighty", "Mint", "Modern", "Nimble", "Noble", "Northbridge", "Novel",
	"Oak", "Optimistic", "Orchid", "Pacific", "Patient", "Polished", "Polite", "Practical",
	"Precise", "Quiet", "Radiant", "Redwood", "Reliable", "Resolute", "Sage", "Scarlet",
	"Serene", "Silver", "Solar", "Stellar", "Strategic", "Summit", "Sunny", "Swift",
	"Tidy", "Tranquil", "True", "Velvet", "Warm", "Willow", "Witty",
}

var organizationNouns = []string{
	"Advisory", "Analytics", "Assembly", "Associates", "Badger", "Beacon", "Beehive", "Bureau",
	"Capital", "Capybara", "Cartographers", "Collective", "Committee", "Compass", "Consulting", "Cooperative",
	"Council", "Dynamics", "Energy", "Engine", "Enterprises", "Exchange", "Finance", "Flamingo",
	"Foods", "Forge", "Foundry", "Fox", "Group", "Guild", "Health", "Holdings",
	"Industries", "Institute", "Labs", "Lantern", "Ledger", "Lighthouse", "Logistics", "Marmot",
	"Media", "Mobility", "Networks", "Observatory", "Octopus", "Otter", "Owl", "Partners",
	"Penguin", "Platypus", "Quokka", "Raccoon", "Research", "Rocket", "Services", "Solutions",
	"Studio", "Systems", "Telescope", "Technologies", "Umbrella", "Ventures", "Works", "Workshop",
}

var streetNames = []string{
	"Acacia Lane", "Cedar Avenue", "Harbor Street", "Juniper Road", "Linden Avenue",
	"Maple Street", "Orchard Lane", "River Road", "Willow Street", "Wren Avenue",
}

var nerAllowlist = map[string]struct{}{
	"amazon": {}, "amazon web services": {}, "android": {}, "apple": {}, "aws": {},
	"azure": {}, "cloudflare": {}, "defender": {}, "entra": {}, "github": {}, "google": {},
	"linux": {}, "microsoft": {}, "microsoft defender": {}, "microsoft entra": {},
	"microsoft sentinel": {}, "sentinel": {}, "windows": {},
}

var domainFileExtensions = map[string]struct{}{
	"bak": {}, "bat": {}, "bin": {}, "cfg": {}, "cmd": {}, "conf": {}, "csv": {},
	"dll": {}, "doc": {}, "docx": {}, "env": {}, "exe": {}, "gif": {}, "gz": {},
	"ini": {}, "jpeg": {}, "jpg": {}, "js": {}, "json": {}, "kql": {}, "lock": {},
	"log": {}, "md": {}, "msi": {}, "pdf": {}, "png": {}, "ps1": {}, "py": {},
	"sh": {}, "sql": {}, "svg": {}, "tar": {}, "tmp": {}, "toml": {}, "ts": {},
	"txt": {}, "xls": {}, "xlsx": {}, "xml": {}, "yaml": {}, "yml": {}, "zip": {},
}

func newPseudonymizer(path string) (*pseudonymizer, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		file, err := os.CreateTemp("", "tabledumper-pseudonyms-*.json")
		if err != nil {
			return nil, fmt.Errorf("create temporary pseudonym mapping file: %w", err)
		}
		path = file.Name()
		if err := file.Close(); err != nil {
			os.Remove(path)
			return nil, fmt.Errorf("close temporary pseudonym mapping file: %w", err)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("initialize temporary pseudonym mapping file: %w", err)
		}
	}

	fieldPolicy, err := newPseudonymFieldPolicy(defaultPseudonymFields)
	if err != nil {
		return nil, fmt.Errorf("initialize pseudonym field policy: %w", err)
	}
	p := &pseudonymizer{
		path:        path,
		mappings:    make(map[string]pseudonymMapping),
		used:        make(map[string]string),
		textCache:   make(map[string]string),
		fieldPolicy: fieldPolicy,
	}
	if err := p.loadOrCreate(); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *pseudonymizer) ConfigureFieldPolicy(policy *pseudonymFieldPolicy) error {
	if policy == nil {
		return errors.New("pseudonym field policy must not be nil")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.fieldPolicy = policy
	clear(p.textCache)
	return nil
}

func (p *pseudonymizer) ConfigureFilenamePseudonymization(enabled bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pseudonymizeFilenames = enabled
	clear(p.textCache)
}

func (p *pseudonymizer) filenamesEnabled() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.pseudonymizeFilenames
}

func (p *pseudonymizer) shouldPseudonymizeField(field string) bool {
	p.mu.Lock()
	policy := p.fieldPolicy
	p.mu.Unlock()
	return policy.Matches(field)
}

func (p *pseudonymizer) loadOrCreate() error {
	body, err := os.ReadFile(p.path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("read pseudonym mapping file %s: %w", p.path, err)
		}
		p.seed = make([]byte, 32)
		if _, err := rand.Read(p.seed); err != nil {
			return fmt.Errorf("generate pseudonym mapping seed: %w", err)
		}
		p.createdAt = time.Now().UTC()
		return p.Save()
	}

	var vault pseudonymVault
	if err := json.Unmarshal(body, &vault); err != nil {
		return fmt.Errorf("decode pseudonym mapping file %s: %w", p.path, err)
	}
	if vault.Version != pseudonymVaultVersion {
		return fmt.Errorf("unsupported pseudonym mapping version %d in %s", vault.Version, p.path)
	}
	seed, err := base64.StdEncoding.DecodeString(vault.Seed)
	if err != nil || len(seed) < 32 {
		return fmt.Errorf("invalid pseudonym mapping seed in %s", p.path)
	}
	p.seed = seed
	p.createdAt = vault.CreatedAt
	if p.createdAt.IsZero() {
		p.createdAt = time.Now().UTC()
	}
	for index, mapping := range vault.Mappings {
		kind := entityKind(mapping.EntityType)
		if strings.TrimSpace(mapping.Original) == "" || strings.TrimSpace(mapping.Pseudonym) == "" {
			p.discardedMappings++
			continue
		}
		if !validEntityKind(kind) {
			return fmt.Errorf("invalid pseudonym mapping entry %d in %s: unsupported entity_type %q", index+1, p.path, mapping.EntityType)
		}
		key := entityKey(kind, mapping.Original)
		if existing, ok := p.mappings[key]; ok && existing.Pseudonym != mapping.Pseudonym {
			return fmt.Errorf("conflicting pseudonym mapping entry %d in %s for %s value %q: %q and %q", index+1, p.path, mapping.EntityType, mapping.Original, existing.Pseudonym, mapping.Pseudonym)
		}
		if originalKey, ok := p.used[strings.ToLower(mapping.Pseudonym)]; kind != entityConfigured && ok && originalKey != key && !strings.HasPrefix(originalKey, string(entityConfigured)+"\x00") && !linkedAliasesMaySharePseudonym(kind, originalKey) {
			return fmt.Errorf("conflicting pseudonym mapping entry %d in %s: %s value %q reuses pseudonym %q", index+1, p.path, mapping.EntityType, mapping.Original, mapping.Pseudonym)
		}
		p.mappings[key] = mapping
		if _, exists := p.used[strings.ToLower(mapping.Pseudonym)]; !exists {
			p.used[strings.ToLower(mapping.Pseudonym)] = key
		}
	}
	p.initialSize = len(p.mappings)
	if p.discardedMappings > 0 {
		if err := p.saveLocked(); err != nil {
			return fmt.Errorf("clean unusable legacy mappings from %s: %w", p.path, err)
		}
		return nil
	}
	return os.Chmod(p.path, 0o600)
}

func validEntityKind(kind entityKind) bool {
	switch kind {
	case entityPerson, entityOrganization, entityUsername, entityEmail, entityDomain,
		entityHostname, entityIPAddress, entityMACAddress, entitySID, entityIdentifier,
		entityPhone, entityAddress, entityFilename, entityConfigured, entityAzureResourceID,
		entityAzureResourceGroup, entityAzureResourceName:
		return true
	default:
		return false
	}
}

func (p *pseudonymizer) ConfigureWordReplacements(replacements *wordReplacementSet) error {
	if replacements == nil {
		return errors.New("configured word replacements must not be nil")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, rule := range replacements.rules {
		if mapping, ok := p.mappings[entityKey(entityConfigured, rule.find)]; ok && mapping.Pseudonym != rule.replacement {
			return errors.New("configured word replacement conflicts with the existing pseudonym mapping file; restore the previous replacement or use a new mapping file")
		}
	}
	p.wordReplacements = replacements
	clear(p.textCache)
	return nil
}

func (p *pseudonymizer) Path() string {
	return p.path
}

func (p *pseudonymizer) MappingCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.mappings)
}

func (p *pseudonymizer) NewMappingCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.mappings) - p.initialSize
}

func (p *pseudonymizer) DiscardedMappingCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.discardedMappings
}

func (p *pseudonymizer) Save() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.saveLocked()
}

func (p *pseudonymizer) saveLocked() error {
	mappings := make([]pseudonymMapping, 0, len(p.mappings))
	for _, mapping := range p.mappings {
		mappings = append(mappings, mapping)
	}
	sort.Slice(mappings, func(i, j int) bool {
		if mappings[i].EntityType == mappings[j].EntityType {
			return strings.ToLower(mappings[i].Original) < strings.ToLower(mappings[j].Original)
		}
		return mappings[i].EntityType < mappings[j].EntityType
	})
	vault := pseudonymVault{
		Version:   pseudonymVaultVersion,
		Seed:      base64.StdEncoding.EncodeToString(p.seed),
		CreatedAt: p.createdAt,
		UpdatedAt: time.Now().UTC(),
		Mappings:  mappings,
	}
	body, err := json.MarshalIndent(vault, "", "  ")
	if err != nil {
		return fmt.Errorf("encode pseudonym mapping file: %w", err)
	}
	body = append(body, '\n')

	directory := filepath.Dir(p.path)
	if directory != "." {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return fmt.Errorf("create pseudonym mapping directory %s: %w", directory, err)
		}
	}
	file, err := os.CreateTemp(directory, "."+filepath.Base(p.path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary pseudonym mapping file: %w", err)
	}
	tempPath := file.Name()
	cleanup := func() {
		file.Close()
		os.Remove(tempPath)
	}
	if err := file.Chmod(0o600); err != nil {
		cleanup()
		return fmt.Errorf("secure temporary pseudonym mapping file: %w", err)
	}
	if _, err := file.Write(body); err != nil {
		cleanup()
		return fmt.Errorf("write temporary pseudonym mapping file: %w", err)
	}
	if err := file.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("sync temporary pseudonym mapping file: %w", err)
	}
	if err := file.Close(); err != nil {
		os.Remove(tempPath)
		return fmt.Errorf("close temporary pseudonym mapping file: %w", err)
	}
	if err := os.Rename(tempPath, p.path); err != nil {
		os.Remove(tempPath)
		return fmt.Errorf("replace pseudonym mapping file %s: %w", p.path, err)
	}
	if err := os.Chmod(p.path, 0o600); err != nil {
		return fmt.Errorf("secure pseudonym mapping file %s: %w", p.path, err)
	}
	return nil
}

func (p *pseudonymizer) PseudonymizeResponse(ctx context.Context, response queryResponse) (queryResponse, error) {
	rows, err := p.PseudonymizeRows(ctx, response.Results)
	if err != nil {
		return queryResponse{}, err
	}
	response.Results = rows
	return response, nil
}

func (p *pseudonymizer) PseudonymizeRows(ctx context.Context, rows []map[string]any) ([]map[string]any, error) {
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		value, err := p.pseudonymizeValue(ctx, "", row)
		if err != nil {
			return nil, err
		}
		converted, ok := value.(map[string]any)
		if !ok {
			return nil, errors.New("pseudonymized row was not an object")
		}
		out = append(out, converted)
	}
	return out, nil
}

func (p *pseudonymizer) pseudonymizeValue(ctx context.Context, field string, value any) (any, error) {
	switch typed := value.(type) {
	case map[string]any:
		linkedOverrides := p.primeEntityRelationships(typed)
		for key, replacement := range p.linkedFilenameOverrides(typed) {
			linkedOverrides[key] = replacement
		}
		for key, replacement := range sensitiveCommandLineOverrides(typed, linkedOverrides) {
			linkedOverrides[key] = replacement
		}
		out := make(map[string]any, len(typed))
		for key, child := range typed {
			if replacement, ok := linkedOverrides[key]; ok {
				out[key] = replacement
				continue
			}
			if !p.shouldPseudonymizeField(key) {
				out[key] = child
				continue
			}
			if text, ok := child.(string); ok {
				if isFolderPathField(key) || isPathBearingFilename(key, text) {
					out[key] = p.pseudonymizePath(key, text)
					continue
				}
				if converted, ok := p.pseudonymizeAzureResourceID(text); ok {
					out[key] = converted
					continue
				}
				if kind := contextualEntityKindForValue(key, typed, text); kind != "" {
					if isIPAddress(text) && (kind == entityDomain || kind == entityHostname) {
						out[key] = text
						continue
					}
					if kind == entityFilename && !p.filenamesEnabled() {
						out[key] = text
						continue
					}
					out[key] = p.replacement(kind, text)
					continue
				}
				if isEmbeddedDomainField(key, text) {
					out[key] = p.pseudonymizeEmbeddedDomains(text)
					continue
				}
			}
			converted, err := p.pseudonymizeValue(ctx, key, child)
			if err != nil {
				return nil, err
			}
			out[key] = converted
		}
		return out, nil
	case []any:
		out := make([]any, len(typed))
		for i, child := range typed {
			converted, err := p.pseudonymizeValue(ctx, field, child)
			if err != nil {
				return nil, err
			}
			out[i] = converted
		}
		return out, nil
	case []string:
		out := make([]string, len(typed))
		for i, child := range typed {
			converted, err := p.pseudonymizeString(ctx, field, child)
			if err != nil {
				return nil, err
			}
			out[i] = converted
		}
		return out, nil
	case string:
		return p.pseudonymizeString(ctx, field, typed)
	default:
		return value, nil
	}
}

func (p *pseudonymizer) primeIdentityAliases(row map[string]any) {
	type identityValue struct {
		kind  entityKind
		value string
		alias string
	}
	people := make([]identityValue, 0)
	aliases := make([]identityValue, 0)
	for field, value := range row {
		if !p.shouldPseudonymizeField(field) {
			continue
		}
		text, ok := value.(string)
		if !ok || strings.TrimSpace(text) == "" {
			continue
		}
		switch entityKindForField(field) {
		case entityPerson:
			people = append(people, identityValue{kind: entityPerson, value: text, alias: identityAlias(text)})
		case entityUsername:
			aliases = append(aliases, identityValue{kind: entityUsername, value: text, alias: identityAlias(text)})
		case entityEmail:
			local, _, ok := strings.Cut(text, "@")
			if ok {
				aliases = append(aliases, identityValue{kind: entityEmail, value: text, alias: identityAlias(local)})
			}
		}
	}
	if len(people) == 0 || len(aliases) == 0 {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	for _, person := range people {
		for _, alias := range aliases {
			if !identityAliasesMatch(person.value, alias.alias) {
				continue
			}
			fakeName := ""
			if mapping, ok := p.mappings[entityKey(entityPerson, person.value)]; ok {
				fakeName = mapping.Pseudonym
			}
			if fakeName == "" {
				usernameOriginal := alias.value
				if alias.kind == entityEmail {
					usernameOriginal, _, _ = strings.Cut(alias.value, "@")
				}
				if mapping, ok := p.mappings[entityKey(entityUsername, usernameOriginal)]; ok {
					fakeName = displayNameFromUsername(mapping.Pseudonym)
				}
			}
			if fakeName == "" && alias.kind == entityEmail {
				if mapping, ok := p.mappings[entityKey(entityEmail, alias.value)]; ok {
					local, _, _ := strings.Cut(mapping.Pseudonym, "@")
					fakeName = displayNameFromUsername(local)
				}
			}
			if fakeName == "" {
				fakeName = p.generateCandidate(entityPerson, person.value, 0)
			}
			fakeName = p.forceReplacementLocked(entityPerson, person.value, fakeName)
			fakeUsername := usernameFromDisplayName(fakeName)

			switch alias.kind {
			case entityUsername:
				p.forceReplacementLocked(entityUsername, alias.value, fakeUsername)
			case entityEmail:
				local, domain, ok := strings.Cut(alias.value, "@")
				if !ok {
					continue
				}
				fakeLocal := p.forceReplacementLocked(entityUsername, local, fakeUsername)
				fakeDomain := p.replacementLocked(entityDomain, domain)
				p.forceReplacementLocked(entityEmail, alias.value, fakeLocal+"@"+fakeDomain)
			}
		}
	}
}

func identityAlias(value string) string {
	var builder strings.Builder
	for _, r := range strings.ToLower(value) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			builder.WriteRune(r)
		}
	}
	return strings.TrimRightFunc(builder.String(), unicode.IsDigit)
}

func identityAliasesMatch(personName, alias string) bool {
	fields := strings.Fields(strings.ToLower(personName))
	if len(fields) == 0 || alias == "" {
		return false
	}
	full := identityAlias(personName)
	if alias == full {
		return true
	}
	first := identityAlias(fields[0])
	last := identityAlias(fields[len(fields)-1])
	if first == "" || last == "" {
		return false
	}
	return alias == first[:1]+last || alias == first+last[:1] || alias == last+first[:1]
}

func usernameFromDisplayName(name string) string {
	fields := strings.Fields(name)
	if len(fields) == 0 {
		return "user"
	}
	if len(fields) == 1 {
		return slugName(fields[0])
	}
	return slugName(fields[0]) + "." + slugName(strings.Join(fields[1:], ""))
}

func displayNameFromUsername(username string) string {
	parts := strings.FieldsFunc(username, func(r rune) bool { return r == '.' || r == '_' || r == '-' })
	for i, part := range parts {
		runes := []rune(strings.ToLower(part))
		if len(runes) > 0 {
			runes[0] = unicode.ToUpper(runes[0])
		}
		parts[i] = string(runes)
	}
	return strings.Join(parts, " ")
}

func (p *pseudonymizer) pseudonymizeString(ctx context.Context, field, value string) (string, error) {
	if strings.TrimSpace(value) == "" {
		return value, nil
	}
	if !p.shouldPseudonymizeField(field) {
		return value, nil
	}
	if isFolderPathField(field) || isPathBearingFilename(field, value) {
		return p.pseudonymizePath(field, value), nil
	}
	if entityKindForFieldValue(field, value) == entityFilename && !p.filenamesEnabled() {
		return value, nil
	}

	if decoded, ok := decodeJSONObject(value); ok {
		converted, err := p.pseudonymizeValue(ctx, field, decoded)
		if err != nil {
			return "", err
		}
		body, err := json.Marshal(converted)
		if err != nil {
			return "", fmt.Errorf("encode pseudonymized nested JSON: %w", err)
		}
		return string(body), nil
	}
	if converted, ok := p.pseudonymizeAzureResourceID(value); ok {
		return converted, nil
	}
	if isEmbeddedDomainField(field, value) {
		return p.pseudonymizeEmbeddedDomains(value), nil
	}

	configuredEntities := p.wordReplacements.Recognize(value)
	if len(configuredEntities) == 0 {
		if kind := entityKindForFieldValue(field, value); kind != "" {
			if isIPAddress(value) && (kind == entityDomain || kind == entityHostname) {
				return value, nil
			}
			return p.replacement(kind, value), nil
		}
	}

	cacheKey := normalizeFieldName(field) + "\x00" + value
	p.mu.Lock()
	if cached, ok := p.textCache[cacheKey]; ok {
		p.mu.Unlock()
		return cached, nil
	}
	p.mu.Unlock()

	entities := append(configuredEntities, recognizeAzureResourceIDEntities(value)...)
	entities = append(entities, recognizePatternEntities(value)...)
	if shouldRunNER(field, value) {
		document, err := prose.NewDocumentContext(ctx, value, prose.WithSegmentation(false))
		if err != nil {
			return "", fmt.Errorf("recognize named entities: %w", err)
		}
		for _, entity := range document.Entities() {
			kind := entityKind("")
			switch entity.Label {
			case "PERSON":
				kind = entityPerson
			case "ORG":
				kind = entityOrganization
			default:
				continue
			}
			if _, allowed := nerAllowlist[strings.ToLower(strings.TrimSpace(entity.Text))]; allowed {
				continue
			}
			entities = append(entities, recognizedEntity{Start: entity.Start, End: entity.End(), Kind: kind, Text: entity.Text})
		}
	}

	out := p.replaceEntities(value, entities)
	p.mu.Lock()
	p.textCache[cacheKey] = out
	p.mu.Unlock()
	return out, nil
}

func decodeJSONObject(value string) (any, bool) {
	trimmed := strings.TrimSpace(value)
	if len(trimmed) < 2 || (trimmed[0] != '{' && trimmed[0] != '[') {
		return nil, false
	}
	var decoded any
	if err := json.Unmarshal([]byte(trimmed), &decoded); err != nil {
		return nil, false
	}
	return decoded, true
}

func entityKindForField(field string) entityKind {
	name := normalizeFieldName(field)
	if name == "" {
		return ""
	}
	if strings.Contains(name, "hash") || strings.Contains(name, "sha1") || strings.Contains(name, "sha256") || strings.Contains(name, "md5") {
		return ""
	}
	if strings.HasSuffix(name, "filename") || strings.HasSuffix(name, "fileinternalname") || strings.HasSuffix(name, "fileoriginalname") || strings.HasSuffix(name, "processname") || name == "zonefile" {
		return entityFilename
	}
	if strings.Contains(name, "emailaddress") || name == "senderfromaddress" || name == "sendermailfromaddress" || strings.HasSuffix(name, "email") || strings.HasSuffix(name, "mailaddress") || strings.HasSuffix(name, "mailaddresses") || strings.HasSuffix(name, "userprincipalname") || strings.HasSuffix(name, "userprincipal") || strings.HasSuffix(name, "upn") {
		return entityEmail
	}
	if strings.Contains(name, "iptype") {
		return ""
	}
	if strings.Contains(name, "ipaddress") || strings.HasSuffix(name, "localip") || strings.HasSuffix(name, "remoteip") || strings.HasSuffix(name, "sourceip") || strings.HasSuffix(name, "destinationip") {
		return entityIPAddress
	}
	if strings.Contains(name, "macaddress") {
		return entityMACAddress
	}
	if strings.HasSuffix(name, "sid") || strings.Contains(name, "securityidentifier") {
		return entitySID
	}
	if strings.Contains(name, "phone") || strings.Contains(name, "telephone") || strings.Contains(name, "mobile") {
		return entityPhone
	}
	if strings.Contains(name, "streetaddress") || strings.Contains(name, "postaladdress") || name == "address" {
		return entityAddress
	}
	if strings.HasSuffix(name, "resourcegroup") || strings.HasSuffix(name, "resourcegroupname") {
		return entityAzureResourceGroup
	}
	if strings.HasSuffix(name, "domain") || strings.Contains(name, "domainname") || strings.HasSuffix(name, "dnsname") || strings.HasSuffix(name, "dnsdomain") || strings.HasSuffix(name, "urldomain") || strings.HasSuffix(name, "fqdn") || name == "queryname" || name == "clientprovidedhostheader" {
		return entityDomain
	}
	if name == "computer" || name == "host" || name == "device" || name == "clientname" || name == "workstation" || name == "userworkstations" || strings.Contains(name, "hostname") || strings.Contains(name, "computername") || strings.Contains(name, "devicename") || strings.Contains(name, "machinename") || strings.HasSuffix(name, "workstationname") || strings.HasSuffix(name, "instancevmname") {
		return entityHostname
	}
	if strings.Contains(name, "displayname") {
		switch {
		case strings.Contains(name, "device"), strings.Contains(name, "machine"), strings.Contains(name, "computer"), strings.Contains(name, "host"):
			return entityHostname
		case strings.Contains(name, "application"), strings.Contains(name, "organization"), strings.Contains(name, "company"):
			return entityOrganization
		case strings.Contains(name, "account"), strings.Contains(name, "user"), strings.Contains(name, "owner"), strings.Contains(name, "recipient"), strings.Contains(name, "sender"), strings.Contains(name, "person"):
			return entityPerson
		}
	}
	if strings.Contains(name, "fullname") || strings.Contains(name, "personname") || name == "actorname" || name == "assignedtoname" || name == "createdbyname" || name == "lastmodifiedby" || name == "resolvedby" {
		return entityPerson
	}
	if strings.Contains(name, "accountname") || strings.Contains(name, "username") || strings.Contains(name, "useraccount") || strings.Contains(name, "loginname") || name == "user" || name == "userid" || name == "account" || name == "targetaccount" || name == "alternatesigninname" || name == "lastloginuser" || name == "actorprincipalname" {
		return entityUsername
	}
	if name == "resource" {
		return entityAzureResourceName
	}
	if name == "subscriptionidentity" || name == "resourcesubid" || name == "onbehalfofresid" {
		return entityIdentifier
	}
	if !strings.HasSuffix(name, "id") && (strings.Contains(name, "organization") || strings.Contains(name, "companyname") || strings.Contains(name, "employer")) {
		return entityOrganization
	}
	for _, suffix := range []string{
		"tenantid", "deviceid", "machineid", "objectid", "alertid", "incidentid",
		"reportid", "networkmessageid", "emailclusterid", "sessionid", "requestid",
		"correlationid", "subscriptionid", "resourceid",
	} {
		if strings.HasSuffix(name, suffix) {
			return entityIdentifier
		}
	}
	if strings.HasSuffix(name, "id") {
		switch name {
		case "eventid", "processid", "parentprocessid", "initiatingprocessid", "threadid", "productid", "vendorid", "protocolid":
			return ""
		default:
			return entityIdentifier
		}
	}
	return ""
}

func isFolderPathField(field string) bool {
	name := normalizeFieldName(field)
	return strings.Contains(name, "folderpath") || strings.Contains(name, "filepath") || strings.Contains(name, "fullpath") || strings.Contains(name, "filedirectory") || strings.Contains(name, "workingdirectory") || strings.Contains(name, "currentdirectory") || strings.Contains(name, "homedirectory") || strings.Contains(name, "profilepath") || strings.HasSuffix(name, "sharename")
}

func isPathBearingFilename(field, value string) bool {
	return entityKindForField(field) == entityFilename && strings.ContainsAny(value, `/\`)
}

func entityKindForFieldValue(field, value string) entityKind {
	kind := entityKindForField(field)
	if (kind == entityPerson || kind == entityUsername) && isExactEmail(value) {
		return entityEmail
	}
	return kind
}

func contextualEntityKindForValue(field string, row map[string]any, value string) entityKind {
	kind := contextualEntityKind(field, row)
	if (kind == entityPerson || kind == entityUsername) && isExactEmail(value) {
		return entityEmail
	}
	return kind
}

func isExactEmail(value string) bool {
	value = strings.TrimSpace(value)
	indices := emailPattern.FindStringIndex(value)
	return len(indices) == 2 && indices[0] == 0 && indices[1] == len(value)
}

func isIPAddress(value string) bool {
	value = strings.Trim(strings.TrimSpace(value), "[]")
	_, err := netip.ParseAddr(value)
	return err == nil
}

func isEmbeddedDomainField(field, value string) bool {
	switch normalizeFieldName(field) {
	case "remoteurl":
		return true
	case "name":
		return isIPAddress(value) || domainPattern.MatchString(value)
	default:
		return false
	}
}

func contextualEntityKind(field string, row map[string]any) entityKind {
	if kind := entityKindForField(field); kind != "" {
		return kind
	}
	name := normalizeFieldName(field)
	var typeValue string
	switch name {
	case "label", "name", "nodename":
		typeValue = firstMapString(row, "type", "entityType", "nodeLabel")
	case "sourcenodename":
		typeValue = firstMapString(row, "sourceNodeLabel", "sourceNodeType")
	case "targetnodename":
		typeValue = firstMapString(row, "targetNodeLabel", "targetNodeType")
	default:
		return ""
	}
	switch strings.ToLower(strings.TrimSpace(typeValue)) {
	case "user", "person", "identity":
		return entityPerson
	case "machine", "device", "computer", "host":
		return entityHostname
	case "organization", "organisation", "company", "group", "user_group":
		return entityOrganization
	case "ip", "ipaddress", "address":
		return entityIPAddress
	default:
		return ""
	}
}

func firstMapString(row map[string]any, names ...string) string {
	for _, name := range names {
		for key, value := range row {
			if strings.EqualFold(key, name) {
				if text, ok := value.(string); ok && strings.TrimSpace(text) != "" {
					return text
				}
			}
		}
	}
	return ""
}

func normalizeFieldName(field string) string {
	field = strings.TrimSpace(field)
	// Log Analytics custom columns append a one-letter Kusto type suffix.
	if len(field) > 2 && field[len(field)-2] == '_' && strings.ContainsRune("sdbtgi", unicode.ToLower(rune(field[len(field)-1]))) {
		field = field[:len(field)-2]
	}
	return normalizeRawFieldName(field)
}

func normalizeRawFieldName(field string) string {
	var builder strings.Builder
	for _, r := range strings.ToLower(field) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			builder.WriteRune(r)
		}
	}
	return builder.String()
}

func shouldRunNER(field, value string) bool {
	if len(value) < 3 || len(value) > 16*1024 || !strings.ContainsAny(value, " \t\n") {
		return false
	}
	name := normalizeFieldName(field)
	if strings.Contains(name, "path") {
		return false
	}
	for _, marker := range []string{"description", "message", "title", "details", "summary", "additionalfields", "properties", "body"} {
		if strings.Contains(name, marker) {
			return true
		}
	}
	if strings.ContainsAny(value, `\\{}[]=|<>`) {
		return false
	}
	letters := 0
	for _, r := range value {
		if unicode.IsLetter(r) {
			letters++
		}
	}
	return letters >= 3
}

func recognizePatternEntities(value string) []recognizedEntity {
	entities := make([]recognizedEntity, 0)
	entities = appendPatternEntities(entities, value, emailPattern, entityEmail, nil)
	entities = appendPatternEntities(entities, value, sidPattern, entitySID, nil)
	entities = appendPatternEntities(entities, value, guidPattern, entityIdentifier, nil)
	entities = appendPatternEntities(entities, value, macPattern, entityMACAddress, nil)
	entities = appendPatternEntities(entities, value, ipv4Pattern, entityIPAddress, func(candidate string) bool {
		_, err := netip.ParseAddr(candidate)
		return err == nil
	})
	entities = appendPatternEntities(entities, value, ipv6Pattern, entityIPAddress, func(candidate string) bool {
		_, err := netip.ParseAddr(candidate)
		return err == nil
	})
	entities = appendPatternEntities(entities, value, phonePattern, entityPhone, isLikelyPhoneNumber)
	entities = appendPatternEntities(entities, value, domainPattern, entityDomain, func(candidate string) bool {
		parts := strings.Split(strings.ToLower(candidate), ".")
		_, blocked := domainFileExtensions[parts[len(parts)-1]]
		return !blocked
	})
	entities = appendSubmatchEntities(entities, value, userHomePathPattern, 1, entityUsername)
	entities = appendWindowsAccountEntities(entities, value)
	return entities
}

func (p *pseudonymizer) pseudonymizePath(field, value string) string {
	entities := p.wordReplacements.Recognize(value)
	entities = appendSubmatchEntities(entities, value, userHomePathPattern, 1, entityUsername)
	name := normalizeFieldName(field)
	if p.filenamesEnabled() && (strings.Contains(name, "filepath") || strings.Contains(name, "fullpath") || isPathBearingFilename(field, value)) {
		entities = appendPathLastSegmentEntity(entities, value, entityFilename)
	} else if strings.Contains(name, "homedirectory") || strings.Contains(name, "profilepath") {
		entities = appendPathLastSegmentEntity(entities, value, entityUsername)
	} else if p.filenamesEnabled() && strings.HasSuffix(name, "sharename") {
		entities = appendPathLastSegmentEntity(entities, value, entityFilename)
	}
	return p.replaceEntities(value, entities)
}

func (p *pseudonymizer) pseudonymizeEmbeddedDomains(value string) string {
	entities := p.wordReplacements.Recognize(value)
	entities = appendPatternEntities(entities, value, domainPattern, entityDomain, func(candidate string) bool {
		parts := strings.Split(strings.ToLower(candidate), ".")
		_, blocked := domainFileExtensions[parts[len(parts)-1]]
		return !blocked
	})
	return p.replaceEntities(value, entities)
}

func appendPathLastSegmentEntity(entities []recognizedEntity, value string, kind entityKind) []recognizedEntity {
	end := len(value)
	for end > 0 && isPathSeparator(value[end-1]) {
		end--
	}
	if end == 0 {
		return entities
	}
	start := end
	for start > 0 && !isPathSeparator(value[start-1]) {
		start--
	}
	if start == end || value[start:end] == "." || value[start:end] == ".." {
		return entities
	}
	return append(entities, recognizedEntity{Start: start, End: end, Kind: kind, Text: value[start:end]})
}

func isLikelyPhoneNumber(candidate string) bool {
	candidate = strings.TrimSpace(candidate)
	if numericDatePattern.MatchString(candidate) || numericVersionPattern.MatchString(candidate) {
		return false
	}

	digits := 0
	for _, r := range candidate {
		if r >= '0' && r <= '9' {
			digits++
		}
	}
	return digits >= 8 && digits <= 15
}

func appendPatternEntities(entities []recognizedEntity, value string, pattern *regexp.Regexp, kind entityKind, accept func(string) bool) []recognizedEntity {
	for _, indices := range pattern.FindAllStringIndex(value, -1) {
		candidate := value[indices[0]:indices[1]]
		if accept != nil && !accept(candidate) {
			continue
		}
		entities = append(entities, recognizedEntity{Start: indices[0], End: indices[1], Kind: kind, Text: candidate})
	}
	return entities
}

func appendSubmatchEntities(entities []recognizedEntity, value string, pattern *regexp.Regexp, group int, kind entityKind) []recognizedEntity {
	for _, indices := range pattern.FindAllStringSubmatchIndex(value, -1) {
		startIndex := group * 2
		if startIndex+1 >= len(indices) || indices[startIndex] < 0 {
			continue
		}
		start, end := indices[startIndex], indices[startIndex+1]
		entities = append(entities, recognizedEntity{Start: start, End: end, Kind: kind, Text: value[start:end]})
	}
	return entities
}

func appendWindowsAccountEntities(entities []recognizedEntity, value string) []recognizedEntity {
	for _, indices := range windowsAccountPattern.FindAllStringSubmatchIndex(value, -1) {
		if len(indices) < 6 || indices[0] < 0 || indices[1] < 0 {
			continue
		}
		if indices[0] > 0 && isPathSeparator(value[indices[0]-1]) {
			continue
		}
		if indices[1] < len(value) && isPathSeparator(value[indices[1]]) {
			continue
		}
		entities = append(entities,
			recognizedEntity{Start: indices[2], End: indices[3], Kind: entityDomain, Text: value[indices[2]:indices[3]]},
			recognizedEntity{Start: indices[4], End: indices[5], Kind: entityUsername, Text: value[indices[4]:indices[5]]},
		)
	}
	return entities
}

func isPathSeparator(value byte) bool {
	return value == '/' || value == '\\'
}

func (p *pseudonymizer) replaceEntities(value string, entities []recognizedEntity) string {
	if len(entities) == 0 {
		return value
	}
	sort.SliceStable(entities, func(i, j int) bool {
		if entities[i].Priority != entities[j].Priority {
			return entities[i].Priority > entities[j].Priority
		}
		if entities[i].Priority > 0 {
			leftLength := entities[i].End - entities[i].Start
			rightLength := entities[j].End - entities[j].Start
			if leftLength != rightLength {
				return leftLength > rightLength
			}
		}
		if entities[i].Start != entities[j].Start {
			return entities[i].Start < entities[j].Start
		}
		return entities[i].End > entities[j].End
	})
	selected := make([]recognizedEntity, 0, len(entities))
	for _, entity := range entities {
		if entity.Start < 0 || entity.End > len(value) || entity.Start >= entity.End || overlapsRecognizedEntity(entity, selected) {
			continue
		}
		selected = append(selected, entity)
	}
	if len(selected) == 0 {
		return value
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].Start < selected[j].Start })

	var builder strings.Builder
	position := 0
	for _, entity := range selected {
		builder.WriteString(value[position:entity.Start])
		if entity.Replacement != "" {
			builder.WriteString(p.configuredReplacement(entity.Text, entity.Replacement))
		} else if entity.Kind == entityAzureResourceID {
			replacement, ok := p.pseudonymizeAzureResourceID(entity.Text)
			if !ok {
				replacement = p.replacement(entity.Kind, entity.Text)
			}
			builder.WriteString(replacement)
		} else {
			builder.WriteString(p.replacement(entity.Kind, entity.Text))
		}
		position = entity.End
	}
	builder.WriteString(value[position:])
	return builder.String()
}

func overlapsRecognizedEntity(candidate recognizedEntity, selected []recognizedEntity) bool {
	for _, entity := range selected {
		if candidate.Start < entity.End && candidate.End > entity.Start {
			return true
		}
	}
	return false
}

func (p *pseudonymizer) configuredReplacement(original, replacement string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	key := entityKey(entityConfigured, original)
	if mapping, ok := p.mappings[key]; ok {
		return mapping.Pseudonym
	}
	p.mappings[key] = pseudonymMapping{EntityType: string(entityConfigured), Original: original, Pseudonym: replacement}
	if _, exists := p.used[strings.ToLower(replacement)]; !exists {
		p.used[strings.ToLower(replacement)] = key
	}
	return replacement
}

func (p *pseudonymizer) replacement(kind entityKind, original string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.replacementLocked(kind, original)
}

func (p *pseudonymizer) replacementLocked(kind entityKind, original string) string {
	if strings.TrimSpace(original) == "" {
		return original
	}
	key := entityKey(kind, original)
	if mapping, ok := p.mappings[key]; ok {
		return mapping.Pseudonym
	}

	var candidate string
	for attempt := 0; ; attempt++ {
		switch kind {
		case entityEmail:
			local, domain, ok := strings.Cut(strings.TrimSpace(original), "@")
			if ok && local != "" && domain != "" {
				candidate = p.replacementLocked(entityUsername, local) + "@" + p.replacementLocked(entityDomain, domain)
			} else {
				candidate = p.generateCandidate(kind, original, attempt)
			}
		case entityUsername:
			domain, username, ok := strings.Cut(strings.TrimSpace(original), `\`)
			if ok && domain != "" && username != "" && !strings.Contains(username, `\`) {
				candidate = p.replacementLocked(entityDomain, domain) + `\` + p.replacementLocked(entityUsername, username)
			} else {
				candidate = p.generateCandidate(kind, original, attempt)
			}
		case entityHostname:
			hostname := strings.TrimSpace(original)
			host, domain, ok := strings.Cut(hostname, ".")
			if ok && host != "" && domainPattern.MatchString(domain) {
				candidate = p.generateCandidate(kind, host, attempt) + "." + p.replacementLocked(entityDomain, domain)
			} else {
				candidate = p.generateCandidate(kind, original, attempt)
			}
		case entityDomain:
			if subdomain, baseDomain, ok := splitSubdomain(strings.TrimSpace(original)); ok {
				candidate = p.generateCandidate(entityHostname, subdomain, attempt) + "." + p.replacementLocked(entityDomain, baseDomain)
			} else {
				candidate = p.generateCandidate(kind, original, attempt)
			}
		default:
			candidate = p.generateCandidate(kind, original, attempt)
		}
		if owner, exists := p.used[strings.ToLower(candidate)]; !exists || owner == key {
			break
		}
	}
	mapping := pseudonymMapping{EntityType: string(kind), Original: original, Pseudonym: candidate}
	p.mappings[key] = mapping
	p.used[strings.ToLower(candidate)] = key
	return candidate
}

func splitSubdomain(domain string) (string, string, bool) {
	parts := strings.Split(strings.ToLower(strings.TrimSuffix(domain, ".")), ".")
	if len(parts) < 3 {
		return "", "", false
	}
	baseLabels := 2
	compoundSuffix := parts[len(parts)-2] + "." + parts[len(parts)-1]
	switch compoundSuffix {
	case "co.uk", "com.au", "co.jp", "com.br", "co.nz", "co.za", "com.cn", "com.sg", "com.mx", "com.tr", "co.in", "com.ar":
		baseLabels = 3
	}
	if len(parts) <= baseLabels {
		return "", "", false
	}
	boundary := len(parts) - baseLabels
	return strings.Join(parts[:boundary], "."), strings.Join(parts[boundary:], "."), true
}

func (p *pseudonymizer) forceReplacementLocked(kind entityKind, original, candidate string) string {
	key := entityKey(kind, original)
	if mapping, ok := p.mappings[key]; ok {
		return mapping.Pseudonym
	}
	base := candidate
	for suffix := 2; ; suffix++ {
		if owner, exists := p.used[strings.ToLower(candidate)]; !exists || owner == key {
			break
		}
		switch kind {
		case entityEmail:
			local, domain, ok := strings.Cut(base, "@")
			if ok {
				candidate = fmt.Sprintf("%s%d@%s", local, suffix, domain)
			} else {
				candidate = fmt.Sprintf("%s%d", base, suffix)
			}
		case entityPerson:
			candidate = fmt.Sprintf("%s %c", base, 'A'+rune((suffix-2)%26))
		default:
			candidate = fmt.Sprintf("%s%d", base, suffix)
		}
	}
	mapping := pseudonymMapping{EntityType: string(kind), Original: original, Pseudonym: candidate}
	p.mappings[key] = mapping
	p.used[strings.ToLower(candidate)] = key
	return candidate
}

func entityKey(kind entityKind, original string) string {
	canonical := strings.Join(strings.Fields(strings.ToLower(strings.TrimSpace(original))), " ")
	return string(kind) + "\x00" + canonical
}

func (p *pseudonymizer) generateCandidate(kind entityKind, original string, attempt int) string {
	digest := p.digest(kind, original, attempt)
	switch kind {
	case entityPerson:
		return personFirstNames[indexFromDigest(digest, 0, len(personFirstNames))] + " " + personLastNames[indexFromDigest(digest, 2, len(personLastNames))]
	case entityOrganization:
		return organizationAdjectives[indexFromDigest(digest, 0, len(organizationAdjectives))] + " " + organizationNouns[indexFromDigest(digest, 2, len(organizationNouns))]
	case entityUsername:
		first := personFirstNames[indexFromDigest(digest, 0, len(personFirstNames))]
		last := personLastNames[indexFromDigest(digest, 2, len(personLastNames))]
		return slugName(first) + "." + slugName(last)
	case entityEmail:
		first := personFirstNames[indexFromDigest(digest, 0, len(personFirstNames))]
		last := personLastNames[indexFromDigest(digest, 2, len(personLastNames))]
		domain := strings.ToLower(organizationAdjectives[indexFromDigest(digest, 4, len(organizationAdjectives))])
		return slugName(first) + "." + slugName(last) + "@" + domain + ".example"
	case entityDomain:
		name := strings.ToLower(organizationAdjectives[indexFromDigest(digest, 0, len(organizationAdjectives))] + "-" + organizationNouns[indexFromDigest(digest, 2, len(organizationNouns))])
		name = strings.ReplaceAll(name, " ", "-")
		suffix := ".example"
		lower := strings.ToLower(strings.TrimSpace(original))
		if !strings.Contains(lower, ".") || strings.HasSuffix(lower, ".local") || strings.HasSuffix(lower, ".internal") || strings.HasSuffix(lower, ".lan") {
			suffix = ".internal"
		}
		return name + suffix
	case entityHostname:
		role := hostnameRole(original)
		return fmt.Sprintf("%s-%04d", role, 1+int(binary.BigEndian.Uint16(digest[:2]))%9999)
	case entityIPAddress:
		return pseudonymIPAddress(original, digest)
	case entityMACAddress:
		return fmt.Sprintf("02:%02x:%02x:%02x:%02x:%02x", digest[0], digest[1], digest[2], digest[3], digest[4])
	case entitySID:
		return fmt.Sprintf("S-1-5-21-%d-%d-%d-%d", binary.BigEndian.Uint32(digest[0:4]), binary.BigEndian.Uint32(digest[4:8]), binary.BigEndian.Uint32(digest[8:12]), 1000+binary.BigEndian.Uint32(digest[12:16])%9000)
	case entityPhone:
		return pseudonymPhone(original, digest)
	case entityAddress:
		return fmt.Sprintf("%d %s", 1+binary.BigEndian.Uint16(digest[:2])%399, streetNames[indexFromDigest(digest, 2, len(streetNames))])
	case entityFilename:
		return pseudonymFilename(original, digest)
	case entityAzureResourceGroup:
		name := organizationAdjectives[indexFromDigest(digest, 0, len(organizationAdjectives))]
		return "rg-" + strings.ToLower(name) + "-" + hex.EncodeToString(digest[2:4])
	case entityAzureResourceName:
		return "resource-" + hex.EncodeToString(digest[:5])
	case entityIdentifier:
		if guidPattern.MatchString(strings.TrimSpace(original)) {
			copyDigest := append([]byte(nil), digest[:16]...)
			copyDigest[6] = copyDigest[6]&0x0f | 0x40
			copyDigest[8] = copyDigest[8]&0x3f | 0x80
			encoded := hex.EncodeToString(copyDigest)
			return encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:32]
		}
		return "id-" + hex.EncodeToString(digest[:8])
	default:
		return "entity-" + hex.EncodeToString(digest[:8])
	}
}

func (p *pseudonymizer) digest(kind entityKind, original string, attempt int) []byte {
	hash := hmac.New(sha256.New, p.seed)
	hash.Write([]byte(entityKey(kind, original)))
	hash.Write([]byte{0})
	hash.Write([]byte(strconv.Itoa(attempt)))
	return hash.Sum(nil)
}

func indexFromDigest(digest []byte, offset, length int) int {
	return int(binary.BigEndian.Uint16(digest[offset:offset+2])) % length
}

func slugName(value string) string {
	value = strings.ToLower(value)
	value = strings.ReplaceAll(value, " ", "")
	return value
}

func hostnameRole(original string) string {
	lower := strings.ToLower(original)
	switch {
	case strings.Contains(lower, "domaincontroller") || strings.Contains(lower, "-dc") || strings.HasPrefix(lower, "dc"):
		return "dc"
	case strings.Contains(lower, "server") || strings.Contains(lower, "-srv") || strings.HasPrefix(lower, "srv"):
		return "srv"
	case strings.Contains(lower, "laptop") || strings.Contains(lower, "-lap") || strings.HasPrefix(lower, "lap"):
		return "lap"
	case strings.Contains(lower, "workstation") || strings.Contains(lower, "-ws") || strings.HasPrefix(lower, "ws"):
		return "ws"
	default:
		return "host"
	}
}

func pseudonymIPAddress(original string, digest []byte) string {
	address, err := netip.ParseAddr(strings.TrimSpace(original))
	if err != nil {
		return fmt.Sprintf("198.51.100.%d", 1+int(digest[0])%254)
	}
	if address.Is6() {
		return fmt.Sprintf("2001:db8:%x:%x::%x", binary.BigEndian.Uint16(digest[0:2]), binary.BigEndian.Uint16(digest[2:4]), binary.BigEndian.Uint16(digest[4:6]))
	}
	if address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() {
		return fmt.Sprintf("10.203.%d.%d", digest[0], 1+int(digest[1])%254)
	}
	prefixes := [][3]byte{{192, 0, 2}, {198, 51, 100}, {203, 0, 113}}
	prefix := prefixes[int(digest[0])%len(prefixes)]
	return fmt.Sprintf("%d.%d.%d.%d", prefix[0], prefix[1], prefix[2], 1+int(digest[1])%254)
}

func pseudonymPhone(original string, digest []byte) string {
	var builder strings.Builder
	digitIndex := 0
	for _, r := range original {
		if r >= '0' && r <= '9' {
			builder.WriteByte('0' + digest[digitIndex%len(digest)]%10)
			digitIndex++
		} else {
			builder.WriteRune(r)
		}
	}
	return builder.String()
}

func pseudonymFilename(original string, digest []byte) string {
	name := filepath.Base(strings.TrimSpace(original))
	extension := filepath.Ext(name)
	if strings.HasPrefix(name, ".") && strings.Count(name, ".") == 1 {
		extension = ""
	}
	return "file-" + hex.EncodeToString(digest[:5]) + extension
}

func finalizePseudonymMap(p *pseudonymizer, retention string) (bool, error) {
	switch retention {
	case "keep":
		return true, nil
	case "delete":
		if err := os.Remove(p.Path()); err != nil && !errors.Is(err, os.ErrNotExist) {
			return true, fmt.Errorf("delete pseudonym mapping file %s: %w", p.Path(), err)
		}
		return false, nil
	default:
		return true, fmt.Errorf("unsupported pseudonym mapping retention %q", retention)
	}
}
