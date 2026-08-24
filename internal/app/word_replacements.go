package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maxWordReplacementFileSize    = 1 << 20
	maxWordReplacementRules       = 10_000
	configuredReplacementPriority = 100
)

type wordReplacementConfig struct {
	CaseSensitive bool                   `json:"case_sensitive"`
	WholeWords    *bool                  `json:"whole_words"`
	Replacements  []wordReplacementEntry `json:"replacements"`
}

type wordReplacementEntry struct {
	Find    wordReplacementFind `json:"find"`
	Replace string              `json:"replace"`
}

type wordReplacementFind []string

func (find *wordReplacementFind) UnmarshalJSON(body []byte) error {
	var single string
	if err := json.Unmarshal(body, &single); err == nil {
		*find = []string{single}
		return nil
	}

	var list []string
	if err := json.Unmarshal(body, &list); err != nil {
		return errors.New("find must be a string or an array of strings")
	}
	*find = list
	return nil
}

type compiledWordReplacement struct {
	find        string
	replacement string
	pattern     *regexp.Regexp
	wholeWords  bool
	startsWord  bool
	endsWord    bool
}

type wordReplacementSet struct {
	rules []compiledWordReplacement
}

func loadWordReplacementSet(path string) (*wordReplacementSet, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open pseudonym replacement file %s: %w", path, err)
	}
	defer file.Close()

	body, err := io.ReadAll(io.LimitReader(file, maxWordReplacementFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read pseudonym replacement file %s: %w", path, err)
	}
	if len(body) > maxWordReplacementFileSize {
		return nil, fmt.Errorf("pseudonym replacement file %s exceeds %d bytes", path, maxWordReplacementFileSize)
	}

	var config wordReplacementConfig
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("decode pseudonym replacement file %s: %w", path, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("multiple JSON values")
		}
		return nil, fmt.Errorf("decode pseudonym replacement file %s: %w", path, err)
	}
	if len(config.Replacements) == 0 {
		return nil, errors.New("pseudonym replacement file must contain at least one replacement")
	}
	wholeWords := true
	if config.WholeWords != nil {
		wholeWords = *config.WholeWords
	}
	rules := make([]compiledWordReplacement, 0, len(config.Replacements))
	seen := make(map[string]struct{}, len(config.Replacements))
	for _, entry := range config.Replacements {
		entry.Replace = strings.TrimSpace(entry.Replace)
		if len(entry.Find) == 0 || entry.Replace == "" {
			return nil, errors.New("[!] pseudonym replacement entries require non-empty find and replace values")
		}
		for _, find := range entry.Find {
			find = strings.TrimSpace(find)
			if find == "" {
				return nil, errors.New("[!] pseudonym replacement entries require non-empty find and replace values")
			}
			if len(rules) >= maxWordReplacementRules {
				return nil, fmt.Errorf("pseudonym replacement file contains more than %d find values", maxWordReplacementRules)
			}
			canonical := strings.ToLower(find)
			if _, exists := seen[canonical]; exists {
				return nil, errors.New("pseudonym replacement file contains duplicate find values")
			}
			seen[canonical] = struct{}{}

			expression := regexp.QuoteMeta(find)
			if !config.CaseSensitive {
				expression = "(?i:" + expression + ")"
			}
			pattern, err := regexp.Compile(expression)
			if err != nil {
				return nil, fmt.Errorf("[!] compile literal pseudonym replacement: %w", err)
			}
			first, _ := utf8.DecodeRuneInString(find)
			last, _ := utf8.DecodeLastRuneInString(find)
			rules = append(rules, compiledWordReplacement{
				find:        find,
				replacement: entry.Replace,
				pattern:     pattern,
				wholeWords:  wholeWords,
				startsWord:  isReplacementWordRune(first),
				endsWord:    isReplacementWordRune(last),
			})
		}
	}

	sort.SliceStable(rules, func(i, j int) bool {
		return len(rules[i].find) > len(rules[j].find)
	})
	return &wordReplacementSet{rules: rules}, nil
}

func (s *wordReplacementSet) Len() int {
	if s == nil {
		return 0
	}
	return len(s.rules)
}

func (s *wordReplacementSet) Recognize(value string) []recognizedEntity {
	if s == nil || value == "" {
		return nil
	}
	entities := make([]recognizedEntity, 0)
	for _, rule := range s.rules {
		for _, indices := range rule.pattern.FindAllStringIndex(value, -1) {
			if rule.wholeWords && !replacementHasWordBoundaries(value, indices[0], indices[1], rule.startsWord, rule.endsWord) {
				continue
			}
			entities = append(entities, recognizedEntity{
				Start:       indices[0],
				End:         indices[1],
				Kind:        entityConfigured,
				Text:        value[indices[0]:indices[1]],
				Replacement: rule.replacement,
				Priority:    configuredReplacementPriority,
			})
		}
	}
	return entities
}

func replacementHasWordBoundaries(value string, start, end int, startsWord, endsWord bool) bool {
	if startsWord && start > 0 {
		previous, _ := utf8.DecodeLastRuneInString(value[:start])
		if isReplacementWordRune(previous) {
			return false
		}
	}
	if endsWord && end < len(value) {
		next, _ := utf8.DecodeRuneInString(value[end:])
		if isReplacementWordRune(next) {
			return false
		}
	}
	return true
}

func isReplacementWordRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_'
}
