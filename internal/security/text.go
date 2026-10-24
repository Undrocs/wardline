package security

import (
	"math"
	"regexp"
	"strings"
)

// ShannonEntropy computes the per-character Shannon entropy of s in bits.
// It is used as a secondary signal for detecting random-looking credentials.
func ShannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	total := float64(len(s))
	var entropy float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / total
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// DistinctChars counts unique bytes in s.
func DistinctChars(s string) int {
	var seen [256]bool
	n := 0
	for i := 0; i < len(s); i++ {
		if !seen[s[i]] {
			seen[s[i]] = true
			n++
		}
	}
	return n
}

var placeholderPattern = func() *regexp.Regexp {
	alternatives := []string{
		`placeholder`, `replace[-_ ]?me`, `changeme`, `change[-_ ]?me`,
		`example`, `sample`, `dummy`, `fake`, `test`, `testing`, `secret`,
		`password`, `passwd`, `pass`, `token`, `apikey`, `api[-_]?key`,
		`x{3,}`, `\.{3,}`, `\*{3,}`, `<[^>]+>`, `\$\{[^}]+\}`, `\{\{[^}]+\}`,
		`your[-_ ]?(?:api[-_ ]?)?(?:key|token|secret|password)(?:[-_ ]?here)?`,
		`(?:insert|add|put)[-_ ].*`, `todo`, `none`, `null`, `nil`,
		`undefined`, `true`, `false`, `[a-z]+[-_]example`,
	}
	return regexp.MustCompile(`(?i)^(?:` + strings.Join(alternatives, "|") + `)$`)
}()

// LooksLikePlaceholder reports whether a candidate value is almost certainly a
// documentation placeholder rather than a real credential.
func LooksLikePlaceholder(value string) bool {
	v := strings.TrimSpace(value)
	if v == "" {
		return true
	}
	trimmed := strings.Trim(v, `"'`+"`")
	if trimmed == "" {
		return true
	}
	if placeholderPattern.MatchString(trimmed) {
		return true
	}
	lower := strings.ToLower(trimmed)
	for _, marker := range []string{
		"example.com", "example.org", "your-", "your_", "xxx", "changeme",
		"replace-me", "replaceme", "placeholder", "redacted", "not-a-real",
		"fake", "dummy", "insecure", "development-only", "localhost",
		"<your", "${", "{{",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	// A value made of a single repeated character or a very small alphabet is
	// not a credential.
	if DistinctChars(trimmed) <= 2 && len(trimmed) > 6 {
		return true
	}
	if len(trimmed) >= 3 && allSameRune(trimmed) {
		return true
	}
	return false
}

func allSameRune(s string) bool {
	first := s[0]
	for i := 1; i < len(s); i++ {
		if s[i] != first {
			return false
		}
	}
	return true
}

// LooksRandom applies light heuristics that separate generated values from
// natural language: enough character variety and digits.
func LooksRandom(value string, minEntropy float64) bool {
	if len(value) < 8 {
		return false
	}
	if DistinctChars(value) < 8 {
		return false
	}
	digits, letters := 0, 0
	for i := 0; i < len(value); i++ {
		switch c := value[i]; {
		case c >= '0' && c <= '9':
			digits++
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
			letters++
		}
	}
	if digits == 0 || letters == 0 {
		return false
	}
	return ShannonEntropy(value) >= minEntropy
}

// WithinRootOnce is a small helper used by tests and callers that build paths by
// hand; it reports whether p is free of parent-directory segments.
func WithinRootOnce(p string) bool {
	cleaned := strings.ReplaceAll(p, "\\", "/")
	for _, seg := range strings.Split(cleaned, "/") {
		if seg == ".." {
			return false
		}
	}
	return true
}
