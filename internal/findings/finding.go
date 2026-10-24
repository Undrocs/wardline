// Package findings defines the single finding model shared by every scanner and
// every report writer.
package findings

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// Scanner names. They are stable and appear in reports.
const (
	ScannerSecrets      = "secrets"
	ScannerDependencies = "dependencies"
	ScannerWorkflows    = "workflows"
	ScannerConfig       = "config"
)

// Location is a source position inside the scanned repository.
//
// Path is always slash separated and relative to the scan root. Lines and
// columns are 1-based; zero means "not known".
type Location struct {
	Path        string `json:"path"`
	StartLine   int    `json:"startLine,omitempty"`
	StartColumn int    `json:"startColumn,omitempty"`
	EndLine     int    `json:"endLine,omitempty"`
	EndColumn   int    `json:"endColumn,omitempty"`
}

// String renders "path:line" or just the path.
func (l Location) String() string {
	if l.StartLine <= 0 {
		return l.Path
	}
	if l.StartColumn > 0 {
		return l.Path + ":" + itoa(l.StartLine) + ":" + itoa(l.StartColumn)
	}
	return l.Path + ":" + itoa(l.StartLine)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// Package identifies a dependency involved in a finding.
type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
	Direct    bool   `json:"direct"`
	// Manifest is the lockfile or manifest that supplied the version.
	Manifest string `json:"manifest,omitempty"`
}

// Vulnerability carries advisory metadata for dependency findings.
type Vulnerability struct {
	IDs          []string `json:"ids,omitempty"`
	Summary      string   `json:"summary,omitempty"`
	Details      string   `json:"details,omitempty"`
	Aliases      []string `json:"aliases,omitempty"`
	Affected     string   `json:"affected,omitempty"`
	FixedVersion string   `json:"fixedVersion,omitempty"`
	Published    string   `json:"published,omitempty"`
	Modified     string   `json:"modified,omitempty"`
	// CVSSVector is the published vector when an advisory supplies one. It is
	// never synthesized.
	CVSSVector string `json:"cvssVector,omitempty"`
	// CVSSScore is computed from CVSSVector with the official CVSS v3.1
	// specification, or taken from an advisory that publishes a score.
	CVSSScore *float64 `json:"cvssScore,omitempty"`
}

// Finding is a single, normalised security observation.
//
// Evidence is always sanitised before it reaches this struct: scanners must not
// store raw secrets anywhere in a Finding.
type Finding struct {
	// ID is a deterministic fingerprint derived from rule, path and a
	// structural locator. It stays stable when unrelated lines move.
	ID         string     `json:"id"`
	RuleID     string     `json:"ruleId"`
	Scanner    string     `json:"scanner"`
	Title      string     `json:"title"`
	Severity   Severity   `json:"severity"`
	Confidence Confidence `json:"confidence"`
	Location   Location   `json:"location"`
	// Evidence is a short, sanitised excerpt supporting the finding.
	Evidence      string         `json:"evidence,omitempty"`
	Description   string         `json:"description,omitempty"`
	Impact        string         `json:"impact,omitempty"`
	Remediation   string         `json:"remediation,omitempty"`
	References    []string       `json:"references,omitempty"`
	Package       *Package       `json:"package,omitempty"`
	Vulnerability *Vulnerability `json:"vulnerability,omitempty"`

	// Locator is the structural path used for fingerprinting (for example
	// "jobs.release.permissions"). It is not a display location.
	Locator string `json:"-"`

	Suppressed        bool   `json:"suppressed"`
	SuppressionReason string `json:"suppressionReason,omitempty"`
}

// New builds a finding and computes its stable fingerprint.
func New(f Finding) Finding {
	if f.ID == "" {
		f.ID = Fingerprint(f.RuleID, f.Location.Path, f.Locator)
	}
	return f
}

// Fingerprint derives a stable 16 hex character identifier.
//
// The locator should be structural (YAML path, package name, secret rule inside
// a file) rather than a line number so that unrelated edits do not change it.
func Fingerprint(ruleID, path, locator string) string {
	sum := sha256.Sum256([]byte(ruleID + "\x00" + path + "\x00" + locator))
	return hex.EncodeToString(sum[:8])
}

// LocationString is a convenience for report writers.
func (f Finding) LocationString() string { return f.Location.String() }

// Sort orders findings deterministically: severity first (most severe first,
// unknown last), then path, line, rule and id.
func Sort(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() > b.Severity.Rank()
		}
		if a.Location.Path != b.Location.Path {
			return a.Location.Path < b.Location.Path
		}
		if a.Location.StartLine != b.Location.StartLine {
			return a.Location.StartLine < b.Location.StartLine
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		return a.Title < b.Title
	})
}

// Dedupe removes findings with an identical fingerprint, keeping the first.
// Findings that differ only in evidence keep the most severe variant.
func Dedupe(fs []Finding) []Finding {
	index := make(map[string]int, len(fs))
	out := fs[:0]
	for _, f := range fs {
		key := f.ID
		if f.ID == "" {
			key = Fingerprint(f.RuleID, f.Location.Path, f.Locator)
			f.ID = key
		}
		pos, seen := index[key]
		if !seen {
			index[key] = len(out)
			out = append(out, f)
			continue
		}
		if f.Severity.Rank() > out[pos].Severity.Rank() {
			out[pos] = f
		}
	}
	return out
}

// Counts is the per-severity breakdown used in summaries.
type Counts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	Unknown  int `json:"unknown"`
}

// Add increments the bucket for s.
func (c *Counts) Add(s Severity) {
	switch s {
	case SeverityCritical:
		c.Critical++
	case SeverityHigh:
		c.High++
	case SeverityMedium:
		c.Medium++
	case SeverityLow:
		c.Low++
	case SeverityInfo:
		c.Info++
	default:
		c.Unknown++
	}
}

// Total returns the number of counted findings.
func (c Counts) Total() int {
	return c.Critical + c.High + c.Medium + c.Low + c.Info + c.Unknown
}

// Count counts findings by severity, optionally including suppressed ones.
func Count(fs []Finding, includeSuppressed bool) Counts {
	var c Counts
	for _, f := range fs {
		if f.Suppressed && !includeSuppressed {
			continue
		}
		c.Add(f.Severity)
	}
	return c
}

// MatchesAnyGlob reports whether the finding path matches a path pattern.
// Patterns use slash-separated, doublestar-free semantics: "*" matches within a
// segment, "**" matches across segments, and a trailing "/" matches a prefix.
func MatchesAnyGlob(path string, patterns []string) bool {
	for _, p := range patterns {
		if MatchGlob(p, path) {
			return true
		}
	}
	return false
}

// MatchGlob implements segment-aware glob matching for repository-relative
// slash paths.
func MatchGlob(pattern, path string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return false
	}
	if strings.Contains(pattern, "**") {
		return matchDoubleStar(splitSegments(pattern), splitSegments(path))
	}
	return matchSegments(splitSegments(pattern), splitSegments(path))
}

func splitSegments(p string) []string {
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

func matchDoubleStar(pat, seg []string) bool {
	if len(pat) == 0 {
		return len(seg) == 0
	}
	if pat[0] == "**" {
		for i := 0; i <= len(seg); i++ {
			if matchDoubleStar(pat[1:], seg[i:]) {
				return true
			}
		}
		return false
	}
	if len(seg) == 0 {
		return false
	}
	if !matchSegment(pat[0], seg[0]) {
		return false
	}
	return matchDoubleStar(pat[1:], seg[1:])
}

func matchSegments(pat, seg []string) bool {
	if len(pat) != len(seg) {
		return false
	}
	for i := range pat {
		if !matchSegment(pat[i], seg[i]) {
			return false
		}
	}
	return true
}

// matchSegment matches one path segment. Only '*' is special, and it matches
// any sequence of characters inside the segment; there is no character class or
// brace expansion, which keeps exclusion patterns predictable.
func matchSegment(pattern, s string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == s
	}
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	for i := 1; i < len(parts)-1; i++ {
		idx := strings.Index(s, parts[i])
		if idx < 0 {
			return false
		}
		s = s[idx+len(parts[i]):]
	}
	return strings.HasSuffix(s, parts[len(parts)-1])
}
