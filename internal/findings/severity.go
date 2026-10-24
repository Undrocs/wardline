package findings

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Severity expresses how damaging exploitation of a finding would be.
//
// It is deliberately coarse. Wardline never presents a heuristic severity as an
// official CVSS score; when a severity is derived from an advisory it is mapped
// from the advisory's own rating or from the published CVSS vector.
type Severity int

const (
	// SeverityUnknown means the available data does not support a rating. It is
	// explicitly distinct from SeverityLow.
	SeverityUnknown Severity = iota
	// SeverityInfo is informational hardening guidance.
	SeverityInfo
	// SeverityLow is a low-impact issue.
	SeverityLow
	// SeverityMedium is a meaningful issue requiring attention.
	SeverityMedium
	// SeverityHigh is a serious issue that should be fixed before release.
	SeverityHigh
	// SeverityCritical is an issue allowing direct compromise.
	SeverityCritical
)

var severityNames = [...]string{"unknown", "info", "low", "medium", "high", "critical"}

// String returns the lower-case name used in reports and CLI flags.
func (s Severity) String() string {
	if s < 0 || int(s) >= len(severityNames) {
		return "unknown"
	}
	return severityNames[s]
}

// Label returns the upper-case name used in terminal output.
func (s Severity) Label() string { return strings.ToUpper(s.String()) }

// MarshalJSON encodes the severity as its lower-case name.
func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

// UnmarshalJSON accepts a severity name.
func (s *Severity) UnmarshalJSON(b []byte) error {
	var name string
	if err := json.Unmarshal(b, &name); err != nil {
		return fmt.Errorf("severity must be a string, got %s", string(b))
	}
	parsed, err := ParseSeverity(name)
	if err != nil {
		return err
	}
	*s = parsed
	return nil
}

// ParseSeverity parses a case-insensitive severity name.
func ParseSeverity(name string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "unknown", "unrated":
		return SeverityUnknown, nil
	case "info", "informational", "none":
		return SeverityInfo, nil
	case "low":
		return SeverityLow, nil
	case "medium", "moderate":
		return SeverityMedium, nil
	case "high":
		return SeverityHigh, nil
	case "critical":
		return SeverityCritical, nil
	default:
		return SeverityUnknown, fmt.Errorf("unknown severity %q (valid: info, low, medium, high, critical, unknown)", name)
	}
}

// AtLeast reports whether s is at least as severe as min.
// SeverityUnknown never meets a threshold other than unknown.
func (s Severity) AtLeast(min Severity) bool {
	if min == SeverityUnknown {
		return true
	}
	if s == SeverityUnknown {
		return false
	}
	return s >= min
}

// Rank returns a sortable rank where higher means more severe. Unknown sorts last
// because it cannot be ordered relative to real ratings.
func (s Severity) Rank() int {
	if s == SeverityUnknown {
		return -1
	}
	return int(s)
}

// Confidence expresses how certain Wardline is that a finding is a true positive.
type Confidence string

const (
	// ConfidenceLow is a heuristic match that commonly has benign explanations.
	ConfidenceLow Confidence = "low"
	// ConfidenceMedium is a strong pattern match with some ambiguity.
	ConfidenceMedium Confidence = "medium"
	// ConfidenceHigh is a pattern match with structural or format validation.
	ConfidenceHigh Confidence = "high"
)

// ParseConfidence validates a confidence name.
func ParseConfidence(name string) (Confidence, error) {
	switch Confidence(strings.ToLower(strings.TrimSpace(name))) {
	case ConfidenceLow:
		return ConfidenceLow, nil
	case ConfidenceMedium:
		return ConfidenceMedium, nil
	case ConfidenceHigh:
		return ConfidenceHigh, nil
	default:
		return "", fmt.Errorf("unknown confidence %q (valid: low, medium, high)", name)
	}
}

// Rank returns a sortable rank where higher means more confident.
func (c Confidence) Rank() int {
	switch c {
	case ConfidenceHigh:
		return 3
	case ConfidenceMedium:
		return 2
	case ConfidenceLow:
		return 1
	default:
		return 0
	}
}
