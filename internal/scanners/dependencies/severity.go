package dependencies

import (
	"math"
	"strconv"
	"strings"

	"github.com/Undrocs/wardline/internal/findings"
)

// SeverityFromAdvisory derives a severity for an advisory.
//
// Order of preference:
//  1. an explicit textual severity published by the advisory database
//     (GHSA "CRITICAL"/"HIGH"/"MODERATE"/"LOW");
//  2. a CVSS v3 vector, scored with the published CVSS v3.1 base formula;
//  3. unknown.
//
// A vector that Wardline cannot evaluate (for example CVSS v4) yields unknown
// severity rather than a guess. Heuristic scores are never presented as CVSS.
func SeverityFromAdvisory(vuln *vulnerabilityView) (findings.Severity, *float64, []string) {
	if vuln == nil {
		return findings.SeverityUnknown, nil, nil
	}
	var notes []string
	if sev, ok := parseTextSeverity(vuln.DatabaseSeverity); ok {
		return sev, nil, notes
	}
	for _, entry := range vuln.Vectors {
		vec := strings.TrimSpace(entry.Score)
		if !strings.HasPrefix(strings.ToUpper(vec), "CVSS:3.") {
			if strings.HasPrefix(strings.ToUpper(vec), "CVSS:4.") {
				notes = append(notes, "CVSS v4 vector present but not evaluated; severity may be understated")
			}
			continue
		}
		if score, ok := CVSSv3BaseScore(vec); ok {
			rounded := score
			return severityFromCVSSScore(rounded), &rounded, notes
		}
		notes = append(notes, "CVSS vector could not be parsed; severity is unknown")
	}
	return findings.SeverityUnknown, nil, notes
}

func parseTextSeverity(raw string) (findings.Severity, bool) {
	sev, err := findings.ParseSeverity(strings.ToLower(strings.TrimSpace(raw)))
	if err != nil || sev == findings.SeverityUnknown {
		return findings.SeverityUnknown, false
	}
	return sev, true
}

// severityFromCVSSScore applies the qualitative severity scale defined by the
// CVSS specification (v3.1 section 5).
func severityFromCVSSScore(score float64) findings.Severity {
	switch {
	case score <= 0:
		return findings.SeverityInfo
	case score < 4.0:
		return findings.SeverityLow
	case score < 7.0:
		return findings.SeverityMedium
	case score < 9.0:
		return findings.SeverityHigh
	default:
		return findings.SeverityCritical
	}
}

// CVSSv3BaseScore computes the CVSS v3.1 base score for a vector string.
// It implements the official equations; it is not a heuristic.
func CVSSv3BaseScore(vector string) (float64, bool) {
	parts := strings.Split(vector, "/")
	metrics := map[string]string{}
	for _, part := range parts {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) != 2 {
			continue
		}
		metrics[strings.ToUpper(kv[0])] = strings.ToUpper(kv[1])
	}
	av, okAV := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[metrics["AV"]]
	ac, okAC := map[string]float64{"L": 0.77, "H": 0.44}[metrics["AC"]]
	ui, okUI := map[string]float64{"N": 0.85, "R": 0.62}[metrics["UI"]]
	scope := metrics["S"]
	changed := scope == "C"
	prTable := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	if changed {
		prTable = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
	}
	pr, okPR := prTable[metrics["PR"]]
	cia := map[string]float64{"H": 0.56, "L": 0.22, "N": 0.0}
	c, okC := cia[metrics["C"]]
	i, okI := cia[metrics["I"]]
	a, okA := cia[metrics["A"]]
	if !okAV || !okAC || !okUI || !okPR || !okC || !okI || !okA || (scope != "U" && scope != "C") {
		return 0, false
	}
	iss := 1 - (1-c)*(1-i)*(1-a)
	var impact float64
	if changed {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	exploitability := 8.22 * av * ac * pr * ui
	if impact <= 0 {
		return 0, true
	}
	var base float64
	if changed {
		base = math.Min(1.08*(impact+exploitability), 10)
	} else {
		base = math.Min(impact+exploitability, 10)
	}
	return roundUpOneDecimal(base), true
}

// roundUpOneDecimal implements the CVSS "round up to one decimal place" rule.
func roundUpOneDecimal(x float64) float64 {
	scaled := x * 10
	// Values within floating point noise of an exact tenth must not be rounded
	// up to the next tenth (10.0 must stay 10.0, not become 10.1).
	if math.Abs(scaled-math.Round(scaled)) < 1e-9 {
		scaled = math.Round(scaled)
	}
	return math.Ceil(scaled) / 10
}

// vulnerabilityView is the flattened advisory data the scanner needs.
type vulnerabilityView struct {
	IDs              []string
	Summary          string
	Details          string
	DatabaseSeverity string
	Vectors          []struct {
		Score string
	}
	// Vector is the advisory CVSS vector used for the rating, when present.
	Vector string
	// AffectedRange and FixedVersion are scoped to the queried package.
	AffectedRange string
	FixedVersion  string
	Published     string
	Modified      string
	References    []string
}

// formatScore renders a CVSS score with one decimal place.
func formatScore(score float64) string { return strconv.FormatFloat(score, 'f', 1, 64) }
