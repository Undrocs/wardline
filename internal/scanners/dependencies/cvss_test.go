package dependencies

import (
	"math"
	"testing"

	"github.com/Undrocs/wardline/internal/findings"
)

func TestCVSSv3BaseScore(t *testing.T) {
	// Reference vectors and scores from the CVSS v3.1 specification and the
	// FIRST calculator examples.
	cases := []struct {
		vector string
		want   float64
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5},
		{"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8},
		{"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0},
		{"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
	}
	for _, c := range cases {
		got, ok := CVSSv3BaseScore(c.vector)
		if !ok {
			t.Fatalf("vector %s was not scored", c.vector)
		}
		if math.Abs(got-c.want) > 0.05 {
			t.Errorf("CVSSv3BaseScore(%s) = %.1f, want %.1f", c.vector, got, c.want)
		}
	}
}

func TestCVSSRejectsIncompleteVectors(t *testing.T) {
	for _, vector := range []string{
		"",
		"CVSS:3.1/AV:N/AC:L",
		"CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:X/C:H/I:H/A:H",
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
	} {
		if _, ok := CVSSv3BaseScore(vector); ok {
			t.Errorf("expected %q to be rejected", vector)
		}
	}
}

func TestSeverityFromAdvisory(t *testing.T) {
	cases := []struct {
		name string
		view *vulnerabilityView
		want findings.Severity
	}{
		{"database rating", &vulnerabilityView{DatabaseSeverity: "HIGH"}, findings.SeverityHigh},
		{"ghsa moderate", &vulnerabilityView{DatabaseSeverity: "MODERATE"}, findings.SeverityMedium},
		{"critical", &vulnerabilityView{DatabaseSeverity: "CRITICAL"}, findings.SeverityCritical},
		{"cvss vector", &vulnerabilityView{Vectors: []struct{ Score string }{{Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}}, findings.SeverityCritical},
		{"cvss v4 only", &vulnerabilityView{Vectors: []struct{ Score string }{{Score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}}}, findings.SeverityUnknown},
		{"nothing", &vulnerabilityView{}, findings.SeverityUnknown},
		{"nil", nil, findings.SeverityUnknown},
	}
	for _, c := range cases {
		got, _, _ := SeverityFromAdvisory(c.view)
		if got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestSeverityReportsUnknownSeparatelyFromLow(t *testing.T) {
	// An advisory with no rating must produce unknown, never low.
	sev, score, _ := SeverityFromAdvisory(&vulnerabilityView{})
	if sev != findings.SeverityUnknown {
		t.Fatalf("expected unknown severity, got %v", sev)
	}
	if score != nil {
		t.Fatalf("expected no score, got %v", *score)
	}
}

func TestCVSSVectorIsReportedOnlyWhenEvaluated(t *testing.T) {
	view := &vulnerabilityView{
		DatabaseSeverity: "HIGH",
		Vectors:          []struct{ Score string }{{Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
	}
	sev, _, _ := SeverityFromAdvisory(view)
	if sev != findings.SeverityHigh {
		t.Fatalf("database severity should take precedence, got %v", sev)
	}
}
