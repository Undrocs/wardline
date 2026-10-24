package findings

import (
	"encoding/json"
	"testing"
)

func TestFingerprintStableAndPathScoped(t *testing.T) {
	a := Fingerprint("WL-SEC-001", "src/a.go", "match:AKIA••••••")
	b := Fingerprint("WL-SEC-001", "src/a.go", "match:AKIA••••••")
	if a != b {
		t.Fatal("fingerprint is not deterministic")
	}
	if len(a) != 16 {
		t.Fatalf("unexpected fingerprint length %d", len(a))
	}
	c := Fingerprint("WL-SEC-001", "src/b.go", "match:AKIA••••••")
	if a == c {
		t.Fatal("fingerprint does not depend on the path")
	}
	d := Fingerprint("WL-SEC-002", "src/a.go", "match:AKIA••••••")
	if a == d {
		t.Fatal("fingerprint does not depend on the rule")
	}
}

func TestDedupeKeepsMostSevere(t *testing.T) {
	base := Finding{
		RuleID: "WL-TEST-001", Scanner: ScannerSecrets, Title: "t",
		Location: Location{Path: "a.go", StartLine: 3}, Locator: "x",
	}
	low := New(base)
	low.Severity = SeverityLow
	high := New(base)
	high.Severity = SeverityHigh
	other := New(Finding{RuleID: "WL-TEST-002", Scanner: ScannerSecrets, Title: "t2",
		Location: Location{Path: "a.go", StartLine: 3}, Locator: "y"})
	other.Severity = SeverityMedium

	out := Dedupe([]Finding{low, high, other})
	if len(out) != 2 {
		t.Fatalf("expected 2 findings after dedupe, got %d", len(out))
	}
	Sort(out)
	if out[0].Severity != SeverityHigh {
		t.Fatalf("expected the most severe variant to survive, got %s", out[0].Severity)
	}
}

func TestSortOrder(t *testing.T) {
	list := []Finding{
		{RuleID: "R1", Location: Location{Path: "b.go", StartLine: 1}, Severity: SeverityLow},
		{RuleID: "R2", Location: Location{Path: "a.go", StartLine: 9}, Severity: SeverityCritical},
		{RuleID: "R3", Location: Location{Path: "a.go", StartLine: 2}, Severity: SeverityLow},
		{RuleID: "R4", Location: Location{Path: "a.go", StartLine: 2}, Severity: SeverityUnknown},
	}
	Sort(list)
	if list[0].RuleID != "R2" {
		t.Fatalf("most severe finding is not first: %v", list)
	}
	if list[len(list)-1].RuleID != "R4" {
		t.Fatalf("unknown severity should sort last: %v", list)
	}
}

func TestSeverityParsing(t *testing.T) {
	valid := map[string]Severity{
		"critical": SeverityCritical, "HIGH": SeverityHigh, "medium": SeverityMedium,
		"moderate": SeverityMedium, "low": SeverityLow, "info": SeverityInfo,
		"informational": SeverityInfo, "unknown": SeverityUnknown, "": SeverityUnknown,
	}
	for input, want := range valid {
		got, err := ParseSeverity(input)
		if err != nil {
			t.Fatalf("ParseSeverity(%q): %v", input, err)
		}
		if got != want {
			t.Fatalf("ParseSeverity(%q) = %v, want %v", input, got, want)
		}
	}
	if _, err := ParseSeverity("severe"); err == nil {
		t.Fatal("expected an error for an invalid severity")
	}
}

func TestSeverityThresholds(t *testing.T) {
	if !SeverityHigh.AtLeast(SeverityMedium) {
		t.Fatal("high should meet the medium threshold")
	}
	if SeverityLow.AtLeast(SeverityHigh) {
		t.Fatal("low should not meet the high threshold")
	}
	if SeverityUnknown.AtLeast(SeverityLow) {
		t.Fatal("unknown must not satisfy a real threshold")
	}
	if !SeverityUnknown.AtLeast(SeverityUnknown) {
		t.Fatal("unknown meets the unknown threshold")
	}
}

func TestSeverityJSONRoundTrip(t *testing.T) {
	b, err := json.Marshal(SeverityHigh)
	if err != nil || string(b) != `"high"` {
		t.Fatalf("unexpected JSON: %s (%v)", b, err)
	}
	var s Severity
	if err := json.Unmarshal([]byte(`"critical"`), &s); err != nil || s != SeverityCritical {
		t.Fatalf("unexpected unmarshal: %v %v", s, err)
	}
	if err := json.Unmarshal([]byte(`"nonsense"`), &s); err == nil {
		t.Fatal("expected an error for an invalid severity")
	}
}

func TestMatchGlob(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{
		{".git/**", ".git/config", true},
		{"testdata/**", "testdata/vulnerable/.env", true},
		{"testdata/**", "testdata", true},
		{"**/.env", "a/b/.env", true},
		{"*.go", "main.go", true},
		{"*.go", "src/main.go", false},
		{"src/*.go", "src/main.go", true},
		{"src/*.go", "src/deep/main.go", false},
		{"src/**/*.go", "src/deep/nested/main.go", true},
		{"deploy/docker-compose.yml", "deploy/docker-compose.yml", true},
		{"deploy", "deploy/api/main.go", false},
	}
	for _, c := range cases {
		if got := MatchGlob(c.pattern, c.path); got != c.want {
			t.Errorf("MatchGlob(%q, %q) = %v, want %v", c.pattern, c.path, got, c.want)
		}
	}
}

func TestCounts(t *testing.T) {
	list := []Finding{
		{Severity: SeverityHigh},
		{Severity: SeverityHigh, Suppressed: true},
		{Severity: SeverityLow},
	}
	c := Count(list, false)
	if c.High != 1 || c.Low != 1 || c.Total() != 2 {
		t.Fatalf("unexpected counts: %+v", c)
	}
	all := Count(list, true)
	if all.Total() != 3 {
		t.Fatalf("unexpected counts including suppressed: %+v", all)
	}
}
