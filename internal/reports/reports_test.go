package reports

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Undrocs/wardline/internal/config"
	"github.com/Undrocs/wardline/internal/engine"
	"github.com/Undrocs/wardline/internal/findings"
	"github.com/Undrocs/wardline/internal/scanners"
	"github.com/Undrocs/wardline/internal/version"
)

func sampleResult() *engine.Result {
	start := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	high := findings.New(findings.Finding{
		RuleID: "WL-SEC-001", Scanner: findings.ScannerSecrets, Title: "AWS access key ID",
		Severity: findings.SeverityHigh, Confidence: findings.ConfidenceHigh,
		Location: findings.Location{Path: "src/config.go", StartLine: 12, StartColumn: 5},
		Evidence: "aws_key = \"AKIA••••••3V\"", Description: "desc", Impact: "impact",
		Remediation: "rotate it", References: []string{"https://example.com/aws"},
		Locator: "match:AKIA••••••3V",
	})
	critical := findings.New(findings.Finding{
		RuleID: "WL-WF006", Scanner: findings.ScannerWorkflows, Title: "Privileged checkout",
		Severity: findings.SeverityCritical, Confidence: findings.ConfidenceHigh,
		Location: findings.Location{Path: ".github/workflows/ci.yml", StartLine: 10},
		Evidence: "Checks out pull request head", Locator: "jobs.build.steps[0]",
	})
	suppressed := findings.New(findings.Finding{
		RuleID: "WL-WF004", Scanner: findings.ScannerWorkflows, Title: "Unpinned action",
		Severity: findings.SeverityMedium, Confidence: findings.ConfidenceHigh,
		Location: findings.Location{Path: ".github/workflows/ci.yml", StartLine: 22},
		Evidence: "Action not pinned", Locator: "jobs.build.steps[2].uses",
		Suppressed: true, SuppressionReason: "pinned by policy bot",
	})
	dep := findings.New(findings.Finding{
		RuleID: "WL-DEP-001", Scanner: findings.ScannerDependencies, Title: "Vulnerable dependency",
		Severity: findings.SeverityUnknown, Confidence: findings.ConfidenceHigh,
		Location: findings.Location{Path: "go.mod", StartLine: 6},
		Evidence: "golang.org/x/crypto v0.11.0 (transitive)", Locator: "Go:golang.org/x/crypto@v0.11.0:GO-0000",
		Package:       &findings.Package{Ecosystem: "Go", Name: "golang.org/x/crypto", Version: "v0.11.0", Manifest: "go.mod"},
		Vulnerability: &findings.Vulnerability{IDs: []string{"GO-0000", "CVE-2023-0000"}, FixedVersion: "v0.17.0", Affected: ">= v0.0.0, < v0.17.0"},
	})
	all := []findings.Finding{high, critical, suppressed, dep}
	findings.Sort(all)
	return &engine.Result{
		Target:     "./project",
		Root:       "/tmp/project",
		Mode:       engine.ModeWorkingTree,
		StartedAt:  start,
		FinishedAt: start.Add(1500 * time.Millisecond),
		FileCount:  42,
		Bytes:      4096,
		ConfigPath: ".wardline.yaml",
		Findings:   all,
		Network:    []string{"https://api.osv.dev"},
		Warnings:   []string{"skipped 1 file larger than the limit"},
		Scanners: []engine.ScannerRun{
			{Name: "secrets", Status: scanners.StatusRan, Scope: "42 files", Findings: 1, DurationMS: 10},
			{Name: "dependencies", Status: scanners.StatusPartial, Scope: "6 packages", Findings: 1,
				Skipped: []scanners.SkippedCheck{{Check: "OSV vulnerability lookup", Reason: "network disabled"}}},
			{Name: "workflows", Status: scanners.StatusRan, Scope: "1 workflow", Findings: 2},
		},
	}
}

func buildSample(t *testing.T, minSeverity findings.Severity, failOn findings.Severity) *Report {
	t.Helper()
	cfg := config.Default()
	cfg.Network.Enabled = true
	return Build(sampleResult(), cfg, Options{
		MinSeverity: minSeverity,
		FailOn:      failOn,
		Version:     version.Info{Name: "wardline", Version: "0.1.0", Commit: "abc", GoVersion: "go1.23", Platform: "linux/amd64"},
	})
}

func TestBuildSummaryAndPolicy(t *testing.T) {
	rep := buildSample(t, findings.SeverityInfo, findings.SeverityHigh)
	if rep.Summary.Total != 3 {
		t.Fatalf("expected 3 visible findings, got %d", rep.Summary.Total)
	}
	if rep.Summary.Suppressed != 1 {
		t.Fatalf("expected 1 suppressed finding, got %d", rep.Summary.Suppressed)
	}
	if !rep.Summary.Policy.Failed {
		t.Fatal("expected the policy to fail at high")
	}
	if !rep.Summary.Incomplete {
		t.Fatal("partial scanner must mark the report incomplete")
	}
	if rep.Summary.Counts.Critical != 1 || rep.Summary.Counts.High != 1 || rep.Summary.Counts.Unknown != 1 {
		t.Fatalf("unexpected counts: %+v", rep.Summary.Counts)
	}
	if rep.Summary.ScannersRan != 2 || rep.Summary.ScannersPartial != 1 {
		t.Fatalf("unexpected scanner counters: %+v", rep.Summary)
	}
	if rep.Scan.DurationMS != 1500 {
		t.Fatalf("unexpected duration %d", rep.Scan.DurationMS)
	}
	if !rep.Network.Enabled || len(rep.Network.Destinations) != 1 {
		t.Fatalf("unexpected network info: %+v", rep.Network)
	}
}

func TestSeverityFilterDoesNotHidePolicyFailure(t *testing.T) {
	// Findings below the reporting threshold disappear from the list, but the
	// policy is evaluated over everything.
	rep := buildSample(t, findings.SeverityCritical, findings.SeverityMedium)
	if rep.Summary.Total != 1 {
		t.Fatalf("expected only the critical finding to be reported, got %d", rep.Summary.Total)
	}
	if !rep.Summary.Policy.Failed {
		t.Fatal("policy must still consider findings below the reporting threshold")
	}
	if rep.Summary.Counts.Unknown != 0 {
		t.Fatal("unknown-severity findings must be hidden by a critical threshold")
	}
}

func TestUnknownSeverityReportedByDefault(t *testing.T) {
	rep := buildSample(t, findings.SeverityInfo, findings.SeverityHigh)
	var found bool
	for _, f := range rep.Findings {
		if f.Severity == findings.SeverityUnknown {
			found = true
		}
	}
	if !found {
		t.Fatal("unknown severity findings should be visible at the default threshold")
	}
}

func TestSuppressionsRemainAuditable(t *testing.T) {
	rep := buildSample(t, findings.SeverityInfo, findings.SeverityHigh)
	var suppressed *findings.Finding
	for i := range rep.Findings {
		if rep.Findings[i].Suppressed {
			suppressed = &rep.Findings[i]
		}
	}
	if suppressed == nil {
		t.Fatal("suppressed finding missing from the report")
	}
	if suppressed.SuppressionReason == "" {
		t.Fatal("suppression reason missing")
	}
	if rep.Summary.SuppressedCounts.Medium != 1 {
		t.Fatalf("unexpected suppressed counts: %+v", rep.Summary.SuppressedCounts)
	}
}

func TestJSONReport(t *testing.T) {
	rep := buildSample(t, findings.SeverityInfo, findings.SeverityHigh)
	var buf bytes.Buffer
	if err := WriteJSON(&buf, rep); err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	for _, key := range []string{"schemaVersion", "tool", "scan", "network", "scanners", "findings", "summary", "limitations"} {
		if _, ok := decoded[key]; !ok {
			t.Errorf("missing top-level key %q", key)
		}
	}
	findingsList, ok := decoded["findings"].([]any)
	if !ok || len(findingsList) == 0 {
		t.Fatal("findings array missing")
	}
	first := findingsList[0].(map[string]any)
	for _, key := range []string{"id", "ruleId", "scanner", "title", "severity", "confidence", "location", "suppressed"} {
		if _, ok := first[key]; !ok {
			t.Errorf("finding missing key %q", key)
		}
	}
	// Deterministic output.
	var second bytes.Buffer
	if err := WriteJSON(&second, rep); err != nil {
		t.Fatal(err)
	}
	if buf.String() != second.String() {
		t.Fatal("JSON output is not deterministic")
	}
	// Absolute paths must never be emitted.
	if strings.Contains(buf.String(), "/tmp/project") {
		t.Fatal("report leaked an absolute path")
	}
}

func TestMarkdownReport(t *testing.T) {
	rep := buildSample(t, findings.SeverityInfo, findings.SeverityHigh)
	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, rep); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"# Wardline scan report", "## Summary", "## Scanners", "## Findings",
		"## Suppressed findings", "## Checks not completed", "## Scan limitations",
		"WL-SEC-001", "WL-WF006", "This scan is incomplete", "AKIA••••••3V",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown report missing %q", want)
		}
	}
	if strings.Contains(out, "/tmp/project") {
		t.Error("markdown report leaked an absolute path")
	}
}

func TestSARIFStructure(t *testing.T) {
	rep := buildSample(t, findings.SeverityInfo, findings.SeverityHigh)
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, rep); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID                   string                 `json:"id"`
						ShortDescription     struct{ Text string }  `json:"shortDescription"`
						DefaultConfiguration struct{ Level string } `json:"defaultConfiguration"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string                `json:"ruleId"`
				RuleIndex int                   `json:"ruleIndex"`
				Level     string                `json:"level"`
				Message   struct{ Text string } `json:"message"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI       string `json:"uri"`
							URIBaseID string `json:"uriBaseId"`
						} `json:"artifactLocation"`
						Region *struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
				Suppressions        []struct {
					Kind          string `json:"kind"`
					Justification string `json:"justification"`
				} `json:"suppressions"`
			} `json:"results"`
			Invocations []struct {
				ExecutionSuccessful bool `json:"executionSuccessful"`
			} `json:"invocations"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	if doc.Version != "2.1.0" {
		t.Fatalf("unexpected version %q", doc.Version)
	}
	if !strings.Contains(doc.Schema, "sarif") {
		t.Fatalf("unexpected schema %q", doc.Schema)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("expected a single run, got %d", len(doc.Runs))
	}
	run := doc.Runs[0]
	if run.Tool.Driver.Name != "Wardline" {
		t.Errorf("unexpected driver name %q", run.Tool.Driver.Name)
	}
	if len(run.Results) != len(rep.Findings) {
		t.Fatalf("expected %d results, got %d", len(rep.Findings), len(run.Results))
	}
	ruleIDs := map[string]bool{}
	for _, r := range run.Tool.Driver.Rules {
		ruleIDs[r.ID] = true
	}
	validLevels := map[string]bool{"none": true, "note": true, "warning": true, "error": true}
	for _, res := range run.Results {
		if !ruleIDs[res.RuleID] {
			t.Errorf("result references unknown rule %q", res.RuleID)
		}
		if res.RuleIndex < 0 || res.RuleIndex >= len(run.Tool.Driver.Rules) {
			t.Errorf("ruleIndex %d out of range", res.RuleIndex)
		}
		if run.Tool.Driver.Rules[res.RuleIndex].ID != res.RuleID {
			t.Errorf("ruleIndex does not point at rule %q", res.RuleID)
		}
		if !validLevels[res.Level] {
			t.Errorf("invalid level %q", res.Level)
		}
		if res.Message.Text == "" {
			t.Error("empty result message")
		}
		if len(res.Locations) != 1 {
			t.Errorf("expected one location, got %d", len(res.Locations))
		}
		loc := res.Locations[0].PhysicalLocation
		if loc.ArtifactLocation.URI == "" {
			t.Error("empty artifact URI")
		}
		if filepath.IsAbs(loc.ArtifactLocation.URI) || strings.HasPrefix(loc.ArtifactLocation.URI, "/") {
			t.Errorf("absolute URI emitted: %q", loc.ArtifactLocation.URI)
		}
		if loc.Region != nil && loc.Region.StartLine <= 0 {
			t.Error("region with non-positive start line")
		}
		if res.PartialFingerprints["wardlineFindingId/v1"] == "" {
			t.Error("missing partial fingerprint")
		}
	}
	if len(run.Invocations) != 1 || !run.Invocations[0].ExecutionSuccessful {
		t.Errorf("unexpected invocation: %+v", run.Invocations)
	}
	if strings.Contains(buf.String(), "/tmp/project") {
		t.Error("SARIF leaked an absolute path")
	}
}

func TestSARIFSuppressionAndFailure(t *testing.T) {
	res := sampleResult()
	res.Errors = []string{"dependencies scanner: network unreachable"}
	rep := Build(res, config.Default(), Options{MinSeverity: findings.SeverityInfo, FailOn: findings.SeverityHigh, Version: version.Get()})
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, rep); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"executionSuccessful": false`) {
		t.Error("failed scan should set executionSuccessful=false")
	}
	if !strings.Contains(buf.String(), `"kind": "external"`) {
		t.Error("configuration suppressions should be represented as external")
	}
	if !strings.Contains(buf.String(), `"justification"`) {
		t.Error("suppressions must carry their mandatory reason")
	}
}

func TestTerminalReport(t *testing.T) {
	rep := buildSample(t, findings.SeverityInfo, findings.SeverityHigh)
	var plain bytes.Buffer
	if err := WriteTerminal(&plain, rep, TerminalOptions{Color: false, Width: 100}); err != nil {
		t.Fatal(err)
	}
	out := plain.String()
	for _, want := range []string{"wardline 0.1.0", "findings", "WL-SEC-001", "result", "FAIL", "Suppressed", "Checks not completed"} {
		if !strings.Contains(out, want) {
			t.Errorf("terminal report missing %q", want)
		}
	}
	if strings.Contains(out, "\x1b[") {
		t.Error("colour codes emitted when colour is disabled")
	}

	var colored bytes.Buffer
	if err := WriteTerminal(&colored, rep, TerminalOptions{Color: true, Width: 100}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(colored.String(), "\x1b[") {
		t.Error("colour codes missing when colour is enabled")
	}
}

func TestTerminalIncompleteReport(t *testing.T) {
	res := sampleResult()
	rep := Build(res, config.Default(), Options{MinSeverity: findings.SeverityInfo, FailOn: findings.SeverityCritical, Version: version.Get()})
	// Drop the critical finding so the policy does not fail.
	filtered := rep.Findings[:0]
	for _, f := range rep.Findings {
		if f.Severity != findings.SeverityCritical {
			filtered = append(filtered, f)
		}
	}
	rep.Findings = filtered
	rep.Summary.Policy = evaluatePolicy(rep.Findings, findings.SeverityCritical)
	var buf bytes.Buffer
	if err := WriteTerminal(&buf, rep, TerminalOptions{Width: 100}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "INCOMPLETE") {
		t.Fatalf("incomplete scan should be labelled clearly:\n%s", out)
	}
	if !strings.Contains(out, "not a clean result") {
		t.Fatalf("incomplete result must warn against reading it as clean:\n%s", out)
	}
}

func TestTerminalCleanReport(t *testing.T) {
	res := &engine.Result{
		Target: "./clean", Mode: engine.ModeWorkingTree,
		StartedAt: time.Now(), FinishedAt: time.Now(),
		Scanners: []engine.ScannerRun{{Name: "secrets", Status: scanners.StatusRan, Scope: "3 files"}},
	}
	rep := Build(res, config.Default(), Options{MinSeverity: findings.SeverityInfo, FailOn: findings.SeverityHigh, Version: version.Get()})
	var buf bytes.Buffer
	if err := WriteTerminal(&buf, rep, TerminalOptions{Width: 80}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "No findings") || !strings.Contains(out, "PASS") {
		t.Fatalf("unexpected clean report:\n%s", out)
	}
	if strings.Contains(out, "FAIL") {
		t.Fatal("clean report must not mention FAIL")
	}
}

func TestEmptyReportWriters(t *testing.T) {
	if err := WriteJSON(&bytes.Buffer{}, nil); err == nil {
		t.Error("expected an error for a nil report")
	}
	if err := WriteMarkdown(&bytes.Buffer{}, nil); err == nil {
		t.Error("expected an error for a nil report")
	}
	if err := WriteSARIF(&bytes.Buffer{}, nil); err == nil {
		t.Error("expected an error for a nil report")
	}
	if err := WriteTerminal(&bytes.Buffer{}, nil, TerminalOptions{}); err == nil {
		t.Error("expected an error for a nil report")
	}
}

func TestSARIFURIEncoding(t *testing.T) {
	if got := sarifURI("docs/a b/c#d.yml"); got != "docs/a%20b/c%23d.yml" {
		t.Errorf("unexpected encoded URI %q", got)
	}
	if got := sarifURI("/leading/slash.yml"); got != "leading/slash.yml" {
		t.Errorf("leading slash not stripped: %q", got)
	}
	if got := semanticVersion("0.1.0"); got != "0.1.0" {
		t.Errorf("unexpected semantic version %q", got)
	}
	if got := semanticVersion("0.1.0-dev"); got != "0.1.0" {
		t.Errorf("unexpected semantic version %q", got)
	}
	if got := semanticVersion("0.0.0-dev"); got != "0.0.0" {
		t.Errorf("unexpected semantic version %q", got)
	}
	if got := semanticVersion("dev"); got != "" {
		t.Errorf("expected no semantic version, got %q", got)
	}
}
