package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Undrocs/wardline/internal/config"
	"github.com/Undrocs/wardline/internal/findings"
	"github.com/Undrocs/wardline/internal/scanners"
)

// stubScanner is a controllable scanner used by engine tests.
type stubScanner struct {
	name     string
	findings []findings.Finding
	err      error
	panic    bool
	block    bool
	seen     []scanners.File
}

func (s *stubScanner) Name() string { return s.name }

func (s *stubScanner) Scan(ctx context.Context, req *scanners.Request) (*scanners.Result, error) {
	s.seen = req.Files
	if s.panic {
		panic("boom")
	}
	if s.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if s.err != nil {
		return nil, s.err
	}
	return &scanners.Result{Findings: s.findings, Scope: "stub"}, nil
}

func testConfig() *config.Config {
	cfg := config.Default()
	cfg.Network.Enabled = false
	return cfg
}

func writeTree(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for rel, content := range files {
		path := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRunCollectsFindingsAndScope(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"a.go":                "package a\n",
		"src/b.go":            "package b\n",
		"node_modules/x/y.js": "should be skipped\n",
		".git/config":         "should be skipped\n",
	})
	stub := &stubScanner{name: "secrets", findings: []findings.Finding{
		findings.New(findings.Finding{RuleID: "R1", Scanner: "secrets", Title: "t", Severity: findings.SeverityHigh, Location: findings.Location{Path: "a.go", StartLine: 1}, Locator: "x"}),
	}}
	res, err := Run(context.Background(), Options{
		Target:   dir,
		Config:   testConfig(),
		Scanners: []scanners.Scanner{stub},
		Offline:  true,
		Now:      func() time.Time { return time.Unix(1700000000, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(stub.seen) != 2 {
		t.Fatalf("expected 2 files, got %d: %+v", len(stub.seen), stub.seen)
	}
	if res.FileCount != 2 {
		t.Fatalf("unexpected file count %d", res.FileCount)
	}
	if len(res.Findings) != 1 || res.Counts().High != 1 {
		t.Fatalf("unexpected findings: %+v", res.Findings)
	}
	if res.Mode != ModeWorkingTree {
		t.Errorf("unexpected mode %q", res.Mode)
	}
	if res.FinishedAt.Before(res.StartedAt) {
		t.Error("finish time precedes start time")
	}
	if res.Failed() {
		t.Error("scan should not be marked failed")
	}
}

func TestRunRejectsInvalidTargets(t *testing.T) {
	if _, err := Run(context.Background(), Options{Target: "/nonexistent/wardline", Config: testConfig()}); err == nil {
		t.Fatal("expected an error for a missing target")
	}
	dir := t.TempDir()
	file := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(context.Background(), Options{Target: file, Config: testConfig()}); err == nil {
		t.Fatal("expected an error when the target is a file")
	}
	if _, err := Run(context.Background(), Options{Target: dir}); err == nil {
		t.Fatal("expected an error without a configuration")
	}
}

func TestExcludes(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"keep/a.go":             "package a\n",
		"skip/b.go":             "package b\n",
		"vendor/c.go":           "package c\n",
		"docs/readme.md":        "hello\n",
		"nested/deep/d/keep.go": "package d\n",
	})
	cfg := testConfig()
	cfg.Exclude = []string{"skip/**", "**/*.md"}
	stub := &stubScanner{name: "s"}
	res, err := Run(context.Background(), Options{Target: dir, Config: cfg, Scanners: []scanners.Scanner{stub}})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, f := range stub.seen {
		got[f.Rel] = true
	}
	if got["skip/b.go"] || got["docs/readme.md"] || got["vendor/c.go"] {
		t.Fatalf("excluded files were still scanned: %v", got)
	}
	if !got["keep/a.go"] || !got["nested/deep/d/keep.go"] {
		t.Fatalf("expected files are missing: %v", got)
	}
	if res.FileCount != 2 {
		t.Fatalf("unexpected file count %d", res.FileCount)
	}
}

func TestSymlinksAreNotFollowed(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeTree(t, dir, map[string]string{"real/a.go": "package a\n"})
	if err := os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(dir, "link.txt")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "linkdir")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	stub := &stubScanner{name: "s"}
	res, err := Run(context.Background(), Options{Target: dir, Config: testConfig(), Scanners: []scanners.Scanner{stub}})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range stub.seen {
		if strings.HasPrefix(f.Rel, "link") {
			t.Fatalf("symlink was followed: %s", f.Rel)
		}
	}
	if res.FileCount != 1 {
		t.Fatalf("expected one regular file, got %d", res.FileCount)
	}
	if len(res.Warnings) == 0 || !strings.Contains(strings.Join(res.Warnings, " "), "symbolic link") {
		t.Fatalf("symlink warning missing: %v", res.Warnings)
	}
}

func TestOversizedFilesMakeCoveragePartial(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"big.txt": strings.Repeat("x", 4096), "small.txt": "ok"})
	cfg := testConfig()
	cfg.Limits.MaxFileSize = 1024
	res, err := Run(context.Background(), Options{Target: dir, Config: cfg, Scanners: []scanners.Scanner{&stubScanner{name: "s"}}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.PartialCoverage {
		t.Fatal("skipping an oversized file must mark coverage as partial, not clean")
	}
}

func TestMaxFilesLimitIsAnError(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"a.go": "a", "b.go": "b", "c.go": "c"})
	cfg := testConfig()
	cfg.Limits.MaxFiles = 2
	if _, err := Run(context.Background(), Options{Target: dir, Config: cfg, Scanners: []scanners.Scanner{&stubScanner{name: "s"}}}); err == nil {
		t.Fatal("exceeding the file limit must fail the scan rather than truncate it silently")
	}
}

func TestLargeFilesAreSkipped(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"big.txt": strings.Repeat("x", 2048), "small.txt": "ok"})
	cfg := testConfig()
	cfg.Limits.MaxFileSize = 1024
	stub := &stubScanner{name: "s"}
	res, err := Run(context.Background(), Options{Target: dir, Config: cfg, Scanners: []scanners.Scanner{stub}})
	if err != nil {
		t.Fatal(err)
	}
	if len(stub.seen) != 1 || stub.seen[0].Rel != "small.txt" {
		t.Fatalf("unexpected files: %+v", stub.seen)
	}
	if !strings.Contains(strings.Join(res.Warnings, " "), "larger than") {
		t.Fatalf("missing size warning: %v", res.Warnings)
	}
}

func TestScannerPanicIsIsolated(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"a.go": "package a\n"})
	bad := &stubScanner{name: "bad", panic: true}
	good := &stubScanner{name: "good", findings: []findings.Finding{
		findings.New(findings.Finding{RuleID: "R1", Scanner: "good", Title: "t", Severity: findings.SeverityLow, Location: findings.Location{Path: "a.go"}, Locator: "l"}),
	}}
	res, err := Run(context.Background(), Options{Target: dir, Config: testConfig(), Scanners: []scanners.Scanner{bad, good}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Errors) != 1 || !strings.Contains(res.Errors[0], "panic") {
		t.Fatalf("expected a panic error, got %v", res.Errors)
	}
	if !res.Failed() {
		t.Error("a crashed scanner must mark the scan as failed")
	}
	status := map[string]scanners.Status{}
	for _, run := range res.Scanners {
		status[run.Name] = run.Status
	}
	if status["bad"] != scanners.StatusFailed || status["good"] != scanners.StatusRan {
		t.Fatalf("unexpected statuses: %v", status)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("results from the healthy scanner were lost: %+v", res.Findings)
	}
}

func TestScannerErrorIsReported(t *testing.T) {
	dir := t.TempDir()
	failing := &stubScanner{name: "deps", err: errors.New("network unreachable")}
	res, err := Run(context.Background(), Options{Target: dir, Config: testConfig(), Scanners: []scanners.Scanner{failing}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Failed() || !strings.Contains(strings.Join(res.Errors, " "), "network unreachable") {
		t.Fatalf("scanner error not surfaced: %+v", res.Errors)
	}
	if res.Scanners[0].Status != scanners.StatusFailed {
		t.Fatalf("unexpected status %s", res.Scanners[0].Status)
	}
}

func TestPartialScannerIsNotClean(t *testing.T) {
	dir := t.TempDir()
	res, err := Run(context.Background(), Options{Target: dir, Config: testConfig(), Scanners: []scanners.Scanner{&skippingScanner{}}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Scanners[0].Status != scanners.StatusPartial {
		t.Fatalf("expected partial status, got %s", res.Scanners[0].Status)
	}
	if res.Failed() {
		t.Error("a partial scanner is not an operational failure")
	}
}

type skippingScanner struct{}

func (s *skippingScanner) Name() string { return "deps" }
func (s *skippingScanner) Scan(context.Context, *scanners.Request) (*scanners.Result, error) {
	return &scanners.Result{Skipped: []scanners.SkippedCheck{{Check: "OSV", Reason: "offline"}}}, nil
}

func TestRuleDisableAndSeverityOverride(t *testing.T) {
	dir := t.TempDir()
	stub := &stubScanner{name: "secrets", findings: []findings.Finding{
		findings.New(findings.Finding{RuleID: "R-KEEP", Scanner: "secrets", Title: "keep", Severity: findings.SeverityMedium, Location: findings.Location{Path: "a"}, Locator: "1"}),
		findings.New(findings.Finding{RuleID: "R-DROP", Scanner: "secrets", Title: "drop", Severity: findings.SeverityHigh, Location: findings.Location{Path: "a"}, Locator: "2"}),
	}}
	cfg := testConfig()
	cfg.Rules.Disable = []string{"R-DROP"}
	cfg.Rules.Severity = map[string]string{"R-KEEP": "critical"}
	res, err := Run(context.Background(), Options{Target: dir, Config: cfg, Scanners: []scanners.Scanner{stub}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected one finding, got %+v", res.Findings)
	}
	if res.Findings[0].Severity != findings.SeverityCritical {
		t.Fatalf("severity override not applied: %s", res.Findings[0].Severity)
	}
	if !strings.Contains(strings.Join(res.Warnings, " "), "overridden") {
		t.Fatalf("override should be disclosed: %v", res.Warnings)
	}
}

func TestSuppressionsAndExpiry(t *testing.T) {
	dir := t.TempDir()
	stub := &stubScanner{name: "secrets", findings: []findings.Finding{
		findings.New(findings.Finding{RuleID: "R1", Scanner: "secrets", Title: "one", Severity: findings.SeverityHigh, Location: findings.Location{Path: ".github/workflows/ci.yml", StartLine: 4}, Locator: "1"}),
		findings.New(findings.Finding{RuleID: "R2", Scanner: "secrets", Title: "two", Severity: findings.SeverityHigh, Location: findings.Location{Path: "src/a.go"}, Locator: "2"}),
	}}
	cfg := testConfig()
	cfg.Suppressions = []config.Suppression{
		{Rule: "R1", Path: ".github/workflows/*.yml", Reason: "reviewed", Expires: "2099-01-01"},
		{Rule: "R2", Reason: "stale", Expires: "2020-01-01"},
	}
	res, err := Run(context.Background(), Options{Target: dir, Config: cfg, Scanners: []scanners.Scanner{stub},
		Now: func() time.Time { return time.Unix(1700000000, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	suppressed := 0
	for _, f := range res.Findings {
		if f.Suppressed {
			suppressed++
			if f.RuleID != "R1" {
				t.Errorf("wrong finding suppressed: %s", f.RuleID)
			}
			if f.SuppressionReason != "reviewed" {
				t.Errorf("suppression reason lost: %q", f.SuppressionReason)
			}
		}
	}
	if suppressed != 1 {
		t.Fatalf("expected exactly one suppressed finding, got %d", suppressed)
	}
	if !strings.Contains(strings.Join(res.Warnings, " "), "expired") {
		t.Fatalf("expired suppression should be reported: %v", res.Warnings)
	}
}

func TestSuppressionExpiryBoundary(t *testing.T) {
	// A suppression dated 2026-03-01 covers that entire calendar day and
	// lapses at 00:00 UTC on 2026-03-02, not a day later and not a second
	// earlier.
	finding := findings.New(findings.Finding{RuleID: "R1", Scanner: "secrets", Title: "one",
		Severity: findings.SeverityHigh, Location: findings.Location{Path: "a.go"}, Locator: "1"})
	cases := []struct {
		name     string
		now      time.Time
		suppress bool
	}{
		{"start of expiry day", time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), true},
		{"last second of expiry day", time.Date(2026, 3, 1, 23, 59, 59, 0, time.UTC), true},
		{"first instant of next day", time.Date(2026, 3, 2, 0, 0, 0, 0, time.UTC), false},
		{"later", time.Date(2026, 3, 2, 0, 0, 1, 0, time.UTC), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig()
			cfg.Suppressions = []config.Suppression{{Rule: "R1", Reason: "reviewed", Expires: "2026-03-01"}}
			var warnings []string
			out := applySuppressions([]findings.Finding{finding}, cfg, tc.now, &warnings)
			if got := out[0].Suppressed; got != tc.suppress {
				t.Fatalf("suppressed = %v, want %v (warnings: %v)", got, tc.suppress, warnings)
			}
			if expired := strings.Contains(strings.Join(warnings, " "), "expired"); expired == tc.suppress {
				t.Fatalf("expiry warning mismatch for suppressed=%v: %v", tc.suppress, warnings)
			}
		})
	}
}

func TestApplyRuleSettingsDoesNotAliasInput(t *testing.T) {
	cfg := testConfig()
	cfg.Rules.Disable = []string{"R2"}
	in := []findings.Finding{
		{RuleID: "R1", Severity: findings.SeverityLow},
		{RuleID: "R2", Severity: findings.SeverityHigh},
	}
	before := append([]findings.Finding(nil), in...)
	var warnings []string
	out := applyRuleSettings(in, cfg, &warnings)
	if len(out) != 1 || out[0].RuleID != "R1" {
		t.Fatalf("unexpected filtered output: %+v", out)
	}
	if !reflect.DeepEqual(in, before) {
		t.Fatalf("input slice mutated: %+v", in)
	}
}

func TestCancellationAndDeadline(t *testing.T) {
	dir := t.TempDir()
	blocking := &stubScanner{name: "slow", block: true}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	res, err := Run(ctx, Options{Target: dir, Config: testConfig(), Scanners: []scanners.Scanner{blocking}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Failed() {
		t.Fatal("a cancelled scan must be reported as failed")
	}
	if res.Scanners[0].Status != scanners.StatusFailed {
		t.Fatalf("unexpected status %s", res.Scanners[0].Status)
	}
	if !strings.Contains(res.Scanners[0].Error, "cancel") && !strings.Contains(res.Scanners[0].Error, "deadline") {
		t.Fatalf("cancellation reason missing: %q", res.Scanners[0].Error)
	}
}

func TestFindingsAreDeduplicatedAndSorted(t *testing.T) {
	dir := t.TempDir()
	dup := findings.New(findings.Finding{RuleID: "R1", Scanner: "a", Title: "t", Severity: findings.SeverityHigh, Location: findings.Location{Path: "b.go", StartLine: 2}, Locator: "x"})
	other := findings.New(findings.Finding{RuleID: "R2", Scanner: "b", Title: "t2", Severity: findings.SeverityCritical, Location: findings.Location{Path: "a.go", StartLine: 9}, Locator: "y"})
	res, err := Run(context.Background(), Options{Target: dir, Config: testConfig(), Scanners: []scanners.Scanner{
		&stubScanner{name: "a", findings: []findings.Finding{dup, other}},
		&stubScanner{name: "b", findings: []findings.Finding{dup}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 2 {
		t.Fatalf("expected dedupe to leave 2 findings, got %d", len(res.Findings))
	}
	if res.Findings[0].Severity != findings.SeverityCritical {
		t.Fatalf("findings are not sorted by severity: %+v", res.Findings)
	}
}

func TestNetworkDestinationsRecorded(t *testing.T) {
	dir := t.TempDir()
	netScanner := &netStub{}
	res, err := Run(context.Background(), Options{Target: dir, Config: testConfig(), Scanners: []scanners.Scanner{netScanner}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Network) != 1 || res.Network[0] != "https://api.osv.dev" {
		t.Fatalf("unexpected network destinations: %v", res.Network)
	}
}

type netStub struct{}

func (n *netStub) Name() string { return "dependencies" }
func (n *netStub) Scan(context.Context, *scanners.Request) (*scanners.Result, error) {
	return &scanners.Result{
		Network: []string{"https://api.osv.dev", "https://api.osv.dev"},
		Notes:   []string{"network disclosure"},
	}, nil
}
