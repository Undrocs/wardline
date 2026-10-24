package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const (
	fakeGitHubToken = "ghp_" + "Q7mXr4Tz9KpL2WcV8bN3jH6yF5dS1aE0uG8i"
	fakeDBPassword  = "Zq7pLm2Kd9Rt4Wx1"
)

// newTestApp returns an App with buffers and a fixed clock.
func newTestApp(t *testing.T) (*App, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	app := New(stdout, stderr, strings.NewReader(""))
	app.Now = func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) }
	app.IsTerminal = func(io.Writer) bool { return false }
	app.Getenv = func(string) string { return "" }
	return app, stdout, stderr
}

func writeProject(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for rel, content := range files {
		path := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

var cleanProject = map[string]string{
	"internal/app.go": `package internal

import "os"

func token() string { return os.Getenv("API_TOKEN") }
`,
	".github/workflows/ci.yml": `on: pull_request
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - run: go test ./...
`,
}

var secretProject = map[string]string{
	"config/settings.go": "package config\n\nvar token = \"" + fakeGitHubToken + "\"\n",
}

func TestVersionCommand(t *testing.T) {
	app, stdout, _ := newTestApp(t)
	if code := app.Run(context.Background(), []string{"version"}); code != ExitOK {
		t.Fatalf("exit code %d", code)
	}
	if !strings.Contains(stdout.String(), "wardline") {
		t.Fatalf("unexpected version output: %q", stdout.String())
	}

	stdout.Reset()
	if code := app.Run(context.Background(), []string{"version", "--format", "json"}); code != ExitOK {
		t.Fatalf("exit code %d", code)
	}
	var parsed map[string]string
	if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
		t.Fatalf("version JSON invalid: %v", err)
	}
	if parsed["name"] != "wardline" || parsed["version"] == "" {
		t.Fatalf("unexpected version JSON: %v", parsed)
	}
}

func TestHelpCommands(t *testing.T) {
	cases := [][]string{{}, {"help"}, {"--help"}, {"help", "scan"}, {"help", "audit"}, {"help", "version"}, {"scan", "--help"}}
	for _, args := range cases {
		app, stdout, _ := newTestApp(t)
		code := app.Run(context.Background(), args)
		if code != ExitOK {
			t.Errorf("%v: exit code %d", args, code)
		}
		if stdout.Len() == 0 {
			t.Errorf("%v: no help output", args)
		}
	}
	app, _, stderr := newTestApp(t)
	if code := app.Run(context.Background(), []string{"nonsense"}); code != ExitUsage {
		t.Fatalf("unknown command exit code %d", code)
	}
	if !strings.Contains(stderr.String(), "unknown command") {
		t.Fatalf("unexpected error: %q", stderr.String())
	}
}

func TestScanCleanProject(t *testing.T) {
	dir := writeProject(t, cleanProject)
	app, stdout, stderr := newTestApp(t)
	code := app.Run(context.Background(), []string{"scan", dir, "--offline", "--no-color"})
	if code != ExitOK {
		t.Fatalf("exit code %d, stderr: %s", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "No findings") {
		t.Fatalf("unexpected output:\n%s", out)
	}
	if !strings.Contains(out, "INCOMPLETE") {
		t.Fatalf("offline scan must be labelled incomplete:\n%s", out)
	}
}

func TestScanPolicyFailure(t *testing.T) {
	dir := writeProject(t, secretProject)
	app, stdout, _ := newTestApp(t)
	code := app.Run(context.Background(), []string{"scan", dir, "--offline", "--no-color"})
	if code != ExitPolicy {
		t.Fatalf("expected exit %d, got %d\n%s", ExitPolicy, code, stdout.String())
	}
	if !strings.Contains(stdout.String(), "FAIL") {
		t.Fatalf("policy failure not shown:\n%s", stdout.String())
	}
	// The raw secret must never appear in output.
	if strings.Contains(stdout.String(), fakeGitHubToken) {
		t.Fatal("secret leaked into terminal output")
	}
}

func TestFailOnThreshold(t *testing.T) {
	dir := writeProject(t, secretProject)
	app, _, _ := newTestApp(t)
	if code := app.Run(context.Background(), []string{"scan", dir, "--offline", "--fail-on", "critical"}); code != ExitOK {
		t.Fatalf("expected success when nothing reaches critical, got %d", code)
	}
	app, _, _ = newTestApp(t)
	if code := app.Run(context.Background(), []string{"scan", dir, "--offline", "--fail-on", "low"}); code != ExitPolicy {
		t.Fatalf("expected policy failure at low, got %d", code)
	}
}

func TestSeverityFilterDoesNotHidePolicy(t *testing.T) {
	dir := writeProject(t, secretProject)
	app, stdout, _ := newTestApp(t)
	code := app.Run(context.Background(), []string{
		"scan", dir, "--offline", "--format", "json",
		"--severity", "critical", "--fail-on", "high",
	})
	if code != ExitPolicy {
		t.Fatalf("expected policy failure, got %d", code)
	}
	var rep map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	summary := rep["summary"].(map[string]any)
	if summary["total"].(float64) != 0 {
		t.Fatalf("expected filtering to hide the finding, got %v", summary["total"])
	}
	if summary["policy"].(map[string]any)["failed"] != true {
		t.Fatal("policy should be evaluated over unfiltered findings")
	}
}

func TestMinConfidenceDoesNotHidePolicy(t *testing.T) {
	// A committed credential file is a high-severity, medium-confidence finding:
	// filtering it from the report must not turn the policy result into a pass.
	dir := writeProject(t, map[string]string{
		".npmrc": "//registry.npmjs.org/:_authToken=npm_9xQ2Lm7Tz4Rc8Vb1Nd6Hf3Wk\n",
	})
	app, stdout, _ := newTestApp(t)
	code := app.Run(context.Background(), []string{
		"scan", dir, "--offline", "--format", "json",
		"--min-confidence", "high", "--fail-on", "high",
	})
	if code != ExitPolicy {
		t.Fatalf("expected policy failure, got %d", code)
	}
	var rep struct {
		Summary struct {
			Total  int `json:"total"`
			Policy struct {
				Failed bool `json:"failed"`
			} `json:"policy"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if rep.Summary.Total != 0 {
		t.Fatalf("expected the medium-confidence finding to be filtered, got %d", rep.Summary.Total)
	}
	if !rep.Summary.Policy.Failed {
		t.Fatal("policy must be evaluated over unfiltered findings")
	}
}

func TestReportDoesNotDiscloseAbsoluteTarget(t *testing.T) {
	dir := writeProject(t, secretProject)
	// Scan by a relative path from the working directory, as a CI job would.
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	rel, err := filepath.Rel(wd, dir)
	if err != nil {
		t.Skipf("target outside the working directory: %v", err)
	}
	app, stdout, _ := newTestApp(t)
	app.Run(context.Background(), []string{"scan", rel, "--offline", "--format", "json"})

	var rep struct {
		Scan struct {
			Target string `json:"target"`
		} `json:"scan"`
		Findings []struct {
			Location struct {
				Path string `json:"path"`
			} `json:"location"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if rep.Scan.Target != rel {
		t.Errorf("scan target = %q, want the supplied path %q", rep.Scan.Target, rel)
	}
	if strings.Contains(stdout.String(), wd) {
		t.Errorf("report discloses the absolute working directory %q", wd)
	}
	for _, f := range rep.Findings {
		if filepath.IsAbs(f.Location.Path) {
			t.Errorf("finding location is absolute: %q", f.Location.Path)
		}
	}
}

func TestJSONAndMarkdownAndSARIFOutputs(t *testing.T) {
	dir := writeProject(t, secretProject)
	for _, format := range []string{"json", "markdown", "sarif"} {
		app, stdout, stderr := newTestApp(t)
		code := app.Run(context.Background(), []string{"scan", dir, "--offline", "--format", format})
		if code != ExitPolicy {
			t.Fatalf("%s: exit code %d (%s)", format, code, stderr.String())
		}
		if strings.TrimSpace(stdout.String()) == "" {
			t.Fatalf("%s: empty output", format)
		}
		if strings.Contains(stdout.String(), fakeGitHubToken) {
			t.Fatalf("%s: secret leaked", format)
		}
		switch format {
		case "json", "sarif":
			var doc map[string]any
			if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
				t.Fatalf("%s: invalid JSON: %v", format, err)
			}
		case "markdown":
			if !strings.HasPrefix(stdout.String(), "# Wardline scan report") {
				t.Fatalf("unexpected markdown output")
			}
		}
	}
}

func TestOutputFile(t *testing.T) {
	dir := writeProject(t, secretProject)
	outPath := filepath.Join(t.TempDir(), "report.json")
	app, stdout, stderr := newTestApp(t)
	code := app.Run(context.Background(), []string{"scan", dir, "--offline", "--format", "json", "--output", outPath})
	if code != ExitPolicy {
		t.Fatalf("exit code %d", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout should be empty when writing to a file, got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "report written") {
		t.Fatalf("expected a confirmation on stderr, got %q", stderr.String())
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("invalid JSON in output file: %v", err)
	}
	info, err := os.Stat(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		// Windows reports synthetic permission bits; the POSIX check only makes
		// sense on Unix-like systems.
		if info.Mode().Perm()&0o077 != 0 {
			t.Errorf("report file permissions are too permissive: %v", info.Mode())
		}
	}
}

func TestUnwritableOutputIsOperationalFailure(t *testing.T) {
	dir := writeProject(t, cleanProject)
	app, _, stderr := newTestApp(t)
	// A directory cannot be opened as a report file.
	code := app.Run(context.Background(), []string{
		"scan", dir, "--offline", "--format", "json", "--output", t.TempDir(),
	})
	if code != ExitOperational {
		t.Fatalf("exit code %d, want %d (stderr: %s)", code, ExitOperational, stderr.String())
	}
	if !strings.Contains(stderr.String(), "writing report") {
		t.Fatalf("unexpected stderr: %q", stderr.String())
	}
}

func TestUsageErrors(t *testing.T) {
	dir := writeProject(t, cleanProject)
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"scan", dir, "--format", "xml"}, "unknown format"},
		{[]string{"scan", dir, "--severity", "urgent"}, "--severity"},
		{[]string{"scan", dir, "--fail-on", "unknown"}, "--fail-on"},
		{[]string{"scan", dir, "--timeout", "soon"}, "--timeout"},
		{[]string{"scan", dir, "--min-confidence", "absolute"}, "--min-confidence"},
		{[]string{"scan", dir, dir}, "at most one path"},
		{[]string{"scan", dir, "--config", filepath.Join(dir, "missing.yaml")}, "configuration"},
		{[]string{"audit"}, "requires a scanner"},
		{[]string{"audit", "everything"}, "unknown audit scanner"},
	}
	for _, c := range cases {
		app, _, stderr := newTestApp(t)
		code := app.Run(context.Background(), c.args)
		if code != ExitUsage {
			t.Errorf("%v: expected exit %d, got %d", c.args, ExitUsage, code)
		}
		if !strings.Contains(stderr.String(), c.want) {
			t.Errorf("%v: error %q does not mention %q", c.args, stderr.String(), c.want)
		}
	}
}

func TestInvalidConfigurationFile(t *testing.T) {
	dir := writeProject(t, cleanProject)
	cfg := filepath.Join(dir, ".wardline.yaml")
	if err := os.WriteFile(cfg, []byte("severity:\n  failOn: urgent\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	app, _, stderr := newTestApp(t)
	if code := app.Run(context.Background(), []string{"scan", dir, "--offline"}); code != ExitUsage {
		t.Fatalf("expected exit %d, got %d", ExitUsage, code)
	}
	if !strings.Contains(stderr.String(), "severity.failOn") {
		t.Fatalf("unexpected error: %q", stderr.String())
	}
}

func TestMissingTargetIsOperationalFailure(t *testing.T) {
	app, _, stderr := newTestApp(t)
	code := app.Run(context.Background(), []string{"scan", filepath.Join(t.TempDir(), "missing")})
	if code != ExitOperational {
		t.Fatalf("expected exit %d, got %d", ExitOperational, code)
	}
	if stderr.Len() == 0 {
		t.Fatal("expected an error message")
	}
}

func TestTargetIsFileIsUsageError(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	app, _, stderr := newTestApp(t)
	if code := app.Run(context.Background(), []string{"scan", file}); code != ExitUsage {
		t.Fatalf("expected exit %d, got %d (%s)", ExitUsage, code, stderr.String())
	}
}

func TestAuditSelectsSingleScanner(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"config/settings.go": "package config\n\nvar token = \"" + fakeGitHubToken + "\"\n",
		".github/workflows/ci.yml": `on: pull_request
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`,
	})
	app, stdout, _ := newTestApp(t)
	code := app.Run(context.Background(), []string{"audit", "secrets", dir, "--offline", "--format", "json"})
	if code != ExitPolicy {
		t.Fatalf("exit code %d", code)
	}
	var rep struct {
		Scanners []struct {
			Name string `json:"name"`
		} `json:"scanners"`
		Findings []struct {
			Scanner string `json:"scanner"`
			RuleID  string `json:"ruleId"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.Scanners) != 1 || rep.Scanners[0].Name != "secrets" {
		t.Fatalf("expected only the secrets scanner, got %+v", rep.Scanners)
	}
	for _, f := range rep.Findings {
		if f.Scanner != "secrets" {
			t.Fatalf("unexpected finding from %s", f.Scanner)
		}
	}
}

func TestSuppressionsFromConfiguration(t *testing.T) {
	dir := writeProject(t, secretProject)
	cfg := "suppressions:\n  - rule: WL-SEC-003\n    reason: \"Synthetic test fixture reviewed by the security team.\"\n"
	if err := os.WriteFile(filepath.Join(dir, ".wardline.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	app, stdout, _ := newTestApp(t)
	code := app.Run(context.Background(), []string{"scan", dir, "--offline", "--fail-on", "high"})
	if code != ExitOK {
		t.Fatalf("suppressed finding should not fail the scan, got %d\n%s", code, stdout.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "Suppressed") || !strings.Contains(out, "reviewed by the security team") {
		t.Fatalf("suppressed finding should remain auditable:\n%s", out)
	}
}

func TestOfflineDisablesNetworkAndDiscloses(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"go.mod": "module example.com/app\n\ngo 1.21\n\nrequire example.com/dep v1.0.0\n",
		"go.sum": "example.com/dep v1.0.0 h1:abc=\n",
	})
	app, stdout, _ := newTestApp(t)
	code := app.Run(context.Background(), []string{"scan", dir, "--offline", "--format", "json"})
	if code != ExitOK {
		t.Fatalf("exit code %d", code)
	}
	var rep struct {
		Scan struct {
			Offline bool `json:"offline"`
		} `json:"scan"`
		Network struct {
			Enabled      bool     `json:"enabled"`
			Destinations []string `json:"destinations"`
		} `json:"network"`
		Scanners []struct {
			Name    string `json:"name"`
			Status  string `json:"status"`
			Skipped []struct {
				Reason string `json:"reason"`
			} `json:"skipped"`
		} `json:"scanners"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if !rep.Scan.Offline || rep.Network.Enabled {
		t.Fatal("offline mode not reflected in the report")
	}
	if len(rep.Network.Destinations) != 0 {
		t.Fatalf("offline scan recorded destinations: %v", rep.Network.Destinations)
	}
	var found bool
	for _, sc := range rep.Scanners {
		if sc.Name == "dependencies" {
			for _, sk := range sc.Skipped {
				if strings.Contains(sk.Reason, "offline") {
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatal("offline dependency check was not disclosed")
	}
}

func TestExcludeFlag(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"src/a.go":     "package a\n",
		"vendor/b.go":  "package b\n",
		"secrets/c.go": "package c\n\nvar t = \"" + fakeGitHubToken + "\"\n",
	})
	app, stdout, _ := newTestApp(t)
	code := app.Run(context.Background(), []string{"scan", dir, "--offline", "--exclude", "secrets/**", "--format", "json"})
	if code != ExitOK {
		t.Fatalf("excluded finding should not fail the scan, got %d: %s", code, stdout.String())
	}
	if strings.Contains(stdout.String(), "WL-SEC-003") {
		t.Fatal("excluded path was still scanned")
	}
}

func TestMinConfidenceFilter(t *testing.T) {
	dir := writeProject(t, map[string]string{
		// A generic password assignment is reported with medium confidence.
		"config/db.go": "package config\n\nvar password = \"" + fakeDBPassword + "\"\n",
	})
	app, stdout, _ := newTestApp(t)
	code := app.Run(context.Background(), []string{"scan", dir, "--offline", "--format", "json", "--min-confidence", "high"})
	if code != ExitOK {
		t.Fatalf("unexpected exit code %d", code)
	}
	var rep struct {
		Findings []struct {
			RuleID     string `json:"ruleId"`
			Confidence string `json:"confidence"`
		} `json:"findings"`
		Summary struct {
			Total int `json:"total"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Summary.Total != 0 {
		t.Fatalf("expected medium-confidence findings to be filtered, got %+v", rep.Findings)
	}
}

func TestScanIsReadOnly(t *testing.T) {
	files := map[string]string{
		"config/settings.go": "package config\n\nvar token = \"" + fakeGitHubToken + "\"\n",
		"Dockerfile":         "FROM node:20\nENV API_KEY=Zq7pLm2Kd9Rt4Wx1\n",
	}
	dir := writeProject(t, files)
	before := snapshot(t, dir)
	app, _, _ := newTestApp(t)
	app.Run(context.Background(), []string{"scan", dir, "--offline"})
	after := snapshot(t, dir)
	if len(before) != len(after) {
		t.Fatalf("file count changed during scan: %d -> %d", len(before), len(after))
	}
	for name, content := range before {
		if after[name] != content {
			t.Fatalf("file %s was modified during a scan", name)
		}
	}
}

func snapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		out[path] = string(data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestVerboseDiagnostics(t *testing.T) {
	dir := writeProject(t, cleanProject)
	app, _, stderr := newTestApp(t)
	app.Run(context.Background(), []string{"scan", dir, "--offline", "--verbose"})
	if !strings.Contains(stderr.String(), "wardline:") {
		t.Fatalf("expected verbose diagnostics, got %q", stderr.String())
	}
}

func TestReorderArgs(t *testing.T) {
	cases := []struct {
		in   []string
		want []string
	}{
		{[]string{"scan", ".", "--format", "json"}, []string{"--format", "json", "scan", "."}},
		{[]string{".", "--offline", "--no-color"}, []string{"--offline", "--no-color", "."}},
		{[]string{"--exclude", "a/**", "."}, []string{"--exclude", "a/**", "."}},
		{[]string{"--format=json", "."}, []string{"--format=json", "."}},
		{[]string{"--", "--weird-path"}, []string{"--weird-path"}},
	}
	for _, c := range cases {
		got := reorderArgs(c.in)
		if strings.Join(got, " ") != strings.Join(c.want, " ") {
			t.Errorf("reorderArgs(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}
