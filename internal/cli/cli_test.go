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
	// A Go module with a dependency, so the dependency scanner has real
	// coordinates: an offline scan then has a lookup to skip, which is what makes
	// it incomplete rather than clean.
	"go.mod": "module example.com/clean\n\ngo 1.23\n\nrequire github.com/goccy/go-yaml v1.19.2\n",
	"go.sum": "github.com/goccy/go-yaml v1.19.2 h1:abc123\n",
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

// TestAbsoluteTargetIsReducedForEveryFormat extends the absolute-path test to
// the machine-specific parts of the path and to SARIF.
func TestAbsoluteTargetIsReducedForEveryFormat(t *testing.T) {
	dir := writeProject(t, secretProject)
	// t.TempDir() hands out a path under the test's scratch directory, which
	// contains the OS user's name on most systems.
	abs, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	parent := filepath.Dir(abs)
	for _, format := range []string{"json", "markdown", "sarif", "terminal"} {
		app, stdout, _ := newTestApp(t)
		args := []string{"scan", abs, "--offline", "--no-color"}
		if format != "terminal" {
			args = append(args, "--format", format)
		}
		_ = app.Run(context.Background(), args)
		out := stdout.String()
		if strings.Contains(out, parent) {
			t.Errorf("%s output disclosed the parent directory %q", format, parent)
		}
		if strings.Contains(out, abs) {
			t.Errorf("%s output disclosed the absolute target", format)
		}
		if !strings.Contains(out, filepath.Base(abs)) {
			t.Errorf("%s output does not name the scanned directory", format)
		}
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
			Name     string `json:"name"`
			Disabled bool   `json:"disabled"`
			Findings int    `json:"findings"`
		} `json:"scanners"`
		Findings []struct {
			Scanner string `json:"scanner"`
			RuleID  string `json:"ruleId"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	// Every scanner appears in the report: the one that ran, and the three that
	// were not selected, so a reader can see what was not checked.
	ran := map[string]bool{}
	for _, sc := range rep.Scanners {
		if sc.Disabled {
			continue
		}
		ran[sc.Name] = true
	}
	if len(ran) != 1 || !ran["secrets"] {
		t.Fatalf("expected only the secrets scanner to run, got %+v", rep.Scanners)
	}
	if len(rep.Scanners) != 4 {
		t.Fatalf("expected all four scanners to be reported, got %+v", rep.Scanners)
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

// writeConfig drops a .wardline.yaml into a project directory.
func writeConfig(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, ".wardline.yaml"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestMaliciousConfigCannotRedirectNetwork covers the case where a scanned
// repository ships a .wardline.yaml pointing the dependency scanner at an
// attacker-controlled host: a metadata service, a private address or an
// arbitrary public host. None of them may be contacted without approval.
func TestMaliciousConfigCannotRedirectNetwork(t *testing.T) {
	cases := []struct {
		name     string
		endpoint string
		wantExit int
		wantErr  string
	}{
		{"metadata service", "https://169.254.169.254", ExitUsage, "metadata"},
		{"private address", "https://10.0.0.5:8080", ExitUsage, "allow-custom-endpoint"},
		{"public custom host", "https://collector.example.com", ExitUsage, "allow-custom-endpoint"},
		{"plain http public host", "http://osv.example.com", ExitUsage, "must use https"},
		{"loopback", "https://127.0.0.1:9999", ExitUsage, "allow-custom-endpoint"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := writeProject(t, cleanProject)
			writeConfig(t, dir, "network:\n  osvEndpoint: "+c.endpoint+"\n")
			app, _, stderr := newTestApp(t)
			code := app.Run(context.Background(), []string{"scan", dir, "--no-color"})
			if code != c.wantExit {
				t.Fatalf("exit code %d (%s), want %d", code, stderr.String(), c.wantExit)
			}
			if !strings.Contains(stderr.String(), c.wantErr) {
				t.Fatalf("stderr %q does not explain the rejection (%q)", stderr.String(), c.wantErr)
			}
		})
	}
}

func TestApprovedCustomEndpointIsUsedAndDisclosed(t *testing.T) {
	// The endpoint is approved but unreachable, so the dependency scanner fails
	// and the scan is reported as incomplete. What matters here is that the
	// approval is honoured and recorded in the report.
	dir := writeProject(t, map[string]string{
		"go.mod": "module example.com/app\n\ngo 1.23\n\nrequire github.com/pkg/errors v0.9.1\n",
	})
	writeConfig(t, dir, "network:\n  osvEndpoint: https://127.0.0.1:1\n")
	app, stdout, _ := newTestApp(t)
	code := app.Run(context.Background(), []string{
		"scan", dir, "--allow-custom-endpoint", "--format", "json", "--timeout", "30s",
	})
	_ = code // the exit code depends on the unreachable endpoint; the report is what we assert
	var rep struct {
		PolicyNotices []string `json:"policyNotices"`
		Network       struct {
			Destinations []string `json:"destinations"`
		} `json:"network"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
		t.Fatalf("decode report: %v (%s)", err, stdout.String())
	}
	joined := strings.Join(rep.PolicyNotices, "\n")
	if !strings.Contains(joined, "127.0.0.1:1") || !strings.Contains(joined, "approved") {
		t.Fatalf("approval was not disclosed: %v", rep.PolicyNotices)
	}
}

func TestStrictModeIgnoresRepositoryOverrides(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"app/secrets.go": "package app\n\nconst token = \"" + fakeGitHubToken + "\"\n",
	})
	// Every one of these settings would weaken the scan if it were honoured.
	writeConfig(t, dir, `
scanners:
  secrets: false
  dependencies: true
  workflows: true
  config: true
exclude:
  - "**"
severity:
  failOn: critical
report:
  minSeverity: high
rules:
  disable: [WL-SEC-003]
  severity:
    WL-SEC-003: info
suppressions:
  - rule: WL-SEC-003
    reason: "Trust us."
network:
  enabled: false
`)
	app, stdout, _ := newTestApp(t)
	code := app.Run(context.Background(), []string{"scan", dir, "--strict", "--offline", "--format", "json"})
	if code != ExitPolicy {
		t.Fatalf("strict mode exited %d, want %d (the secret must still be found and fail the gate)", code, ExitPolicy)
	}
	var rep struct {
		Findings []struct {
			RuleID     string                `json:"ruleId"`
			Suppressed bool                  `json:"suppressed"`
			Severity   string                `json:"severity"`
			Location   struct{ Path string } `json:"location"`
		} `json:"findings"`
		PolicyNotices []string `json:"policyNotices"`
		Summary       struct {
			Policy struct {
				FailOn string `json:"failOn"`
			} `json:"policy"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range rep.Findings {
		if f.RuleID == "WL-SEC-003" {
			found = true
			if f.Suppressed {
				t.Error("strict mode honoured a repository suppression")
			}
			if f.Severity != "high" {
				t.Errorf("strict mode honoured a rule severity override: %s", f.Severity)
			}
		}
	}
	if !found {
		t.Fatal("strict mode excluded the file through the repository's exclude pattern")
	}
	if rep.Summary.Policy.FailOn != "high" {
		t.Errorf("strict mode did not restore the fail-on threshold: %s", rep.Summary.Policy.FailOn)
	}
	joined := strings.Join(rep.PolicyNotices, "\n")
	for _, want := range []string{"scanners.secrets", "exclude", "suppression", "rules.disable", "rules.severity", "failOn", "minSeverity"} {
		if !strings.Contains(joined, want) {
			t.Errorf("policy notices do not mention %q:\n%s", want, joined)
		}
	}
}

func TestStrictModeKeepsUntrustedEndpointOut(t *testing.T) {
	dir := writeProject(t, cleanProject)
	writeConfig(t, dir, "network:\n  osvEndpoint: https://collector.example.com\n")
	app, stdout, _ := newTestApp(t)
	code := app.Run(context.Background(), []string{"scan", dir, "--strict", "--offline", "--format", "json"})
	if code != ExitOK {
		t.Fatalf("strict scan exited %d", code)
	}
	if strings.Contains(stdout.String(), "collector.example.com") {
		t.Fatalf("strict mode kept the untrusted endpoint: %s", stdout.String())
	}
}

func TestFailIncompleteTurnsPartialCoverageIntoFailure(t *testing.T) {
	// An oversized file is skipped, which makes coverage partial without any
	// scanner failing.
	dir := writeProject(t, cleanProject)
	writeConfig(t, dir, "limits:\n  maxFileSize: 1KiB\n")
	big := strings.Repeat("x", 4096)
	if err := os.WriteFile(filepath.Join(dir, "big.txt"), []byte(big), 0o600); err != nil {
		t.Fatal(err)
	}

	app, _, _ := newTestApp(t)
	if code := app.Run(context.Background(), []string{"scan", dir, "--offline", "--no-color"}); code != ExitOK {
		t.Fatalf("baseline scan exited %d, want 0", code)
	}

	app, stdout, stderr := newTestApp(t)
	code := app.Run(context.Background(), []string{"scan", dir, "--offline", "--no-color", "--fail-incomplete"})
	if code != ExitOperational {
		t.Fatalf("--fail-incomplete exited %d, want %d", code, ExitOperational)
	}
	if !strings.Contains(stderr.String(), "incomplete") {
		t.Fatalf("stderr does not explain the failure: %s", stderr.String())
	}
	if !strings.Contains(stdout.String(), "INCOMPLETE") {
		t.Fatalf("the report should still be produced: %s", stdout.String())
	}
}

func TestQuietSuppressesOutputOnlyWhenClean(t *testing.T) {
	// A project with no dependency manifest: nothing is skipped, so the scan is
	// genuinely complete. (An offline scan of a project that does have
	// dependencies is incomplete, and --quiet must not hide that.)
	clean := writeProject(t, map[string]string{
		"internal/app.go": cleanProject["internal/app.go"],
	})
	app, stdout, _ := newTestApp(t)
	if code := app.Run(context.Background(), []string{"scan", clean, "--offline", "--quiet"}); code != ExitOK {
		t.Fatalf("exit %d", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("--quiet printed %q on a clean scan", stdout.String())
	}

	// A failing scan must still be visible.
	dirty := writeProject(t, secretProject)
	app, stdout, _ = newTestApp(t)
	if code := app.Run(context.Background(), []string{"scan", dirty, "--offline", "--quiet"}); code != ExitPolicy {
		t.Fatalf("exit %d", code)
	}
	if stdout.Len() == 0 {
		t.Fatal("--quiet hid a failing scan")
	}
}

func TestSummaryPrintsCountsWithoutFindings(t *testing.T) {
	dir := writeProject(t, secretProject)
	app, stdout, _ := newTestApp(t)
	if code := app.Run(context.Background(), []string{"scan", dir, "--offline", "--summary"}); code != ExitPolicy {
		t.Fatalf("exit %d", code)
	}
	out := stdout.String()
	if !strings.Contains(out, "findings") || !strings.Contains(out, "result") {
		t.Fatalf("summary is missing its summary: %s", out)
	}
	if strings.Contains(out, "WL-SEC-003") {
		t.Fatalf("--summary listed individual findings: %s", out)
	}
}

// TestEvidenceIsRedactedInEveryFormat scans a project whose build files carry
// credentials in their command lines, then checks that no report format leaks
// them. This is the end-to-end guard for the redaction contract: scanners
// redact before storage, and the reporters redact again as a safety net.
func TestEvidenceIsRedactedInEveryFormat(t *testing.T) {
	const bearer = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.c2lnbmF0dXJlLXZhbHVl"
	const dbPassword = "Secr3tP4ss99"
	const pypiPassword = "PyP1Secret77"
	project := map[string]string{
		"deploy/Dockerfile": "FROM alpine:3.20\n" +
			"USER app\n" +
			"RUN curl -H 'Authorization: Bearer " + bearer + "' https://api.example.com/install.sh | sh\n" +
			"RUN pip install --index-url https://ci:" + pypiPassword + "@packages.example.com/simple demo\n",
		".github/workflows/ci.yml": "name: ci\non: [push]\npermissions:\n  contents: read\n" +
			"jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n" +
			"      - run: mysql --password " + dbPassword + " -e 'select 1'\n",
	}
	dir := writeProject(t, project)

	for _, format := range []string{"json", "markdown", "sarif", "terminal"} {
		t.Run(format, func(t *testing.T) {
			app, stdout, stderr := newTestApp(t)
			args := []string{"scan", dir, "--offline", "--no-color"}
			if format != "terminal" {
				args = append(args, "--format", format)
			}
			_ = app.Run(context.Background(), args)
			out := stdout.String() + stderr.String()
			for _, secret := range []string{bearer, dbPassword, pypiPassword} {
				if strings.Contains(out, secret) {
					t.Fatalf("%s output leaked a credential (%q)\n%s", format, secret, out)
				}
			}
			// The findings must still be there: redaction removes the secret,
			// not the evidence that the rule fired.
			if !strings.Contains(out, "WL-CFG-008") && !strings.Contains(out, "WL-WF-") {
				t.Fatalf("%s output lost the findings entirely:\n%s", format, out)
			}
			if format == "json" || format == "sarif" {
				if !json.Valid(stdout.Bytes()) {
					t.Fatalf("%s output is not valid JSON after redaction", format)
				}
			}
		})
	}
}
