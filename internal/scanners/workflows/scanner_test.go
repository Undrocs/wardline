package workflows

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Undrocs/wardline/internal/config"
	"github.com/Undrocs/wardline/internal/findings"
	"github.com/Undrocs/wardline/internal/scanners"
)

func scanWorkflow(t *testing.T, rel, content string) *scanners.Result {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	req := &scanners.Request{
		Root: dir, Config: config.Default(), Now: time.Unix(1700000000, 0), Offline: true,
		Files: []scanners.File{{Rel: rel, Abs: path, Size: info.Size()}},
	}
	res, err := New().Scan(context.Background(), req)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	return res
}

func ruleIDs(res *scanners.Result) []string {
	out := make([]string, 0, len(res.Findings))
	for _, f := range res.Findings {
		out = append(out, f.RuleID)
	}
	return out
}

func hasRule(res *scanners.Result, rule string) bool {
	for _, f := range res.Findings {
		if f.RuleID == rule {
			return true
		}
	}
	return false
}

func TestDetectsEachRule(t *testing.T) {
	cases := []struct {
		name     string
		workflow string
		rule     string
	}{
		{
			name: "write-all permissions",
			workflow: `on: push
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo build
`,
			rule: "WL-WF001",
		},
		{
			name: "missing permissions",
			workflow: `on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo build
`,
			rule: "WL-WF002",
		},
		{
			name: "broad write scope",
			workflow: `on: push
permissions:
  contents: write
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo build
`,
			rule: "WL-WF003",
		},
		{
			name: "unpinned action",
			workflow: `on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: some-org/action@v1.2.3
`,
			rule: "WL-WF004",
		},
		{
			name: "pull_request_target",
			workflow: `on:
  pull_request_target:
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo safe
`,
			rule: "WL-WF005",
		},
		{
			name: "privileged checkout",
			workflow: `on: pull_request_target
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`,
			rule: "WL-WF006",
		},
		{
			name: "script injection",
			workflow: `on: pull_request
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.pull_request.title }}"
`,
			rule: "WL-WF007",
		},
		{
			name: "secret echo",
			workflow: `on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ secrets.DEPLOY_TOKEN }}"
`,
			rule: "WL-WF008",
		},
		{
			name: "artifact trust",
			workflow: `on:
  workflow_run:
    workflows: ["CI"]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
`,
			rule: "WL-WF009",
		},
		{
			name: "self hosted on pull requests",
			workflow: `on: pull_request
permissions:
  contents: read
jobs:
  build:
    runs-on: [self-hosted, linux]
    steps:
      - run: echo build
`,
			rule: "WL-WF010",
		},
		{
			name: "remote script",
			workflow: `on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: curl -fsSL https://example.com/install.sh | bash
`,
			rule: "WL-WF011",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rel := ".github/workflows/test.yml"
			res := scanWorkflow(t, rel, c.workflow)
			if !hasRule(res, c.rule) {
				t.Fatalf("expected %s, got %v", c.rule, ruleIDs(res))
			}
			// Every finding must carry a rule id, a line, evidence and remediation.
			for _, f := range res.Findings {
				if f.RuleID == c.rule {
					if f.Location.StartLine <= 0 {
						t.Errorf("finding %s has no line", f.RuleID)
					}
					if f.Location.Path != rel {
						t.Errorf("unexpected path %q", f.Location.Path)
					}
					if f.Remediation == "" || f.Impact == "" || f.Description == "" {
						t.Errorf("finding %s is missing guidance", f.RuleID)
					}
					if f.Confidence == "" {
						t.Errorf("finding %s has no confidence", f.RuleID)
					}
				}
			}
		})
	}
}

func TestJobScopedWritePermissionNeedsUntrustedTrigger(t *testing.T) {
	// Least privilege: a single job may request a write scope when the workflow
	// only runs on trusted events.
	trusted := `on:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  release:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - run: gh release create v1
`
	if res := scanWorkflow(t, ".github/workflows/release.yml", trusted); hasRule(res, "WL-WF003") {
		t.Fatalf("job-scoped write scope on a trusted trigger should not be reported: %v", ruleIDs(res))
	}

	// The same grant in a workflow reachable from untrusted events is reported.
	exposed := strings.Replace(trusted, "on:\n  push:\n    branches: [main]", "on: pull_request", 1)
	if res := scanWorkflow(t, ".github/workflows/release.yml", exposed); !hasRule(res, "WL-WF003") {
		t.Fatalf("job-scoped write scope on an untrusted trigger should be reported: %v", ruleIDs(res))
	}

	// A workflow-wide write scope is always reported.
	workflowWide := strings.Replace(trusted, "permissions:\n  contents: read", "permissions: write-all", 1)
	if res := scanWorkflow(t, ".github/workflows/release.yml", workflowWide); !hasRule(res, "WL-WF001") {
		t.Fatalf("workflow-wide write-all should be reported: %v", ruleIDs(res))
	}
}

func TestSafeWorkflowHasNoFindings(t *testing.T) {
	workflow := `name: CI
on:
  pull_request:
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - name: Safe usage
        env:
          PR_TITLE: ${{ github.event.pull_request.title }}
        run: |
          echo "title length: ${#PR_TITLE}"
          go test ./...
      - name: OIDC
        permissions:
          id-token: write
        run: echo "requesting token"
`
	res := scanWorkflow(t, ".github/workflows/ci.yml", workflow)
	if len(res.Findings) != 0 {
		for _, f := range res.Findings {
			t.Logf("unexpected: %s %s %s", f.RuleID, f.LocationString(), f.Evidence)
		}
		t.Fatalf("expected no findings, got %v", ruleIDs(res))
	}
}

func TestInjectionVariants(t *testing.T) {
	unsafeExpressions := []string{
		"github.event.issue.title",
		"github.event.issue.body",
		"github.event.comment.body",
		"github.event.pull_request.body",
		"github.event.pull_request.head.ref",
		"github.event.pull_request.head.label",
		"github.head_ref",
		"github.event.head_commit.message",
		"github.event.commits[0].message",
		"github.event.workflow_run.head_branch",
		"github.event.workflow_run.pull_requests[0].head.ref",
		"github.event.review.body",
		"github.event.pages[0].page_name",
		"github.event.client_payload.command",
	}
	for _, expr := range unsafeExpressions {
		if !isUntrustedExpression(expr) {
			t.Errorf("expected %q to be treated as untrusted", expr)
		}
	}
	safeExpressions := []string{
		"github.sha",
		"github.repository",
		"github.event.pull_request.base.ref",
		"github.event.pull_request.base.repo.full_name",
		"github.event.inputs.name",
		"github.event_name",
		"secrets.DEPLOY_TOKEN",
		"github.event.pull_request.number",
		"matrix.go-version",
	}
	for _, expr := range safeExpressions {
		if isUntrustedExpression(expr) {
			t.Errorf("expected %q to be treated as safe", expr)
		}
	}
}

func TestExpressionDetectionInMultilineScript(t *testing.T) {
	workflow := `on: pull_request
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: multiline
        run: |
          echo "first line"
          echo "issue: ${{ github.event.issue.title }}"
`
	res := scanWorkflow(t, ".github/workflows/ci.yml", workflow)
	var found bool
	for _, f := range res.Findings {
		if f.RuleID == "WL-WF007" {
			found = true
			if f.Location.StartLine != 11 {
				t.Errorf("expected line 11, got %d", f.Location.StartLine)
			}
		}
	}
	if !found {
		t.Fatal("injection inside a block scalar was not detected")
	}
}

func TestUnpinnedActionSeverities(t *testing.T) {
	workflow := `on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: some-org/action@main
      - uses: some-org/action@v2
      - uses: actions/checkout@v4
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - uses: ./local-action
      - uses: docker://alpine:3.20
`
	res := scanWorkflow(t, ".github/workflows/ci.yml", workflow)
	severities := map[string]findings.Severity{}
	for _, f := range res.Findings {
		if f.RuleID == "WL-WF004" {
			severities[f.Evidence] = f.Severity
		}
	}
	if len(severities) != 4 {
		t.Fatalf("expected 4 unpinned findings, got %d: %v", len(severities), severities)
	}
	for evidence, sev := range severities {
		switch {
		case strings.Contains(evidence, "@main"):
			if sev != findings.SeverityHigh {
				t.Errorf("branch ref should be high severity, got %s", sev)
			}
		case strings.Contains(evidence, "actions/checkout@v4"):
			if sev != findings.SeverityLow {
				t.Errorf("first-party tag should be low severity, got %s", sev)
			}
		case strings.Contains(evidence, "some-org/action@v2"):
			if sev != findings.SeverityMedium {
				t.Errorf("third-party tag should be medium severity, got %s", sev)
			}
		}
	}
}

func TestMalformedWorkflowIsSkippedNotClean(t *testing.T) {
	res := scanWorkflow(t, ".github/workflows/broken.yml", "on: [push\njobs: : :\n")
	if len(res.Skipped) == 0 {
		t.Fatal("malformed workflow must be reported as a skipped check")
	}
	if !strings.Contains(strings.Join(res.Warnings, " "), "broken.yml") {
		t.Fatalf("expected a warning, got %v", res.Warnings)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("unexpected findings: %v", ruleIDs(res))
	}
}

func TestNonWorkflowFilesIgnored(t *testing.T) {
	workflow := `on: push
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`
	for _, rel := range []string{"ci.yaml", ".github/ci.yml", "docs/.github/workflows/x.yml", ".github/workflows/nested/deep.yml"} {
		res := scanWorkflow(t, rel, workflow)
		if len(res.Findings) != 0 {
			t.Errorf("%s should not be audited, got %v", rel, ruleIDs(res))
		}
	}
}

func TestNoWorkflowsNote(t *testing.T) {
	dir := t.TempDir()
	req := &scanners.Request{Root: dir, Config: config.Default(), Offline: true}
	res, err := New().Scan(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 || len(res.Skipped) != 0 {
		t.Fatalf("unexpected result: %+v", res)
	}
	if len(res.Notes) == 0 {
		t.Fatal("expected a note explaining that no workflows were found")
	}
}

func TestCatalogIsComplete(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range Catalog() {
		if r.ID == "" || r.Title == "" || r.Remediation == "" || r.Impact == "" || len(r.References) == 0 {
			t.Errorf("rule %q has incomplete metadata", r.ID)
		}
		if seen[r.ID] {
			t.Errorf("duplicate rule id %q", r.ID)
		}
		seen[r.ID] = true
	}
	if len(Catalog()) < 10 {
		t.Fatalf("expected at least 10 workflow rules, got %d", len(Catalog()))
	}
}

func FuzzParseWorkflow(f *testing.F) {
	f.Add([]byte("on: push\njobs: {}\n"))
	f.Add([]byte("permissions: write-all\n"))
	f.Add([]byte("jobs:\n  a:\n    steps:\n      - run: |\n          echo hi\n"))
	f.Add([]byte("\xff\xfe\x00"))
	f.Fuzz(func(t *testing.T, data []byte) {
		root, err := parseWorkflow(data)
		if err != nil {
			return
		}
		wf := buildWorkflow(".github/workflows/fuzz.yml", root)
		// Detection must never panic on arbitrary but parseable input.
		found := checkPermissions(wf)
		found = append(found, checkTriggers(wf)...)
		found = append(found, checkActions(wf)...)
		found = append(found, checkSteps(wf)...)
		for _, f := range found {
			if f.Location.StartLine < 0 {
				t.Fatalf("negative line number")
			}
		}
	})
}
