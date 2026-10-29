// Package secrets implements Wardline's credential detection.
//
// The detector is a native, rule-based engine. It deliberately avoids invoking
// external scanners or uploading content anywhere: files are read locally, each
// match is validated, and only redacted excerpts ever leave this package.
package secrets

import (
	"context"
	"crypto/sha256"
	"fmt"
	"path"
	"regexp"
	"runtime"
	"strings"
	"sync"

	"github.com/Undrocs/wardline/internal/findings"
	"github.com/Undrocs/wardline/internal/scanners"
	"github.com/Undrocs/wardline/internal/security"
)

const (
	// maxLineLength bounds work on minified or generated files. Content beyond
	// the limit on a single line is not scanned for secrets.
	maxLineLength = 8192
	// maxMatchesPerLine prevents a pathological line from producing thousands of
	// findings.
	maxMatchesPerLine = 8
	// maxFindingsPerFile bounds output for a single file.
	maxFindingsPerFile = 100
	// evidenceContext is how much surrounding text is included as evidence.
	evidenceContext = 40
)

// Scanner detects credential material in repository files.
type Scanner struct {
	rules []*Rule
}

// New returns a configured secret scanner.
func New() *Scanner {
	return &Scanner{rules: Rules()}
}

// Name implements scanners.Scanner.
func (s *Scanner) Name() string { return findings.ScannerSecrets }

// Scan implements scanners.Scanner.
func (s *Scanner) Scan(ctx context.Context, req *scanners.Request) (*scanners.Result, error) {
	res := &scanners.Result{}
	files := req.Files

	outcomes := make([]fileOutcome, len(files))

	// Fixed-size worker pool: one goroutine per worker rather than one per file,
	// so a repository with a million files cannot exhaust memory.
	workers := workersFor(req)
	if workers > len(files) {
		workers = len(files)
	}
	jobs := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				outcomes[i] = s.scanFile(ctx, req, files[i])
			}
		}()
	}
	for i := range files {
		if ctx.Err() != nil {
			break
		}
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	scanned, skippedBinary, skippedUnreadable := 0, 0, 0
	truncatedLines, cappedFiles := 0, 0
	for _, out := range outcomes {
		switch {
		case out.err != nil:
			if out.binary {
				skippedBinary++
			} else {
				skippedUnreadable++
			}
		default:
			scanned++
			res.Findings = append(res.Findings, out.findings...)
		}
		res.Warnings = append(res.Warnings, out.warnings...)
		truncatedLines += out.truncatedLines
		if out.matchLimitReached {
			cappedFiles++
		}
	}
	res.Scope = fmt.Sprintf("%d file(s) scanned", scanned)

	// Everything below is coverage the operator must know about: a partial check
	// that is reported only as a warning would let a clean verdict stand on
	// content that was never inspected.
	if skippedBinary > 0 {
		res.Warnings = append(res.Warnings, fmt.Sprintf("skipped %d file(s) with binary content", skippedBinary))
		res.Skipped = append(res.Skipped, scanners.SkippedCheck{
			Check:  "secret scan of binary files",
			Reason: fmt.Sprintf("%d file(s) contain binary content and were not searched for credentials", skippedBinary),
		})
	}
	if skippedUnreadable > 0 {
		res.Warnings = append(res.Warnings, fmt.Sprintf("skipped %d unreadable file(s)", skippedUnreadable))
		res.Skipped = append(res.Skipped, scanners.SkippedCheck{
			Check:  "secret scan of unreadable files",
			Reason: fmt.Sprintf("%d file(s) could not be read and were not scanned", skippedUnreadable),
		})
	}
	if truncatedLines > 0 {
		res.Skipped = append(res.Skipped, scanners.SkippedCheck{
			Check:  "secret scan of very long lines",
			Reason: fmt.Sprintf("%d line(s) exceeded %d bytes and were only partially scanned; a credential beyond the cut would not be reported", truncatedLines, maxLineLength),
		})
	}
	if cappedFiles > 0 {
		res.Skipped = append(res.Skipped, scanners.SkippedCheck{
			Check:  "secret scan match limit",
			Reason: fmt.Sprintf("%d file(s) produced more matches than the per-file limit; further matches in those files were not reported", cappedFiles),
		})
	}
	return res, nil
}

// fileOutcome is the result of scanning one file.
type fileOutcome struct {
	findings []findings.Finding
	warnings []string
	err      error
	binary   bool
	// truncatedLines counts lines longer than maxLineLength, which are only
	// partially scanned.
	truncatedLines int
	// matchLimitReached records that the per-file finding cap suppressed output.
	matchLimitReached bool
}

// scanFile scans one file, recording everything that limited coverage.
func (s *Scanner) scanFile(ctx context.Context, req *scanners.Request, file scanners.File) fileOutcome {
	if file.Size == 0 {
		return fileOutcome{}
	}
	content, err := security.ReadFileLimitedVerified(file.Abs, file.Info, req.Config.Limits.MaxFileSize)
	if err != nil {
		return fileOutcome{err: err}
	}
	if security.IsBinary(content) {
		return fileOutcome{binary: true, err: fmt.Errorf("binary")}
	}
	if ctx.Err() != nil {
		return fileOutcome{err: ctx.Err()}
	}

	relLower := strings.ToLower(file.Rel)
	var out []findings.Finding
	var warnings []string
	outcome := fileOutcome{}
	base := path.Base(file.Rel)

	// File-level rules (committed credential stores).
	for _, rule := range s.rules {
		if !rule.FileLevel || !rule.appliesToPath(relLower) {
			continue
		}
		if reason, ok := credentialFile(base, content); ok {
			out = append(out, fileFinding(rule, file.Rel, reason))
		}
	}

	seen := make(map[[32]byte]bool)
	lines := splitLines(content)
	for idx, raw := range lines {
		if ctx.Err() != nil {
			outcome.findings, outcome.warnings = out, warnings
			outcome.err = ctx.Err()
			return outcome
		}
		lineNo := idx + 1
		line := raw
		if len(line) > maxLineLength {
			warnings = append(warnings, fmt.Sprintf("%s:%d is longer than %d bytes and was partially scanned", file.Rel, lineNo, maxLineLength))
			outcome.truncatedLines++
			line = line[:maxLineLength]
		}
		line = trimTrailingCR(line)
		if len(line) > 0 {
			lower := strings.ToLower(string(line))
			for _, rule := range s.rules {
				if rule.FileLevel || !rule.appliesToPath(relLower) {
					continue
				}
				if !rule.keywordMatch(lower) {
					continue
				}
				// One extra match is requested so that hitting the per-line cap is
				// observable instead of being silently indistinguishable from a
				// line that happened to contain exactly that many matches.
				matches := rule.Pattern.FindAllSubmatchIndex(line, maxMatchesPerLine+1)
				if len(matches) > maxMatchesPerLine {
					warnings = append(warnings, fmt.Sprintf("%s:%d has more than %d matches; only the first %d were examined", file.Rel, lineNo, maxMatchesPerLine, maxMatchesPerLine))
					outcome.matchLimitReached = true
					matches = matches[:maxMatchesPerLine]
				}
				for _, m := range matches {
					if len(out) >= maxFindingsPerFile {
						warnings = append(warnings, fmt.Sprintf("%s: more than %d findings on one file; further matches were suppressed", file.Rel, maxFindingsPerFile))
						outcome.matchLimitReached = true
						break
					}
					f, ok := s.buildFinding(rule, file.Rel, line, m, lineNo)
					if !ok {
						continue
					}
					key := sha256.Sum256([]byte(rule.ID + "\x00" + f.Locator))
					if seen[key] {
						continue
					}
					seen[key] = true
					out = append(out, f)
				}
			}
		}
		// A YAML/Ansible style block scalar puts the value on the following
		// indented line, where no assignment pattern can see it.
		if f, ok := s.blockScalarFinding(file.Rel, lines, idx); ok {
			key := sha256.Sum256([]byte(f.RuleID + "\x00" + f.Locator))
			if !seen[key] {
				seen[key] = true
				out = append(out, f)
			}
		}
	}
	outcome.findings = out
	outcome.warnings = warnings
	return outcome
}

// splitLines splits content into lines without their terminators. The content
// has already been size-limited by the caller.
func splitLines(content []byte) [][]byte {
	if len(content) == 0 {
		return nil
	}
	lines := make([][]byte, 0, 1+strings.Count(string(content), "\n"))
	start := 0
	for start <= len(content) {
		end := start
		for end < len(content) && content[end] != '\n' {
			end++
		}
		lines = append(lines, trimTrailingCR(content[start:end]))
		if end >= len(content) {
			break
		}
		start = end + 1
	}
	return lines
}

// blockScalarKey matches "key: |" and "key: >-" style declarations whose value
// lives on the following indented lines.
var blockScalarKey = regexp.MustCompile(`(?i)^\s*(?:-[ ]+)?([A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|private[_-]?key|client[_-]?secret|access[_-]?key|credential)[A-Za-z0-9_.-]*)["']?\s*:\s*[|>][-+]?\s*$`)

// blockScalarFinding inspects the indented block that follows a block-scalar
// key and reports a literal credential stored there.
func (s *Scanner) blockScalarFinding(rel string, lines [][]byte, keyIndex int) (findings.Finding, bool) {
	m := blockScalarKey.FindSubmatch(lines[keyIndex])
	if m == nil {
		return findings.Finding{}, false
	}
	keyName := string(m[1])
	keyIndent := indentWidth(lines[keyIndex])
	for j := keyIndex + 1; j < len(lines); j++ {
		text := string(lines[j])
		if strings.TrimSpace(text) == "" {
			continue
		}
		if indentWidth(lines[j]) <= keyIndent {
			return findings.Finding{}, false
		}
		value := strings.TrimSpace(text)
		if value == "" || strings.HasPrefix(value, "#") {
			continue
		}
		rule := passwordLikeKey(keyName)
		if !acceptValue(rule, value) {
			return findings.Finding{}, false
		}
		start := strings.Index(text, value)
		if start < 0 {
			return findings.Finding{}, false
		}
		masked := security.MaskSecret(value)
		evidence := fmt.Sprintf("%s: %s", keyName, masked)
		return findings.New(findings.Finding{
			RuleID:      rule.ID,
			Scanner:     findings.ScannerSecrets,
			Title:       rule.Title,
			Severity:    rule.Severity,
			Confidence:  rule.Confidence,
			Location:    findings.Location{Path: rel, StartLine: j + 1, StartColumn: start + 1, EndLine: j + 1, EndColumn: start + len(value) + 1},
			Evidence:    security.RedactEvidence(evidence, 160),
			Description: rule.Description,
			Impact:      rule.Impact,
			Remediation: remediation(rule),
			References:  rule.References,
			Locator:     "match:" + masked,
		}), true
	}
	return findings.Finding{}, false
}

// passwordLikeKey picks the rule that describes a block-scalar key.
func passwordLikeKey(key string) *Rule {
	lower := strings.ToLower(key)
	if strings.Contains(lower, "pass") || strings.Contains(lower, "pwd") {
		return findRule("WL-SEC-022")
	}
	return findRule("WL-SEC-023")
}

// findRule returns the rule with the given ID, or the first rule if it is
// missing (which cannot happen unless the catalogue is edited).
func findRule(id string) *Rule {
	for _, r := range Rules() {
		if r.ID == id {
			return r
		}
	}
	return Rules()[0]
}

// indentWidth counts leading spaces and tabs.
func indentWidth(line []byte) int {
	n := 0
	for _, b := range line {
		if b != ' ' && b != '\t' {
			break
		}
		n++
	}
	return n
}

// acceptValue applies the rule's validity checks to a candidate value that was
// not located by the rule's own pattern.
func acceptValue(rule *Rule, value string) bool {
	if value == "" {
		return false
	}
	if rule.MinLength > 0 && len(value) < rule.MinLength {
		return false
	}
	if rule.MaxLength > 0 && len(value) > rule.MaxLength {
		return false
	}
	if !rule.AllowPlaceholders && security.LooksLikePlaceholder(value) {
		return false
	}
	if rule.MinEntropy > 0 && security.ShannonEntropy(value) < rule.MinEntropy {
		return false
	}
	if rule.Validate != nil && !rule.Validate(value) {
		return false
	}
	return true
}

func (s *Scanner) buildFinding(rule *Rule, rel string, line []byte, match []int, lineNo int) (findings.Finding, bool) {
	group := rule.SecretGroup
	if 2*group+1 >= len(match) || match[2*group] < 0 {
		return findings.Finding{}, false
	}
	start, end := match[2*group], match[2*group+1]
	if start < 0 || end > len(line) || start >= end {
		return findings.Finding{}, false
	}
	value := string(line[start:end])
	value = strings.Trim(value, `"'`+"` \t")
	if value == "" {
		return findings.Finding{}, false
	}
	if rule.MinLength > 0 && len(value) < rule.MinLength {
		return findings.Finding{}, false
	}
	if rule.MaxLength > 0 && len(value) > rule.MaxLength {
		return findings.Finding{}, false
	}
	if !rule.AllowPlaceholders && security.LooksLikePlaceholder(value) {
		return findings.Finding{}, false
	}
	if rule.MinEntropy > 0 && security.ShannonEntropy(value) < rule.MinEntropy {
		return findings.Finding{}, false
	}
	if rule.Validate != nil && !rule.Validate(value) {
		return findings.Finding{}, false
	}
	if rule.ValidateMatch != nil && !rule.ValidateMatch(string(line), match) {
		return findings.Finding{}, false
	}

	masked := security.MaskSecret(value)
	confidence := rule.Confidence
	if rule.ConfidenceForMatch != nil {
		confidence = rule.ConfidenceForMatch(line, match)
	}
	evidence := buildEvidence(line, start, end, value)
	if rule.ID == "WL-SEC-020" {
		// The PEM header itself is not secret and is far more useful than a mask.
		evidence = "private key block: " + security.RedactEvidence(value, 80)
	}
	return findings.New(findings.Finding{
		RuleID:      rule.ID,
		Scanner:     findings.ScannerSecrets,
		Title:       rule.Title,
		Severity:    rule.Severity,
		Confidence:  confidence,
		Location:    findings.Location{Path: rel, StartLine: lineNo, StartColumn: start + 1, EndLine: lineNo, EndColumn: end + 1},
		Evidence:    evidence,
		Description: rule.Description,
		Impact:      rule.Impact,
		Remediation: remediation(rule),
		References:  rule.References,
		Locator:     "match:" + masked,
	}), true
}

func remediation(rule *Rule) string {
	base := "Remove the value from the working tree and from Git history, then revoke or rotate the credential with the provider. Deleting the line does not make an exposed credential safe: assume it is compromised."
	if rule.Remediation == "" {
		return base
	}
	return rule.Remediation + " Removing the value from source is not sufficient: revoke or rotate the credential."
}

// buildEvidence produces a redacted, single-line excerpt around the match.
func buildEvidence(line []byte, start, end int, secret string) string {
	from := start - evidenceContext
	if from < 0 {
		from = 0
	}
	to := end + evidenceContext
	if to > len(line) {
		to = len(line)
	}
	prefix := scrubTokens(string(line[from:start]))
	suffix := scrubTokens(string(line[end:to]))
	masked := security.MaskSecret(secret)
	evidence := prefix + masked + suffix
	// Final guarantee: the raw value must not appear anywhere in the evidence,
	// even if it was repeated on the same line.
	if strings.Contains(evidence, secret) {
		evidence = strings.ReplaceAll(evidence, secret, masked)
	}
	return security.RedactEvidence(evidence, 160)
}

// scrubTokens masks machine-generated tokens in surrounding context so a second
// credential on the same line is not leaked by the first finding. The shared
// implementation lives in internal/security so every scanner redacts the same
// way.
func scrubTokens(s string) string {
	return security.RedactCredentials(s)
}

func trimTrailingCR(b []byte) []byte {
	if n := len(b); n > 0 && b[n-1] == '\r' {
		return b[:n-1]
	}
	return b
}

// credentialFile recognises committed credential stores whose contents make the
// risk unambiguous. It returns the reason used as evidence.
func credentialFile(base string, content []byte) (string, bool) {
	lower := strings.ToLower(string(content))
	name := strings.ToLower(base)
	switch {
	case strings.HasPrefix(name, "id_rsa"), strings.HasPrefix(name, "id_dsa"),
		strings.HasPrefix(name, "id_ecdsa"), strings.HasPrefix(name, "id_ed25519"):
		if strings.Contains(lower, "private key") {
			return "SSH private key file", true
		}
	case name == ".git-credentials":
		if strings.Contains(lower, "@") {
			return "stored Git credentials file", true
		}
	case name == ".netrc":
		if strings.Contains(lower, "password") || strings.Contains(lower, "login") {
			return "netrc credentials file", true
		}
	case name == ".pypirc":
		if strings.Contains(lower, "password") || strings.Contains(lower, "token") {
			return "PyPI credentials file", true
		}
	case name == ".npmrc":
		if strings.Contains(lower, "_authtoken") || strings.Contains(lower, "_auth=") || strings.Contains(lower, "_password") {
			return "npm registry credentials file", true
		}
	case name == ".htpasswd":
		if strings.Contains(string(content), ":") {
			return "HTTP basic-auth password file", true
		}
	case name == "service-account.json", name == "credentials.json":
		if strings.Contains(lower, "private_key") || strings.Contains(lower, "refresh_token") {
			return "cloud service account credential file", true
		}
	}
	return "", false
}

func fileFinding(rule *Rule, rel, reason string) findings.Finding {
	return findings.New(findings.Finding{
		RuleID:      rule.ID,
		Scanner:     findings.ScannerSecrets,
		Title:       rule.Title,
		Severity:    rule.Severity,
		Confidence:  rule.Confidence,
		Location:    findings.Location{Path: rel, StartLine: 1},
		Evidence:    security.RedactEvidence(reason, 120),
		Description: rule.Description + " Detected: " + reason + ".",
		Impact:      rule.Impact,
		Remediation: remediation(rule),
		References:  rule.References,
		Locator:     "file:" + reason,
	})
}

// workersFor resolves the parallelism for file scanning. An unset limit means
// "one worker per CPU, capped", matching the documented configuration default.
func workersFor(req *scanners.Request) int {
	if req.Config != nil && req.Config.Limits.Workers > 0 {
		return req.Config.Limits.Workers
	}
	n := runtime.GOMAXPROCS(0)
	if n < 2 {
		n = 2
	}
	if n > 8 {
		n = 8
	}
	return n
}
