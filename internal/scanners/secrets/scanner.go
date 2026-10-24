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

	type fileOutcome struct {
		findings []findings.Finding
		warnings []string
		err      error
		binary   bool
	}
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
				fs, warns, binary, err := s.scanFile(ctx, req, files[i])
				outcomes[i] = fileOutcome{findings: fs, warnings: warns, err: err, binary: binary}
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
	}
	res.Scope = fmt.Sprintf("%d file(s) scanned", scanned)
	if skippedBinary > 0 {
		res.Warnings = append(res.Warnings, fmt.Sprintf("skipped %d file(s) with binary content", skippedBinary))
	}
	if skippedUnreadable > 0 {
		res.Warnings = append(res.Warnings, fmt.Sprintf("skipped %d unreadable file(s)", skippedUnreadable))
		res.Skipped = append(res.Skipped, scanners.SkippedCheck{
			Check:  "secret scan of unreadable files",
			Reason: fmt.Sprintf("%d file(s) could not be read and were not scanned", skippedUnreadable),
		})
	}
	return res, nil
}

// scanFile returns findings, warnings and whether the file was rejected as binary.
func (s *Scanner) scanFile(ctx context.Context, req *scanners.Request, file scanners.File) ([]findings.Finding, []string, bool, error) {
	if file.Size == 0 {
		return nil, nil, false, nil
	}
	content, err := security.ReadFileLimited(file.Abs, req.Config.Limits.MaxFileSize)
	if err != nil {
		return nil, nil, false, err
	}
	if security.IsBinary(content) {
		return nil, nil, true, fmt.Errorf("binary")
	}
	if ctx.Err() != nil {
		return nil, nil, false, ctx.Err()
	}

	relLower := strings.ToLower(file.Rel)
	var out []findings.Finding
	var warnings []string
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
	lineNo := 0
	for start := 0; start <= len(content); {
		if ctx.Err() != nil {
			return out, warnings, false, ctx.Err()
		}
		end := start
		for end < len(content) && content[end] != '\n' {
			end++
		}
		lineNo++
		line := content[start:end]
		if len(line) > maxLineLength {
			warnings = append(warnings, fmt.Sprintf("%s:%d is longer than %d bytes and was partially scanned", file.Rel, lineNo, maxLineLength))
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
				matches := rule.Pattern.FindAllSubmatchIndex(line, maxMatchesPerLine)
				for _, m := range matches {
					if len(out) >= maxFindingsPerFile {
						warnings = append(warnings, fmt.Sprintf("%s: more than %d findings on one file; further matches were suppressed", file.Rel, maxFindingsPerFile))
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
		if end >= len(content) {
			break
		}
		start = end + 1
	}
	return out, warnings, false, nil
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
	evidence := buildEvidence(line, start, end, value)
	if rule.ID == "WL-SEC-020" {
		// The PEM header itself is not secret and is far more useful than a mask.
		evidence = "private key block: " + security.SanitizeEvidence(value, 80)
	}
	return findings.New(findings.Finding{
		RuleID:      rule.ID,
		Scanner:     findings.ScannerSecrets,
		Title:       rule.Title,
		Severity:    rule.Severity,
		Confidence:  rule.Confidence,
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
	return security.SanitizeEvidence(evidence, 160)
}

var longTokenPattern = regexp.MustCompile(`[A-Za-z0-9_\-+/=.]{16,}`)

// credentialPrefixes identify machine-generated tokens even when they contain no
// digits, so context scrubbing still catches a second credential on the line.
var credentialPrefixes = []string{
	"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "glpat-",
	"sk_live_", "sk_test_", "sk-proj-", "npm_", "pypi-", "aiza", "akia",
	"asia", "xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-", "sg.", "hvs.",
	"hvb.", "hvr.", "dop_v1_", "sq0atp-", "sq0csp-", "whsec_", "accountkey=",
}

// scrubTokens masks machine-generated tokens in surrounding context so a second
// credential on the same line is not leaked by the first finding. Ordinary
// identifiers such as AWS_SECRET_ACCESS_KEY are left readable.
func scrubTokens(s string) string {
	return longTokenPattern.ReplaceAllStringFunc(s, func(token string) string {
		if security.LooksLikePlaceholder(token) {
			return token
		}
		lower := strings.ToLower(token)
		for _, prefix := range credentialPrefixes {
			if strings.HasPrefix(lower, prefix) || strings.Contains(lower, prefix) {
				return security.MaskSecret(token)
			}
		}
		if security.LooksRandom(token, 3.0) {
			return security.MaskSecret(token)
		}
		return token
	})
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
		Evidence:    security.SanitizeEvidence(reason, 120),
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
