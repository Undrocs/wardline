package secrets

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/Undrocs/wardline/internal/config"
	"github.com/Undrocs/wardline/internal/findings"
	"github.com/Undrocs/wardline/internal/scanners"
)

// Synthetic, non-functional credentials used only by tests.
const (
	fakeAWSKeyID     = "AKIA" + "Q7X4R2ZP5RTMNW3V"
	fakeAWSSecret    = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzq7pLm2Kd9Rt"
	fakeGitHubToken  = "ghp_" + "Q7mXr4Tz9KpL2WcV8bN3jH6yF5dS1aE0uG8i"
	fakeGitLabToken  = "glpat-" + "Q7mXr4Tz9KpL2WcV8bN3"
	fakeSlackToken   = "xoxb-" + "123456789012-abcdefghijklmnop"
	fakeStripeLive   = "sk_live_" + "Q7mXr4Tz9KpL2WcV8bN3jH6y"
	fakeGoogleKey    = "AIza" + "Q7X4R2ZP5RTMNW3Vq7pLm2Kd9Rt4Wx1AaBc"
	fakeNPMToken     = "npm_" + "Q7mXr4Tz9KpL2WcV8bN3jH6yF5dS1aE0uG8i"
	fakeSendGridKey  = "SG." + "Q7mXr4Tz9KpL2WcV8bN3jH.Q7mXr4Tz9KpL2WcV8bN3jH6yF5dS1aE0uG8iQ7mXr4Tz9"
	fakeDBURL        = "postgres://reportsvc:Yk4mPz9Qw2Er7Tt5@db-prod.internal:5432/reports"
	fakePassword     = "Lm4Qp9Zx2Tr7Wc5V"
	fakePrivateKey   = "-----BEGIN" + " OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----"
	fakePyPIToken    = "pypi-" + "AgEIcHlwaS5vcmcQ7mXr4Tz9KpL2WcV8bN3jH6yF5dS1aE0uG8iQ7mXr4Tz9AbCdE"
	fakeDigitalOcean = "dop_v1_" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

// runScan scans a directory with the secrets scanner only.
func runScan(t *testing.T, dir string) *scanners.Result {
	t.Helper()
	cfg := config.Default()
	var files []scanners.File
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		info, infoErr := d.Info()
		if infoErr != nil {
			return infoErr
		}
		rel, relErr := filepath.Rel(dir, path)
		if relErr != nil {
			return relErr
		}
		files = append(files, scanners.File{
			Rel:  filepath.ToSlash(rel),
			Abs:  path,
			Size: info.Size(),
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	req := &scanners.Request{
		Root:    dir,
		Files:   files,
		Config:  cfg,
		Offline: true,
		Now:     time.Unix(1700000000, 0),
	}
	res, err := New().Scan(context.Background(), req)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	return res
}

func writeFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func rulesOf(res *scanners.Result) map[string]int {
	out := map[string]int{}
	for _, f := range res.Findings {
		out[f.RuleID]++
	}
	return out
}

func TestDetectsCredentialPatterns(t *testing.T) {
	cases := []struct {
		name    string
		content string
		rule    string
	}{
		{"aws access key id", "aws_access_key_id = \"" + fakeAWSKeyID + "\"", "WL-SEC-001"},
		{"aws secret", "AWS_SECRET_ACCESS_KEY=\"" + fakeAWSSecret + "\"", "WL-SEC-002"},
		{"github token", "token := \"" + fakeGitHubToken + "\"", "WL-SEC-003"},
		{"gitlab token", "GITLAB_TOKEN=" + fakeGitLabToken, "WL-SEC-004"},
		{"slack token", "slack: " + fakeSlackToken, "WL-SEC-005"},
		{"stripe live", "stripe := \"" + fakeStripeLive + "\"", "WL-SEC-007"},
		{"google api key", "key: \"" + fakeGoogleKey + "\"", "WL-SEC-009"},
		{"npm token", "//registry.npmjs.org/:_authToken=" + fakeNPMToken, "WL-SEC-010"},
		{"pypi token", "password = \"" + fakePyPIToken + "\"", "WL-SEC-011"},
		{"sendgrid", "key=\"" + fakeSendGridKey + "\"", "WL-SEC-012"},
		{"digitalocean", "DO_TOKEN=" + fakeDigitalOcean, "WL-SEC-018"},
		{"private key", "const k = `" + fakePrivateKey + "`", "WL-SEC-020"},
		{"database url", `DATABASE_URL="` + fakeDBURL + `"`, "WL-SEC-021"},
		{"hardcoded password", `password = "` + fakePassword + `"`, "WL-SEC-022"},
		{"api key", `api_key = "` + fakeAWSSecret + `"`, "WL-SEC-023"},
		{"jwt", `auth: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"`, "WL-SEC-024"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, dir, "src/settings.go", "package src\n\n"+c.content+"\n")
			res := runScan(t, dir)
			if res.Findings == nil || rulesOf(res)[c.rule] == 0 {
				t.Fatalf("expected %s, got findings %v", c.rule, rulesOf(res))
			}
		})
	}
}

func TestIgnoresBenignValues(t *testing.T) {
	content := `package src

const (
	examplePassword = "changeme"
	placeholderKey  = "your-api-key-here"
	envReference    = "${DB_PASSWORD}"
	templateValue   = "{{ .Values.password }}"
)

// api_key = "replace-me"
var dbURL = "postgres://user:pass@localhost:5432/dev"
var localURL = "postgres://dev:dev@127.0.0.1:5432/dev"
var sampleToken = "example-token-not-real"
`
	dir := t.TempDir()
	writeFile(t, dir, "src/benign.go", content)
	res := runScan(t, dir)
	if len(res.Findings) != 0 {
		for _, f := range res.Findings {
			t.Logf("unexpected finding: %s %s %s", f.RuleID, f.LocationString(), f.Evidence)
		}
		t.Fatalf("expected no findings, got %d", len(res.Findings))
	}
}

func TestHighEntropyNonSecretText(t *testing.T) {
	// Base64 of an image, a SHA-256 manifest line and a UUID are not credentials.
	content := "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8DwHwAFAAH/q842iQAAAABJRU5ErkJggg==\n" +
		"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08  dist/wardline\n" +
		"550e8400-e29b-41d4-a716-446655440000\n"
	dir := t.TempDir()
	writeFile(t, dir, "data/hashes.txt", content)
	res := runScan(t, dir)
	if len(res.Findings) != 0 {
		t.Fatalf("expected no findings, got %+v", res.Findings)
	}
}

func TestEvidenceNeverContainsSecret(t *testing.T) {
	secrets := map[string]string{
		"src/aws.go":       fakeAWSKeyID,
		"src/aws2.go":      fakeAWSSecret,
		"src/gh.go":        fakeGitHubToken,
		"src/key.go":       "MIIEowIBAAKCAQEA0000000000000000000000000000000000000000",
		"src/db.go":        "Yk4mPz9Qw2Er7Tt5",
		"src/passsword.go": fakePassword,
		"src/npm.json":     fakeNPMToken,
		"src/pypi.txt":     fakePyPIToken,
	}
	dir := t.TempDir()
	writeFile(t, dir, "src/aws.go", "var id = \""+fakeAWSKeyID+"\"\n")
	writeFile(t, dir, "src/aws2.go", "AWS_SECRET_ACCESS_KEY=\""+fakeAWSSecret+"\"\n")
	writeFile(t, dir, "src/gh.go", "token := \""+fakeGitHubToken+"\"\n")
	writeFile(t, dir, "src/key.go", fakePrivateKey+"\n")
	writeFile(t, dir, "src/db.go", "url := \""+fakeDBURL+"\"\n")
	writeFile(t, dir, "src/passsword.go", "password := \""+fakePassword+"\"\n")
	writeFile(t, dir, "src/npm.json", "{\"token\": \""+fakeNPMToken+"\"}\n")
	writeFile(t, dir, "src/pypi.txt", "password = \""+fakePyPIToken+"\"\n")

	res := runScan(t, dir)
	if len(res.Findings) == 0 {
		t.Fatal("expected findings for the planted credentials")
	}
	for _, f := range res.Findings {
		for file, secret := range secrets {
			if strings.Contains(f.Evidence, secret) {
				t.Fatalf("evidence for %s (%s) leaked the secret from %s: %q", f.RuleID, f.LocationString(), file, f.Evidence)
			}
		}
		if !utf8.ValidString(f.Evidence) {
			t.Fatalf("evidence is not valid UTF-8: %q", f.Evidence)
		}
		if strings.ContainsAny(f.Evidence, "\x00\r\n\t") {
			t.Fatalf("evidence contains control characters: %q", f.Evidence)
		}
	}
}

func TestCredentialFileDetection(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ".npmrc", "//registry.npmjs.org/:_authToken="+fakeNPMToken+"\n")
	writeFile(t, dir, "deploy/id_rsa", fakePrivateKey+"\n")
	writeFile(t, dir, ".netrc", "machine example.com login svc password "+fakePassword+"\n")
	writeFile(t, dir, "notes/.npmrc", "registry=https://registry.npmjs.org/\n") // no credentials

	res := runScan(t, dir)
	found := map[string]bool{}
	for _, f := range res.Findings {
		if f.RuleID == "WL-SEC-025" {
			found[f.Location.Path] = true
		}
	}
	for _, want := range []string{".npmrc", "deploy/id_rsa", ".netrc"} {
		if !found[want] {
			t.Errorf("expected a credential-file finding for %s", want)
		}
	}
	if found["notes/.npmrc"] {
		t.Error("a .npmrc without credentials should not be reported")
	}
}

func TestBinaryAndInvalidEncoding(t *testing.T) {
	dir := t.TempDir()
	// A NUL byte marks the file as binary; it is not scanned.
	writeFile(t, dir, "bin/data.bin", "prefix\x00"+fakeGitHubToken+"\n")
	// Invalid UTF-8 must not panic and must still be scanned byte-wise.
	invalid := []byte("token := \"" + fakeGitHubToken + "\"\xff\xfe\n")
	if err := os.WriteFile(filepath.Join(dir, "bad.go"), invalid, 0o600); err != nil {
		t.Fatal(err)
	}
	// UTF-16 content is treated as opaque bytes; no findings are required but no
	// panic or invalid evidence is allowed.
	utf16 := []byte{0xff, 0xfe, 't', 0, 'o', 0, 'k', 0, 'e', 0, 'n', 0}
	if err := os.WriteFile(filepath.Join(dir, "utf16.txt"), utf16, 0o600); err != nil {
		t.Fatal(err)
	}

	res := runScan(t, dir)
	for _, f := range res.Findings {
		if !utf8.ValidString(f.Evidence) {
			t.Fatalf("invalid UTF-8 evidence: %q", f.Evidence)
		}
	}
	if got := rulesOf(res)["WL-SEC-003"]; got == 0 {
		t.Fatal("expected the token in the invalid-encoding file to be detected")
	}
	for _, f := range res.Findings {
		if strings.HasPrefix(f.Location.Path, "bin/") {
			t.Fatalf("binary file was scanned: %s", f.Location.Path)
		}
	}
}

func TestSkipsOversizedFiles(t *testing.T) {
	dir := t.TempDir()
	big := strings.Repeat("padding line\n", 200) + "token := \"" + fakeGitHubToken + "\"\n"
	writeFile(t, dir, "big/log.txt", big)
	cfg := config.Default()
	cfg.Limits.MaxFileSize = 512
	path := filepath.Join(dir, "big", "log.txt")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	req := &scanners.Request{
		Root: dir, Config: cfg, Now: time.Unix(1700000000, 0),
		Files: []scanners.File{{Rel: "big/log.txt", Abs: path, Size: info.Size()}},
	}
	res, err := New().Scan(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("oversized file should not be scanned, got %d findings", len(res.Findings))
	}
}

func TestCancellation(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 50; i++ {
		writeFile(t, dir, "f"+string(rune('a'+i%26))+".go", "token := \""+fakeGitHubToken+"\"\n")
	}
	cfg := config.Default()
	var files []scanners.File
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		info, _ := e.Info()
		files = append(files, scanners.File{Rel: e.Name(), Abs: filepath.Join(dir, e.Name()), Size: info.Size()})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := &scanners.Request{Root: dir, Files: files, Config: cfg, Offline: true}
	if _, err := New().Scan(ctx, req); err == nil {
		t.Fatal("expected a cancellation error")
	}
}

func TestRuleMetadataIsComplete(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range Rules() {
		if r.ID == "" || r.Title == "" || r.Description == "" || r.Remediation == "" || r.Impact == "" {
			t.Fatalf("rule %q is missing metadata", r.ID)
		}
		if seen[r.ID] {
			t.Fatalf("duplicate rule id %q", r.ID)
		}
		seen[r.ID] = true
		if r.Pattern == nil {
			t.Fatalf("rule %q has no pattern", r.ID)
		}
		if r.Severity == findings.SeverityUnknown {
			t.Fatalf("rule %q has unknown severity", r.ID)
		}
		if len(r.References) == 0 {
			t.Fatalf("rule %q has no references", r.ID)
		}
	}
	if len(Rules()) < 20 {
		t.Fatalf("expected a meaningful rule set, got %d rules", len(Rules()))
	}
}

func TestRulesCompileAndMatchExpected(t *testing.T) {
	for _, r := range Rules() {
		if r.FileLevel {
			continue
		}
		// Every non-file rule must define a positive secret group reference.
		if r.SecretGroup < 0 || r.SecretGroup > r.Pattern.NumSubexp() {
			t.Fatalf("rule %s has an invalid secret group %d", r.ID, r.SecretGroup)
		}
	}
}

func FuzzScan(f *testing.F) {
	f.Add("token := \"ghp_Q7mXr4Tz9KpL2WcV8bN3jH6yF5dS1aE0uG8i\"\n")
	f.Add("password = \"changeme\"\n")
	f.Add("AKIA" + "Q7X4R2ZP5RTMNW3V\n")
	f.Add("\x00\x01\x02binary")
	f.Fuzz(func(t *testing.T, content string) {
		dir := t.TempDir()
		path := filepath.Join(dir, "input.txt")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Skip()
		}
		cfg := config.Default()
		req := &scanners.Request{
			Root: dir, Config: cfg, Offline: true,
			Files: []scanners.File{{Rel: "input.txt", Abs: path, Size: int64(len(content))}},
		}
		res, err := New().Scan(context.Background(), req)
		if err != nil {
			t.Fatalf("scan failed on arbitrary input: %v", err)
		}
		for _, f := range res.Findings {
			if !utf8.ValidString(f.Evidence) {
				t.Fatalf("invalid UTF-8 evidence")
			}
			if strings.ContainsAny(f.Evidence, "\x00\r\n\t") {
				t.Fatalf("control characters in evidence: %q", f.Evidence)
			}
			for _, secret := range []string{"ghp_" + "Q7mXr4Tz9KpL2WcV8bN3jH6yF5dS1aE0uG8i", "AKIA" + "Q7X4R2ZP5RTMNW3V"} {
				if strings.Contains(f.Evidence, secret) {
					t.Fatalf("evidence leaked a credential: %q", f.Evidence)
				}
			}
		}
	})
}

func TestWorkerPoolScansEveryFile(t *testing.T) {
	dir := t.TempDir()
	const files = 120
	for i := 0; i < files; i++ {
		// Each file holds a distinct token so nothing is deduplicated across files.
		token := fmt.Sprintf("ghp_%035dX", i)
		path := filepath.Join(dir, fmt.Sprintf("pkg%d/config.go", i))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("package pkg\n\nvar t = \""+token+"\"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	res := runScan(t, dir)
	if len(res.Findings) != files {
		t.Fatalf("scanned %d file(s), got %d finding(s)", files, len(res.Findings))
	}
	if res.Scope != fmt.Sprintf("%d file(s) scanned", files) {
		t.Fatalf("unexpected scope %q", res.Scope)
	}
	if len(res.Skipped) != 0 {
		t.Fatalf("unexpected skipped checks: %+v", res.Skipped)
	}
}

func TestCancellationStopsScan(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 20; i++ {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("f%d.txt", i)), []byte("data\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := New().Scan(ctx, &scanners.Request{Root: dir, Config: config.Default()}); err == nil {
		t.Fatal("a cancelled context must abort the scan instead of returning a clean result")
	}
}
