package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Undrocs/wardline/internal/findings"
)

const fullConfig = `
version: 1
scanners:
  secrets: true
  dependencies: false
  workflows: true
  config: true
exclude:
  - "testdata/**"
  - "**/*.min.js"
limits:
  maxFileSize: 3MiB
  maxFiles: 5000
  workers: 4
severity:
  failOn: critical
network:
  enabled: false
  osvEndpoint: https://osv.example.internal
timeouts:
  scan: 90s
  http: 10s
report:
  format: json
  minSeverity: medium
rules:
  disable: [WL-WF002]
  severity:
    WL-WF004: low
suppressions:
  - rule: WL-WF002
    path: ".github/workflows/*.yml"
    reason: "Repository default is read-only; verified by the platform team."
  - rule: WL-DEP-001
    reason: "Accepted until the next major release."
    expires: 2027-01-31
`

func TestRuleIdentifiersAreCaseInsensitive(t *testing.T) {
	// A lowercase rule id in configuration must still disable the rule: a silent
	// miss would leave a finding the operator believed was handled.
	cfg, err := Parse([]byte(`rules:
  disable: [wl-wf002]
  severity:
    wl-cfg-007: low
suppressions:
  - rule: wl-sec-008
    reason: "Test keys are never live keys."
`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.RuleDisabled("WL-WF002") {
		t.Error("lowercase rule id did not disable the rule")
	}
	if sev, ok := cfg.SeverityOverride("WL-CFG-007"); !ok || sev != findings.SeverityLow {
		t.Errorf("lowercase severity override not applied: %v %v", sev, ok)
	}
	if cfg.Suppressions[0].Rule != "WL-SEC-008" {
		t.Errorf("suppression rule id not normalised: %q", cfg.Suppressions[0].Rule)
	}
}

func TestInvalidMaxFileSizeIsReported(t *testing.T) {
	if _, err := Parse([]byte("limits:\n  maxFileSize: lots\n")); err == nil {
		t.Fatal("expected an error for an unparseable size")
	}
	if _, err := Parse([]byte("limits:\n  maxFileSize: 10B\n")); err == nil {
		t.Fatal("expected an error for a size below the 1 KiB minimum")
	}
}

func TestParseFullConfig(t *testing.T) {
	cfg, err := Parse([]byte(fullConfig))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Scanners.Dependencies {
		t.Error("dependencies scanner should be disabled")
	}
	if len(cfg.Exclude) != 2 {
		t.Errorf("unexpected exclude list: %v", cfg.Exclude)
	}
	if cfg.Limits.MaxFileSize != 3<<20 {
		t.Errorf("maxFileSize = %d", cfg.Limits.MaxFileSize)
	}
	if cfg.Limits.Workers != 4 || cfg.Limits.MaxFiles != 5000 {
		t.Errorf("unexpected limits: %+v", cfg.Limits)
	}
	if cfg.FailOn != findings.SeverityCritical {
		t.Errorf("failOn = %v", cfg.FailOn)
	}
	if cfg.Network.Enabled {
		t.Error("network should be disabled")
	}
	if cfg.Timeouts.Scan.Seconds() != 90 || cfg.Timeouts.HTTP.Seconds() != 10 {
		t.Errorf("unexpected timeouts: %+v", cfg.Timeouts)
	}
	if cfg.Report.Format != "json" || cfg.MinSeverity != findings.SeverityMedium {
		t.Errorf("unexpected report settings: %+v min=%v", cfg.Report, cfg.MinSeverity)
	}
	if !cfg.RuleDisabled("WL-WF002") {
		t.Error("WL-WF002 should be disabled")
	}
	if sev, ok := cfg.SeverityOverride("WL-WF004"); !ok || sev != findings.SeverityLow {
		t.Errorf("severity override not applied: %v %v", sev, ok)
	}
	if len(cfg.Suppressions) != 2 {
		t.Fatalf("unexpected suppressions: %+v", cfg.Suppressions)
	}
	if cfg.Suppressions[1].Expires != "2027-01-31" {
		t.Errorf("expiry not parsed: %+v", cfg.Suppressions[1])
	}
}

func TestParseDefaults(t *testing.T) {
	cfg, err := Parse(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.FailOn != findings.SeverityHigh {
		t.Errorf("unexpected default failOn: %v", cfg.FailOn)
	}
	if cfg.Limits.MaxFileSize != DefaultMaxFileSize {
		t.Errorf("unexpected default maxFileSize: %d", cfg.Limits.MaxFileSize)
	}
	if !cfg.Network.Enabled || cfg.Network.OSVEndpoint != DefaultOSVEndpoint {
		t.Errorf("unexpected default network settings: %+v", cfg.Network)
	}
	if cfg.Report.Format != DefaultFormat {
		t.Errorf("unexpected default format: %s", cfg.Report.Format)
	}
}

func TestParseRejectsInvalidSettings(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{"unknown field", "unknownSetting: true", "invalid YAML"},
		{"bad version", "version: 99", "unsupported configuration version"},
		{"all scanners disabled", "scanners:\n  secrets: false\n  dependencies: false\n  workflows: false\n  config: false", "at least one scanner"},
		{"bad severity", "severity:\n  failOn: urgent", "severity.failOn"},
		{"unknown failOn", "severity:\n  failOn: unknown", "must be one of"},
		{"bad size", "limits:\n  maxFileSize: huge", "limits.maxFileSize"},
		{"tiny size", "limits:\n  maxFileSize: 10", "too small"},
		{"bad workers", "limits:\n  workers: 0", "limits.workers"},
		{"bad timeout", "timeouts:\n  scan: soon", "timeouts.scan"},
		{"bad format", "report:\n  format: xml", "report.format"},
		{"bad min severity", "report:\n  minSeverity: meh", "report.minSeverity"},
		{"suppression without reason", "suppressions:\n  - rule: WL-WF002", "reason"},
		{"suppression without rule", "suppressions:\n  - reason: why", "rule"},
		{"bad expiry", "suppressions:\n  - rule: X\n    reason: y\n    expires: soon", "YYYY-MM-DD"},
		{"absolute exclude", "exclude:\n  - /etc/passwd", "relative"},
		{"traversal exclude", "exclude:\n  - ../secrets", "must not contain"},
		{"bad endpoint", "network:\n  osvEndpoint: ftp://example.com", "http(s)"},
		{"bad rule severity", "rules:\n  severity:\n    WL-WF004: nope", "rules.severity"},
		{"empty disable", "rules:\n  disable: ['']", "empty rule id"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Parse([]byte(c.yaml))
			if err == nil {
				t.Fatalf("expected an error for %s", c.name)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %q does not mention %q", err.Error(), c.want)
			}
		})
	}
}

func TestParseReportsAllProblems(t *testing.T) {
	data := `
version: 7
severity:
  failOn: nope
limits:
  workers: -1
`
	_, err := Parse([]byte(data))
	if err == nil {
		t.Fatal("expected an error")
	}
	cfgErr, ok := err.(*Error)
	if !ok {
		t.Fatalf("expected *config.Error, got %T", err)
	}
	if len(cfgErr.Details) < 3 {
		t.Fatalf("expected all problems to be reported, got %v", cfgErr.Details)
	}
}

func TestParseSize(t *testing.T) {
	cases := map[string]int64{
		"1024":     1024,
		"1KiB":     1024,
		"2MiB":     2 << 20,
		"1.5MiB":   3 << 19,
		"1GB":      1_000_000_000,
		"512k":     512 << 10,
		"100B":     100,
		" 4 MiB  ": 4 << 20,
	}
	for input, want := range cases {
		got, err := ParseSize(input)
		if err != nil {
			t.Fatalf("ParseSize(%q): %v", input, err)
		}
		if got != want {
			t.Fatalf("ParseSize(%q) = %d, want %d", input, got, want)
		}
	}
	for _, bad := range []string{"", "-1", "lots", "1XiB"} {
		if _, err := ParseSize(bad); err == nil {
			t.Errorf("expected an error for %q", bad)
		}
	}
}

func TestParseDuration(t *testing.T) {
	d, err := ParseDuration("90")
	if err != nil || d.Seconds() != 90 {
		t.Fatalf("numeric seconds failed: %v %v", d, err)
	}
	d, err = ParseDuration("2m30s")
	if err != nil || d.Seconds() != 150 {
		t.Fatalf("duration parsing failed: %v %v", d, err)
	}
	for _, bad := range []string{"", "0", "-5s", "soon"} {
		if _, err := ParseDuration(bad); err == nil {
			t.Errorf("expected an error for %q", bad)
		}
	}
}

func TestLoadAndDiscover(t *testing.T) {
	dir := t.TempDir()
	if _, err := Discover(dir); err != nil {
		t.Fatalf("discover without a file should return defaults: %v", err)
	}
	cfg, err := Discover(dir)
	if err != nil || cfg.Path != "" {
		t.Fatalf("expected built-in defaults, got %+v %v", cfg, err)
	}
	path := filepath.Join(dir, DefaultFilename)
	if err := os.WriteFile(path, []byte("severity:\n  failOn: low\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err = Discover(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.FailOn != findings.SeverityLow || cfg.Path != path {
		t.Fatalf("unexpected config: %+v", cfg)
	}
	if _, err := Load(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Fatal("expected an error for a missing file")
	}
	// A directory in place of a configuration file must not be read.
	sub := filepath.Join(dir, "asdir")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(sub); err == nil {
		t.Fatal("expected an error when the configuration path is a directory")
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte("version: 1\n"))
	f.Add([]byte("scanners:\n  secrets: true\n"))
	f.Add([]byte("suppressions:\n  - rule: a\n    reason: b\n"))
	f.Add([]byte("\x00\xff\xfe"))
	f.Fuzz(func(t *testing.T, data []byte) {
		// Parsing untrusted configuration must never panic.
		_, _ = Parse(data)
	})
}
