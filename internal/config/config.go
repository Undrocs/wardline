// Package config loads and validates .wardline.yaml.
//
// Configuration is validated before any scanner runs. Invalid settings are
// reported as a list of concrete, actionable messages rather than a single
// generic failure.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/goccy/go-yaml"

	"github.com/Undrocs/wardline/internal/findings"
	"github.com/Undrocs/wardline/internal/security"
)

// DefaultFilename is the configuration file Wardline looks for.
const DefaultFilename = ".wardline.yaml"

// Defaults used when a setting is omitted.
const (
	DefaultMaxFileSize = 2 << 20 // 2 MiB
	DefaultMaxFiles    = 200_000
	DefaultWorkers     = 0 // resolved to NumCPU, capped
	DefaultFailOn      = "high"
	DefaultOSVEndpoint = "https://api.osv.dev"
	DefaultScanTimeout = 10 * time.Minute
	DefaultHTTPTimeout = 20 * time.Second
	DefaultFormat      = "terminal"
)

// ScannerToggles selects which scanners run.
type ScannerToggles struct {
	Secrets      bool `yaml:"secrets" json:"secrets"`
	Dependencies bool `yaml:"dependencies" json:"dependencies"`
	Workflows    bool `yaml:"workflows" json:"workflows"`
	Config       bool `yaml:"config" json:"config"`
}

// AllEnabled is the default scanner selection.
func AllEnabled() ScannerToggles {
	return ScannerToggles{Secrets: true, Dependencies: true, Workflows: true, Config: true}
}

// Any reports whether at least one scanner is enabled.
func (s ScannerToggles) Any() bool { return s.Secrets || s.Dependencies || s.Workflows || s.Config }

// Limits bounds resource use during a scan.
type Limits struct {
	MaxFileSize int64 `yaml:"maxFileSize" json:"maxFileSize"`
	MaxFiles    int   `yaml:"maxFiles" json:"maxFiles"`
	Workers     int   `yaml:"workers" json:"workers"`
}

// Network controls outbound traffic.
type Network struct {
	Enabled     bool   `yaml:"enabled" json:"enabled"`
	OSVEndpoint string `yaml:"osvEndpoint" json:"osvEndpoint"`
}

// Timeouts bounds scan duration and HTTP requests.
type Timeouts struct {
	Scan time.Duration `yaml:"-" json:"scan"`
	HTTP time.Duration `yaml:"-" json:"http"`
}

// Report holds default report settings.
type Report struct {
	Format string `yaml:"format" json:"format"`
}

// Rules customises rule behaviour.
type Rules struct {
	// Disable turns rules off by ID.
	Disable []string `yaml:"disable" json:"disable"`
	// Severity overrides the severity of specific rules by ID. Overrides are
	// recorded in reports so the deviation from the built-in rating is visible.
	Severity map[string]string `yaml:"severity" json:"severity"`
}

// Suppression silences a known finding. A reason is mandatory.
type Suppression struct {
	Rule   string `yaml:"rule" json:"rule"`
	Path   string `yaml:"path" json:"path"`
	Line   int    `yaml:"line" json:"line"`
	Reason string `yaml:"reason" json:"reason"`
	// Expires is an optional YYYY-MM-DD date. The suppression stays active
	// through that whole day (UTC) and is ignored from 00:00 UTC the next day,
	// at which point the finding re-appears and the expiry is reported.
	Expires string `yaml:"expires" json:"expires"`
}

// Config is the validated configuration used by the engine.
type Config struct {
	Version      int
	Scanners     ScannerToggles
	Exclude      []string
	Limits       Limits
	FailOn       findings.Severity
	MinSeverity  findings.Severity
	Network      Network
	Timeouts     Timeouts
	Report       Report
	Rules        Rules
	Suppressions []Suppression

	// Path is the configuration file that was loaded, empty when defaults were
	// used.
	Path string
}

// Default returns the built-in configuration.
func Default() *Config {
	return &Config{
		Version:     1,
		Scanners:    AllEnabled(),
		Limits:      Limits{MaxFileSize: DefaultMaxFileSize, MaxFiles: DefaultMaxFiles, Workers: DefaultWorkers},
		FailOn:      findings.SeverityHigh,
		MinSeverity: findings.SeverityInfo,
		Network:     Network{Enabled: true, OSVEndpoint: DefaultOSVEndpoint},
		Timeouts:    Timeouts{Scan: DefaultScanTimeout, HTTP: DefaultHTTPTimeout},
		Report:      Report{Format: DefaultFormat},
		Rules:       Rules{Severity: map[string]string{}},
	}
}

// rawConfig mirrors the on-disk schema. Durations and sizes are strings so that
// users can write "2MiB" and "10m" and receive precise error messages.
type rawConfig struct {
	Version  *int `yaml:"version"`
	Scanners *struct {
		Secrets      *bool `yaml:"secrets"`
		Dependencies *bool `yaml:"dependencies"`
		Workflows    *bool `yaml:"workflows"`
		Config       *bool `yaml:"config"`
	} `yaml:"scanners"`
	Exclude []string `yaml:"exclude"`
	Limits  *struct {
		MaxFileSize *string `yaml:"maxFileSize"`
		MaxFiles    *int    `yaml:"maxFiles"`
		Workers     *int    `yaml:"workers"`
	} `yaml:"limits"`
	Severity *struct {
		FailOn *string `yaml:"failOn"`
	} `yaml:"severity"`
	Network *struct {
		Enabled     *bool   `yaml:"enabled"`
		OSVEndpoint *string `yaml:"osvEndpoint"`
	} `yaml:"network"`
	Timeouts *struct {
		Scan *string `yaml:"scan"`
		HTTP *string `yaml:"http"`
	} `yaml:"timeouts"`
	Report *struct {
		Format      *string `yaml:"format"`
		MinSeverity *string `yaml:"minSeverity"`
	} `yaml:"report"`
	Rules *struct {
		Disable  []string          `yaml:"disable"`
		Severity map[string]string `yaml:"severity"`
	} `yaml:"rules"`
	Suppressions []struct {
		Rule    string `yaml:"rule"`
		Path    string `yaml:"path"`
		Line    int    `yaml:"line"`
		Reason  string `yaml:"reason"`
		Expires string `yaml:"expires"`
	} `yaml:"suppressions"`
}

// Load reads and validates the configuration file at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read configuration: %w", err)
	}
	cfg, err := Parse(data)
	if err != nil {
		return nil, err
	}
	cfg.Path = path
	return cfg, nil
}

// Discover looks for .wardline.yaml in root. It returns defaults when the file
// does not exist.
func Discover(root string) (*Config, error) {
	candidate := filepath.Join(root, DefaultFilename)
	info, err := os.Stat(candidate)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Default(), nil
		}
		return nil, fmt.Errorf("stat configuration: %w", err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("configuration path %s is a directory", candidate)
	}
	return Load(candidate)
}

// Parse validates configuration data. All problems are reported together.
func Parse(data []byte) (*Config, error) {
	cfg := Default()
	if len(strings.TrimSpace(string(data))) == 0 {
		return cfg, nil
	}
	var raw rawConfig
	if err := yaml.UnmarshalWithOptions(data, &raw, yaml.DisallowUnknownField()); err != nil {
		return nil, &Error{Details: []string{fmt.Sprintf("invalid YAML: %v", err)}}
	}

	var problems []string
	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }

	if raw.Version != nil {
		if *raw.Version != 1 {
			add("version: unsupported configuration version %d (expected 1)", *raw.Version)
		}
		cfg.Version = *raw.Version
	}
	if raw.Scanners != nil {
		s := cfg.Scanners
		if raw.Scanners.Secrets != nil {
			s.Secrets = *raw.Scanners.Secrets
		}
		if raw.Scanners.Dependencies != nil {
			s.Dependencies = *raw.Scanners.Dependencies
		}
		if raw.Scanners.Workflows != nil {
			s.Workflows = *raw.Scanners.Workflows
		}
		if raw.Scanners.Config != nil {
			s.Config = *raw.Scanners.Config
		}
		cfg.Scanners = s
	}
	if !cfg.Scanners.Any() {
		add("scanners: at least one scanner must be enabled")
	}
	for i, pattern := range raw.Exclude {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			add("exclude[%d]: empty pattern", i)
			continue
		}
		if strings.HasPrefix(pattern, "/") || strings.Contains(pattern, `\`) {
			add("exclude[%d]: %q must be a relative, slash-separated pattern", i, pattern)
			continue
		}
		if !security.WithinRootOnce(pattern) {
			add("exclude[%d]: %q must not contain '..'", i, pattern)
			continue
		}
		cfg.Exclude = append(cfg.Exclude, pattern)
	}
	if raw.Limits != nil {
		if raw.Limits.MaxFileSize != nil {
			size, err := ParseSize(*raw.Limits.MaxFileSize)
			if err != nil {
				add("limits.maxFileSize: %v", err)
			} else {
				cfg.Limits.MaxFileSize = size
			}
		}
		if raw.Limits.MaxFiles != nil {
			if *raw.Limits.MaxFiles < 1 {
				add("limits.maxFiles: must be at least 1")
			} else if *raw.Limits.MaxFiles > 5_000_000 {
				add("limits.maxFiles: %d is unreasonably high (max 5000000)", *raw.Limits.MaxFiles)
			} else {
				cfg.Limits.MaxFiles = *raw.Limits.MaxFiles
			}
		}
		if raw.Limits.Workers != nil {
			if *raw.Limits.Workers < 1 || *raw.Limits.Workers > 256 {
				add("limits.workers: must be between 1 and 256")
			} else {
				cfg.Limits.Workers = *raw.Limits.Workers
			}
		}
	}
	if cfg.Limits.MaxFileSize < 1024 {
		add("limits.maxFileSize: %d bytes is too small (minimum 1024)", cfg.Limits.MaxFileSize)
	}
	if raw.Severity != nil && raw.Severity.FailOn != nil {
		sev, err := findings.ParseSeverity(*raw.Severity.FailOn)
		if err != nil {
			add("severity.failOn: %v", err)
		} else if sev == findings.SeverityUnknown {
			add("severity.failOn: must be one of info, low, medium, high, critical")
		} else {
			cfg.FailOn = sev
		}
	}
	if raw.Network != nil {
		if raw.Network.Enabled != nil {
			cfg.Network.Enabled = *raw.Network.Enabled
		}
		if raw.Network.OSVEndpoint != nil {
			endpoint := strings.TrimSpace(*raw.Network.OSVEndpoint)
			if endpoint == "" {
				add("network.osvEndpoint: must not be empty")
			} else if !strings.HasPrefix(endpoint, "https://") && !strings.HasPrefix(endpoint, "http://") {
				add("network.osvEndpoint: %q must be an http(s) URL", endpoint)
			} else {
				cfg.Network.OSVEndpoint = strings.TrimRight(endpoint, "/")
			}
		}
	}
	if raw.Timeouts != nil {
		if raw.Timeouts.Scan != nil {
			d, err := ParseDuration(*raw.Timeouts.Scan)
			if err != nil {
				add("timeouts.scan: %v", err)
			} else {
				cfg.Timeouts.Scan = d
			}
		}
		if raw.Timeouts.HTTP != nil {
			d, err := ParseDuration(*raw.Timeouts.HTTP)
			if err != nil {
				add("timeouts.http: %v", err)
			} else {
				cfg.Timeouts.HTTP = d
			}
		}
	}
	if raw.Report != nil {
		if raw.Report.Format != nil {
			f := strings.ToLower(strings.TrimSpace(*raw.Report.Format))
			if !validFormat(f) {
				add("report.format: unknown format %q (valid: terminal, json, markdown, sarif)", *raw.Report.Format)
			} else {
				cfg.Report.Format = f
			}
		}
		if raw.Report.MinSeverity != nil {
			sev, err := findings.ParseSeverity(*raw.Report.MinSeverity)
			if err != nil {
				add("report.minSeverity: %v", err)
			} else {
				cfg.MinSeverity = sev
			}
		}
	}
	if raw.Rules != nil {
		for i, rule := range raw.Rules.Disable {
			rule = strings.TrimSpace(rule)
			if rule == "" {
				add("rules.disable[%d]: empty rule id", i)
				continue
			}
			cfg.Rules.Disable = append(cfg.Rules.Disable, strings.ToUpper(rule))
		}
		if raw.Rules.Severity != nil {
			for rule, value := range raw.Rules.Severity {
				sev, err := findings.ParseSeverity(value)
				if err != nil {
					add("rules.severity[%s]: %v", rule, err)
					continue
				}
				if sev == findings.SeverityUnknown {
					add("rules.severity[%s]: must be one of info, low, medium, high, critical", rule)
					continue
				}
				cfg.Rules.Severity[strings.ToUpper(strings.TrimSpace(rule))] = sev.String()
			}
		}
	}
	for i, s := range raw.Suppressions {
		prefix := fmt.Sprintf("suppressions[%d]", i)
		supp := Suppression{
			Rule:    strings.ToUpper(strings.TrimSpace(s.Rule)),
			Path:    strings.TrimSpace(s.Path),
			Line:    s.Line,
			Reason:  strings.TrimSpace(s.Reason),
			Expires: strings.TrimSpace(s.Expires),
		}
		if supp.Rule == "" {
			add("%s.rule: required", prefix)
		}
		if supp.Reason == "" {
			add("%s.reason: a written justification is required for every suppression", prefix)
		}
		if supp.Path != "" {
			if strings.HasPrefix(supp.Path, "/") || strings.Contains(supp.Path, `\`) {
				add("%s.path: must be a relative, slash-separated pattern", prefix)
			} else if !security.WithinRootOnce(supp.Path) {
				add("%s.path: must not contain '..'", prefix)
			}
		}
		if supp.Line < 0 {
			add("%s.line: must not be negative", prefix)
		}
		if supp.Expires != "" {
			if _, err := time.Parse("2006-01-02", supp.Expires); err != nil {
				add("%s.expires: must be a YYYY-MM-DD date", prefix)
			}
		}
		cfg.Suppressions = append(cfg.Suppressions, supp)
	}

	if len(problems) > 0 {
		sort.Strings(problems)
		return nil, &Error{Details: problems}
	}
	return cfg, nil
}

// Error aggregates configuration validation problems.
type Error struct {
	Details []string
}

func (e *Error) Error() string {
	if len(e.Details) == 1 {
		return e.Details[0]
	}
	return "configuration has " + strconv.Itoa(len(e.Details)) + " problems: " + strings.Join(e.Details, "; ")
}

func validFormat(f string) bool {
	switch f {
	case "terminal", "json", "markdown", "sarif":
		return true
	}
	return false
}

// ParseSize parses a byte size such as "512KiB", "2MiB", "1GB" or "1048576".
// Both binary (KiB) and decimal (kB) suffixes are accepted.
func ParseSize(s string) (int64, error) {
	v := strings.TrimSpace(s)
	if v == "" {
		return 0, errors.New("value is empty")
	}
	upper := strings.ToUpper(v)
	multipliers := []struct {
		suffix string
		factor int64
	}{
		{"KIB", 1 << 10}, {"MIB", 1 << 20}, {"GIB", 1 << 30},
		{"KB", 1000}, {"MB", 1000 * 1000}, {"GB", 1000 * 1000 * 1000},
		{"K", 1 << 10}, {"M", 1 << 20}, {"G", 1 << 30},
		{"B", 1},
	}
	for _, m := range multipliers {
		if strings.HasSuffix(upper, m.suffix) {
			number := strings.TrimSpace(strings.TrimSuffix(upper, m.suffix))
			n, err := strconv.ParseFloat(number, 64)
			if err != nil {
				return 0, fmt.Errorf("%q is not a valid size", s)
			}
			if n < 0 {
				return 0, fmt.Errorf("%q must not be negative", s)
			}
			return int64(n * float64(m.factor)), nil
		}
	}
	n, err := strconv.ParseInt(upper, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%q is not a valid size (examples: 1048576, 512KiB, 2MiB)", s)
	}
	if n < 0 {
		return 0, fmt.Errorf("%q must not be negative", s)
	}
	return n, nil
}

// ParseDuration parses a duration like "30s", "10m" or a bare number of seconds.
func ParseDuration(s string) (time.Duration, error) {
	v := strings.TrimSpace(s)
	if v == "" {
		return 0, errors.New("value is empty")
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs <= 0 {
			return 0, fmt.Errorf("%q must be positive", s)
		}
		return time.Duration(secs) * time.Second, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%q is not a valid duration (examples: 30s, 10m)", s)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%q must be positive", s)
	}
	return d, nil
}

// RuleDisabled reports whether a rule id is disabled by configuration.
func (c *Config) RuleDisabled(ruleID string) bool {
	for _, r := range c.Rules.Disable {
		if r == ruleID {
			return true
		}
	}
	return false
}

// SeverityOverride returns the configured severity for a rule, if any.
func (c *Config) SeverityOverride(ruleID string) (findings.Severity, bool) {
	value, ok := c.Rules.Severity[ruleID]
	if !ok {
		return findings.SeverityUnknown, false
	}
	sev, err := findings.ParseSeverity(value)
	if err != nil {
		return findings.SeverityUnknown, false
	}
	return sev, true
}
