package cli

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Undrocs/wardline/internal/config"
	"github.com/Undrocs/wardline/internal/findings"
)

// strictFailOnFloor is the weakest threshold strict mode accepts. A repository
// may raise the bar (fail on a lower severity) but never lower it.
var strictFailOnFloor = findings.SeverityHigh

// applyStrictPolicy removes, and reports, every security-relevant setting that
// came from the scanned repository's configuration.
//
// The configuration file is untrusted input: it lives in the repository under
// audit, so anyone who can open a pull request can edit it. Strict mode is for
// automated gates, where the enforcement policy has to come from the pipeline
// rather than from the code being scanned. Settings that only make a scan
// cheaper or narrower in a harmless direction (a smaller file size limit, a
// longer timeout) are kept; settings that could hide risk are reset.
func applyStrictPolicy(cfg *config.Config, opts scanOptions) []string {
	var notices []string
	add := func(format string, args ...any) { notices = append(notices, fmt.Sprintf(format, args...)) }

	// Scanner selection: a repository must not be able to switch off a check.
	if !cfg.Scanners.Any() || cfg.Scanners != config.AllEnabled() {
		var disabled []string
		for _, s := range []struct {
			name    string
			enabled bool
		}{
			{findings.ScannerSecrets, cfg.Scanners.Secrets},
			{findings.ScannerDependencies, cfg.Scanners.Dependencies},
			{findings.ScannerWorkflows, cfg.Scanners.Workflows},
			{findings.ScannerConfig, cfg.Scanners.Config},
		} {
			if !s.enabled {
				disabled = append(disabled, s.name)
			}
		}
		if len(disabled) > 0 {
			add("strict: ignored scanners.%s=false from configuration; all scanners run", strings.Join(disabled, ", "))
			cfg.Scanners = config.AllEnabled()
		}
	}

	// Rule tuning: disabling a rule or lowering its severity hides a finding.
	if len(cfg.Rules.Disable) > 0 {
		ids := append([]string(nil), cfg.Rules.Disable...)
		sort.Strings(ids)
		add("strict: ignored rules.disable for %s", strings.Join(ids, ", "))
		cfg.Rules.Disable = nil
	}
	if len(cfg.Rules.Severity) > 0 {
		ids := make([]string, 0, len(cfg.Rules.Severity))
		for id := range cfg.Rules.Severity {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		add("strict: ignored rules.severity overrides for %s", strings.Join(ids, ", "))
		cfg.Rules.Severity = map[string]string{}
	}

	// Suppressions: a justification in the repository under audit cannot waive a
	// finding for a pipeline that does not trust that repository.
	if len(cfg.Suppressions) > 0 {
		add("strict: ignored %d suppression(s) from configuration; suppressed findings are reported", len(cfg.Suppressions))
		cfg.Suppressions = nil
	}

	// Exclusions: `exclude: ["**"]` would hide the entire repository.
	if len(cfg.Exclude) > 0 {
		add("strict: ignored %d exclude pattern(s) from configuration; use --exclude to narrow this scan", len(cfg.Exclude))
		cfg.Exclude = nil
	}

	// Policy threshold: the strongest of the CLI value and the floor wins.
	floor := strictFailOnFloor
	if opts.FailOn != "" {
		if sev, err := findings.ParseSeverity(opts.FailOn); err == nil && sev != findings.SeverityUnknown {
			floor = sev
		}
	}
	if cfg.FailOn.Rank() > floor.Rank() {
		add("strict: raised severity.failOn from %s to %s", cfg.FailOn, floor)
		cfg.FailOn = floor
	}

	// Reporting: raising minSeverity hides findings from the report.
	if cfg.MinSeverity.Rank() > findings.SeverityInfo.Rank() {
		add("strict: reset report.minSeverity from %s to info", cfg.MinSeverity)
		cfg.MinSeverity = findings.SeverityInfo
	}

	// Resource limits: a repository may ask for less, never for more.
	if cfg.Limits.MaxFileSize > config.DefaultMaxFileSize {
		add("strict: capped limits.maxFileSize at %d bytes", config.DefaultMaxFileSize)
		cfg.Limits.MaxFileSize = config.DefaultMaxFileSize
	}
	if cfg.Limits.MaxFiles > config.DefaultMaxFiles {
		add("strict: capped limits.maxFiles at %d", config.DefaultMaxFiles)
		cfg.Limits.MaxFiles = config.DefaultMaxFiles
	}

	// Network: turning the dependency lookup off skips vulnerability checks.
	if !cfg.Network.Enabled && !opts.Offline {
		add("strict: ignored network.enabled=false from configuration; dependency checks run")
		cfg.Network.Enabled = true
	}

	// A custom endpoint is refused outright in strict mode: the pipeline did not
	// approve it by definition, since only the command line can.
	if !isOfficialEndpoint(cfg.Network.OSVEndpoint) {
		add("strict: ignored network.osvEndpoint from configuration; using the official OSV endpoint")
		cfg.Network.OSVEndpoint = config.DefaultOSVEndpoint
	}

	if len(notices) > 0 {
		sort.Strings(notices)
	}
	return notices
}

// isOfficialEndpoint reports whether the endpoint is the built-in one. It is a
// thin wrapper so the strict policy reads without importing netguard concepts.
func isOfficialEndpoint(endpoint string) bool {
	trimmed := strings.TrimRight(strings.ToLower(strings.TrimSpace(endpoint)), "/")
	return trimmed == "" || trimmed == strings.TrimRight(strings.ToLower(config.DefaultOSVEndpoint), "/")
}
