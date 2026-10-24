// Package reports converts an engine result into the four supported output
// formats: terminal, JSON, Markdown and SARIF 2.1.0.
//
// All writers share one report model so counts, suppressions and scanner status
// stay consistent between formats. Evidence has already been redacted by the
// scanners; report writers never handle raw credential values.
package reports

import (
	"fmt"
	"time"

	"github.com/Undrocs/wardline/internal/config"
	"github.com/Undrocs/wardline/internal/engine"
	"github.com/Undrocs/wardline/internal/findings"
	"github.com/Undrocs/wardline/internal/scanners"
	"github.com/Undrocs/wardline/internal/version"
)

// SchemaVersion is the version of Wardline's JSON report document.
const SchemaVersion = "1.0"

// Tool describes the producing binary.
type Tool struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"buildDate"`
	GoVersion string `json:"goVersion"`
	Platform  string `json:"platform"`
}

// ScanInfo describes what was scanned and how.
type ScanInfo struct {
	Target     string `json:"target"`
	Mode       string `json:"mode"`
	StartedAt  string `json:"startedAt"`
	FinishedAt string `json:"finishedAt"`
	DurationMS int64  `json:"durationMs"`
	Files      int    `json:"files"`
	Bytes      int64  `json:"bytes"`
	Offline    bool   `json:"offline"`
	ConfigFile string `json:"configFile,omitempty"`
}

// NetworkInfo records outbound traffic in an auditable way.
type NetworkInfo struct {
	Enabled      bool     `json:"enabled"`
	Destinations []string `json:"destinations"`
	Disclosure   string   `json:"disclosure"`
}

// Policy records the evaluated failure threshold.
type Policy struct {
	FailOn string `json:"failOn"`
	Failed bool   `json:"failed"`
	// Reason explains the outcome in one sentence.
	Reason string `json:"reason"`
}

// Summary aggregates counts and completeness indicators.
type Summary struct {
	Total            int             `json:"total"`
	Counts           findings.Counts `json:"counts"`
	Suppressed       int             `json:"suppressed"`
	SuppressedCounts findings.Counts `json:"suppressedCounts"`
	ScannersRan      int             `json:"scannersRan"`
	ScannersPartial  int             `json:"scannersPartial"`
	ScannersSkipped  int             `json:"scannersSkipped"`
	ScannersFailed   int             `json:"scannersFailed"`
	// Incomplete is true when any scanner failed, was skipped or reported
	// skipped checks. Clean results from an incomplete scan must not be read as
	// a clean bill of health.
	Incomplete bool   `json:"incomplete"`
	Policy     Policy `json:"policy"`
}

// Report is the normalised, serialisable scan report.
type Report struct {
	SchemaVersion string              `json:"schemaVersion"`
	Tool          Tool                `json:"tool"`
	Scan          ScanInfo            `json:"scan"`
	Network       NetworkInfo         `json:"network"`
	Scanners      []engine.ScannerRun `json:"scanners"`
	Findings      []findings.Finding  `json:"findings"`
	Summary       Summary             `json:"summary"`
	Warnings      []string            `json:"warnings,omitempty"`
	Errors        []string            `json:"errors,omitempty"`
	// Limitations lists scan-level caveats that readers must not ignore.
	Limitations []string `json:"limitations"`
}

// Options controls report construction.
type Options struct {
	// MinSeverity filters reported findings. Suppressed findings are always
	// included, marked as suppressed, so audits remain traceable.
	MinSeverity findings.Severity
	// MinConfidence hides findings below this confidence. Like MinSeverity it
	// is a reporting filter only: the policy threshold is always evaluated over
	// every unsuppressed finding.
	MinConfidence findings.Confidence
	// FailOn is the severity threshold that fails the scan.
	FailOn findings.Severity
	// Version is the binary metadata.
	Version version.Info
}

// Limitations that apply to every scan, independent of findings.
func baseLimitations() []string {
	return []string{
		"Wardline scans the working tree only. It does not read Git history, so credentials removed from files but present in earlier commits are not detected.",
		"Detection is pattern and rule based. A clean report does not prove that a repository is free of vulnerabilities.",
		"Severity and confidence are Wardline's own assessments unless a finding cites an advisory rating; they are not official CVSS scores.",
	}
}

// Build assembles a report from an engine result.
func Build(res *engine.Result, cfg *config.Config, opts Options) *Report {
	if res == nil {
		return nil
	}
	rep := &Report{
		SchemaVersion: SchemaVersion,
		Tool: Tool{
			Name:      opts.Version.Name,
			Version:   opts.Version.Version,
			Commit:    opts.Version.Commit,
			BuildDate: opts.Version.BuildDate,
			GoVersion: opts.Version.GoVersion,
			Platform:  opts.Version.Platform,
		},
		Scan: ScanInfo{
			Target:     res.Target,
			Mode:       res.Mode,
			StartedAt:  res.StartedAt.Format(time.RFC3339),
			FinishedAt: res.FinishedAt.Format(time.RFC3339),
			DurationMS: res.Duration().Milliseconds(),
			Files:      res.FileCount,
			Bytes:      res.Bytes,
			Offline:    res.Offline,
			ConfigFile: res.ConfigPath,
		},
		Scanners:    res.Scanners,
		Warnings:    res.Warnings,
		Errors:      res.Errors,
		Limitations: baseLimitations(),
	}

	networkEnabled := false
	if cfg != nil {
		networkEnabled = cfg.Network.Enabled && !res.Offline
	}
	rep.Network = NetworkInfo{
		Enabled:      networkEnabled,
		Destinations: res.Network,
		Disclosure: "When dependency scanning runs online, only package coordinates (ecosystem, name, resolved version) are sent to the OSV.dev API. " +
			"File contents, source code and discovered secrets are never transmitted.",
	}
	if rep.Network.Destinations == nil {
		rep.Network.Destinations = []string{}
	}

	var suppressedCounts findings.Counts
	suppressed := 0
	visible := make([]findings.Finding, 0, len(res.Findings))
	for _, f := range res.Findings {
		if f.Suppressed {
			suppressed++
			suppressedCounts.Add(f.Severity)
			visible = append(visible, f)
			continue
		}
		if !passesThreshold(f.Severity, opts.MinSeverity) {
			continue
		}
		if opts.MinConfidence != "" && f.Confidence.Rank() < opts.MinConfidence.Rank() {
			continue
		}
		visible = append(visible, f)
	}
	rep.Findings = visible
	if rep.Findings == nil {
		rep.Findings = []findings.Finding{}
	}

	var counts findings.Counts
	for _, f := range rep.Findings {
		if f.Suppressed {
			continue
		}
		counts.Add(f.Severity)
	}
	rep.Summary = Summary{
		Total:            counts.Total(),
		Counts:           counts,
		Suppressed:       suppressed,
		SuppressedCounts: suppressedCounts,
		Policy:           evaluatePolicy(res.Findings, opts.FailOn),
	}
	for _, run := range res.Scanners {
		switch run.Status {
		case scanners.StatusRan:
			rep.Summary.ScannersRan++
		case scanners.StatusPartial:
			rep.Summary.ScannersPartial++
		case scanners.StatusSkipped:
			rep.Summary.ScannersSkipped++
		case scanners.StatusFailed:
			rep.Summary.ScannersFailed++
		}
	}
	rep.Summary.Incomplete = res.PartialCoverage || len(res.Errors) > 0 ||
		rep.Summary.ScannersPartial > 0 || rep.Summary.ScannersSkipped > 0 ||
		rep.Summary.ScannersFailed > 0
	return rep
}

// partitionSuppressed splits findings into the ones that are still live and the
// ones a suppression in the configuration matched, preserving input order. Both
// renderers print the suppressed group separately, so the split lives here
// rather than being re-implemented per format.
func partitionSuppressed(in []findings.Finding) (live, suppressed []findings.Finding) {
	for _, f := range in {
		if f.Suppressed {
			suppressed = append(suppressed, f)
			continue
		}
		live = append(live, f)
	}
	return live, suppressed
}

// evaluatePolicy applies the failure threshold to all unsuppressed findings,
// regardless of any reporting filter.
func evaluatePolicy(all []findings.Finding, failOn findings.Severity) Policy {
	policy := Policy{FailOn: failOn.String()}
	if failOn == findings.SeverityUnknown {
		policy.Reason = "no failure threshold configured"
		return policy
	}
	count := 0
	for _, f := range all {
		if f.Suppressed {
			continue
		}
		if f.Severity.AtLeast(failOn) {
			count++
		}
	}
	if count > 0 {
		policy.Failed = true
		policy.Reason = fmt.Sprintf("%d finding(s) at or above %s", count, failOn)
		return policy
	}
	policy.Reason = fmt.Sprintf("no findings at or above %s", failOn)
	return policy
}

// passesThreshold reports whether a severity is at or above the reporting
// threshold. Unknown severity is reported only when the threshold includes
// informational output, because it cannot be ordered against real ratings.
func passesThreshold(sev, min findings.Severity) bool {
	if min == findings.SeverityUnknown || min == findings.SeverityInfo {
		return true
	}
	if sev == findings.SeverityUnknown {
		return false
	}
	return sev.AtLeast(min)
}
