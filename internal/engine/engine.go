// Package engine orchestrates a Wardline scan: it discovers files, runs the
// enabled scanners with bounded concurrency and timeouts, isolates failures,
// applies configuration (rule overrides and suppressions) and produces a single
// normalised result.
package engine

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Undrocs/wardline/internal/config"
	"github.com/Undrocs/wardline/internal/findings"
	"github.com/Undrocs/wardline/internal/scanners"
)

// ModeWorkingTree documents that Wardline scans files as they exist on disk and
// never reads Git history or object storage.
const ModeWorkingTree = "working-tree"

// Options configures a scan.
type Options struct {
	// Target is the directory to scan, as supplied by the user.
	Target string
	// Config is the validated configuration.
	Config *config.Config
	// Offline disables network-dependent checks.
	Offline bool
	// Logf receives verbose diagnostics.
	Logf func(format string, args ...any)
	// Scanners is the set of scanners available to the engine. The CLI supplies
	// them so the engine stays independent of individual modules.
	Scanners []scanners.Scanner
	// HTTPClient is forwarded to network-capable scanners.
	HTTPClient *http.Client
	// DisabledScanners lists scanner names that were not selected. They are
	// reported as disabled rather than omitted, so a report always states which
	// checks did not run.
	DisabledScanners []string
	// Now is injectable for deterministic tests.
	Now func() time.Time
}

// ScannerRun records the outcome of one scanner.
type ScannerRun struct {
	Name       string                  `json:"name"`
	Status     scanners.Status         `json:"status"`
	Scope      string                  `json:"scope,omitempty"`
	Findings   int                     `json:"findings"`
	Counts     findings.Counts         `json:"counts"`
	DurationMS int64                   `json:"durationMs"`
	Skipped    []scanners.SkippedCheck `json:"skipped,omitempty"`
	Notes      []string                `json:"notes,omitempty"`
	Warnings   []string                `json:"warnings,omitempty"`
	Error      string                  `json:"error,omitempty"`
	// Disabled is true when the scanner was not selected at all, either by the
	// command line or by configuration. A disabled scanner is listed in the
	// report instead of disappearing from it.
	Disabled bool `json:"disabled,omitempty"`
}

// Result is the complete output of a scan.
type Result struct {
	Target     string
	Root       string
	Mode       string
	StartedAt  time.Time
	FinishedAt time.Time
	Offline    bool
	ConfigPath string
	FileCount  int
	Bytes      int64
	Scanners   []ScannerRun
	Findings   []findings.Finding
	Network    []string
	Warnings   []string
	// Errors holds scanner failures and operational problems. Any error means
	// the scan is incomplete and must not be reported as clean.
	Errors []string
	// PartialCoverage is true when files or directories were skipped for a
	// reason other than the documented exclusion rules (oversized files, deep
	// nesting, unreadable paths). The scan still produced results, but part of
	// the repository was never examined.
	PartialCoverage bool
}

// Duration returns the wall-clock duration of the scan.
func (r *Result) Duration() time.Duration {
	if r.StartedAt.IsZero() || r.FinishedAt.IsZero() {
		return 0
	}
	return r.FinishedAt.Sub(r.StartedAt)
}

// Failed reports whether any scanner or the traversal failed.
func (r *Result) Failed() bool { return len(r.Errors) > 0 }

// Counts returns counts of non-suppressed findings.
func (r *Result) Counts() findings.Counts { return findings.Count(r.Findings, false) }

// Run executes a scan.
func Run(ctx context.Context, opts Options) (*Result, error) {
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	cfg := opts.Config
	if cfg == nil {
		return nil, errors.New("engine: configuration is required")
	}
	root, err := filepath.Abs(opts.Target)
	if err != nil {
		return nil, fmt.Errorf("resolve target: %w", err)
	}
	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("target %q: %w", opts.Target, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("target %q is not a directory", opts.Target)
	}

	res := &Result{
		Target:     opts.Target,
		Root:       root,
		Mode:       ModeWorkingTree,
		StartedAt:  now().UTC(),
		Offline:    opts.Offline,
		ConfigPath: relativeToRoot(root, cfg.Path),
	}

	files, stats, err := collectFiles(ctx, root, cfg)
	if err != nil {
		return nil, fmt.Errorf("traverse %q: %w", opts.Target, err)
	}
	res.FileCount = len(files)
	res.Bytes = stats.Bytes
	if stats.Symlinks > 0 {
		res.Warnings = append(res.Warnings, fmt.Sprintf("skipped %d symbolic link(s); links are never followed", stats.Symlinks))
	}
	if stats.SkippedLarge > 0 {
		res.PartialCoverage = true
		res.Warnings = append(res.Warnings, fmt.Sprintf("skipped %d file(s) larger than %d bytes", stats.SkippedLarge, cfg.Limits.MaxFileSize))
	}
	if stats.SkippedDeep > 0 {
		res.PartialCoverage = true
		res.Warnings = append(res.Warnings, fmt.Sprintf("skipped %d directories nested deeper than %d levels; their contents were not scanned", stats.SkippedDeep, maxWalkDepth))
	}
	if stats.Irregular > 0 {
		res.PartialCoverage = true
		res.Warnings = append(res.Warnings, fmt.Sprintf("skipped %d unreadable or irregular path(s)", stats.Irregular))
	}

	req := &scanners.Request{
		Root:       root,
		Files:      files,
		Config:     cfg,
		Offline:    opts.Offline,
		Now:        res.StartedAt,
		Logf:       opts.Logf,
		HTTPClient: opts.HTTPClient,
	}

	outcomes := runScanners(ctx, opts.Scanners, req)

	var all []findings.Finding
	for _, out := range outcomes {
		all = append(all, out.findings...)
		res.Network = append(res.Network, out.network...)
		res.Warnings = append(res.Warnings, out.Warnings...)
		if out.Error != "" {
			res.Errors = append(res.Errors, fmt.Sprintf("%s scanner: %s", out.Name, out.Error))
		}
	}

	all = applyRuleSettings(all, cfg, &res.Warnings)
	all = applySuppressions(all, cfg, res.StartedAt, &res.Warnings)
	relativizeFindings(root, all)
	all = findings.Dedupe(all)
	findings.Sort(all)
	res.Findings = all

	runs := make([]ScannerRun, 0, len(outcomes)+len(opts.DisabledScanners))
	for _, name := range opts.DisabledScanners {
		runs = append(runs, ScannerRun{
			Name:     name,
			Status:   scanners.StatusSkipped,
			Disabled: true,
			Skipped: []scanners.SkippedCheck{{
				Check:  name + " scanner",
				Reason: "not selected: the scanner is disabled by configuration or was not requested",
			}},
		})
	}
	for _, out := range outcomes {
		run := out.ScannerRun
		counts := findings.Counts{}
		for _, f := range all {
			if f.Scanner == run.Name && !f.Suppressed {
				counts.Add(f.Severity)
			}
		}
		run.Counts = counts
		run.Findings = counts.Total()
		runs = append(runs, run)
	}
	sort.SliceStable(runs, func(i, j int) bool { return runs[i].Name < runs[j].Name })
	res.Scanners = runs
	res.Network = dedupeStrings(res.Network)
	res.FinishedAt = now().UTC()
	return res, nil
}

type runOutcome struct {
	ScannerRun
	findings []findings.Finding
	network  []string
}

// runScanners executes the scanners concurrently. They are independent: each
// reads the file list, keeps its own state and returns its own result, so the
// only shared work is the network wait in the dependency scanner, which is why
// running them together shortens wall-clock time. Results are written by index,
// making the outcome independent of completion order.
func runScanners(ctx context.Context, list []scanners.Scanner, req *scanners.Request) []runOutcome {
	out := make([]runOutcome, len(list))
	var wg sync.WaitGroup
	for i, sc := range list {
		wg.Add(1)
		go func(i int, sc scanners.Scanner) {
			defer wg.Done()
			out[i] = runOne(ctx, sc, req)
		}(i, sc)
	}
	wg.Wait()
	return out
}

func runOne(ctx context.Context, sc scanners.Scanner, req *scanners.Request) (out runOutcome) {
	start := time.Now()
	out.Name = sc.Name()
	defer func() {
		out.DurationMS = time.Since(start).Milliseconds()
		if rec := recover(); rec != nil {
			out.Status = scanners.StatusFailed
			out.Error = fmt.Sprintf("panic: %v", rec)
			out.findings = nil
			out.Notes = append(out.Notes, "scanner crashed; it produced no results")
		}
		if out.Status == "" {
			switch {
			case out.Error != "":
				out.Status = scanners.StatusFailed
			case len(out.Skipped) > 0:
				out.Status = scanners.StatusPartial
			default:
				out.Status = scanners.StatusRan
			}
		}
	}()
	if ctx.Err() != nil {
		out.Status = scanners.StatusFailed
		out.Error = "scan cancelled before the scanner started"
		return out
	}
	res, err := sc.Scan(ctx, req)
	if err != nil {
		out.Status = scanners.StatusFailed
		if ctx.Err() != nil {
			out.Error = fmt.Sprintf("scan cancelled: %v", ctx.Err())
		} else {
			out.Error = err.Error()
		}
		return out
	}
	if res == nil {
		out.Status = scanners.StatusFailed
		out.Error = "scanner returned no result"
		return out
	}
	out.Scope = res.Scope
	out.Skipped = res.Skipped
	out.Notes = res.Notes
	out.Warnings = res.Warnings
	out.network = res.Network
	out.findings = res.Findings
	return out
}

// relativizeFindings guarantees that no finding carries an absolute filesystem
// path into a report. The engine already hands scanners relative paths, so this
// is a safety net for a scanner that builds its own location.
func relativizeFindings(root string, all []findings.Finding) {
	for i := range all {
		path := all[i].Location.Path
		if path == "" || !filepath.IsAbs(path) {
			continue
		}
		if rel, err := filepath.Rel(root, path); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			all[i].Location.Path = filepath.ToSlash(rel)
			continue
		}
		all[i].Location.Path = filepath.Base(path)
	}
}

// applyRuleSettings applies rules.disable and rules.severity from configuration.
func applyRuleSettings(in []findings.Finding, cfg *config.Config, warnings *[]string) []findings.Finding {
	if len(cfg.Rules.Disable) == 0 && len(cfg.Rules.Severity) == 0 {
		return in
	}
	overridden := map[string]string{}
	// A fresh slice keeps the caller's findings untouched; the engine owns the
	// backing array today, but aliasing it here would break any caller that
	// keeps a reference to the unfiltered slice.
	out := make([]findings.Finding, 0, len(in))
	for _, f := range in {
		if cfg.RuleDisabled(f.RuleID) {
			continue
		}
		if sev, ok := cfg.SeverityOverride(f.RuleID); ok && sev != f.Severity {
			overridden[f.RuleID] = fmt.Sprintf("%s: severity overridden by configuration (%s -> %s)", f.RuleID, f.Severity, sev)
			f.Severity = sev
		}
		out = append(out, f)
	}
	keys := make([]string, 0, len(overridden))
	for k := range overridden {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		*warnings = append(*warnings, overridden[k])
	}
	return out
}

// applySuppressions marks matching findings as suppressed. Expired suppressions
// do not apply and are reported, so stale exceptions cannot silently hide risk.
func applySuppressions(in []findings.Finding, cfg *config.Config, now time.Time, warnings *[]string) []findings.Finding {
	if len(cfg.Suppressions) == 0 {
		return in
	}
	active := make([]config.Suppression, 0, len(cfg.Suppressions))
	for _, s := range cfg.Suppressions {
		if s.Expires != "" {
			expiry, err := time.Parse("2006-01-02", s.Expires)
			// A suppression stays valid through the whole stated day, so it
			// expires at 00:00 UTC on the following day. Config validation
			// rejects unparseable dates; if one slips through, treat the
			// suppression as expired rather than letting it apply silently.
			if err != nil || !now.Before(expiry.AddDate(0, 0, 1)) {
				*warnings = append(*warnings, fmt.Sprintf("suppression for %s expired on %s and was ignored", s.Rule, s.Expires))
				continue
			}
		}
		active = append(active, s)
	}
	for i := range in {
		for _, s := range active {
			if s.Rule != in[i].RuleID {
				continue
			}
			if s.Line > 0 && s.Line != in[i].Location.StartLine {
				continue
			}
			if s.Path != "" && !findings.MatchGlob(s.Path, in[i].Location.Path) {
				continue
			}
			in[i].Suppressed = true
			in[i].SuppressionReason = s.Reason
			break
		}
	}
	return in
}

// relativeToRoot renders a path relative to the scan root so reports do not
// disclose where the scanned repository lives on the machine. Paths outside the
// root are reduced to their base name.
func relativeToRoot(root, path string) string {
	if path == "" {
		return ""
	}
	rel, err := filepath.Rel(root, path)
	if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return filepath.ToSlash(rel)
	}
	return filepath.Base(path)
}

// dedupeStrings returns the non-empty values in sorted, de-duplicated order.
func dedupeStrings(in []string) []string {
	out := slices.Clone(in)
	out = slices.DeleteFunc(out, func(s string) bool { return s == "" })
	slices.Sort(out)
	return slices.Compact(out)
}
