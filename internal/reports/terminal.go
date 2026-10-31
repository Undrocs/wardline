package reports

import (
	"fmt"
	"io"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/Undrocs/wardline/internal/findings"
	"github.com/Undrocs/wardline/internal/scanners"
)

// TerminalOptions controls terminal rendering.
type TerminalOptions struct {
	// Color enables ANSI colour. Callers must already have checked that the
	// destination is a terminal, that NO_COLOR is unset and that --no-color was
	// not passed.
	Color bool
	// Verbose prints scanner notes and network disclosure details.
	Verbose bool
	// Width is the wrapping width for evidence lines (minimum 60).
	Width int
}

// severityColumn is the width of the severity column in finding blocks.
const severityColumn = 10

const (
	ansiReset  = "\x1b[0m"
	ansiBold   = "\x1b[1m"
	ansiDim    = "\x1b[2m"
	ansiRed    = "\x1b[31m"
	ansiYellow = "\x1b[33m"
	ansiBlue   = "\x1b[34m"
	ansiGray   = "\x1b[90m"
)

func paint(enabled bool, code, s string) string {
	if !enabled || code == "" {
		return s
	}
	return code + s + ansiReset
}

func severityColor(s findings.Severity) string {
	switch s {
	case findings.SeverityCritical:
		return ansiRed + ansiBold
	case findings.SeverityHigh:
		return ansiRed
	case findings.SeverityMedium:
		return ansiYellow
	case findings.SeverityLow:
		return ansiBlue
	case findings.SeverityInfo:
		return ansiGray
	default:
		return ansiGray
	}
}

// WriteTerminal renders the human-readable report.
func WriteTerminal(w io.Writer, rep *Report, opts TerminalOptions) error {
	if rep == nil {
		return fmt.Errorf("no report")
	}
	width := opts.Width
	if width < 60 {
		width = 80
	}
	bw := &errWriter{w: w}

	// Header.
	bw.printf("%s\n", paint(opts.Color, ansiBold, fmt.Sprintf("%s %s", rep.Tool.Name, rep.Tool.Version)))
	bw.printf("%s\n", paint(opts.Color, ansiDim,
		fmt.Sprintf("working-tree scan of %s · %s · %d file(s) · %s",
			rep.Scan.Target, orDefault(rep.Scan.ConfigFile, "built-in defaults"),
			rep.Scan.Files, humanDuration(rep.Scan.DurationMS))))

	// Scanner status line.
	var statusParts []string
	for _, run := range rep.Scanners {
		label := run.Name
		if run.Scope != "" {
			label += " " + run.Scope
		}
		status := ""
		switch {
		case run.Disabled:
			status = " (disabled)"
		case run.Status == scanners.StatusPartial:
			status = " (partial)"
		case run.Status == scanners.StatusSkipped:
			status = " (skipped)"
		case run.Status == scanners.StatusFailed:
			status = " (failed)"
		}
		statusParts = append(statusParts, label+status)
	}
	if len(statusParts) > 0 {
		bw.printf("%s\n", paint(opts.Color, ansiDim, "scanners   "+strings.Join(statusParts, " · ")))
	}
	if len(rep.Network.Destinations) > 0 {
		bw.printf("%s\n", paint(opts.Color, ansiDim, "network    "+strings.Join(rep.Network.Destinations, ", ")+" (package coordinates only)"))
	}
	bw.printf("\n")

	// Severity summary.
	summary := formatCounts(rep.Summary.Counts, opts.Color)
	bw.printf("findings   %s\n", summary)
	if rep.Summary.Suppressed > 0 {
		bw.printf("suppressed %d\n", rep.Summary.Suppressed)
	}
	bw.printf("\n")

	// Findings. Suppressed findings are listed in their own section below.
	live, suppressed := partitionSuppressed(rep.Findings)
	for _, f := range live {
		writeTerminalFinding(bw, f, opts, width)
	}
	if rep.Summary.Total == 0 {
		bw.printf("%s\n\n", paint(opts.Color, ansiDim, "No findings above the configured reporting threshold."))
	}

	// Suppressed findings.
	if len(suppressed) > 0 {
		bw.printf("%s\n", paint(opts.Color, ansiBold, "Suppressed"))
		for _, f := range suppressed {
			bw.printf("  %s  %s  %s\n", f.RuleID, f.LocationString(), paint(opts.Color, ansiDim, "reason: "+f.SuppressionReason))
		}
		bw.printf("\n")
	}

	// Policy notices are always shown: they record decisions that weaken or
	// redirect the scan, and hiding them behind --verbose would make an ignored
	// override silent.
	if len(rep.PolicyNotices) > 0 {
		bw.printf("%s\n", paint(opts.Color, ansiBold, "Policy"))
		for _, notice := range rep.PolicyNotices {
			bw.wrap("  ", notice, width)
		}
		bw.printf("\n")
	}

	// Incomplete checks.
	var skippedLines []string
	for _, run := range rep.Scanners {
		if run.Disabled {
			continue
		}
		for _, sk := range run.Skipped {
			skippedLines = append(skippedLines, fmt.Sprintf("%s: %s — %s", run.Name, sk.Check, sk.Reason))
		}
		if run.Error != "" {
			skippedLines = append(skippedLines, fmt.Sprintf("%s: scanner failed — %s", run.Name, run.Error))
		}
	}
	if len(skippedLines) > 0 {
		bw.printf("%s\n", paint(opts.Color, ansiBold, "Checks not completed"))
		for _, line := range skippedLines {
			bw.wrap("  ", line, width)
		}
		bw.printf("\n")
	}

	if len(rep.Warnings) > 0 && opts.Verbose {
		bw.printf("%s\n", paint(opts.Color, ansiBold, "Warnings"))
		for _, warning := range dedupe(rep.Warnings) {
			bw.wrap("  ", warning, width)
		}
		bw.printf("\n")
	}
	if len(rep.Errors) > 0 {
		bw.printf("%s\n", paint(opts.Color, ansiBold, "Errors"))
		for _, e := range rep.Errors {
			bw.wrap("  ", e, width)
		}
		bw.printf("\n")
	}

	// Result line.
	if rep.Summary.Policy.Failed {
		bw.printf("%s\n", paint(opts.Color, ansiRed+ansiBold,
			fmt.Sprintf("result     FAIL — %s", rep.Summary.Policy.Reason)))
	} else if rep.Summary.Incomplete {
		bw.printf("%s\n", paint(opts.Color, ansiYellow,
			fmt.Sprintf("result     INCOMPLETE — %d finding(s), but some checks did not run (threshold %s not met); "+
				"this is not a clean result", rep.Summary.Total, rep.Summary.Policy.FailOn)))
	} else {
		bw.printf("%s\n", paint(opts.Color, ansiBold,
			fmt.Sprintf("result     PASS — no findings at or above %s", rep.Summary.Policy.FailOn)))
	}
	return bw.err
}

// WriteSummary renders a compact, machine-independent summary: the result, the
// severity counts and which checks did not run. It never lists individual
// findings, so a CI log stays short while still stating whether the scan can be
// trusted.
func WriteSummary(w io.Writer, rep *Report, opts TerminalOptions) error {
	if rep == nil {
		return fmt.Errorf("no report")
	}
	width := opts.Width
	if width < 60 {
		width = 80
	}
	bw := &errWriter{w: w}

	bw.printf("%s %s · %s\n", rep.Tool.Name, rep.Tool.Version, orDefault(rep.Scan.Target, "."))
	bw.printf("findings   %s\n", formatCounts(rep.Summary.Counts, opts.Color))
	if rep.Summary.Suppressed > 0 {
		bw.printf("suppressed %d (listed in the full report)\n", rep.Summary.Suppressed)
	}

	var disabled []string
	var partial []string
	for _, run := range rep.Scanners {
		switch {
		case run.Disabled:
			disabled = append(disabled, run.Name)
		case run.Status != scanners.StatusRan:
			partial = append(partial, fmt.Sprintf("%s (%s)", run.Name, run.Status))
		}
	}
	if len(disabled) > 0 {
		bw.printf("%s\n", paint(opts.Color, ansiDim, "not selected: "+strings.Join(disabled, ", ")))
	}
	if len(partial) > 0 {
		bw.printf("%s\n", paint(opts.Color, ansiYellow, "incomplete checks: "+strings.Join(partial, ", ")))
	}
	for _, notice := range rep.PolicyNotices {
		bw.wrap("policy     ", notice, width)
	}

	if rep.Summary.Total > 0 {
		bw.printf("%s\n", paint(opts.Color, ansiDim,
			fmt.Sprintf("%d finding(s) omitted; use --format json or markdown for detail", rep.Summary.Total)))
	}

	switch {
	case rep.Summary.Policy.Failed:
		bw.printf("%s\n", paint(opts.Color, ansiRed+ansiBold, "result     FAIL — "+rep.Summary.Policy.Reason))
	case rep.Summary.Incomplete:
		bw.printf("%s\n", paint(opts.Color, ansiYellow, "result     INCOMPLETE — some checks did not run; this is not a clean result"))
	default:
		bw.printf("%s\n", paint(opts.Color, ansiBold, "result     PASS — no findings at or above "+rep.Summary.Policy.FailOn))
	}
	return bw.err
}

func writeTerminalFinding(bw *errWriter, f findings.Finding, opts TerminalOptions, width int) {
	// Pad the uncoloured label, then paint it: format width counts bytes, so
	// painting first would misalign every row when colour is enabled.
	label := fmt.Sprintf("%-*s", severityColumn, f.Severity.Label())
	sev := paint(opts.Color, severityColor(f.Severity), label)
	bw.printf("%s %s  %s\n", sev, paint(opts.Color, ansiBold, f.RuleID), f.Title)
	meta := fmt.Sprintf("%s · confidence %s", f.LocationString(), f.Confidence)
	if f.Package != nil {
		kind := "transitive"
		if f.Package.Direct {
			kind = "direct"
		}
		meta = fmt.Sprintf("%s · %s dependency · confidence %s", f.LocationString(), kind, f.Confidence)
	}
	bw.printf("           %s\n", paint(opts.Color, ansiDim, meta))
	if f.Evidence != "" {
		bw.wrap("           "+paint(opts.Color, ansiDim, "evidence  "), f.Evidence, width)
	}
	if f.Vulnerability != nil && len(f.Vulnerability.IDs) > 0 {
		bw.wrap("           "+paint(opts.Color, ansiDim, "advisory  "), strings.Join(f.Vulnerability.IDs, ", "), width)
		if f.Vulnerability.Affected != "" {
			bw.wrap("           "+paint(opts.Color, ansiDim, "affected  "), f.Vulnerability.Affected, width)
		}
		if f.Vulnerability.FixedVersion != "" {
			bw.wrap("           "+paint(opts.Color, ansiDim, "fixed in  "), f.Vulnerability.FixedVersion, width)
		}
	}
	if f.Impact != "" {
		bw.wrap("           "+paint(opts.Color, ansiDim, "impact    "), f.Impact, width)
	}
	if f.Remediation != "" {
		bw.wrap("           "+paint(opts.Color, ansiDim, "fix       "), f.Remediation, width)
	}
	if len(f.References) > 0 {
		bw.wrap("           "+paint(opts.Color, ansiDim, "refs      "), strings.Join(f.References, " "), width)
	}
	bw.printf("\n")
}

// errWriter tracks the first write error and wraps text.
type errWriter struct {
	w   io.Writer
	err error
}

func (e *errWriter) printf(format string, args ...any) {
	if e.err != nil {
		return
	}
	_, err := fmt.Fprintf(e.w, format, args...)
	if err != nil {
		e.err = err
	}
}

// wrap prints label followed by word-wrapped continuation lines. The label is
// expected to include its own trailing padding.
func (e *errWriter) wrap(label, text string, width int) {
	if e.err != nil {
		return
	}
	indent := strings.Repeat(" ", utf8.RuneCountInString(stripANSI(label)))
	words := strings.Fields(text)
	if len(words) == 0 {
		e.printf("%s\n", strings.TrimRight(label, " "))
		return
	}
	if width < len(indent)+20 {
		width = len(indent) + 40
	}
	line := label + words[0]
	col := utf8.RuneCountInString(stripANSI(line))
	for _, word := range words[1:] {
		wlen := utf8.RuneCountInString(word)
		if col+1+wlen > width {
			e.printf("%s\n", line)
			line = indent + word
			col = len(indent) + wlen
			continue
		}
		line += " " + word
		col += 1 + wlen
	}
	e.printf("%s\n", line)
}

func stripANSI(s string) string {
	var b strings.Builder
	inEscape := false
	for _, r := range s {
		switch {
		case r == '\x1b':
			inEscape = true
		case inEscape:
			if r == 'm' {
				inEscape = false
			}
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func formatCounts(c findings.Counts, color bool) string {
	type entry struct {
		name  string
		value int
		sev   findings.Severity
	}
	entries := []entry{
		{"critical", c.Critical, findings.SeverityCritical},
		{"high", c.High, findings.SeverityHigh},
		{"medium", c.Medium, findings.SeverityMedium},
		{"low", c.Low, findings.SeverityLow},
		{"info", c.Info, findings.SeverityInfo},
		{"unknown", c.Unknown, findings.SeverityUnknown},
	}
	var parts []string
	for _, e := range entries {
		if e.value == 0 {
			continue
		}
		parts = append(parts, paint(color, severityColor(e.sev), fmt.Sprintf("%s %d", e.name, e.value)))
	}
	if len(parts) == 0 {
		return "0"
	}
	return strings.Join(parts, " · ")
}

func orDefault(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

func humanDuration(ms int64) string {
	if ms < 1000 {
		return fmt.Sprintf("%dms", ms)
	}
	return fmt.Sprintf("%.1fs", float64(ms)/1000)
}

// dedupe returns the values in sorted, de-duplicated order.
func dedupe(in []string) []string {
	out := slices.Clone(in)
	slices.Sort(out)
	return slices.Compact(out)
}
