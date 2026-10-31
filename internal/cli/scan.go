package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Undrocs/wardline/internal/config"
	"github.com/Undrocs/wardline/internal/engine"
	"github.com/Undrocs/wardline/internal/findings"
	"github.com/Undrocs/wardline/internal/netguard"
	"github.com/Undrocs/wardline/internal/reports"
	"github.com/Undrocs/wardline/internal/scanners"
	confscanner "github.com/Undrocs/wardline/internal/scanners/config"
	"github.com/Undrocs/wardline/internal/scanners/dependencies"
	"github.com/Undrocs/wardline/internal/scanners/secrets"
	"github.com/Undrocs/wardline/internal/scanners/workflows"
	"github.com/Undrocs/wardline/internal/version"
)

const scanHelpText = `wardline scan

Usage:
  wardline scan [path] [flags]

Scans a directory for exposed secrets, vulnerable dependencies, risky GitHub
Actions workflows and insecure configuration. The working tree is scanned; Git
history is not read.

Flags:
  --format <fmt>       terminal (default), json, markdown or sarif
  --output <path>      Write the report to a file instead of stdout
  --severity <level>   Minimum reported severity (default: configured, else info)
  --fail-on <level>    Policy threshold for exit code 1 (default: high)
  --exclude <glob>     Additional exclusion pattern (repeatable)
  --config <path>      Configuration file (default: <path>/.wardline.yaml)
  --offline            Perform no network requests
  --timeout <duration> Overall scan timeout (default: configured, else 10m)
  --no-color           Disable ANSI colour
  --verbose            Print diagnostics to stderr
  --min-confidence <c> Hide findings below confidence low|medium|high
  --allow-custom-endpoint
                       Approve network.osvEndpoint as a destination. Without it
                       only the official OSV endpoint is contacted.
  --strict             Trust only this command line for security-relevant
                       settings: scanners cannot be disabled, findings cannot be
                       suppressed and thresholds cannot be weakened by the
                       scanned repository's configuration.
  --fail-incomplete    Exit 3 when any check did not run, so CI cannot pass on a
                       partial scan.
  --quiet              Print nothing on success (errors still go to stderr)
  --summary            Print one summary line (severity counts) instead of the
                       full finding list

Exit codes: 0 success, 1 policy failure, 2 usage/configuration error,
3 operational failure.
`

// scanOptions holds the parsed command line.
type scanOptions struct {
	Target        string
	Format        string
	Output        string
	Severity      string
	FailOn        string
	MinConfidence string
	Exclude       multiFlag
	ConfigPath    string
	Offline       bool
	Timeout       string
	NoColor       bool
	Verbose       bool
	// AllowCustomEndpoint approves a network.osvEndpoint supplied by
	// configuration. It is the only way a repository can direct Wardline at a
	// host other than the official OSV endpoint.
	AllowCustomEndpoint bool
	// Strict ignores security-relevant overrides from the scanned repository.
	Strict bool
	// FailIncomplete turns incomplete coverage into an operational failure.
	FailIncomplete bool
	// Quiet suppresses terminal output when the scan succeeds.
	Quiet bool
	// Summary prints severity and coverage counts instead of every finding.
	Summary bool
	// Help indicates that usage was requested and printed.
	Help bool
}

// multiFlag collects repeatable string flags.
type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }

func (m *multiFlag) Set(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("value must not be empty")
	}
	*m = append(*m, value)
	return nil
}

// runScan implements `wardline scan` and `wardline audit`.
func (a *App) runScan(ctx context.Context, args []string, only string) int {
	opts, code := a.parseScanArgs(args)
	if code != ExitOK {
		return code
	}
	if opts.Help {
		return ExitOK
	}

	// Resolve the target before loading configuration so configuration discovery
	// is relative to the directory being scanned.
	target := opts.Target
	if target == "" {
		target = "."
	}
	targetAbs, err := filepath.Abs(target)
	if err != nil {
		fmt.Fprintf(a.Stderr, "wardline: cannot resolve %q: %v\n", target, err)
		return ExitOperational
	}
	info, err := os.Stat(targetAbs)
	if err != nil {
		fmt.Fprintf(a.Stderr, "wardline: %v\n", err)
		return ExitOperational
	}
	if !info.IsDir() {
		fmt.Fprintf(a.Stderr, "wardline: %q is not a directory\n", target)
		return ExitUsage
	}

	// Configuration: explicit flag, otherwise discover in the target directory.
	cfg, err := a.loadConfig(opts.ConfigPath, targetAbs)
	if err != nil {
		fmt.Fprintf(a.Stderr, "wardline: configuration error: %v\n", err)
		return ExitUsage
	}

	// Strict mode discards security-relevant settings that came from the
	// scanned repository before any of them take effect. The notices are
	// reported, never silently applied.
	var notices []string
	if opts.Strict {
		notices = append(notices, applyStrictPolicy(cfg, opts)...)
	}

	// CLI overrides.
	if opts.Format != "" {
		format := strings.ToLower(strings.TrimSpace(opts.Format))
		if !validFormat(format) {
			fmt.Fprintf(a.Stderr, "wardline: unknown format %q (valid: terminal, json, markdown, sarif)\n", opts.Format)
			return ExitUsage
		}
		cfg.Report.Format = format
	}
	if opts.Severity != "" {
		sev, err := findings.ParseSeverity(opts.Severity)
		if err != nil {
			fmt.Fprintf(a.Stderr, "wardline: --severity: %v\n", err)
			return ExitUsage
		}
		cfg.MinSeverity = sev
	}
	if opts.FailOn != "" {
		sev, err := findings.ParseSeverity(opts.FailOn)
		if err != nil {
			fmt.Fprintf(a.Stderr, "wardline: --fail-on: %v\n", err)
			return ExitUsage
		}
		if sev == findings.SeverityUnknown {
			fmt.Fprintln(a.Stderr, "wardline: --fail-on requires a severity: info, low, medium, high or critical")
			return ExitUsage
		}
		cfg.FailOn = sev
	}
	if opts.Offline {
		cfg.Network.Enabled = false
	}

	// Outbound destination policy. The endpoint may have come from the scanned
	// repository's configuration, so it is only used when the operator approved
	// it on the command line; the official endpoint never needs approval.
	policy := netguard.Policy{AllowCustomEndpoint: opts.AllowCustomEndpoint}
	endpoint, err := netguard.Check(cfg.Network.OSVEndpoint, policy)
	if err != nil {
		fmt.Fprintf(a.Stderr, "wardline: network.osvEndpoint: %v\n", err)
		return ExitUsage
	}
	cfg.Network.OSVEndpoint = endpoint
	cfg.Network.AllowCustomEndpoint = policy.AllowCustomEndpoint
	if policy.AllowCustomEndpoint && !netguard.IsOfficial(endpoint) {
		notices = append(notices, fmt.Sprintf("network: custom endpoint %s approved with --allow-custom-endpoint", endpoint))
	}
	if len(opts.Exclude) > 0 {
		cfg.Exclude = append(cfg.Exclude, opts.Exclude...)
	}
	if opts.Timeout != "" {
		d, err := config.ParseDuration(opts.Timeout)
		if err != nil {
			fmt.Fprintf(a.Stderr, "wardline: --timeout: %v\n", err)
			return ExitUsage
		}
		cfg.Timeouts.Scan = d
	}
	minConfidence := findings.Confidence("")
	if opts.MinConfidence != "" {
		c, err := findings.ParseConfidence(opts.MinConfidence)
		if err != nil {
			fmt.Fprintf(a.Stderr, "wardline: --min-confidence: %v\n", err)
			return ExitUsage
		}
		minConfidence = c
	}

	// Scanner selection: `audit` forces exactly one scanner.
	selected := cfg.Scanners
	if only != "" {
		selected = config.ScannerToggles{}
		switch only {
		case findings.ScannerSecrets:
			selected.Secrets = true
		case findings.ScannerDependencies:
			selected.Dependencies = true
		case findings.ScannerWorkflows:
			selected.Workflows = true
		case findings.ScannerConfig:
			selected.Config = true
		}
	}
	list, skippedScanners := buildScanners(selected)
	if len(list) == 0 {
		fmt.Fprintln(a.Stderr, "wardline: no scanners are enabled")
		return ExitUsage
	}

	if opts.Verbose {
		for _, name := range skippedScanners {
			a.verbosef("scanner %s was not selected", name)
		}
	}

	timeout := cfg.Timeouts.Scan
	if timeout <= 0 {
		timeout = config.DefaultScanTimeout
	}
	scanCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	logf := func(format string, args ...any) {
		if opts.Verbose {
			a.verbosef(format, args...)
		}
	}

	httpClient := netguard.NewHTTPClient(policy, cfg.Timeouts.HTTP,
		netguard.IsProxyConfigured(a.Getenv))
	start := a.now()
	if opts.Verbose {
		a.verbosef("scanning %s (offline=%t, timeout=%s)", targetAbs, !cfg.Network.Enabled || opts.Offline, timeout)
	}

	result, err := engine.Run(scanCtx, engine.Options{
		// The target is echoed as typed so reports do not disclose absolute
		// paths of the machine that produced them; the engine resolves it.
		Target:           target,
		Config:           cfg,
		Offline:          !cfg.Network.Enabled || opts.Offline,
		Logf:             logf,
		Scanners:         list,
		DisabledScanners: skippedScanners,
		HTTPClient:       httpClient,
		Now:              a.Now,
	})
	if err != nil {
		if errors.Is(scanCtx.Err(), context.DeadlineExceeded) {
			fmt.Fprintf(a.Stderr, "wardline: scan timed out after %s\n", timeout)
		} else if errors.Is(scanCtx.Err(), context.Canceled) {
			fmt.Fprintln(a.Stderr, "wardline: scan cancelled")
		} else {
			fmt.Fprintf(a.Stderr, "wardline: scan failed: %v\n", err)
		}
		return ExitOperational
	}
	if result == nil {
		fmt.Fprintln(a.Stderr, "wardline: scan produced no result")
		return ExitOperational
	}

	if len(skippedScanners) > 0 {
		notices = append(notices, "scanners not selected for this scan: "+strings.Join(skippedScanners, ", "))
	}
	rep := reports.Build(result, cfg, reports.Options{
		MinSeverity:   cfg.MinSeverity,
		MinConfidence: minConfidence,
		FailOn:        cfg.FailOn,
		Version:       version.Get(),
		PolicyNotices: notices,
	})

	format := cfg.Report.Format
	if format == "" {
		format = config.DefaultFormat
	}
	// --quiet keeps CI logs readable but must never hide a problem: output is
	// suppressed only when the scan both completed and passed.
	suppress := opts.Quiet && format == "terminal" && opts.Output == "" &&
		!rep.Summary.Policy.Failed && !rep.Summary.Incomplete && len(rep.Errors) == 0
	if !suppress {
		if err := a.writeReport(rep, format, opts); err != nil {
			fmt.Fprintf(a.Stderr, "wardline: writing report: %v\n", err)
			return ExitOperational
		}
	}

	if opts.Verbose {
		a.verbosef("scan finished in %s with %d finding(s)", a.now().Sub(start).Round(time.Millisecond), rep.Summary.Total)
	}

	// Operational failure takes precedence over a policy failure: an incomplete
	// scan must never look like a clean or a merely-failing one.
	if result.Failed() {
		for _, e := range result.Errors {
			fmt.Fprintf(a.Stderr, "wardline: %s\n", e)
		}
		fmt.Fprintln(a.Stderr, "wardline: scan did not complete; results are partial")
		return ExitOperational
	}
	if rep.Summary.Policy.Failed {
		return ExitPolicy
	}
	if opts.FailIncomplete && rep.Summary.Incomplete {
		fmt.Fprintln(a.Stderr, "wardline: scan is incomplete and --fail-incomplete is set; treat this result as not passed")
		return ExitOperational
	}
	return ExitOK
}

// loadConfig loads the explicit configuration file or discovers one.
func (a *App) loadConfig(explicit, targetAbs string) (*config.Config, error) {
	if explicit != "" {
		if _, err := os.Stat(explicit); err != nil {
			return nil, fmt.Errorf("configuration file %q: %w", explicit, err)
		}
		return config.Load(explicit)
	}
	return config.Discover(targetAbs)
}

func (a *App) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

// writeReport renders the report to the configured destination.
func (a *App) writeReport(rep *reports.Report, format string, opts scanOptions) error {
	render := func(w io.Writer) error {
		switch format {
		case "json":
			return reports.WriteJSON(w, rep)
		case "markdown":
			return reports.WriteMarkdown(w, rep)
		case "sarif":
			return reports.WriteSARIF(w, rep)
		default:
			if opts.Summary {
				color := !opts.NoColor && opts.Output == "" && a.colorSupported()
				return reports.WriteSummary(w, rep, reports.TerminalOptions{Color: color, Width: 100})
			}
			color := !opts.NoColor && opts.Output == "" && a.colorSupported()
			return reports.WriteTerminal(w, rep, reports.TerminalOptions{
				Color:   color,
				Verbose: opts.Verbose,
				Width:   100,
			})
		}
	}

	if opts.Output == "" || opts.Output == "-" {
		return render(a.Stdout)
	}

	// Resolve relative output paths against the current working directory.
	path := opts.Output
	if !filepath.IsAbs(path) {
		abs, err := filepath.Abs(path)
		if err != nil {
			return err
		}
		path = abs
	}
	// The report is staged in a temporary file and renamed into place: an
	// existing file keeps its identity but not its old permissions, a symbolic
	// link is refused rather than followed, and a failed write cannot leave a
	// truncated report behind.
	if err := writeReportFile(path, render); err != nil {
		return err
	}
	fmt.Fprintf(a.Stderr, "wardline: %s report written to %s\n", format, path)
	return nil
}

// colorSupported reports whether ANSI colour should be used. NO_COLOR is
// honoured when present with a non-empty value, as https://no-color.org/
// specifies.
func (a *App) colorSupported() bool {
	if a.Getenv != nil {
		if a.Getenv("NO_COLOR") != "" {
			return false
		}
		if a.Getenv("TERM") == "dumb" {
			return false
		}
	}
	if a.IsTerminal == nil {
		return false
	}
	return a.IsTerminal(a.Stdout)
}

// parseScanArgs parses scan/audit flags.
func (a *App) parseScanArgs(args []string) (scanOptions, int) {
	var opts scanOptions
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&opts.Format, "format", "", "")
	fs.StringVar(&opts.Output, "output", "", "")
	fs.StringVar(&opts.Severity, "severity", "", "")
	fs.StringVar(&opts.FailOn, "fail-on", "", "")
	fs.StringVar(&opts.MinConfidence, "min-confidence", "", "")
	fs.Var(&opts.Exclude, "exclude", "")
	fs.StringVar(&opts.ConfigPath, "config", "", "")
	fs.BoolVar(&opts.Offline, "offline", false, "")
	fs.StringVar(&opts.Timeout, "timeout", "", "")
	fs.BoolVar(&opts.NoColor, "no-color", false, "")
	fs.BoolVar(&opts.Verbose, "verbose", false, "")
	fs.BoolVar(&opts.AllowCustomEndpoint, "allow-custom-endpoint", false, "")
	fs.BoolVar(&opts.Strict, "strict", false, "")
	fs.BoolVar(&opts.FailIncomplete, "fail-incomplete", false, "")
	fs.BoolVar(&opts.Quiet, "quiet", false, "")
	fs.BoolVar(&opts.Summary, "summary", false, "")
	fs.Bool("help", false, "")
	fs.Bool("h", false, "")

	if err := fs.Parse(reorderArgs(args)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(a.Stdout, scanHelpText)
			return opts, ExitOK
		}
		fmt.Fprintf(a.Stderr, "wardline: %v\n", err)
		fmt.Fprintln(a.Stderr, "Run 'wardline help scan' for usage.")
		return opts, ExitUsage
	}
	help := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "help" || f.Name == "h" {
			help = true
		}
	})
	if help {
		fmt.Fprint(a.Stdout, scanHelpText)
		opts.Help = true
		return opts, ExitOK
	}
	positional := fs.Args()
	if len(positional) > 1 {
		fmt.Fprintf(a.Stderr, "wardline: expected at most one path, got %d\n", len(positional))
		return opts, ExitUsage
	}
	if len(positional) == 1 {
		opts.Target = positional[0]
	}
	return opts, ExitOK
}

// reorderArgs moves flags before positional arguments so that both
// `wardline scan --format json .` and `wardline scan . --format json` work.
// The standard library flag package stops parsing at the first positional
// argument, which is surprising for a scanner that takes a path first.
func reorderArgs(args []string) []string {
	valueFlags := map[string]bool{
		"format": true, "output": true, "severity": true, "fail-on": true,
		"min-confidence": true, "exclude": true, "config": true, "timeout": true,
	}
	var flags, positional []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			positional = append(positional, arg)
			continue
		}
		name := strings.TrimLeft(arg, "-")
		if idx := strings.Index(name, "="); idx >= 0 {
			flags = append(flags, arg)
			continue
		}
		flags = append(flags, arg)
		if valueFlags[name] && i+1 < len(args) {
			i++
			flags = append(flags, args[i])
		}
	}
	return append(flags, positional...)
}

func validFormat(f string) bool {
	switch f {
	case "terminal", "json", "markdown", "sarif":
		return true
	}
	return false
}

// buildScanners instantiates the enabled scanners.
func buildScanners(toggles config.ScannerToggles) ([]scanners.Scanner, []string) {
	var (
		list     []scanners.Scanner
		disabled []string
	)
	add := func(enabled bool, name string, sc scanners.Scanner) {
		if !enabled {
			disabled = append(disabled, name)
			return
		}
		list = append(list, sc)
	}
	add(toggles.Secrets, findings.ScannerSecrets, secrets.New())
	add(toggles.Dependencies, findings.ScannerDependencies, dependencies.New())
	add(toggles.Workflows, findings.ScannerWorkflows, workflows.New())
	add(toggles.Config, findings.ScannerConfig, confscanner.New())
	return list, disabled
}

// newHTTPClient builds the bounded HTTP client used for OSV requests.
func newHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = config.DefaultHTTPTimeout
	}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		MaxIdleConns:          8,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: 2 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}
}
