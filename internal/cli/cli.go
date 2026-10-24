// Package cli implements the wardline command line interface.
//
// The package is deliberately thin: it parses arguments, loads and validates
// configuration, selects scanners, and hands control to the engine and report
// writers. All security relevant logic lives in those packages.
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/Undrocs/wardline/internal/version"
)

// Stable exit codes. These are part of the CLI contract and are documented in
// the README and docs/rules.md.
const (
	// ExitOK: the scan completed and no configured threshold was exceeded.
	ExitOK = 0
	// ExitPolicy: the scan completed but findings met the --fail-on threshold.
	ExitPolicy = 1
	// ExitUsage: invalid command, flag or configuration.
	ExitUsage = 2
	// ExitOperational: the scan could not complete (I/O error, scanner failure,
	// network failure, timeout or cancellation).
	ExitOperational = 3
)

// App is the CLI application. Dependencies are injected so commands can be
// tested without touching the real filesystem, clock or network.
type App struct {
	Stdout io.Writer
	Stderr io.Writer
	Stdin  io.Reader
	// Now is the clock used for scan timestamps.
	Now func() time.Time
	// Getwd resolves the working directory for default targets.
	Getwd func() (string, error)
	// Getenv reads environment variables (NO_COLOR, TERM).
	Getenv func(string) string
	// IsTerminal reports whether the writer is an interactive terminal.
	IsTerminal func(io.Writer) bool
}

// New returns an App wired to the process environment.
func New(stdout, stderr io.Writer, stdin io.Reader) *App {
	return &App{
		Stdout:     stdout,
		Stderr:     stderr,
		Stdin:      stdin,
		Now:        time.Now,
		Getwd:      os.Getwd,
		Getenv:     os.Getenv,
		IsTerminal: isTerminalWriter,
	}
}

// Run dispatches a command line and returns the process exit code.
func (a *App) Run(ctx context.Context, args []string) int {
	if len(args) == 0 {
		a.printUsage(a.Stdout)
		return ExitOK
	}
	command := args[0]
	rest := args[1:]
	switch command {
	case "help", "-h", "--help":
		a.printHelp(rest)
		return ExitOK
	case "version", "--version", "-v":
		return a.runVersion(rest)
	case "scan":
		return a.runScan(ctx, rest, "")
	case "audit":
		return a.runAudit(ctx, rest)
	case "--":
		a.printUsage(a.Stderr)
		return ExitUsage
	default:
		if strings.HasPrefix(command, "-") {
			fmt.Fprintf(a.Stderr, "wardline: unknown flag %q\n", command)
			fmt.Fprintln(a.Stderr, "Run 'wardline help' for usage.")
			return ExitUsage
		}
		fmt.Fprintf(a.Stderr, "wardline: unknown command %q\n", command)
		fmt.Fprintln(a.Stderr, "Run 'wardline help' for usage.")
		return ExitUsage
	}
}

func (a *App) runAudit(ctx context.Context, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(a.Stderr, "wardline: audit requires a scanner: secrets, dependencies, workflows or config")
		return ExitUsage
	}
	scanner := args[0]
	switch scanner {
	case "secrets", "dependencies", "workflows", "config":
		return a.runScan(ctx, args[1:], scanner)
	case "help", "-h", "--help":
		a.printAuditHelp(a.Stdout)
		return ExitOK
	default:
		fmt.Fprintf(a.Stderr, "wardline: unknown audit scanner %q (expected secrets, dependencies, workflows or config)\n", scanner)
		return ExitUsage
	}
}

func (a *App) runVersion(args []string) int {
	info := version.Get()
	jsonOut := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "-h" || arg == "--help":
			a.printVersionHelp(a.Stdout)
			return ExitOK
		case arg == "--format" || arg == "-format":
			if i+1 >= len(args) {
				fmt.Fprintln(a.Stderr, "wardline: version --format requires a value (text or json)")
				return ExitUsage
			}
			i++
			value := strings.ToLower(args[i])
			switch value {
			case "json":
				jsonOut = true
			case "text":
				jsonOut = false
			default:
				fmt.Fprintf(a.Stderr, "wardline: unknown version format %q\n", args[i])
				return ExitUsage
			}
		case strings.HasPrefix(arg, "--format=") || strings.HasPrefix(arg, "-format="):
			value := strings.ToLower(arg[strings.Index(arg, "=")+1:])
			switch value {
			case "json":
				jsonOut = true
			case "text":
				jsonOut = false
			default:
				fmt.Fprintf(a.Stderr, "wardline: unknown version format %q\n", value)
				return ExitUsage
			}
		default:
			fmt.Fprintf(a.Stderr, "wardline: unexpected argument %q for version\n", arg)
			return ExitUsage
		}
	}
	if jsonOut {
		enc := json.NewEncoder(a.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(info); err != nil {
			fmt.Fprintf(a.Stderr, "wardline: writing version information: %v\n", err)
			return ExitOperational
		}
		return ExitOK
	}
	fmt.Fprintln(a.Stdout, info.String())
	return ExitOK
}

func (a *App) printHelp(args []string) {
	if len(args) == 0 {
		a.printUsage(a.Stdout)
		return
	}
	switch args[0] {
	case "scan":
		fmt.Fprint(a.Stdout, scanHelpText)
	case "audit":
		a.printAuditHelp(a.Stdout)
	case "version":
		a.printVersionHelp(a.Stdout)
	default:
		fmt.Fprintf(a.Stderr, "wardline: no help available for %q\n", args[0])
		a.printUsage(a.Stderr)
	}
}

func (a *App) printVersionHelp(w io.Writer) {
	fmt.Fprint(w, `wardline version

Usage:
  wardline version [--format text|json]

Prints the version, commit, build date, Go version and platform of the binary.
Development builds report 0.0.0-dev when the version was not injected at build
time.
`)
}

func (a *App) printAuditHelp(w io.Writer) {
	fmt.Fprint(w, `wardline audit

Run a single scanner.

Usage:
  wardline audit secrets       [path] [flags]
  wardline audit dependencies  [path] [flags]
  wardline audit workflows     [path] [flags]
  wardline audit config        [path] [flags]

The scanner argument selects one module and takes precedence over the
'scanners:' section of the configuration; every other flag is identical to
'wardline scan'. Scanners that are not selected are reported as skipped, never
as clean.
`)
}

func (a *App) printUsage(w io.Writer) {
	fmt.Fprint(w, `wardline — security auditing for local repositories

Usage:
  wardline scan [path]            Scan a directory (default: current directory)
  wardline audit <scanner> [path] Run one scanner: secrets, dependencies,
                                  workflows or config
  wardline version                Print version information
  wardline help [command]         Show help for a command

Scan flags:
  --format <fmt>       terminal (default), json, markdown or sarif
  --output <path>      Write the report to a file instead of stdout
  --severity <level>   Minimum reported severity: info, low, medium, high,
                       critical or unknown (suppressed findings are still listed)
  --fail-on <level>    Exit 1 when a finding at or above this severity exists
                       (default: high)
  --exclude <glob>     Exclude a path pattern (repeatable)
  --config <path>      Configuration file (default: <path>/.wardline.yaml)
  --offline            Disable all network access; online checks are reported as
                       skipped, never as clean
  --timeout <duration> Overall scan timeout (for example 2m, 90s)
  --no-color           Disable ANSI colour
  --verbose            Print diagnostics to stderr
  --min-confidence <c> Hide findings below this confidence: low, medium or high

Exit codes:
  0  scan completed, no configured threshold exceeded
  1  scan completed, but findings met the --fail-on threshold
  2  invalid command, flag or configuration
  3  scan could not complete (I/O, scanner or network failure, timeout)

Wardline never transmits source code or secrets. When dependency scanning runs
online, package names and resolved versions are sent to the OSV.dev API.
`)
}

func (a *App) verbosef(format string, args ...any) {
	fmt.Fprintf(a.Stderr, "wardline: "+format+"\n", args...)
}
