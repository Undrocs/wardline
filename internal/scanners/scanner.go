// Package scanners defines the contract every Wardline scanner implements.
//
// Scanners are isolated from each other: a failure or panic in one scanner is
// reported as a scanner error and never prevents the remaining scanners from
// running, and never turns a failed scan into a clean result.
package scanners

import (
	"context"
	"net/http"
	"os"
	"time"

	"github.com/Undrocs/wardline/internal/config"
	"github.com/Undrocs/wardline/internal/findings"
)

// File describes a repository file selected for scanning.
type File struct {
	// Rel is the slash-separated path relative to the scan root.
	Rel string
	// Abs is the absolute filesystem path.
	Abs string
	// Size is the file size in bytes at traversal time.
	Size int64
	// Info is the metadata recorded during traversal. Scanners pass it to
	// security.ReadFileLimitedVerified so a file that was replaced between the
	// walk and the read is rejected instead of silently scanned.
	Info os.FileInfo
}

// Status describes how a scanner run finished.
type Status string

const (
	// StatusRan means the scanner completed all of its checks.
	StatusRan Status = "ran"
	// StatusPartial means the scanner ran but skipped some checks.
	StatusPartial Status = "partial"
	// StatusSkipped means the scanner did not run at all.
	StatusSkipped Status = "skipped"
	// StatusFailed means the scanner returned an error or panicked.
	StatusFailed Status = "failed"
)

// SkippedCheck records a check that could not run, and why.
type SkippedCheck struct {
	Check  string `json:"check"`
	Reason string `json:"reason"`
}

// Request is the immutable input shared by all scanners.
type Request struct {
	// Root is the absolute path of the scan root.
	Root string
	// Files are the candidate files discovered by the engine.
	Files []File
	// Config is the validated configuration.
	Config *config.Config
	// Offline disables every network-dependent check.
	Offline bool
	// Now is the scan start time, injected for deterministic tests.
	Now time.Time
	// Logf writes a verbose diagnostic line. It may be nil.
	Logf func(format string, args ...any)
	// HTTPClient is used for outbound API calls. When nil the scanner must fall
	// back to a safe default or report the check as skipped.
	HTTPClient *http.Client
}

// Log emits a verbose diagnostic message.
func (r *Request) Log(format string, args ...any) {
	if r.Logf != nil {
		r.Logf(format, args...)
	}
}

// Result is what a scanner returns.
type Result struct {
	Findings []findings.Finding
	// Skipped lists checks that did not run, with reasons. A non-empty list
	// downgrades the scanner status to partial.
	Skipped []SkippedCheck
	// Notes are informational statements displayed in reports (for example the
	// network disclosure for dependency scanning).
	Notes []string
	// Network lists endpoints that were contacted.
	Network []string
	// Warnings are non-fatal problems worth surfacing, such as a malformed
	// manifest that was ignored.
	Warnings []string
	// Scope describes what the scanner actually inspected, for example
	// "38 files" or "412 packages".
	Scope string
}

// Scanner is implemented by each detection module.
type Scanner interface {
	// Name is the stable identifier used in reports.
	Name() string
	// Scan runs the checks. Returning an error marks the scanner as failed and
	// makes the overall scan exit with the operational-failure status.
	Scan(ctx context.Context, req *Request) (*Result, error)
}
