// Package workflows audits GitHub Actions workflow files.
//
// Workflows are parsed structurally (never executed), each detection is tied to
// a rule identifier and a line in the source file, and ambiguous situations are
// reported with lower confidence instead of being treated as automatically
// vulnerable.
package workflows

import (
	"context"
	"fmt"
	"path"
	"strings"

	"github.com/Undrocs/wardline/internal/findings"
	"github.com/Undrocs/wardline/internal/scanners"
	"github.com/Undrocs/wardline/internal/security"
)

// WorkflowDir is the directory GitHub reads workflows from.
const WorkflowDir = ".github/workflows"

// Scanner audits GitHub Actions workflows.
type Scanner struct{}

// New returns a workflow scanner.
func New() *Scanner { return &Scanner{} }

// Name implements scanners.Scanner.
func (s *Scanner) Name() string { return findings.ScannerWorkflows }

// Scan implements scanners.Scanner.
func (s *Scanner) Scan(ctx context.Context, req *scanners.Request) (*scanners.Result, error) {
	res := &scanners.Result{}

	var candidates []scanners.File
	for _, file := range req.Files {
		if !isWorkflowPath(file.Rel) {
			continue
		}
		candidates = append(candidates, file)
	}

	if len(candidates) == 0 {
		res.Scope = "0 workflow(s)"
		res.Notes = append(res.Notes, "No GitHub Actions workflows found under .github/workflows; workflow checks did not apply to this repository.")
		return res, nil
	}

	audited := 0
	for _, file := range candidates {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		data, err := security.ReadFileLimited(file.Abs, req.Config.Limits.MaxFileSize)
		if err != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("%s: could not be read: %v", file.Rel, err))
			res.Skipped = append(res.Skipped, scanners.SkippedCheck{
				Check:  "workflow audit: " + file.Rel,
				Reason: "file could not be read",
			})
			continue
		}
		root, err := parseWorkflow(data)
		if err != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("%s: %v", file.Rel, err))
			res.Skipped = append(res.Skipped, scanners.SkippedCheck{
				Check:  "workflow audit: " + file.Rel,
				Reason: "workflow could not be parsed: " + err.Error(),
			})
			continue
		}
		wf := buildWorkflow(file.Rel, root)
		if len(wf.Triggers) == 0 {
			res.Warnings = append(res.Warnings, fmt.Sprintf("%s: no `on:` triggers were found", file.Rel))
		}
		if len(wf.Jobs) == 0 {
			res.Warnings = append(res.Warnings, fmt.Sprintf("%s: no jobs were found", file.Rel))
		}
		found := checkPermissions(wf)
		found = append(found, checkTriggers(wf)...)
		found = append(found, checkActions(wf)...)
		found = append(found, checkSteps(wf)...)
		res.Findings = append(res.Findings, found...)
		audited++
	}
	res.Scope = fmt.Sprintf("%d workflow(s)", audited)
	return res, nil
}

// isWorkflowPath reports whether rel is a workflow file GitHub would load.
func isWorkflowPath(rel string) bool {
	slash := strings.ReplaceAll(rel, "\\", "/")
	if !strings.HasPrefix(strings.ToLower(slash), WorkflowDir+"/") {
		return false
	}
	rest := slash[len(WorkflowDir)+1:]
	// GitHub only loads files directly inside .github/workflows.
	if strings.Contains(rest, "/") {
		return false
	}
	switch strings.ToLower(path.Ext(rest)) {
	case ".yml", ".yaml":
		return true
	}
	return false
}
