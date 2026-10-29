// Package dependencies implements dependency vulnerability scanning for Go
// modules and npm projects using the OSV.dev database.
//
// Only package coordinates are sent to OSV. A missing lockfile, an unreachable
// API or an unsupported ecosystem is reported as a skipped or partial check:
// Wardline never implies that unchecked dependencies are clean.
package dependencies

import (
	"context"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/Undrocs/wardline/internal/config"
	"github.com/Undrocs/wardline/internal/findings"
	"github.com/Undrocs/wardline/internal/netguard"
	"github.com/Undrocs/wardline/internal/osv"
	"github.com/Undrocs/wardline/internal/scanners"
	"github.com/Undrocs/wardline/internal/security"
	"github.com/Undrocs/wardline/internal/version"
)

// RuleVulnerableDependency is the rule id used for advisory findings.
const RuleVulnerableDependency = "WL-DEP-001"

// Scanner performs dependency vulnerability scanning.
type Scanner struct{}

// New returns a dependency scanner.
func New() *Scanner { return &Scanner{} }

// Name implements scanners.Scanner.
func (s *Scanner) Name() string { return findings.ScannerDependencies }

// Scan implements scanners.Scanner.
func (s *Scanner) Scan(ctx context.Context, req *scanners.Request) (*scanners.Result, error) {
	res := &scanners.Result{}

	packages, skipped, warnings, notes := s.collectPackages(ctx, req)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	res.Skipped = append(res.Skipped, skipped...)
	res.Warnings = append(res.Warnings, warnings...)
	res.Notes = append(res.Notes, notes...)

	unique := dedupePackages(packages)
	res.Scope = fmt.Sprintf("%d resolvable package(s)", len(unique))

	if len(unique) == 0 {
		// No manifest is not a coverage gap: there is nothing to look up. It is
		// recorded as a note so the report still states the scope, but it does
		// not mark the scan incomplete the way a skipped lookup does.
		res.Notes = append(res.Notes, "No supported dependency manifest or lockfile was found (go.mod, go.sum, package-lock.json, npm-shrinkwrap.json); there were no dependency coordinates to check.")
		return res, nil
	}

	if req.Offline {
		res.Skipped = append(res.Skipped, scanners.SkippedCheck{
			Check:  "OSV vulnerability lookup",
			Reason: "network disabled (--offline); dependency vulnerabilities were not checked",
		})
		res.Notes = append(res.Notes, "Dependency vulnerability checks were skipped because Wardline is running offline. This scan does not establish that dependencies are free of known vulnerabilities.")
		return res, nil
	}

	endpoint := config.DefaultOSVEndpoint
	policy := netguard.Policy{}
	if req.Config != nil && strings.TrimSpace(req.Config.Network.OSVEndpoint) != "" {
		endpoint = req.Config.Network.OSVEndpoint
		policy = req.Config.EndpointPolicy()
	}
	if req.Config != nil && !req.Config.Network.Enabled {
		res.Skipped = append(res.Skipped, scanners.SkippedCheck{
			Check:  "OSV vulnerability lookup",
			Reason: "network access disabled in configuration; dependency vulnerabilities were not checked",
		})
		return res, nil
	}

	// Identify the client with its version so OSV operators can attribute
	// traffic. No repository or user information is included.
	userAgent := "wardline/" + version.Get().Version
	// The endpoint may come from the scanned repository's configuration, so it
	// is validated against the approval policy before any request is prepared.
	if _, err := netguard.Check(endpoint, policy); err != nil {
		return nil, fmt.Errorf("OSV endpoint rejected: %w", err)
	}
	options := []osv.Option{osv.WithUserAgent(userAgent), osv.WithPolicy(policy)}
	if req.Logf != nil {
		options = append(options, osv.WithLogger(func(format string, args ...any) { req.Log(format, args...) }))
	}
	client, err := osv.New(endpoint, req.HTTPClient, options...)
	if err != nil {
		return nil, err
	}

	queries := make([]osv.Query, len(unique))
	for i, p := range unique {
		queries[i] = osv.Query{Package: osv.Package{Ecosystem: p.Ecosystem, Name: p.Name}, Version: p.Version}
	}

	res.Network = append(res.Network, endpoint)
	res.Notes = append(res.Notes, fmt.Sprintf("Dependency metadata disclosure: package names, ecosystems and resolved versions for %d package(s) were sent to %s (OSV.dev). No file contents, source code or secrets are transmitted.", len(unique), endpoint))

	results, batchErr := client.QueryBatch(ctx, queries)
	if batchErr != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if len(results) == 0 {
			return nil, fmt.Errorf("OSV vulnerability lookup failed: %w; dependency vulnerabilities were not checked", batchErr)
		}
		// Name the packages that were never queried: a count alone cannot be
		// acted on, and these packages must not be read as clean.
		unchecked := unique[len(results):]
		res.Skipped = append(res.Skipped, scanners.SkippedCheck{
			Check:  "OSV vulnerability lookup",
			Reason: fmt.Sprintf("%d of %d package(s) were not queried (%s): %v", len(unchecked), len(unique), summarizeNames(unchecked, 8), batchErr),
		})
		res.Warnings = append(res.Warnings, "The dependency scan is incomplete; the unqueried packages listed above must not be assumed clean.")
	}

	// Map results back to packages and collect advisory identifiers.
	type hit struct {
		pkg  Package
		vuln string
	}
	var hits []hit
	seenHits := map[string]bool{}
	vulnIDs := map[string]bool{}
	checked := len(results)
	for i := range results {
		if i >= len(unique) {
			break
		}
		for _, v := range results[i].Vulns {
			if v.ID == "" {
				continue
			}
			key := unique[i].Key() + "\x00" + v.ID
			if seenHits[key] {
				continue
			}
			seenHits[key] = true
			hits = append(hits, hit{pkg: unique[i], vuln: v.ID})
			vulnIDs[v.ID] = true
		}
	}
	ids := make([]string, 0, len(vulnIDs))
	for id := range vulnIDs {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	details, detailErrs := client.FetchMany(ctx, ids)
	if len(detailErrs) > 0 {
		// The vulnerability itself was detected, so these findings stay in the
		// report. Only their metadata is degraded, which is a warning rather
		// than a coverage gap, and the affected advisories are named so the
		// report distinguishes them from fully resolved ones.
		failed := make([]string, 0, len(detailErrs))
		for id := range detailErrs {
			failed = append(failed, id)
		}
		sort.Strings(failed)
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"%d advisory detail request(s) failed (%s); the affected findings are reported with reduced metadata (identifier, summary and severity may be missing), and their identity and severity were not confirmed by the advisory text",
			len(failed), summarizeStrings(failed, 8)))
	}

	for _, h := range hits {
		vuln := details[h.vuln]
		view := toView(vuln, h.vuln, h.pkg)
		finding, advisoryNotes := buildFinding(h.pkg, view)
		res.Findings = append(res.Findings, finding)
		res.Warnings = append(res.Warnings, advisoryNotes...)
	}

	if checked < len(unique) {
		res.Scope = fmt.Sprintf("%d of %d package(s) checked", checked, len(unique))
	}
	return res, nil
}

// collectPackages parses every supported manifest and reports what could not be
// resolved.
func (s *Scanner) collectPackages(ctx context.Context, req *scanners.Request) ([]Package, []scanners.SkippedCheck, []string, []string) {
	var (
		packages []Package
		skipped  []scanners.SkippedCheck
		warnings []string
		notes    []string
	)
	type dirInfo struct {
		goMod    *scanners.File
		goSum    []byte
		lockfile *scanners.File
		pkgJSON  []byte
	}
	dirs := map[string]*dirInfo{}
	order := []string{}
	var workspaceReplaces []goReplace

	for i := range req.Files {
		file := req.Files[i]
		kind := classify(file.Rel)
		if kind == kindUnknown {
			continue
		}
		dir := path.Dir(file.Rel)
		if dir == "." {
			dir = ""
		}
		info, ok := dirs[dir]
		if !ok {
			info = &dirInfo{}
			dirs[dir] = info
			order = append(order, dir)
		}
		switch kind {
		case kindGoMod:
			f := file
			info.goMod = &f
		case kindGoSum:
			data, err := security.ReadFileLimitedVerified(file.Abs, file.Info, req.Config.Limits.MaxFileSize)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("%s: could not be read: %v", file.Rel, err))
				continue
			}
			info.goSum = data
		case kindNPMLock:
			f := file
			info.lockfile = &f
		case kindPackageJSON:
			data, err := security.ReadFileLimitedVerified(file.Abs, file.Info, req.Config.Limits.MaxFileSize)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("%s: could not be read: %v", file.Rel, err))
				continue
			}
			info.pkgJSON = data
		case kindGoWork:
			data, err := security.ReadFileLimitedVerified(file.Abs, file.Info, req.Config.Limits.MaxFileSize)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("%s: could not be read: %v", file.Rel, err))
				continue
			}
			replaces, uses, warns := parseGoWork(file.Rel, data)
			workspaceReplaces = append(workspaceReplaces, replaces...)
			warnings = append(warnings, warns...)
			if len(uses) > 0 {
				notes = append(notes, fmt.Sprintf("%s: workspace members %s are resolved through their own go.mod files", file.Rel, strings.Join(uses, ", ")))
			}
		}
	}

	for _, dir := range order {
		if ctx.Err() != nil {
			return packages, skipped, warnings, notes
		}
		info := dirs[dir]
		where := dir
		if where == "" {
			where = "."
		}

		if info.goMod != nil {
			data, err := security.ReadFileLimited(info.goMod.Abs, req.Config.Limits.MaxFileSize)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("%s: could not be read: %v", info.goMod.Rel, err))
			} else {
				modFile, warns := parseGoMod(info.goMod.Rel, data)
				warnings = append(warnings, warns...)
				// Replacements from go.work apply to every module in the
				// workspace, so they are merged with the module's own.
				resolved, localised, replaceNotes := applyGoReplacements(
					modFile.Requires,
					append(append([]goReplace{}, workspaceReplaces...), modFile.Replaces...),
					modFile.Excludes,
				)
				warnings = append(warnings, replaceNotes...)
				if len(localised) > 0 {
					names := make([]string, 0, len(localised))
					for _, pkg := range localised {
						names = append(names, pkg.Name)
					}
					sort.Strings(names)
					skipped = append(skipped, scanners.SkippedCheck{
						Check:  "go replace directives",
						Reason: fmt.Sprintf("%s: %s replaced by a local path; the published version is not what the build uses and was not checked", where, strings.Join(names, ", ")),
					})
				}
				verified := 0
				sumSet := parseGoSum(info.goSum)
				for _, pkg := range resolved {
					if sumSet[pkg.Name+"@"+pkg.Version] {
						verified++
					}
					packages = append(packages, pkg)
				}
				switch {
				case info.goSum == nil:
					skipped = append(skipped, scanners.SkippedCheck{
						Check:  "go.sum verification",
						Reason: fmt.Sprintf("%s: go.sum not found; resolved module versions could not be corroborated (the go.mod module graph was still scanned)", where),
					})
				case verified < len(resolved):
					skipped = append(skipped, scanners.SkippedCheck{
						Check:  "go.sum verification",
						Reason: fmt.Sprintf("%s: %d of %d go.mod requirements are absent from go.sum and may not be part of the build", where, len(resolved)-verified, len(resolved)),
					})
				}
			}
		}

		if info.lockfile != nil {
			data, err := security.ReadFileLimited(info.lockfile.Abs, req.Config.Limits.MaxFileSize)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("%s: could not be read: %v", info.lockfile.Rel, err))
			} else {
				parsed, err := parseNPMLock(info.lockfile.Rel, data)
				if err != nil {
					warnings = append(warnings, err.Error())
					skipped = append(skipped, scanners.SkippedCheck{
						Check:  "npm lockfile",
						Reason: fmt.Sprintf("%s: could not be parsed; npm dependencies were not checked", info.lockfile.Rel),
					})
				} else {
					warnings = append(warnings, parsed.Warnings...)
					packages = append(packages, parsed.Packages...)
				}
			}
		} else if info.pkgJSON != nil {
			_, _, warns := parsePackageJSON(path.Join(dir, "package.json"), info.pkgJSON)
			warnings = append(warnings, warns...)
			skipped = append(skipped, scanners.SkippedCheck{
				Check:  "npm dependency resolution",
				Reason: fmt.Sprintf("%s: package.json only declares version ranges and no package-lock.json or npm-shrinkwrap.json is present; npm dependencies were not checked", where),
			})
		}
	}

	// Note unsupported ecosystems so coverage is not overstated.
	supportedFound := len(packages) > 0 || len(skipped) > 0
	unsupported := map[string]string{
		"requirements.txt": "Python",
		"pyproject.toml":   "Python",
		"cargo.toml":       "Rust",
		"pom.xml":          "Maven",
		"composer.json":    "Composer",
		"gemfile":          "Ruby",
	}
	foundUnsupported := map[string]bool{}
	for _, file := range req.Files {
		if ecosystem, ok := unsupported[strings.ToLower(path.Base(file.Rel))]; ok {
			foundUnsupported[ecosystem] = true
		}
	}
	if len(foundUnsupported) > 0 {
		names := make([]string, 0, len(foundUnsupported))
		for name := range foundUnsupported {
			names = append(names, name)
		}
		sort.Strings(names)
		notes = append(notes, "Dependency manifests for "+strings.Join(names, ", ")+" are present but those ecosystems are not supported yet; they were not scanned.")
	}
	if supportedFound {
		notes = append(notes, "Direct/transitive classification reflects manifest metadata and may be approximate when a lockfile does not state it.")
	}
	return packages, skipped, warnings, notes
}

func dedupePackages(in []Package) []Package {
	seen := map[string]bool{}
	out := make([]Package, 0, len(in))
	for _, p := range in {
		key := p.Key()
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, p)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Ecosystem != out[j].Ecosystem {
			return out[i].Ecosystem < out[j].Ecosystem
		}
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Version < out[j].Version
	})
	return out
}

func toView(vuln *osv.Vulnerability, fallbackID string, pkg Package) *vulnerabilityView {
	view := &vulnerabilityView{}
	if vuln == nil {
		view.IDs = []string{fallbackID}
		return view
	}
	view.IDs = append(view.IDs, vuln.ID)
	for _, alias := range vuln.Aliases {
		if alias != "" && alias != vuln.ID {
			view.IDs = append(view.IDs, alias)
		}
	}
	view.Summary = security.RedactEvidence(vuln.Summary, 300)
	view.Details = security.RedactEvidence(vuln.Details, 600)
	view.DatabaseSeverity = vuln.DatabaseSpecific.Severity
	for _, s := range vuln.Severity {
		view.Vectors = append(view.Vectors, struct{ Score string }{Score: s.Score})
		if view.Vector == "" && strings.HasPrefix(strings.ToUpper(s.Score), "CVSS:3.") {
			view.Vector = s.Score
		}
	}
	view.FixedVersion = vuln.AffectedFixedVersion(pkg.Ecosystem, pkg.Name)
	view.AffectedRange = vuln.AffectedRange(pkg.Ecosystem, pkg.Name)
	view.Published = vuln.Published
	view.Modified = vuln.Modified
	for i, ref := range vuln.References {
		if i >= 5 || ref.URL == "" {
			break
		}
		view.References = append(view.References, ref.URL)
	}
	return view
}

func buildFinding(pkg Package, view *vulnerabilityView) (findings.Finding, []string) {
	severity, score, notes := SeverityFromAdvisory(view)
	primaryID := ""
	if len(view.IDs) > 0 {
		primaryID = view.IDs[0]
	}
	vuln := &findings.Vulnerability{
		IDs: view.IDs, Summary: view.Summary, Details: view.Details,
		Affected: view.AffectedRange, FixedVersion: view.FixedVersion,
		Published: view.Published, Modified: view.Modified,
		CVSSVector: view.Vector, CVSSScore: score,
	}
	var refs []string
	if primaryID != "" {
		refs = append(refs, "https://osv.dev/vulnerability/"+primaryID)
	}
	refs = append(refs, view.References...)
	title := "Vulnerable dependency: " + pkg.String()
	if primaryID != "" {
		title += " (" + primaryID + ")"
	}
	remediation := fmt.Sprintf("Upgrade %s to a version that is not affected and redeploy.", pkg.Name)
	if view.FixedVersion != "" {
		remediation = fmt.Sprintf("Upgrade %s to %s or later and redeploy.", pkg.Name, view.FixedVersion)
	}
	if view.Summary == "" {
		notes = append(notes, fmt.Sprintf("advisory %s could not be fully retrieved; severity and remediation detail are reduced", primaryID))
	}
	description := view.Summary
	if description == "" {
		description = "A known vulnerability affects this package version."
	}
	impact := "Applications using this dependency may be exposed to the vulnerability described by the advisory."
	if view.Details != "" {
		impact = view.Details
	}
	return findings.New(findings.Finding{
		RuleID:      RuleVulnerableDependency,
		Scanner:     findings.ScannerDependencies,
		Title:       title,
		Severity:    severity,
		Confidence:  findings.ConfidenceHigh,
		Location:    findings.Location{Path: pkg.Manifest, StartLine: pkg.Line},
		Evidence:    evidenceFor(pkg),
		Description: description,
		Impact:      impact,
		Remediation: remediation,
		References:  refs,
		Package: &findings.Package{
			Ecosystem: pkg.Ecosystem,
			Name:      pkg.Name,
			Version:   pkg.Version,
			Direct:    pkg.Direct,
			Manifest:  pkg.Manifest,
		},
		Vulnerability: vuln,
		Locator:       pkg.Ecosystem + ":" + pkg.Name + "@" + pkg.Version + ":" + primaryID,
	}), notes
}

func evidenceFor(pkg Package) string {
	kind := "transitive"
	if pkg.Direct {
		kind = "direct"
	}
	if pkg.Development {
		kind += ", development"
	}
	return fmt.Sprintf("%s %s (%s)", pkg.Name, pkg.Version, kind)
}

// summarizeNames renders package names for a human-readable report, bounded so
// a large failure cannot flood the console.
func summarizeNames(pkgs []Package, limit int) string {
	names := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		names = append(names, p.Name+"@"+p.Version)
	}
	return summarizeStrings(names, limit)
}

// summarizeStrings joins values, truncating to limit entries with a count of
// the remainder.
func summarizeStrings(values []string, limit int) string {
	if len(values) == 0 {
		return "none"
	}
	if len(values) <= limit {
		return strings.Join(values, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(values[:limit], ", "), len(values)-limit)
}
