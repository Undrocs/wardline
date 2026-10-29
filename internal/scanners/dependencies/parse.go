package dependencies

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"
)

// Ecosystem identifiers as used by OSV.
const (
	EcosystemGo  = "Go"
	EcosystemNPM = "npm"
)

// Package is a resolved dependency coordinate.
type Package struct {
	Ecosystem string
	Name      string
	Version   string
	// Direct is true when the project declares the dependency itself rather than
	// pulling it in transitively.
	Direct bool
	// Development marks npm packages that are only used for development.
	Development bool
	// Manifest is the repository-relative file that supplied this coordinate.
	Manifest string
	// Line is the declaration line in the manifest, when known.
	Line int
}

// Key is a stable identity for deduplication.
func (p Package) Key() string {
	return p.Ecosystem + "\x00" + p.Name + "\x00" + p.Version + "\x00" + p.Manifest
}

// String renders name@version.
func (p Package) String() string { return p.Name + "@" + p.Version }

// parseResult is the outcome of parsing one manifest or lockfile.
type parseResult struct {
	Packages []Package
	// MissingResolution is set when the file does not pin resolved versions.
	MissingResolution string
	Warnings          []string
	// Resolved is false when the file only declares version ranges.
	Resolved bool
}

// goReplace is one replace directive.
type goReplace struct {
	OldPath    string
	OldVersion string // empty when the directive replaces every version
	NewPath    string
	NewVersion string // empty for a filesystem replacement
	// Local is true when the replacement is a filesystem path, which means the
	// module content is not the published version at all.
	Local bool
}

// goExclude is one exclude directive.
type goExclude struct {
	Path    string
	Version string
}

// goModFile is the parsed content of a go.mod file, including the directives
// that change which module version is actually selected.
type goModFile struct {
	Requires []Package
	Replaces []goReplace
	Excludes []goExclude
}

// parseGoMod extracts the module requirements of a go.mod file plus the replace
// and exclude directives that change which versions are actually built.
func parseGoMod(rel string, data []byte) (goModFile, []string) {
	var (
		out      goModFile
		warnings []string
		section  string
	)
	lines := bytes.Split(data, []byte("\n"))
	for i, raw := range lines {
		line := string(raw)
		code := stripLineComment(line)
		trimmed := strings.TrimSpace(code)
		if trimmed == "" {
			continue
		}
		where := fmt.Sprintf("%s:%d", rel, i+1)
		switch {
		case strings.HasSuffix(trimmed, "("):
			section = strings.TrimSpace(strings.TrimSuffix(trimmed, "("))
			continue
		case trimmed == ")":
			section = ""
			continue
		}
		verb := ""
		switch {
		case strings.HasPrefix(trimmed, "require "):
			verb = "require"
			trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, "require"))
		case strings.HasPrefix(trimmed, "replace "):
			verb = "replace"
			trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, "replace"))
		case strings.HasPrefix(trimmed, "exclude "):
			verb = "exclude"
			trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, "exclude"))
		case section == "require":
			verb = "require"
		case section == "replace":
			verb = "replace"
		case section == "exclude":
			verb = "exclude"
		default:
			continue
		}

		switch verb {
		case "require":
			fields := strings.Fields(trimmed)
			if len(fields) < 2 {
				warnings = append(warnings, fmt.Sprintf("%s: unrecognised require directive", where))
				continue
			}
			name := strings.Trim(fields[0], `"`)
			version := strings.Trim(fields[1], `"`)
			if name == "" || version == "" || strings.HasPrefix(version, "=>") {
				continue
			}
			if !isGoVersion(version) {
				warnings = append(warnings, fmt.Sprintf("%s: unsupported version %q for %s", where, version, name))
				continue
			}
			out.Requires = append(out.Requires, Package{
				Ecosystem: EcosystemGo,
				Name:      name,
				Version:   version,
				Direct:    !strings.Contains(strings.ToLower(line), "// indirect"),
				Manifest:  rel,
				Line:      i + 1,
			})
		case "replace":
			rep, ok := parseGoReplace(trimmed)
			if !ok {
				warnings = append(warnings, fmt.Sprintf("%s: unrecognised replace directive", where))
				continue
			}
			out.Replaces = append(out.Replaces, rep)
		case "exclude":
			fields := strings.Fields(trimmed)
			if len(fields) != 2 {
				warnings = append(warnings, fmt.Sprintf("%s: unrecognised exclude directive", where))
				continue
			}
			out.Excludes = append(out.Excludes, goExclude{
				Path:    strings.Trim(fields[0], `"`),
				Version: strings.Trim(fields[1], `"`),
			})
		}
	}
	if section != "" {
		warnings = append(warnings, fmt.Sprintf("%s: unterminated %s block", rel, section))
	}
	return out, warnings
}

// parseGoReplace parses the body of a replace directive:
//
//	old [v1] => new [v2]
//
// A local filesystem target has no version and is marked Local.
func parseGoReplace(body string) (goReplace, bool) {
	parts := strings.SplitN(body, "=>", 2)
	if len(parts) != 2 {
		return goReplace{}, false
	}
	left := strings.Fields(strings.TrimSpace(parts[0]))
	right := strings.Fields(strings.TrimSpace(parts[1]))
	if len(left) == 0 || len(right) == 0 {
		return goReplace{}, false
	}
	rep := goReplace{
		OldPath: strings.Trim(left[0], `"`),
		NewPath: strings.Trim(right[0], `"`),
	}
	if len(left) > 1 {
		rep.OldVersion = strings.Trim(left[1], `"`)
	}
	if len(right) > 1 {
		rep.NewVersion = strings.Trim(right[1], `"`)
	} else if looksLikePath(rep.NewPath) {
		rep.Local = true
	}
	return rep, rep.OldPath != "" && rep.NewPath != ""
}

// looksLikePath reports whether a replace target is a filesystem path rather
// than a module path. Module paths contain a dot in their first element
// (example.com/mod); local paths start with a separator or "." and never carry a
// version.
func looksLikePath(target string) bool {
	if target == "" {
		return false
	}
	if strings.HasPrefix(target, ".") || strings.HasPrefix(target, "/") {
		return true
	}
	first := strings.SplitN(target, "/", 2)[0]
	return !strings.Contains(first, ".")
}

// applyGoReplacements rewrites the required modules according to the replace
// directives, and drops versions excluded by the module file.
//
// A filesystem replacement is removed from the result: the published version of
// that module is not what the build uses, so querying OSV for it would report a
// vulnerability in code the project does not compile.
func applyGoReplacements(reqs []Package, replaces []goReplace, excludes []goExclude) (out []Package, local []Package, notes []string) {
	excluded := map[string]map[string]bool{}
	for _, ex := range excludes {
		if excluded[ex.Path] == nil {
			excluded[ex.Path] = map[string]bool{}
		}
		excluded[ex.Path][ex.Version] = true
	}
	for _, req := range reqs {
		replaced := false
		// drop is set when the published version is not what the build uses.
		drop := false
		for _, rep := range replaces {
			if rep.OldPath != req.Name {
				continue
			}
			if rep.OldVersion != "" && rep.OldVersion != req.Version {
				continue
			}
			replaced = true
			if rep.Local {
				local = append(local, req)
				drop = true
				break
			}
			if rep.NewPath != req.Name {
				notes = append(notes, fmt.Sprintf("%s is replaced by %s %s; the replacement is checked instead", req.Name, rep.NewPath, rep.NewVersion))
				req.Name = rep.NewPath
			} else if rep.NewVersion != req.Version {
				notes = append(notes, fmt.Sprintf("%s is replaced from %s to %s; the replacement is checked instead", req.Name, req.Version, rep.NewVersion))
			}
			if rep.NewVersion != "" {
				req.Version = rep.NewVersion
			}
			break
		}
		if drop || (replaced && req.Version == "") {
			continue
		}
		if versions, ok := excluded[req.Name]; ok && versions[req.Version] {
			notes = append(notes, fmt.Sprintf("%s %s is excluded by the module file; the selected version cannot be determined from go.mod and was not checked", req.Name, req.Version))
			continue
		}
		out = append(out, req)
	}
	return out, local, notes
}

// parseGoModRequirements is the compatibility entry point used by tests: it
// returns only the resolved requirements.
func parseGoModRequirements(rel string, data []byte) parseResult {
	file, warnings := parseGoMod(rel, data)
	res := parseResult{Resolved: true, Warnings: warnings, Packages: file.Requires}
	return res
}

// parseGoWork reads the use and replace directives of a go.work file. Wardline
// cannot run the Go tool, so workspace replacements are applied to every module
// in the repository, which matches the common single-workspace layout.
func parseGoWork(rel string, data []byte) (replaces []goReplace, uses []string, warnings []string) {
	section := ""
	lines := bytes.Split(data, []byte("\n"))
	for i, raw := range lines {
		trimmed := strings.TrimSpace(stripLineComment(string(raw)))
		if trimmed == "" {
			continue
		}
		where := fmt.Sprintf("%s:%d", rel, i+1)
		switch {
		case strings.HasSuffix(trimmed, "("):
			section = strings.TrimSpace(strings.TrimSuffix(trimmed, "("))
			continue
		case trimmed == ")":
			section = ""
			continue
		case strings.HasPrefix(trimmed, "replace "):
			trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, "replace"))
		case strings.HasPrefix(trimmed, "use "):
			trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, "use"))
			uses = append(uses, strings.Trim(trimmed, `"`))
			continue
		case section == "replace":
		case section == "use":
			uses = append(uses, strings.Trim(trimmed, `"`))
			continue
		default:
			continue
		}
		rep, ok := parseGoReplace(trimmed)
		if !ok {
			warnings = append(warnings, fmt.Sprintf("%s: unrecognised replace directive", where))
			continue
		}
		replaces = append(replaces, rep)
	}
	return replaces, uses, warnings
}

// parseGoSum returns the set of module@version pairs recorded in go.sum.
func parseGoSum(data []byte) map[string]bool {
	out := map[string]bool{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		out[fields[0]+"@"+fields[1]] = true
	}
	return out
}

func stripLineComment(line string) string {
	if idx := strings.Index(line, "//"); idx >= 0 {
		// A "//" inside a quoted module path is not a comment.
		before := line[:idx]
		if strings.Count(before, `"`)%2 == 0 {
			return before
		}
	}
	return line
}

func isGoVersion(v string) bool {
	if !strings.HasPrefix(v, "v") || len(v) < 2 {
		return false
	}
	body := v[1:]
	if body == "" || !strings.ContainsAny(body[0:1], "0123456789") {
		return false
	}
	return true
}

// npmLock is the subset of package-lock.json / npm-shrinkwrap.json Wardline uses.
type npmLock struct {
	Name            string                    `json:"name"`
	Version         string                    `json:"version"`
	LockfileVersion int                       `json:"lockfileVersion"`
	Packages        map[string]npmLockPackage `json:"packages"`
	Dependencies    map[string]npmLockDepend  `json:"dependencies"`
}

type npmLockPackage struct {
	Name            string            `json:"name"`
	Version         string            `json:"version"`
	Resolved        string            `json:"resolved"`
	Link            bool              `json:"link"`
	Dev             bool              `json:"dev"`
	Optional        bool              `json:"optional"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

type npmLockDepend struct {
	Version      string                   `json:"version"`
	Dev          bool                     `json:"dev"`
	Optional     bool                     `json:"optional"`
	Dependencies map[string]npmLockDepend `json:"dependencies"`
}

// npmMaxLockfileVersion is the highest lockfile format Wardline understands.
// A newer format is refused rather than parsed on a best-effort basis: silently
// misreading it would report the wrong versions or none at all.
const npmMaxLockfileVersion = 3

// isRegistryResolution reports whether a lockfile "resolved" value points at a
// registry tarball. Git dependencies, file: links and workspace protocols are
// not published packages, so OSV has nothing to say about them.
func isRegistryResolution(resolved string) bool {
	if resolved == "" {
		return true
	}
	lower := strings.ToLower(resolved)
	for _, prefix := range []string{"file:", "link:", "workspace:", "git+", "git:", "github:", "portal:", "patch:"} {
		if strings.HasPrefix(lower, prefix) {
			return false
		}
	}
	return strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")
}

// parseNPMLock parses package-lock.json v1, v2 and v3 layouts.
//
// The result records every entry it could not use, so the scanner can report
// partial coverage instead of pretending the dependency set is complete.
func parseNPMLock(rel string, data []byte) (parseResult, error) {
	res := parseResult{Resolved: true}
	var lock npmLock
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&lock); err != nil {
		return res, fmt.Errorf("%s: invalid JSON: %w", rel, err)
	}

	// The lockfile version decides which layout to read. Version 2 files carry
	// both layouts; the "packages" map is authoritative there.
	switch {
	case lock.LockfileVersion > npmMaxLockfileVersion:
		return res, fmt.Errorf("%s: lockfileVersion %d is newer than the supported version %d; npm dependencies were not checked", rel, lock.LockfileVersion, npmMaxLockfileVersion)
	case lock.LockfileVersion < 0:
		return res, fmt.Errorf("%s: lockfileVersion %d is invalid", rel, lock.LockfileVersion)
	case lock.LockfileVersion == 0 && len(lock.Packages) == 0 && len(lock.Dependencies) == 0:
		return res, fmt.Errorf("%s: no packages and no lockfileVersion; the file is not a usable lockfile", rel)
	case lock.LockfileVersion == 3 && len(lock.Packages) == 0:
		return res, fmt.Errorf("%s: lockfileVersion 3 requires a packages map", rel)
	}

	if lock.LockfileVersion == 1 || (len(lock.Packages) == 0 && len(lock.Dependencies) > 0) {
		if lock.LockfileVersion == 0 {
			res.Warnings = append(res.Warnings, fmt.Sprintf("%s: lockfileVersion is missing; parsing as version 1", rel))
		}
		root := lock.Dependencies
		var walk func(deps map[string]npmLockDepend, nested bool)
		walk = func(deps map[string]npmLockDepend, nested bool) {
			names := make([]string, 0, len(deps))
			for name := range deps {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				dep := deps[name]
				if dep.Version == "" {
					res.Warnings = append(res.Warnings, fmt.Sprintf("%s: package %q has no resolved version and was skipped", rel, name))
					continue
				}
				if !isSemverLike(dep.Version) {
					res.Warnings = append(res.Warnings, fmt.Sprintf("%s: package %q uses the non-registry version %q and was skipped", rel, name, dep.Version))
					continue
				}
				res.Packages = append(res.Packages, Package{
					Ecosystem:   EcosystemNPM,
					Name:        name,
					Version:     dep.Version,
					Direct:      !nested,
					Development: dep.Dev,
					Manifest:    rel,
				})
				if len(dep.Dependencies) > 0 {
					walk(dep.Dependencies, true)
				}
			}
		}
		walk(root, false)
		return res, nil
	}

	if len(lock.Packages) == 0 {
		return res, fmt.Errorf("%s: no resolved packages found (lockfileVersion %d)", rel, lock.LockfileVersion)
	}
	root, hasRoot := lock.Packages[""]
	direct := map[string]bool{}
	devDirect := map[string]bool{}
	for name := range root.Dependencies {
		direct[name] = true
	}
	for name := range root.DevDependencies {
		direct[name] = true
		devDirect[name] = true
	}
	if !hasRoot {
		res.Warnings = append(res.Warnings, fmt.Sprintf("%s: root package entry missing; direct/transitive classification is approximate", rel))
	}

	// Stale lockfile detection: a dependency declared in the root but absent
	// from the package map means the lockfile was not regenerated.
	var stale []string
	for name := range direct {
		if !lockfileContainsPackage(lock.Packages, name) {
			stale = append(stale, name)
		}
	}
	if len(stale) > 0 {
		sort.Strings(stale)
		res.Warnings = append(res.Warnings, fmt.Sprintf("%s: %d declared dependency(ies) are missing from the lockfile (%s); run npm install to refresh it", rel, len(stale), strings.Join(stale, ", ")))
	}

	keys := make([]string, 0, len(lock.Packages))
	for key := range lock.Packages {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		entry := lock.Packages[key]
		if key == "" {
			continue
		}
		name := entry.Name
		if name == "" {
			name = npmPackageNameFromPath(key)
		}
		if entry.Link {
			res.Warnings = append(res.Warnings, fmt.Sprintf("%s: %s is a link to a local package and was skipped", rel, key))
			continue
		}
		if name == "" || entry.Version == "" {
			res.Warnings = append(res.Warnings, fmt.Sprintf("%s: entry %q has no name or version and was skipped", rel, key))
			continue
		}
		if !isRegistryResolution(entry.Resolved) {
			res.Warnings = append(res.Warnings, fmt.Sprintf("%s: %s resolves to a non-registry source (%s) and was skipped", rel, name, entry.Resolved))
			continue
		}
		res.Packages = append(res.Packages, Package{
			Ecosystem:   EcosystemNPM,
			Name:        name,
			Version:     entry.Version,
			Direct:      direct[name],
			Development: entry.Dev || devDirect[name],
			Manifest:    rel,
		})
	}
	return res, nil
}

// lockfileContainsPackage reports whether any entry in the lockfile provides the
// named package.
func lockfileContainsPackage(packages map[string]npmLockPackage, name string) bool {
	suffix := "node_modules/" + name
	for key := range packages {
		if key == suffix || strings.HasSuffix(key, "/"+suffix) {
			return true
		}
	}
	return false
}

// isSemverLike reports whether a version looks like a published registry
// version rather than a git reference, file path or workspace protocol.
func isSemverLike(version string) bool {
	if version == "" {
		return false
	}
	first := version[0]
	if first < '0' || first > '9' {
		return false
	}
	return true
}

// npmPackageNameFromPath converts a lockfile "packages" key such as
// "node_modules/@scope/pkg" or "node_modules/a/node_modules/b" into "pkg".
func npmPackageNameFromPath(key string) string {
	idx := strings.LastIndex(key, "node_modules/")
	rest := key
	if idx >= 0 {
		rest = key[idx+len("node_modules/"):]
	}
	parts := strings.Split(rest, "/")
	if len(parts) == 0 {
		return ""
	}
	if strings.HasPrefix(parts[0], "@") && len(parts) >= 2 {
		return parts[0] + "/" + parts[1]
	}
	return parts[0]
}

// parsePackageJSON records the declared dependency names so the lockfile entries
// can be classified as direct where a lockfile root entry is absent, and reports
// that ranges alone are not scannable.
func parsePackageJSON(rel string, data []byte) (direct map[string]bool, dev map[string]bool, warns []string) {
	var pkg struct {
		Dependencies         map[string]json.RawMessage `json:"dependencies"`
		DevDependencies      map[string]json.RawMessage `json:"devDependencies"`
		OptionalDependencies map[string]json.RawMessage `json:"optionalDependencies"`
		PeerDependencies     map[string]json.RawMessage `json:"peerDependencies"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, nil, []string{fmt.Sprintf("%s: invalid JSON: %v", rel, err)}
	}
	direct = map[string]bool{}
	dev = map[string]bool{}
	for name := range pkg.Dependencies {
		direct[name] = true
	}
	for name := range pkg.OptionalDependencies {
		direct[name] = true
	}
	for name := range pkg.DevDependencies {
		dev[name] = true
	}
	return direct, dev, nil
}

// manifestKind classifies a file for dependency parsing.
type manifestKind int

const (
	kindUnknown manifestKind = iota
	kindGoMod
	kindGoSum
	kindNPMLock
	kindPackageJSON
	kindGoWork
)

func classify(rel string) manifestKind {
	base := strings.ToLower(path.Base(rel))
	switch base {
	case "go.mod":
		return kindGoMod
	case "go.sum":
		return kindGoSum
	case "package-lock.json", "npm-shrinkwrap.json":
		return kindNPMLock
	case "package.json":
		return kindPackageJSON
	case "go.work":
		return kindGoWork
	}
	return kindUnknown
}
