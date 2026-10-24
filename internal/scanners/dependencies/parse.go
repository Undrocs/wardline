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

// parseGoMod extracts require directives from a go.mod file.
//
// The module graph maintained by the Go tool since 1.17 lists every module in
// the build (direct entries plus `// indirect` entries), so go.mod requirements
// are the effective selected versions. go.sum is used to corroborate that the
// versions were actually part of the build.
func parseGoMod(rel string, data []byte) parseResult {
	res := parseResult{Resolved: true}
	lines := bytes.Split(data, []byte("\n"))
	inRequire := false
	for i, raw := range lines {
		line := string(raw)
		code := stripLineComment(line)
		trimmed := strings.TrimSpace(code)
		if trimmed == "" {
			continue
		}
		switch {
		case strings.HasPrefix(trimmed, "require ("):
			inRequire = true
			continue
		case inRequire && trimmed == ")":
			inRequire = false
			continue
		case strings.HasPrefix(trimmed, "require "):
			trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, "require"))
		case !inRequire:
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 2 {
			res.Warnings = append(res.Warnings, fmt.Sprintf("%s:%d: unrecognised require directive", rel, i+1))
			continue
		}
		name := strings.Trim(fields[0], `"`)
		version := strings.Trim(fields[1], `"`)
		if name == "" || version == "" || strings.HasPrefix(version, "=>") {
			continue
		}
		if !isGoVersion(version) {
			res.Warnings = append(res.Warnings, fmt.Sprintf("%s:%d: unsupported version %q for %s", rel, i+1, version, name))
			continue
		}
		indirect := strings.Contains(strings.ToLower(line), "// indirect")
		res.Packages = append(res.Packages, Package{
			Ecosystem: EcosystemGo,
			Name:      name,
			Version:   version,
			Direct:    !indirect,
			Manifest:  rel,
			Line:      i + 1,
		})
	}
	if inRequire {
		res.Warnings = append(res.Warnings, fmt.Sprintf("%s: unterminated require block", rel))
	}
	return res
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

// parseNPMLock parses package-lock.json v1, v2 and v3 layouts.
func parseNPMLock(rel string, data []byte) (parseResult, error) {
	res := parseResult{Resolved: true}
	var lock npmLock
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&lock); err != nil {
		return res, fmt.Errorf("%s: invalid JSON: %w", rel, err)
	}
	if lock.LockfileVersion == 1 || (len(lock.Packages) == 0 && len(lock.Dependencies) > 0) {
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
	for name := range root.Dependencies {
		direct[name] = true
	}
	for name := range root.DevDependencies {
		direct[name] = true
	}
	if !hasRoot && lock.Name != "" {
		res.Warnings = append(res.Warnings, fmt.Sprintf("%s: root package entry missing; direct/transitive classification may be approximate", rel))
	}
	for key, entry := range lock.Packages {
		if key == "" {
			continue
		}
		name := entry.Name
		if name == "" {
			name = npmPackageNameFromPath(key)
		}
		if name == "" || entry.Version == "" {
			continue
		}
		res.Packages = append(res.Packages, Package{
			Ecosystem:   EcosystemNPM,
			Name:        name,
			Version:     entry.Version,
			Direct:      direct[name],
			Development: entry.Dev,
			Manifest:    rel,
		})
	}
	return res, nil
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
	}
	return kindUnknown
}
