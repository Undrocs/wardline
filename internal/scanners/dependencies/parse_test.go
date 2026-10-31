package dependencies

import (
	"strings"
	"testing"
)

func TestParseGoMod(t *testing.T) {
	data := []byte(`module example.com/app

go 1.21

require (
	github.com/golang-jwt/jwt v3.2.1+incompatible
	golang.org/x/crypto v0.11.0 // indirect
	example.com/quoted v1.2.3 // indirect
)

require golang.org/x/net v0.10.0

replace example.com/old => example.com/new v1.0.0

exclude example.com/bad v1.0.0
`)
	mod, warnings := parseGoMod("go.mod", data)
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	// Replacements are applied by applyGoReplacements; the parse step keeps the
	// directives so callers can decide what to do with them.
	resolved, local, notes := applyGoReplacements(mod.Requires, mod.Replaces, mod.Excludes)
	if len(local) != 0 || len(notes) != 0 {
		t.Fatalf("unexpected replacements: local=%v notes=%v", local, notes)
	}
	if len(resolved) != 4 {
		t.Fatalf("expected 4 packages, got %d: %+v", len(resolved), resolved)
	}
	byName := map[string]Package{}
	for _, p := range resolved {
		byName[p.Name] = p
		if p.Ecosystem != EcosystemGo {
			t.Errorf("unexpected ecosystem %q", p.Ecosystem)
		}
	}
	if p, ok := byName["github.com/golang-jwt/jwt"]; !ok || !p.Direct {
		t.Errorf("expected a direct jwt dependency: %+v", p)
	}
	if p, ok := byName["golang.org/x/crypto"]; !ok || p.Direct {
		t.Errorf("expected a transitive crypto dependency: %+v", p)
	}
	if p := byName["golang.org/x/net"]; p.Version != "v0.10.0" || !p.Direct || p.Line != 11 {
		t.Errorf("single-line require not parsed correctly: %+v", p)
	}
}

func TestParseGoModMalformed(t *testing.T) {
	data := []byte(`module example.com/app
require (
	notenoughfields
	example.com/missing-version
	example.com/badversion not-a-version
`)
	mod, warnings := parseGoMod("go.mod", data)
	if len(mod.Requires) != 0 {
		t.Fatalf("expected no usable packages, got %+v", mod.Requires)
	}
	if len(warnings) < 2 {
		t.Fatalf("expected warnings for malformed directives, got %v", warnings)
	}
	if !strings.Contains(strings.Join(warnings, " "), "unterminated") {
		t.Errorf("expected an unterminated block warning: %v", warnings)
	}
}

func TestParseGoSum(t *testing.T) {
	sums := parseGoSum([]byte(`golang.org/x/crypto v0.11.0 h1:abc=
golang.org/x/crypto v0.11.0/go.mod h1:def=
garbage
`))
	if !sums["golang.org/x/crypto@v0.11.0"] {
		t.Fatal("expected the module version to be indexed")
	}
	if len(sums) != 2 {
		t.Fatalf("unexpected entries: %v", sums)
	}
}

func TestParseNPMLockV3(t *testing.T) {
	data := []byte(`{
	  "name": "app",
	  "lockfileVersion": 3,
	  "packages": {
	    "": {"name": "app", "dependencies": {"lodash": "4.17.21"}, "devDependencies": {"jest": "29.0.0"}},
	    "node_modules/lodash": {"version": "4.17.21"},
	    "node_modules/jest": {"version": "29.0.0", "dev": true},
	    "node_modules/@scope/pkg": {"version": "1.2.3"},
	    "node_modules/a/node_modules/nested": {"version": "2.0.0"}
	  }
	}`)
	res, err := parseNPMLock("package-lock.json", data)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Packages) != 4 {
		t.Fatalf("expected 4 packages, got %+v", res.Packages)
	}
	byName := map[string]Package{}
	for _, p := range res.Packages {
		byName[p.Name] = p
	}
	if p := byName["lodash"]; p.Version != "4.17.21" || !p.Direct {
		t.Errorf("lodash parsed incorrectly: %+v", p)
	}
	if p := byName["jest"]; !p.Development {
		t.Errorf("dev flag lost: %+v", p)
	}
	if p, ok := byName["@scope/pkg"]; !ok || p.Direct {
		t.Errorf("scoped transitive package parsed incorrectly: %+v", p)
	}
	if p, ok := byName["nested"]; !ok || p.Direct {
		t.Errorf("nested package name not derived: %+v", p)
	}
}

func TestParseNPMLockV1(t *testing.T) {
	data := []byte(`{
	  "lockfileVersion": 1,
	  "dependencies": {
	    "lodash": {"version": "4.17.15"},
	    "minimist": {"version": "1.2.0", "dev": true},
	    "left-pad": {"version": "1.3.0", "dependencies": {"nested-dep": {"version": "0.1.0"}}}
	  }
	}`)
	res, err := parseNPMLock("package-lock.json", data)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Packages) != 4 {
		t.Fatalf("expected 4 packages, got %+v", res.Packages)
	}
	byName := map[string]Package{}
	for _, p := range res.Packages {
		byName[p.Name] = p
	}
	if p := byName["nested-dep"]; p.Direct {
		t.Errorf("nested dependency marked direct: %+v", p)
	}
	if p := byName["minimist"]; !p.Development {
		t.Errorf("dev flag lost: %+v", p)
	}
}

func TestParseNPMLockMalformed(t *testing.T) {
	if _, err := parseNPMLock("package-lock.json", []byte("{not json")); err == nil {
		t.Fatal("expected an error for invalid JSON")
	}
	if _, err := parseNPMLock("package-lock.json", []byte(`{"lockfileVersion": 3}`)); err == nil {
		t.Fatal("expected an error for a lockfile without packages")
	}
}

func TestParsePackageJSON(t *testing.T) {
	direct, dev, warns := parsePackageJSON("package.json", []byte(`{
	  "dependencies": {"lodash": "^4.0.0"},
	  "devDependencies": {"jest": "^29.0.0"},
	  "optionalDependencies": {"fsevents": "^2.0.0"}
	}`))
	if len(warns) != 0 {
		t.Fatalf("unexpected warnings: %v", warns)
	}
	if !direct["lodash"] || !direct["fsevents"] || !dev["jest"] {
		t.Fatalf("unexpected classification: direct=%v dev=%v", direct, dev)
	}
	if _, _, warns := parsePackageJSON("package.json", []byte("{oops")); len(warns) == 0 {
		t.Fatal("expected a warning for invalid JSON")
	}
}

func TestClassify(t *testing.T) {
	cases := map[string]manifestKind{
		"go.mod":                 kindGoMod,
		"sub/go.mod":             kindGoMod,
		"go.sum":                 kindGoSum,
		"web/package-lock.json":  kindNPMLock,
		"npm-shrinkwrap.json":    kindNPMLock,
		"package.json":           kindPackageJSON,
		"Cargo.toml":             kindUnknown,
		"docs/package.json.bak":  kindUnknown,
		"package.json/README.md": kindUnknown,
	}
	for path, want := range cases {
		if got := classify(path); got != want {
			t.Errorf("classify(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestNpmPackageNameFromPath(t *testing.T) {
	cases := map[string]string{
		"node_modules/lodash":                     "lodash",
		"node_modules/@scope/pkg":                 "@scope/pkg",
		"node_modules/a/node_modules/nested":      "nested",
		"node_modules/@scope/a/node_modules/@s/b": "@s/b",
		"": "",
	}
	for input, want := range cases {
		if got := npmPackageNameFromPath(input); got != want {
			t.Errorf("npmPackageNameFromPath(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestApplyGoReplacements(t *testing.T) {
	requires := []Package{
		{Ecosystem: EcosystemGo, Name: "example.com/local", Version: "v1.0.0", Direct: true},
		{Ecosystem: EcosystemGo, Name: "example.com/bump", Version: "v1.0.0", Direct: true},
		{Ecosystem: EcosystemGo, Name: "example.com/swap", Version: "v1.0.0", Direct: true},
		{Ecosystem: EcosystemGo, Name: "example.com/gone", Version: "v1.0.0", Direct: true},
		{Ecosystem: EcosystemGo, Name: "example.com/kept", Version: "v2.0.0", Direct: true},
	}
	replaces := []goReplace{
		{OldPath: "example.com/local", NewPath: "../local", Local: true},
		{OldPath: "example.com/bump", OldVersion: "v1.0.0", NewPath: "example.com/bump", NewVersion: "v1.4.2"},
		{OldPath: "example.com/swap", NewPath: "example.com/fork", NewVersion: "v0.9.0"},
	}
	excludes := []goExclude{{Path: "example.com/gone", Version: "v1.0.0"}}

	out, local, notes := applyGoReplacements(requires, replaces, excludes)
	byName := map[string]Package{}
	for _, p := range out {
		byName[p.Name] = p
	}
	if _, ok := byName["example.com/local"]; ok {
		t.Error("a module replaced by a local path must not be reported at its published version")
	}
	if len(local) != 1 || local[0].Name != "example.com/local" {
		t.Errorf("local replacement not reported: %+v", local)
	}
	if got := byName["example.com/bump"].Version; got != "v1.4.2" {
		t.Errorf("version replacement not applied: %s", got)
	}
	if got, ok := byName["example.com/fork"]; !ok || got.Version != "v0.9.0" {
		t.Errorf("module replacement not applied: %+v", out)
	}
	if _, ok := byName["example.com/swap"]; ok {
		t.Error("the replaced module still appears under its original name")
	}
	if _, ok := byName["example.com/gone"]; ok {
		t.Error("an excluded version was still reported")
	}
	if got := byName["example.com/kept"].Version; got != "v2.0.0" {
		t.Errorf("unreplaced module changed: %s", got)
	}
	if len(notes) < 3 {
		t.Errorf("replacements should be disclosed in the report: %v", notes)
	}
}

func TestParseGoWork(t *testing.T) {
	data := []byte(`go 1.23

use (
	./service
	./library
)

replace example.com/old => ../vendor/old

replace example.com/bump v1.0.0 => example.com/bump v1.2.0
`)
	replaces, uses, warnings := parseGoWork("go.work", data)
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	if len(uses) != 2 || uses[0] != "./service" || uses[1] != "./library" {
		t.Fatalf("workspace members not parsed: %v", uses)
	}
	if len(replaces) != 2 {
		t.Fatalf("expected two replacements, got %+v", replaces)
	}
	if !replaces[0].Local {
		t.Errorf("filesystem replacement not marked local: %+v", replaces[0])
	}
	if replaces[1].NewVersion != "v1.2.0" {
		t.Errorf("version replacement not parsed: %+v", replaces[1])
	}
}

func TestParseNPMLockRejectsUnsupportedFormats(t *testing.T) {
	cases := []struct {
		name string
		data string
		want string
	}{
		{"future version", `{"lockfileVersion": 9, "packages": {"": {}}}`, "newer than the supported"},
		{"v3 without packages", `{"lockfileVersion": 3}`, "requires a packages map"},
		{"empty lockfile", `{}`, "not a usable lockfile"},
		{"invalid json", `{`, "invalid JSON"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := parseNPMLock("package-lock.json", []byte(c.data))
			if err == nil {
				t.Fatal("malformed lockfile accepted")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %q does not mention %q", err, c.want)
			}
		})
	}
}

func TestParseNPMLockSkipsNonRegistrySources(t *testing.T) {
	data := []byte(`{
	  "lockfileVersion": 3,
	  "packages": {
	    "": {"dependencies": {"registry-pkg": "^1.0.0", "linked-pkg": "file:../linked"}},
	    "node_modules/registry-pkg": {"version": "1.2.3", "resolved": "https://registry.npmjs.org/registry-pkg/-/registry-pkg-1.2.3.tgz"},
	    "node_modules/linked-pkg": {"version": "1.0.0", "resolved": "file:../linked"}
	  }
	}`)
	res, err := parseNPMLock("package-lock.json", data)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Packages) != 1 || res.Packages[0].Name != "registry-pkg" {
		t.Fatalf("non-registry packages must be skipped: %+v", res.Packages)
	}
	if !res.Packages[0].Direct {
		t.Error("registry-pkg should be classified as a direct dependency")
	}
	joined := strings.Join(res.Warnings, " ")
	if !strings.Contains(joined, "linked-pkg") || !strings.Contains(joined, "non-registry") {
		t.Fatalf("the skipped package was not disclosed: %v", res.Warnings)
	}
}

func TestParseNPMLockDetectsStaleLockfile(t *testing.T) {
	// package.json declares left-pad, but the lockfile has no entry for it: npm
	// install has not been run since the dependency was added.
	data := []byte(`{
	  "lockfileVersion": 3,
	  "packages": {
	    "": {"dependencies": {"left-pad": "^1.3.0"}},
	    "node_modules/other": {"version": "2.0.0"}
	  }
	}`)
	res, err := parseNPMLock("package-lock.json", data)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(res.Warnings, " "), "missing from the lockfile") {
		t.Fatalf("stale lockfile not reported: %v", res.Warnings)
	}
}

func TestParseNPMLockClassifiesDirectAndTransitive(t *testing.T) {
	data := []byte(`{
	  "lockfileVersion": 2,
	  "packages": {
	    "": {"dependencies": {"direct-pkg": "^1.0.0"}, "devDependencies": {"dev-pkg": "^2.0.0"}},
	    "node_modules/direct-pkg": {"version": "1.1.0"},
	    "node_modules/dev-pkg": {"version": "2.1.0", "dev": true},
	    "node_modules/direct-pkg/node_modules/nested": {"version": "3.0.0"}
	  }
	}`)
	res, err := parseNPMLock("package-lock.json", data)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]Package{}
	for _, p := range res.Packages {
		byName[p.Name] = p
	}
	if !byName["direct-pkg"].Direct {
		t.Error("direct-pkg should be direct")
	}
	if byName["nested"].Direct {
		t.Error("nested should be transitive")
	}
	if !byName["dev-pkg"].Development {
		t.Error("dev-pkg should be marked as a development dependency")
	}
}
