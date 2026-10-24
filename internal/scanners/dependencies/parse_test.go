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
	res := parseGoMod("go.mod", data)
	if len(res.Packages) != 4 {
		t.Fatalf("expected 4 packages, got %d: %+v", len(res.Packages), res.Packages)
	}
	byName := map[string]Package{}
	for _, p := range res.Packages {
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
	res := parseGoMod("go.mod", data)
	if len(res.Packages) != 0 {
		t.Fatalf("expected no usable packages, got %+v", res.Packages)
	}
	if len(res.Warnings) < 2 {
		t.Fatalf("expected warnings for malformed directives, got %v", res.Warnings)
	}
	if !strings.Contains(strings.Join(res.Warnings, " "), "unterminated") {
		t.Errorf("expected an unterminated block warning: %v", res.Warnings)
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
