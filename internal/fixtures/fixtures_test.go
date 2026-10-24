package fixtures

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExpandSubstitutesEveryPlaceholder(t *testing.T) {
	out, err := expand([]byte("KEY=file{{DB_PASSWORD}}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "{{") {
		t.Fatalf("placeholder survived: %s", out)
	}
	if !strings.Contains(string(out), credentials["DB_PASSWORD"]) {
		t.Fatalf("substitution missing from %s", out)
	}
}

func TestExpandRejectsUnknownPlaceholder(t *testing.T) {
	if _, err := expand([]byte("KEY={{NOT_A_PLACEHOLDER}}")); err == nil {
		t.Fatal("expected an error for an unknown placeholder")
	}
	if _, err := expand([]byte("KEY={{NOT_CLOSED")); err == nil {
		t.Fatal("expected an error for an unterminated placeholder")
	}
}

func TestMaterializeWritesScannableFixture(t *testing.T) {
	dst := t.TempDir()
	if err := Materialize(dst); err != nil {
		t.Fatal(err)
	}
	// Template files are expanded under their real names.
	data, err := os.ReadFile(filepath.Join(dst, "app", "credentials.go"))
	if err != nil {
		t.Fatalf("materialised credentials file missing: %v", err)
	}
	if !strings.Contains(string(data), credentials["AWS_ACCESS_KEY_ID"]) {
		t.Fatal("materialised credentials file does not carry the synthetic value")
	}
	if _, err := os.Stat(filepath.Join(dst, "app", "credentials.go.tmpl")); !os.IsNotExist(err) {
		t.Fatalf("template suffix survived materialisation: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dst, "web", ".npmrc")); err != nil {
		t.Fatalf("dotfile not materialised: %v", err)
	}
}

func TestCredentialValuesAreDistinct(t *testing.T) {
	seen := map[string]bool{}
	for _, v := range CredentialValues() {
		if len(v) < 8 {
			t.Errorf("credential %q is too short to be a useful fixture", v)
		}
		if seen[v] {
			t.Errorf("duplicate credential %q", v)
		}
		seen[v] = true
	}
}
