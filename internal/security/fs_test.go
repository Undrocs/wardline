package security

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadFileLimited(t *testing.T) {
	dir := t.TempDir()
	small := filepath.Join(dir, "small.txt")
	if err := os.WriteFile(small, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := ReadFileLimited(small, 1024)
	if err != nil || string(data) != "hello" {
		t.Fatalf("unexpected read result: %q, %v", data, err)
	}

	large := filepath.Join(dir, "large.txt")
	if err := os.WriteFile(large, []byte(strings.Repeat("a", 2048)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFileLimited(large, 1024); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("expected ErrTooLarge, got %v", err)
	}

	if _, err := ReadFileLimited(dir, 1024); !errors.Is(err, ErrIrregularFile) {
		t.Fatalf("expected ErrIrregularFile for a directory, got %v", err)
	}

	if _, err := ReadFileLimited(filepath.Join(dir, "missing"), 1024); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected not-exist error, got %v", err)
	}
}

func TestNormalizeRel(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	rel, err := NormalizeRel(root, filepath.Join(nested, "file.txt"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rel != "a/b/file.txt" {
		t.Fatalf("got %q", rel)
	}
	if _, err := NormalizeRel(root, filepath.Join(root, "..", "outside.txt")); err == nil {
		t.Fatal("expected traversal to be rejected")
	}
	if !IsWithinRoot(root, nested) {
		t.Fatal("expected nested path to be inside root")
	}
	if IsWithinRoot(root, filepath.Dir(root)) {
		t.Fatal("expected parent directory to be outside root")
	}
}

func TestIsBinary(t *testing.T) {
	if IsBinary([]byte("plain text content")) {
		t.Fatal("text was detected as binary")
	}
	if !IsBinary([]byte("abc\x00def")) {
		t.Fatal("NUL byte was not detected")
	}
	if !IsBinary(append(make([]byte, 8000), 0)) {
		t.Fatal("NUL byte beyond the sample window was not detected")
	}
}

func TestIsGeneratedPath(t *testing.T) {
	generated := []string{"node_modules/pkg/index.js", "vendor/x/y.go", ".git/config", "a/.venv/lib/b.py"}
	for _, p := range generated {
		if !IsGeneratedPath(p) {
			t.Errorf("expected %q to be treated as generated", p)
		}
	}
	// Build output is intentionally not skipped.
	for _, p := range []string{"build/Dockerfile", "dist/app.js", "src/main.go"} {
		if IsGeneratedPath(p) {
			t.Errorf("expected %q to be scanned", p)
		}
	}
}

func TestSensitivePath(t *testing.T) {
	for _, p := range []string{".env", "deploy/.env.production", "keys/id_rsa", "certs/server.pem", ".npmrc"} {
		if !SensitivePath(p) {
			t.Errorf("expected %q to be sensitive", p)
		}
	}
	for _, p := range []string{"README.md", "src/main.go", "public/cert.pem.pub"} {
		if SensitivePath(p) {
			t.Errorf("did not expect %q to be sensitive", p)
		}
	}
}

func TestWithinRootOnce(t *testing.T) {
	if WithinRootOnce("a/../b") {
		t.Fatal("parent segment was accepted")
	}
	if !WithinRootOnce("a/b/c") {
		t.Fatal("normal path was rejected")
	}
}
