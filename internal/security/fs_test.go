package security

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
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

func TestSanitizeTargetNeverDisclosesMachinePaths(t *testing.T) {
	cases := []struct {
		name   string
		target string
		want   string
		absent []string
	}{
		{"relative", "testdata/vulnerable", "testdata/vulnerable", nil},
		{"current directory", ".", ".", nil},
		{"empty", "", ".", nil},
		{"absolute posix", "/srv/builds/wardline", "wardline", []string{"/srv", "/srv/builds"}},
		{"absolute windows", `C:\Users\alice\src\wardline`, "wardline", []string{"alice", `C:\Users`}},
		{"unc path", `\\server\share\repo`, "repo", []string{"server", "share"}},
		{"root", "/", "<absolute path>", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := SanitizeTarget(c.target)
			if got != c.want {
				t.Fatalf("SanitizeTarget(%q) = %q, want %q", c.target, got, c.want)
			}
			for _, absent := range c.absent {
				if strings.Contains(got, absent) {
					t.Fatalf("sanitised target still contains %q: %q", absent, got)
				}
			}
		})
	}
}

func TestSanitizeTargetHidesTheHomeDirectory(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		t.Skip("no home directory in this environment")
	}
	if got := SanitizeTarget(home); got != "<home directory>" {
		t.Fatalf("scanning the home directory disclosed it: %q", got)
	}
	// A repository inside the home directory keeps its own name, which is not
	// sensitive, but never its parents.
	inside := filepath.Join(home, "project")
	if got := SanitizeTarget(inside); got != "project" {
		t.Fatalf("path inside home: %q", got)
	}
}

func TestReadFileLimitedVerifiedAcceptsAnUnchangedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(path, []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	data, err := ReadFileLimitedVerified(path, info, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "content" {
		t.Fatalf("unexpected content %q", data)
	}
}

func TestReadFileLimitedVerifiedRejectsReplacement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate the race: the file is replaced after the walk recorded it.
	replacement := filepath.Join(dir, "b.txt")
	if err := os.WriteFile(replacement, []byte("attacker content"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFileLimitedVerified(path, info, 1024); !errors.Is(err, ErrFileChanged) {
		t.Fatalf("replacement was not detected: %v", err)
	}
}

func TestReadFileLimitedVerifiedRejectsSymlinkSwap(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privileges on Windows")
	}
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("outside the scan root"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(path, []byte("inside"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}
	data, err := ReadFileLimitedVerified(path, info, 1024)
	if err == nil {
		t.Fatalf("the symlink was followed and returned %q", data)
	}
	if strings.Contains(string(data), "outside the scan root") {
		t.Fatal("content from outside the scan root was read")
	}
}

func TestReadFileLimitedVerifiedRejectsGrowth(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(path, []byte("small"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Same file, appended to after the metadata was recorded.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(strings.Repeat("x", 4096)); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := ReadFileLimitedVerified(path, info, 1<<20); !errors.Is(err, ErrFileChanged) {
		t.Fatalf("a file that grew after discovery was accepted: %v", err)
	}
}
