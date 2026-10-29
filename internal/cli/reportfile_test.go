package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestReportFileTightensExistingPermissions covers the case where the output
// path already exists with a permissive mode (for example a report committed by
// an earlier run, or a file created with O_TRUNC and a stale mode).
func TestReportFileTightensExistingPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose POSIX permission bits")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	if err := os.WriteFile(path, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeReportFile(path, func(w io.Writer) error {
		_, err := io.WriteString(w, "fresh")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("report mode is %o, want 600", mode)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "fresh" {
		t.Fatalf("report content is %q", data)
	}
}

func TestReportFileRefusesSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs privileges on Windows")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "outside.txt")
	if err := os.WriteFile(target, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "report.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	err := writeReportFile(link, func(w io.Writer) error {
		_, werr := io.WriteString(w, "overwritten")
		return werr
	})
	if err == nil {
		t.Fatal("writing through a symbolic link was allowed")
	}
	if !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("unexpected error: %v", err)
	}
	data, readErr := os.ReadFile(target)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(data) != "untouched" {
		t.Fatalf("the symlink target was modified: %q", data)
	}
}

func TestReportFileRefusesNonRegularDestination(t *testing.T) {
	dir := t.TempDir()
	err := writeReportFile(dir, func(w io.Writer) error { return nil })
	if err == nil {
		t.Fatal("writing over a directory was allowed")
	}
	if !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestReportFileFailureLeavesNoTrace checks cleanup and that a failed write does
// not destroy the previous report.
func TestReportFileFailureLeavesNoTrace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	if err := os.WriteFile(path, []byte("previous"), 0o600); err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("renderer exploded")
	err := writeReportFile(path, func(w io.Writer) error {
		if _, werr := io.WriteString(w, "partial"); werr != nil {
			return werr
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("unexpected error: %v", err)
	}
	data, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(data) != "previous" {
		t.Fatalf("a failed write replaced the report: %q", data)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".wardline-report-") {
			t.Fatalf("temporary file left behind: %s", e.Name())
		}
	}
}

func TestReportFileUnwritableDirectory(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("permission bits are not enforced for this user")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	err := writeReportFile(filepath.Join(dir, "report.json"), func(w io.Writer) error { return nil })
	if err == nil {
		t.Fatal("writing into a read-only directory succeeded")
	}
}

// TestOutputFileReplacesStaleContent exercises the CLI path end to end: a second
// run must replace the report rather than append to or inherit the old file.
func TestOutputFileReplacesStaleContent(t *testing.T) {
	dir := writeProject(t, cleanProject)
	out := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(out, []byte(strings.Repeat("x", 5000)), 0o644); err != nil {
		t.Fatal(err)
	}
	app, _, _ := newTestApp(t)
	if code := app.Run(context.Background(), []string{
		"scan", dir, "--offline", "--format", "json", "--output", out,
	}); code != ExitOK {
		t.Fatalf("exit %d", code)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "xxxx") {
		t.Fatal("the previous report content survived")
	}
	var rep map[string]any
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(out)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("report mode is %o, want 600", info.Mode().Perm())
		}
	}
}
