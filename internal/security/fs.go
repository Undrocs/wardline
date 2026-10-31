package security

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// ErrTooLarge is returned when a file exceeds the configured read limit.
var ErrTooLarge = errors.New("file exceeds size limit")

// ErrIrregularFile is returned for files that are not regular files.
var ErrIrregularFile = errors.New("not a regular file")

// ErrFileChanged is returned when a file no longer matches the metadata the
// directory walk recorded for it, which means it was replaced or rewritten while
// the scan was running.
var ErrFileChanged = errors.New("file changed while it was being scanned")

// ReadFileLimited reads at most limit bytes from a regular file.
//
// It refuses directories, devices, FIFOs and sockets, and detects files that
// grew beyond the limit after the initial metadata read. The extra byte in the
// limit makes truncation observable instead of silent.
func ReadFileLimited(filename string, limit int64) ([]byte, error) {
	return ReadFileLimitedVerified(filename, nil, limit)
}

// ReadFileLimitedVerified reads a file only if it is still the file the walk saw.
//
// expected is the metadata recorded during traversal. When it is non-nil the file
// is opened without following symbolic links, and the opened file must be the
// same file (same inode, same size) as the one that was recorded; otherwise
// ErrFileChanged is returned. This closes the window in which a scan could be
// steered at content outside the scan root, or at a file that grew after the
// size limit was enforced.
func ReadFileLimitedVerified(filename string, expected os.FileInfo, limit int64) ([]byte, error) {
	if limit <= 0 {
		limit = 1 << 20
	}
	f, err := openNoFollow(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, ErrIrregularFile
	}
	if expected != nil {
		if !os.SameFile(expected, info) {
			return nil, fmt.Errorf("%w: %s was replaced after it was discovered", ErrFileChanged, filename)
		}
		if expected.Size() != info.Size() {
			return nil, fmt.Errorf("%w: %s changed size (%d -> %d)", ErrFileChanged, filename, expected.Size(), info.Size())
		}
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("%w: %d bytes (limit %d)", ErrTooLarge, info.Size(), limit)
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%w: more than %d bytes", ErrTooLarge, limit)
	}
	return data, nil
}

// NormalizeRel converts a filesystem path into a clean, slash-separated path
// relative to root. It rejects paths that escape root.
func NormalizeRel(root, target string) (string, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	absTarget, err := filepath.Abs(target)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(absRoot, absTarget)
	if err != nil {
		return "", err
	}
	rel = filepath.ToSlash(rel)
	if rel == "." {
		return "", nil
	}
	if rel == ".." || strings.HasPrefix(rel, "../") {
		return "", fmt.Errorf("path %q escapes scan root", rel)
	}
	cleaned := path.Clean(rel)
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", fmt.Errorf("path %q escapes scan root", rel)
	}
	return cleaned, nil
}

// IsWithinRoot reports whether target resolves to root or a descendant.
func IsWithinRoot(root, target string) bool {
	_, err := NormalizeRel(root, target)
	return err == nil
}

// SensitivePath reports whether a repository path commonly holds credentials.
func SensitivePath(rel string) bool {
	base := strings.ToLower(path.Base(rel))
	switch base {
	case ".env", ".env.local", ".env.production", ".env.development", ".env.test",
		"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".netrc", ".npmrc", ".pypirc",
		".git-credentials", ".htpasswd", "credentials", "credentials.json",
		"secrets.yml", "secrets.yaml", "keystore.jks", "service-account.json":
		return true
	}
	switch strings.ToLower(path.Ext(base)) {
	case ".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".ppk":
		return true
	}
	return strings.HasPrefix(base, ".env.")
}

// IsBinary Heuristically detects binary content using the presence of NUL bytes
// in the sampled prefix.
func IsBinary(sample []byte) bool {
	limit := len(sample)
	if limit > 8000 {
		limit = 8000
	}
	for i := 0; i < limit; i++ {
		if sample[i] == 0 {
			return true
		}
	}
	return false
}

// IsGeneratedPath reports whether a path is inside a directory that scanners
// skip by default because it holds vendored, cached or generated third-party
// content. Build output directories such as build/ and dist/ are deliberately
// not skipped: they occasionally contain Dockerfiles and deployment manifests
// that still need auditing.
func IsGeneratedPath(rel string) bool {
	segments := strings.Split(rel, "/")
	for _, s := range segments {
		switch s {
		case "node_modules", "vendor", "bower_components", ".git", ".hg", ".svn",
			".venv", "venv", "__pycache__", ".terraform", ".next", ".nuxt",
			".gradle", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".cache":
			return true
		}
	}
	return false
}

// isAbsPath reports whether p is absolute on any supported platform. It is
// deliberately separator-agnostic: a Windows path can appear in a report
// produced on Linux (for example when scanning a mounted volume or replaying a
// report), and filepath.IsAbs would not recognise it.
func isAbsPath(p string) bool {
	if strings.HasPrefix(p, "/") || strings.HasPrefix(p, `\\`) {
		return true
	}
	if len(p) >= 2 && p[1] == ':' && ((p[0] >= 'a' && p[0] <= 'z') || (p[0] >= 'A' && p[0] <= 'Z')) {
		return true
	}
	return filepath.IsAbs(p)
}

// portableBase returns the last element of a path that may use either separator.
func portableBase(p string) string {
	p = strings.TrimRight(p, `/\`)
	if p == "" {
		return ""
	}
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}

func pathDepth(p string) int {
	n := 0
	for _, seg := range strings.FieldsFunc(p, func(r rune) bool { return r == '/' || r == '\\' }) {
		if seg != "" {
			n++
		}
	}
	return n
}

// SanitizeTarget renders a scan target for a report without disclosing the
// machine it ran on.
//
// A relative target is returned unchanged apart from slash normalisation. An
// absolute target is reduced to its final element, because every parent
// directory in the path (a home directory especially) identifies a user or a
// machine. When the final element is itself a home directory or one of its
// ancestors, it is replaced with a placeholder rather than printed.
func SanitizeTarget(target string) string {
	t := strings.TrimSpace(target)
	if t == "" {
		return "."
	}
	if !isAbsPath(t) {
		return filepath.ToSlash(t)
	}
	base := portableBase(t)
	if base == "" {
		return "<absolute path>"
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		homeBase := portableBase(home)
		if homeBase != "" && strings.EqualFold(homeBase, base) && pathDepth(t) <= pathDepth(home) {
			return "<home directory>"
		}
	}
	return base
}
