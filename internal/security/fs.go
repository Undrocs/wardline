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

// ReadFileLimited reads at most limit bytes from a regular file.
//
// It refuses directories, devices, FIFOs and sockets, and detects files that
// grew beyond the limit after the initial metadata read. The extra byte in the
// limit makes truncation observable instead of silent.
func ReadFileLimited(filename string, limit int64) ([]byte, error) {
	if limit <= 0 {
		limit = 1 << 20
	}
	f, err := os.Open(filename)
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
