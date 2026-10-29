package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// reportFileMode is the permission bits of every report Wardline writes. Reports
// can contain the location and metadata of leaked credentials, so they are
// private to the user who produced them.
const reportFileMode = 0o600

// tempFilePattern names the staging file created next to the destination. The
// leading dot keeps it out of directory listings, and the prefix makes a
// leftover file (for example after a crash) easy to identify.
const tempFilePattern = ".wardline-report-*"

// writeReportFile writes a report to path safely.
//
// Requirements this satisfies, all of which a plain O_TRUNC open does not:
//
//   - the destination is never followed: an existing symbolic link is refused
//     instead of being written through, so a repository cannot point the report
//     at a file elsewhere on the machine;
//   - the destination must be a regular file when it exists, so a directory,
//     device or FIFO cannot be replaced;
//   - the bytes are written to a fresh temporary file with mode 0600 and renamed
//     into place, so an existing file's permissive mode is never inherited and a
//     reader never observes a half-written report;
//   - a failed write removes the temporary file and leaves the previous report
//     untouched, so a truncated report cannot be mistaken for a complete one.
func writeReportFile(path string, write func(io.Writer) error) (err error) {
	dir := filepath.Dir(path)
	info, statErr := os.Lstat(path)
	switch {
	case statErr == nil && info.Mode()&os.ModeSymlink != 0:
		return fmt.Errorf("refusing to write the report: %s is a symbolic link", path)
	case statErr == nil && !info.Mode().IsRegular():
		return fmt.Errorf("refusing to write the report: %s is not a regular file", path)
	case statErr != nil && !errors.Is(statErr, os.ErrNotExist):
		return fmt.Errorf("inspect %s: %w", path, statErr)
	}

	tmp, err := os.CreateTemp(dir, tempFilePattern)
	if err != nil {
		return fmt.Errorf("create report file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			if closeErr := tmp.Close(); closeErr != nil && !errors.Is(closeErr, os.ErrClosed) {
				err = errors.Join(err, closeErr)
			}
			_ = os.Remove(tmpName)
		}
	}()

	// CreateTemp already uses 0600; the explicit chmod keeps the guarantee if
	// that ever changes and documents the intent.
	if err = tmp.Chmod(reportFileMode); err != nil {
		return fmt.Errorf("set report permissions: %w", err)
	}
	if err = write(tmp); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	// Sync before the rename: a crash after rename must not leave an empty file
	// where a complete report is expected.
	if err = tmp.Sync(); err != nil {
		return fmt.Errorf("flush report: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("close report: %w", err)
	}
	// The rename is atomic within a directory on every supported platform. On
	// Windows os.Rename replaces an existing file (MOVEFILE_REPLACE_EXISTING); if
	// another process holds the destination open it fails instead, the old
	// report stays in place and the temporary file is removed by the deferred
	// cleanup above.
	if err = os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	syncDir(dir)
	return nil
}

// syncDir flushes the directory entry so the rename survives a crash. It is
// best effort: Windows cannot open a directory for this purpose, and the report
// is already complete at this point.
func syncDir(dir string) {
	f, err := os.Open(dir)
	if err != nil {
		return
	}
	defer f.Close()
	_ = f.Sync()
}
