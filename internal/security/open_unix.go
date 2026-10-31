//go:build !windows

package security

import (
	"os"
	"syscall"
)

// openNoFollow opens path for reading without following a symbolic link.
//
// Between the directory walk and the actual read, an attacker who can write to
// the scanned tree can replace a regular file with a symlink; without
// O_NOFOLLOW the read would then follow the link and return content from outside
// the scan root. The flag is unavailable on Windows and plan9, where the
// identity re-check in ReadFileLimitedVerified is the only defence.
func openNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
}
