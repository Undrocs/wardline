//go:build windows

package security

import "os"

// openNoFollow opens path for reading. Windows has no O_NOFOLLOW equivalent, so
// the identity check performed after opening is what detects that the path was
// swapped for a link or a different file.
func openNoFollow(path string) (*os.File, error) {
	return os.Open(path)
}
