package cli

import (
	"io"
	"os"
)

// isTerminalWriter reports whether w is an interactive character device.
// It intentionally avoids external terminal-detection dependencies.
func isTerminalWriter(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
