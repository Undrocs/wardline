// Package version carries build metadata for the Wardline binary.
//
// The values are injected at build time with -ldflags, for example:
//
//	go build -ldflags "-X github.com/Undrocs/wardline/internal/version.Version=0.1.0 \
//	  -X github.com/Undrocs/wardline/internal/version.Commit=$(git rev-parse HEAD) \
//	  -X github.com/Undrocs/wardline/internal/version.BuildDate=2026-01-01T00:00:00Z"
//
// Defaults identify an unversioned development build on purpose: Wardline never
// claims a released version it was not built with.
package version

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
)

var (
	// Version is the semantic version of the build.
	Version = "0.0.0-dev"
	// Commit is the git commit the binary was built from.
	Commit = "unknown"
	// BuildDate is the UTC build timestamp.
	BuildDate = "unknown"
)

// Info is the machine-readable description of the running binary.
type Info struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"buildDate"`
	GoVersion string `json:"goVersion"`
	Platform  string `json:"platform"`
}

// Get returns build metadata, filling gaps from Go's embedded build info when
// the linker flags were not supplied.
func Get() Info {
	commit := Commit
	if commit == "unknown" {
		if bi, ok := debug.ReadBuildInfo(); ok {
			for _, s := range bi.Settings {
				if s.Key == "vcs.revision" && s.Value != "" {
					commit = s.Value
				}
			}
		}
	}
	v := Version
	if v == "" {
		v = "0.0.0-dev"
	}
	return Info{
		Name:      "wardline",
		Version:   v,
		Commit:    commit,
		BuildDate: BuildDate,
		GoVersion: runtime.Version(),
		Platform:  fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
	}
}

// String renders a single-line human readable version string.
func (i Info) String() string {
	parts := []string{
		fmt.Sprintf("wardline %s", i.Version),
		fmt.Sprintf("commit %s", i.Commit),
	}
	if i.BuildDate != "unknown" {
		parts = append(parts, fmt.Sprintf("built %s", i.BuildDate))
	}
	parts = append(parts, i.GoVersion, i.Platform)
	return strings.Join(parts, "  ")
}
