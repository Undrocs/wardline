package version

import (
	"strings"
	"testing"
)

func TestGetDefaults(t *testing.T) {
	info := Get()
	if info.Name != "wardline" {
		t.Fatalf("unexpected name %q", info.Name)
	}
	if info.Version == "" {
		t.Fatal("version must not be empty")
	}
	if info.Platform == "" || info.GoVersion == "" {
		t.Fatal("platform and Go version must be populated")
	}
	if !strings.Contains(info.String(), "wardline") {
		t.Fatalf("unexpected string form %q", info.String())
	}
}

func TestStringOmitsUnknownBuildDate(t *testing.T) {
	info := Info{Name: "wardline", Version: "1.2.3", Commit: "abc", BuildDate: "unknown", GoVersion: "go1.23", Platform: "linux/amd64"}
	out := info.String()
	if strings.Contains(out, "built") {
		t.Fatalf("unknown build date should be omitted: %q", out)
	}
	info.BuildDate = "2026-01-01T00:00:00Z"
	if !strings.Contains(info.String(), "built") {
		t.Fatalf("build date missing: %q", info.String())
	}
}
