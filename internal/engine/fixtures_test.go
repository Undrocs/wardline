package engine

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Undrocs/wardline/internal/config"
	"github.com/Undrocs/wardline/internal/fixtures"
	"github.com/Undrocs/wardline/internal/scanners"
	confscanner "github.com/Undrocs/wardline/internal/scanners/config"
	"github.com/Undrocs/wardline/internal/scanners/secrets"
	"github.com/Undrocs/wardline/internal/scanners/workflows"
)

// materializeVulnerable writes the vulnerable fixture into a temporary
// directory. The fixture stores credential-shaped values as templates, so it has
// to be materialised before it can exercise the secret rules.
func materializeVulnerable(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := fixtures.Materialize(dir); err != nil {
		t.Fatalf("materialize fixture: %v", err)
	}
	return dir
}

// offlineScanners is the scanner set used for fixture scans: everything that
// works without network access.
func offlineScanners() []scanners.Scanner {
	return []scanners.Scanner{secrets.New(), workflows.New(), confscanner.New()}
}

// TestVulnerableFixtureExercisesEveryOfflineRule scans the synthetic vulnerable
// fixture with the real scanner set and asserts that every rule which can fire
// without network access actually does. A rule that no fixture can trigger is
// either unreachable or its detection has regressed, and both must fail here
// rather than being discovered by a user.
func TestVulnerableFixtureExercisesEveryOfflineRule(t *testing.T) {
	dir := materializeVulnerable(t)
	cfg := config.Default()
	cfg.Network.Enabled = false
	cfg.Exclude = nil

	res, err := Run(context.Background(), Options{
		Target:   dir,
		Config:   cfg,
		Offline:  true,
		Now:      func() time.Time { return time.Unix(1700000000, 0) },
		Scanners: offlineScanners(),
	})
	if err != nil {
		t.Fatalf("scan fixture: %v", err)
	}

	got := map[string]bool{}
	for _, f := range res.Findings {
		got[f.RuleID] = true
	}

	var want []string
	for _, r := range secrets.Rules() {
		want = append(want, r.ID)
	}
	for _, r := range workflows.Catalog() {
		want = append(want, r.ID)
	}
	for _, r := range confscanner.Catalog() {
		want = append(want, r.ID)
	}
	sort.Strings(want)

	var missing []string
	for _, id := range want {
		if !got[id] {
			missing = append(missing, id)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("the vulnerable fixture does not trigger %d rule(s): %v\nadd a synthetic fixture or fix the detection", len(missing), missing)
	}

	// Anything reported must belong to a catalogue: an unlisted rule ID would be
	// undocumented and could not be configured.
	known := map[string]bool{}
	for _, id := range want {
		known[id] = true
	}
	for _, f := range res.Findings {
		if f.RuleID == "WL-DEP-001" {
			continue // network-only rule; offline scans cannot produce it
		}
		if !known[f.RuleID] {
			t.Errorf("finding uses undocumented rule id %q", f.RuleID)
		}
	}
}

// TestCleanFixtureHasNoFindings is the counterpart: the clean fixture must stay
// clean, otherwise the false-positive rate is climbing unnoticed.
func TestCleanFixtureHasNoFindings(t *testing.T) {
	dir, err := fixtures.Clean()
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Network.Enabled = false

	res, err := Run(context.Background(), Options{
		Target:   dir,
		Config:   cfg,
		Offline:  true,
		Now:      func() time.Time { return time.Unix(1700000000, 0) },
		Scanners: offlineScanners(),
	})
	if err != nil {
		t.Fatalf("scan fixture: %v", err)
	}
	if len(res.Findings) > 0 {
		for _, f := range res.Findings {
			t.Errorf("unexpected finding in the clean fixture: %s at %s (%s)", f.RuleID, f.Location, f.Evidence)
		}
	}
}

// TestVulnerableFixtureSecretsAreRedacted scans the fixture, then checks that
// none of the synthetic credentials it plants appears in any finding field.
// Evidence, titles and remediation text are the fields that reach every report
// format, so a leak there would reach users.
func TestVulnerableFixtureSecretsAreRedacted(t *testing.T) {
	dir := materializeVulnerable(t)
	planted := fixtures.CredentialValues()
	if len(planted) < 10 {
		t.Fatalf("expected the fixture to plant many credentials, found %d", len(planted))
	}

	cfg := config.Default()
	cfg.Network.Enabled = false
	cfg.Exclude = nil
	res, err := Run(context.Background(), Options{
		Target:   dir,
		Config:   cfg,
		Offline:  true,
		Now:      func() time.Time { return time.Unix(1700000000, 0) },
		Scanners: []scanners.Scanner{secrets.New()},
	})
	if err != nil {
		t.Fatalf("scan fixture: %v", err)
	}
	if len(res.Findings) == 0 {
		t.Fatal("the secrets scanner found nothing in a fixture full of credentials")
	}

	for _, f := range res.Findings {
		fields := map[string]string{
			"title":       f.Title,
			"description": f.Description,
			"impact":      f.Impact,
			"remediation": f.Remediation,
			"evidence":    f.Evidence,
			"location":    f.LocationString(),
			"locator":     f.Locator,
		}
		for name, value := range fields {
			for _, secret := range planted {
				if strings.Contains(value, secret) {
					t.Errorf("%s contains a raw credential %q (rule %s)", name, secret, f.RuleID)
				}
			}
		}
		if f.Evidence == "" {
			t.Errorf("finding %s has no evidence; a user cannot see what was matched", f.RuleID)
		}
	}
}

// TestFixtureTemplatesAreComplete guards the template mechanism itself: every
// materialised file must be free of leftover placeholders and the template
// suffix must not survive into the fixture.
func TestFixtureTemplatesAreComplete(t *testing.T) {
	dir := materializeVulnerable(t)
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".tmpl") {
			t.Errorf("template suffix survived materialisation: %s", path)
		}
		// Only templated files are substituted; workflow files legitimately
		// contain GitHub expression syntax such as ${{ github.sha }}.
		if filepath.Base(path) != "credentials.go" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(data), "{{") {
			t.Errorf("unexpanded placeholder in %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
