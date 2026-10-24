package workflows

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Undrocs/wardline/internal/config"
	"github.com/Undrocs/wardline/internal/findings"
	"github.com/Undrocs/wardline/internal/scanners"
)

// TestRepositoryWorkflowsHaveNoHighSeverityFindings dogfoods the scanner on
// Wardline's own CI configuration. It fails if a workflow gains a dangerous
// trigger, an unpinned action or an unsafe permission grant.
func TestRepositoryWorkflowsHaveNoHighSeverityFindings(t *testing.T) {
	root := filepath.Join("..", "..", "..", ".github", "workflows")
	if _, err := os.Stat(root); err != nil {
		t.Skipf("repository workflows unavailable: %v", err)
	}

	var files []scanners.File
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		info, infoErr := d.Info()
		if infoErr != nil {
			return infoErr
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		files = append(files, scanners.File{
			Rel:  ".github/workflows/" + filepath.ToSlash(rel),
			Abs:  path,
			Size: info.Size(),
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no workflows found; the repository should ship CI configuration")
	}

	res, err := New().Scan(context.Background(), &scanners.Request{
		Root:   root,
		Files:  files,
		Config: config.Default(),
		Now:    time.Unix(1700000000, 0),
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res.Skipped) > 0 {
		t.Fatalf("repository workflows could not be audited: %+v", res.Skipped)
	}

	for _, f := range res.Findings {
		if f.Severity.Rank() >= findings.SeverityHigh.Rank() {
			t.Errorf("%s at %s: %s (%s)", f.RuleID, f.Location, f.Title, f.Evidence)
		}
		if f.RuleID == "WL-WF004" {
			t.Errorf("action is not pinned to a full commit SHA: %s", f.Location)
		}
	}
}

// TestRepositoryWorkflowsGrantMinimalPermissions asserts that no workflow
// declares a workflow-wide write permission; write scopes must be scoped to the
// job that needs them.
func TestRepositoryWorkflowsGrantMinimalPermissions(t *testing.T) {
	root := filepath.Join("..", "..", "..", ".github", "workflows")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Skipf("repository workflows unavailable: %v", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(root, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		node, err := parseWorkflow(data)
		if err != nil {
			t.Fatalf("%s: %v", entry.Name(), err)
		}
		perms, ok := node.Get("permissions")
		if !ok {
			t.Errorf("%s: no top-level permissions block", entry.Name())
			continue
		}
		for _, pair := range perms.Pairs {
			if pair.Value != nil && strings.EqualFold(pair.Value.Value, "write") {
				t.Errorf("%s: top-level permission %s: write", entry.Name(), pair.Key)
			}
		}
	}
}
