package yamlpos

import (
	"strings"
	"testing"
)

func TestParseMappingWithLineNumbers(t *testing.T) {
	root, err := ParseMapping([]byte(`name: CI
on:
  pull_request:
permissions:
  contents: read
  issues: write
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`))
	if err != nil {
		t.Fatal(err)
	}
	if root.Kind != KindMapping {
		t.Fatalf("unexpected kind %v", root.Kind)
	}
	name, ok := root.Get("name")
	if !ok || name.Line != 1 {
		t.Fatalf("unexpected name node: %+v", name)
	}
	perms, ok := root.Get("permissions")
	if !ok || perms.Kind != KindMapping {
		t.Fatalf("unexpected permissions node: %+v", perms)
	}
	issues, ok := perms.Get("issues")
	if !ok || issues.Value != "write" || issues.Line != 6 {
		t.Fatalf("unexpected issues node: %+v", issues)
	}
	jobs, _ := root.Get("jobs")
	build, _ := jobs.Get("build")
	steps, _ := build.Get("steps")
	items := steps.Seq()
	if len(items) != 1 {
		t.Fatalf("unexpected steps: %+v", steps)
	}
	run, ok := items[0].Get("run")
	if !ok || run.Value != "echo hi" {
		t.Fatalf("unexpected run node: %+v", run)
	}
}

func TestParseBlockScalar(t *testing.T) {
	root, err := ParseMapping([]byte(`run: |
  line one
  line two
`))
	if err != nil {
		t.Fatal(err)
	}
	run, _ := root.Get("run")
	if run.Kind != KindBlock {
		t.Fatalf("expected a block scalar, got %v", run.Kind)
	}
	if !strings.Contains(run.Value, "line one") || !strings.Contains(run.Value, "line two") {
		t.Fatalf("block content lost: %q", run.Value)
	}
	if got := run.BlockLineOffset(0); got != 2 {
		t.Fatalf("first content line = %d, want 2", got)
	}
}

func TestParseSequencesAndScalars(t *testing.T) {
	root, err := ParseMapping([]byte(`list:
  - a
  - 42
  - true
  - null
nested: [1, 2]
`))
	if err != nil {
		t.Fatal(err)
	}
	list, _ := root.Get("list")
	items := list.Seq()
	if len(items) != 4 {
		t.Fatalf("unexpected items: %+v", items)
	}
	want := []string{"a", "42", "true", ""}
	for i, item := range items {
		if item.Value != want[i] {
			t.Errorf("item %d = %q, want %q", i, item.Value, want[i])
		}
	}
	if items[3].Kind != KindNull {
		t.Errorf("expected a null node, got %v", items[3].Kind)
	}
}

func TestParseRejectsNonMappingRoot(t *testing.T) {
	if _, err := ParseMapping([]byte("- a\n- b\n")); err == nil {
		t.Fatal("expected an error for a sequence document")
	}
}

func TestParseErrors(t *testing.T) {
	for _, input := range []string{"", "a: [", "key: 'unterminated", "a:\n\tb: 1\n c: 2"} {
		if _, err := Parse([]byte(input)); err == nil {
			t.Errorf("expected an error for %q", input)
		}
	}
}

func TestDepthLimit(t *testing.T) {
	var b strings.Builder
	b.WriteString("root:\n")
	for i := 0; i < MaxDepth+5; i++ {
		b.WriteString(strings.Repeat("  ", i+1) + "child:\n")
	}
	if _, err := ParseMapping([]byte(b.String())); err == nil {
		t.Fatal("expected the nesting limit to be enforced")
	}
}

func TestAliasIsTreatedAsUnknown(t *testing.T) {
	root, err := ParseMapping([]byte("base: &a\n  x: 1\ncopy: *a\n"))
	if err != nil {
		t.Fatal(err)
	}
	copyNode, ok := root.Get("copy")
	if !ok || copyNode.Kind != KindNull {
		t.Fatalf("expected the alias to be treated as null, got %+v", copyNode)
	}
}

func TestWalkScalars(t *testing.T) {
	root, err := ParseMapping([]byte("a: 1\nb:\n  - x\n  - y\nc:\n  d: z\n"))
	if err != nil {
		t.Fatal(err)
	}
	var values []string
	root.WalkScalars(func(n *Node) { values = append(values, n.Value) })
	joined := strings.Join(values, ",")
	for _, want := range []string{"1", "x", "y", "z"} {
		if !strings.Contains(joined, want) {
			t.Errorf("walk missed %q: %v", want, values)
		}
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte("a: 1\n"))
	f.Add([]byte("jobs:\n  b:\n    steps:\n      - run: |\n          echo hi\n"))
	f.Add([]byte("a: &x 1\nb: *x\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		root, err := Parse(data)
		if err != nil {
			return
		}
		root.WalkScalars(func(n *Node) {
			if n.Line < 0 {
				t.Fatalf("negative line")
			}
		})
	})
}
