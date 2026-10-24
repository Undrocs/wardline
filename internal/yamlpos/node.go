// Package yamlpos parses YAML into a compact, line-aware tree.
//
// Wardline needs structural parsing (not regex matching) for workflow and
// configuration files, together with the source line of every node. This package
// keeps that concern in one place so multiple scanners share one hardened parser
// and one depth limit.
package yamlpos

import (
	"fmt"
	"strings"

	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"
)

// Kind is the structural kind of a YAML node.
type Kind int

const (
	// KindNull is an empty or null value.
	KindNull Kind = iota
	// KindScalar is a scalar value.
	KindScalar
	// KindMapping is a mapping.
	KindMapping
	// KindSequence is a sequence.
	KindSequence
	// KindBlock is a block scalar (| or >).
	KindBlock
)

// String names the kind.
func (k Kind) String() string {
	switch k {
	case KindMapping:
		return "mapping"
	case KindSequence:
		return "sequence"
	case KindScalar:
		return "scalar"
	case KindBlock:
		return "block scalar"
	default:
		return "null"
	}
}

// Node is a line-aware YAML node.
type Node struct {
	Kind   Kind
	Line   int
	Column int
	// Value holds the scalar or block-scalar text.
	Value string
	// Style is the block scalar indicator ("|" or ">").
	Style string
	Pairs []Pair
	Items []*Node
}

// Pair is one mapping entry, preserving document order.
type Pair struct {
	Key     string
	KeyLine int
	Value   *Node
}

// Get returns the value for a mapping key.
func (n *Node) Get(key string) (*Node, bool) {
	if n == nil || n.Kind != KindMapping {
		return nil, false
	}
	for _, p := range n.Pairs {
		if p.Key == key {
			return p.Value, true
		}
	}
	return nil, false
}

// Scalar returns the scalar text and whether the node holds a scalar value.
func (n *Node) Scalar() (string, bool) {
	if n == nil {
		return "", false
	}
	if n.Kind == KindScalar || n.Kind == KindBlock {
		return n.Value, true
	}
	return "", false
}

// Seq returns sequence items, or nil when the node is not a sequence.
func (n *Node) Seq() []*Node {
	if n == nil || n.Kind != KindSequence {
		return nil
	}
	return n.Items
}

// WalkScalars calls fn for every scalar in the subtree.
func (n *Node) WalkScalars(fn func(*Node)) {
	if n == nil {
		return
	}
	switch n.Kind {
	case KindScalar, KindBlock:
		fn(n)
	case KindMapping:
		for _, p := range n.Pairs {
			p.Value.WalkScalars(fn)
		}
	case KindSequence:
		for _, item := range n.Items {
			item.WalkScalars(fn)
		}
	}
}

// BlockLineOffset maps a zero-based line index inside a block scalar to a file
// line number. The block indicator sits on Node.Line, so content starts on the
// following line.
func (n *Node) BlockLineOffset(index int) int {
	if n == nil || n.Kind != KindBlock {
		return 0
	}
	return n.Line + 1 + index
}

// MaxDepth bounds nesting so a hostile document cannot exhaust the stack.
const MaxDepth = 64

// Parse parses the first document of a YAML file.
func Parse(data []byte) (*Node, error) {
	file, err := parser.ParseBytes(data, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("invalid YAML: %w", err)
	}
	if len(file.Docs) == 0 || file.Docs[0].Body == nil {
		return nil, fmt.Errorf("empty YAML document")
	}
	return convert(file.Docs[0].Body, 0)
}

// ParseMapping parses the first document and requires a mapping root.
func ParseMapping(data []byte) (*Node, error) {
	root, err := Parse(data)
	if err != nil {
		return nil, err
	}
	if root.Kind != KindMapping {
		return nil, fmt.Errorf("document root must be a mapping, got %s", root.Kind)
	}
	return root, nil
}

func convert(n ast.Node, depth int) (*Node, error) {
	if n == nil {
		return &Node{Kind: KindNull}, nil
	}
	if depth > MaxDepth {
		return nil, fmt.Errorf("YAML nesting exceeds %d levels", MaxDepth)
	}
	tok := n.GetToken()
	line, col := 0, 0
	if tok != nil {
		line, col = tok.Position.Line, tok.Position.Column
	}
	switch v := n.(type) {
	case *ast.MappingNode:
		out := &Node{Kind: KindMapping, Line: line, Column: col}
		for _, item := range v.Values {
			p, err := convertPair(item, depth+1)
			if err != nil {
				return nil, err
			}
			if p != nil {
				out.Pairs = append(out.Pairs, *p)
			}
		}
		return out, nil
	case *ast.MappingValueNode:
		p, err := convertPair(v, depth+1)
		if err != nil {
			return nil, err
		}
		if p == nil {
			return &Node{Kind: KindNull, Line: line, Column: col}, nil
		}
		return &Node{Kind: KindMapping, Line: line, Column: col, Pairs: []Pair{*p}}, nil
	case *ast.SequenceNode:
		out := &Node{Kind: KindSequence, Line: line, Column: col}
		for _, item := range v.Values {
			child, err := convert(item, depth+1)
			if err != nil {
				return nil, err
			}
			out.Items = append(out.Items, child)
		}
		return out, nil
	case *ast.SequenceEntryNode:
		return convert(v.Value, depth+1)
	case *ast.StringNode:
		return &Node{Kind: KindScalar, Line: line, Column: col, Value: v.Value}, nil
	case *ast.LiteralNode:
		text, style := "", ""
		if v.Value != nil {
			text = v.Value.Value
		}
		if tok := n.GetToken(); tok != nil {
			style = tok.Value
		}
		return &Node{Kind: KindBlock, Line: line, Column: col, Style: style, Value: text}, nil
	case *ast.BoolNode:
		return &Node{Kind: KindScalar, Line: line, Column: col, Value: fmt.Sprintf("%v", v.Value)}, nil
	case *ast.IntegerNode:
		return &Node{Kind: KindScalar, Line: line, Column: col, Value: fmt.Sprintf("%v", v.Value)}, nil
	case *ast.FloatNode:
		return &Node{Kind: KindScalar, Line: line, Column: col, Value: fmt.Sprintf("%v", v.Value)}, nil
	case *ast.NullNode:
		return &Node{Kind: KindNull, Line: line, Column: col}, nil
	case *ast.AnchorNode:
		return convert(v.Value, depth+1)
	case *ast.AliasNode:
		// Aliases are treated as unknown rather than resolved: resolving them
		// safely requires cross-document state and is not needed by any rule.
		return &Node{Kind: KindNull, Line: line, Column: col}, nil
	case *ast.TagNode:
		return convert(v.Value, depth+1)
	default:
		if tok != nil && tok.Value != "" {
			return &Node{Kind: KindScalar, Line: line, Column: col, Value: tok.Value}, nil
		}
		return &Node{Kind: KindNull, Line: line, Column: col}, nil
	}
}

func convertPair(n ast.Node, depth int) (*Pair, error) {
	mv, ok := n.(*ast.MappingValueNode)
	if !ok {
		return nil, nil
	}
	key, err := convert(mv.Key, depth+1)
	if err != nil {
		return nil, err
	}
	value, err := convert(mv.Value, depth+1)
	if err != nil {
		return nil, err
	}
	keyName := strings.TrimSpace(key.Value)
	if key.Kind != KindScalar || keyName == "" {
		return nil, nil
	}
	return &Pair{Key: keyName, KeyLine: key.Line, Value: value}, nil
}
