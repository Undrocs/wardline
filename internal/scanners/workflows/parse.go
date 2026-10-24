package workflows

import "github.com/Undrocs/wardline/internal/yamlpos"

// node and pair alias the shared line-aware YAML model so rule code stays
// readable while all parsing logic lives in one hardened package.
type (
	node = yamlpos.Node
	pair = yamlpos.Pair
)

const (
	kindNull     = yamlpos.KindNull
	kindScalar   = yamlpos.KindScalar
	kindMapping  = yamlpos.KindMapping
	kindSequence = yamlpos.KindSequence
	kindBlock    = yamlpos.KindBlock
)

// parseWorkflow parses a GitHub Actions workflow file.
func parseWorkflow(data []byte) (*node, error) { return yamlpos.ParseMapping(data) }
