package reports

import (
	"encoding/json"
	"fmt"
	"io"
)

// WriteJSON writes the report as indented JSON with a trailing newline.
//
// Output is deterministic for a given scan: findings are sorted by the engine
// and maps are avoided in the document model.
func WriteJSON(w io.Writer, rep *Report) error {
	if rep == nil {
		return fmt.Errorf("no report")
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(rep); err != nil {
		return fmt.Errorf("encode JSON report: %w", err)
	}
	return nil
}
