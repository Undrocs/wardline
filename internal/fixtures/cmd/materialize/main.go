// Command materialize writes the synthetic vulnerable fixture to a directory so
// it can be scanned by hand or by scripts/smoke.sh.
//
// Usage:
//
//	go run ./internal/fixtures/cmd/materialize <target-dir>
package main

import (
	"fmt"
	"os"

	"github.com/Undrocs/wardline/internal/fixtures"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: materialize <target-dir>")
		os.Exit(2)
	}
	if err := fixtures.Materialize(os.Args[1]); err != nil {
		fmt.Fprintf(os.Stderr, "materialize: %v\n", err)
		os.Exit(1)
	}
}
