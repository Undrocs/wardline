// Command wardline is the Wardline security scanner.
//
// It scans a local repository for exposed secrets, vulnerable dependencies,
// unsafe GitHub Actions workflows and insecure configuration, and emits
// terminal, JSON, Markdown or SARIF reports.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/Undrocs/wardline/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	app := cli.New(os.Stdout, os.Stderr, os.Stdin)
	os.Exit(app.Run(ctx, os.Args[1:]))
}
