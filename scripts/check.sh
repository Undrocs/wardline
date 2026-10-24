#!/bin/sh
# Format, vet, test and race-check Wardline the same way CI does.
#
# Usage: scripts/check.sh [--fuzz]
#   --fuzz  additionally run a short fuzz pass over every fuzz target.
set -eu

cd "$(dirname "$0")/.."

run_fuzz=false
if [ "${1:-}" = "--fuzz" ]; then
	run_fuzz=true
fi

echo "== gofmt"
unformatted="$(gofmt -l .)"
if [ -n "$unformatted" ]; then
	echo "not gofmt-clean:" >&2
	echo "$unformatted" >&2
	exit 1
fi

echo "== go vet"
go vet ./...

echo "== go test"
go test ./... -timeout 300s

echo "== go test -race"
go test -race ./... -timeout 600s

if [ "$run_fuzz" = true ]; then
	echo "== fuzz (10s per target)"
	for target in \
		"./internal/scanners/secrets FuzzScan" \
		"./internal/yamlpos FuzzParse" \
		"./internal/scanners/workflows FuzzWorkflowRules" \
		"./internal/scanners/config FuzzCheckDockerfile" \
		"./internal/scanners/config FuzzCheckCompose"; do
		set -- $target
		echo "-- $2"
		go test "$1" -run '^$' -fuzz "^$2\$" -fuzztime 10s
	done
fi

echo "all checks passed"
