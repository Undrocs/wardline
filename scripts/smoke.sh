#!/bin/sh
# Build the binary and verify the documented exit-code contract against the
# synthetic fixtures.
#
# Usage: scripts/smoke.sh
# Requires: go, and nothing else. Never contacts the network (--offline).
set -eu

cd "$(dirname "$0")/.."

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

binary="$tmp/wardline"
echo "== build"
go build -o "$binary" ./cmd/wardline

# The vulnerable fixture keeps its credential-shaped values in templates so that
# no committed file matches a vendor credential pattern. Materialise it first.
echo "== fixture"
vuln="$tmp/vulnerable"
go run ./internal/fixtures/cmd/materialize "$vuln"

fail=0
expect() {
	description=$1
	want=$2
	shift 2
	set +e
	"$@" >"$tmp/out" 2>"$tmp/err"
	got=$?
	set -e
	if [ "$got" -ne "$want" ]; then
		echo "FAIL: $description (exit $got, want $want)" >&2
		cat "$tmp/err" >&2
		fail=1
	else
		echo "ok: $description"
	fi
}

expect "version" 0 "$binary" version
expect "help" 0 "$binary" help
expect "scan --help" 0 "$binary" scan --help
expect "unknown command exits 2" 2 "$binary" nonsense
expect "missing target exits 3" 3 "$binary" scan "$tmp/does-not-exist"
expect "file target exits 2" 2 "$binary" scan "$vuln/go.mod"
expect "clean fixture passes" 0 "$binary" scan testdata/clean --offline --no-color
expect "vulnerable fixture fails policy" 1 "$binary" scan "$vuln" --offline --no-color
expect "audit secrets fails policy" 1 "$binary" audit secrets "$vuln" --offline --no-color
expect "sarif output" 1 "$binary" scan "$vuln" --offline --format sarif --output "$tmp/report.sarif"
# Audit-policy flags: a strict scan of the vulnerable fixture still fails, and an
# incomplete scan can be turned into an operational failure.
expect "strict scan of the vulnerable fixture fails policy" 1 "$binary" scan "$vuln" --offline --no-color --strict
expect "fail-incomplete turns partial coverage into exit 3" 3 "$binary" scan testdata/clean --offline --no-color --fail-incomplete
expect "offline scan without fail-incomplete still succeeds" 0 "$binary" scan testdata/clean --offline --no-color

# Reports must never contain a raw fixture credential.
if grep -q "sk_live_" "$tmp/report.sarif"; then
	echo "FAIL: SARIF report contains an unmasked credential" >&2
	fail=1
else
	echo "ok: SARIF report is redacted"
fi

if [ "$fail" -ne 0 ]; then
	echo "smoke checks failed" >&2
	exit 1
fi
echo "smoke checks passed"
