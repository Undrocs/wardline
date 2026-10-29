# Contributing to Wardline

Wardline is proprietary, source-available software owned by Undrocs. The source
is published for transparency and security review. **No license is granted to
modify, redistribute or repackage it** (see [LICENSE](LICENSE)).

Because of that, contributions are accepted only after the contributor agrees
that their contribution may be distributed by Undrocs as part of this
proprietary project. Do not submit code you cannot license on those terms, and
do not paste code from projects with incompatible licenses.

## Before you start

- Read [docs/architecture.md](docs/architecture.md),
  [docs/threat-model.md](docs/threat-model.md) and
  [docs/limitations.md](docs/limitations.md).
- For a security issue in Wardline itself, follow [SECURITY.md](SECURITY.md) and
  report privately. Do not open a public issue.
- For a false positive or a missing detection, open an issue with a minimal
  synthetic fixture. Never include a real credential.

## Development environment

Requires Go 1.23 or newer. There are no other build tools, generators or
vendored binaries.

```sh
go build ./...
go test ./...
go vet ./...
gofmt -l .          # must print nothing
go test -race ./...
```

Useful focused commands:

```sh
go test ./internal/scanners/secrets/ -run TestDetectsEachRule -v
go test ./internal/scanners/config/ -run FuzzCheckDockerfile -fuzz FuzzCheckDockerfile -fuzztime 30s
go test ./internal/yamlpos/ -run FuzzParse -fuzz FuzzParse -fuzztime 30s
```

`scripts/check.sh` runs formatting, vet, tests and the race detector in one
step; `scripts/smoke.sh` builds the binary and verifies the documented exit
codes against the fixtures. Two optional passes:

```sh
scripts/check.sh --fuzz      # 10s per fuzz target
scripts/check.sh --release   # build and verify Linux + Windows release archives
```

`scripts/release-smoke.sh` can be run on its own; it builds one Linux archive
(and executes it) and one Windows archive, then checks that the verifier rejects
a Windows archive without `wardline.exe`, a missing file, a mismatched platform
name and an unsafe tag.

## Continuous integration

`.github/workflows/ci.yml` runs formatting, vet, `go mod tidy` verification,
tests on Linux/macOS/Windows, the race detector, a time-boxed fuzz pass, the
smoke script, the self-scan and the release-packaging check.
`.github/workflows/security.yml` runs CodeQL, `govulncheck` and dependency review.
Actions are pinned to full commit SHAs; add a new action only with its full SHA
and a version comment.

## Non-negotiable rules

These constraints exist because Wardline scans hostile input, and a defect can
leak the very secrets it is meant to find.

1. **Never execute scanned content.** No `os/exec`, no shells, no package
   managers, no Docker, no evaluation of repository scripts or hooks. Scanning
   is static analysis only.
2. **Never write to the scanned repository.** Scanners open files read-only.
   The only file Wardline may create is the report the user requested with
   `--output`.
3. **Never print a secret.** Build evidence with `security.MaskSecret` and
   `security.SanitizeEvidence`; never format a raw match, a request body or a
   configuration value into a message, log line or error. Tests must assert the
   absence of the raw value, not just the presence of the masked one.
4. **Never fabricate coverage.** If a check did not run, record a
   `scanners.SkippedCheck` with a reason. If a scanner failed, return the error
   and let the engine mark the scan incomplete. Never report a skipped or failed
   check as clean.
5. **Never add telemetry or auto-upload.** The only permitted network call is
   the OSV query in the dependency scanner, and it must be disabled entirely by
   `--offline` and `network.enabled: false`.
6. **Keep findings deterministic.** Stable ordering, stable fingerprints
   derived from rule ID, path and structural locator. Tests must not depend on
   wall-clock time or map iteration order.
7. **Do not change the license or add dependencies casually.** New modules need
   license review, an entry in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)
   and a reason in the pull request. Permissive licenses only, and no new
   dependency when the standard library suffices — the CLI deliberately uses
   `flag` rather than a framework.

## Adding a rule

1. Choose the next unused ID in the scanner's namespace (`WL-SEC-*`,
   `WL-WF*`, `WL-CFG-*`). IDs are never reused.
2. Add the rule metadata: title, description, impact, remediation, severity,
   confidence and references.
3. Implement the detection. Prefer structure over regular expressions; when a
   pattern is unavoidable, keep it anchored, avoid nested quantifiers and gate
   it with a keyword or a literal prefix so large files stay cheap.
4. Add tests: one that fires, one near miss that must not fire, and a case for
   the evidence redaction.
5. Document the rule in [docs/rules.md](docs/rules.md).
6. Add a synthetic trigger to `testdata/vulnerable`; the engine test
   `TestVulnerableFixtureExercisesEveryOfflineRule` fails if any catalogued rule
   never fires. Fixtures stay under `testdata/`, which the repository's own
   `.wardline.yaml` excludes.
7. Store the credential-shaped value in a `.tmpl` file with a `{{PLACEHOLDER}}`
   marker and add the value to `internal/fixtures`. The repository must never
   contain a string that matches a vendor credential pattern, otherwise secret
   scanners and GitHub push protection reject the push.

## Tests and fixtures

The vulnerable fixture is stored as templates (`*.tmpl`) because a committed
string that matches, for example, a Slack webhook URL is indistinguishable from
a leaked credential. Tests materialise it automatically; to scan it by hand:

```sh
go run ./internal/fixtures/cmd/materialize /tmp/wardline-fixture
go run ./cmd/wardline scan /tmp/wardline-fixture --offline
```

- Fixtures live under `testdata/` and are **synthetic only**. Use obviously
  fake values (for example `AKIA` + `EXAMPLE`-style bodies), never a real key,
  even an expired one.
- Prefix test helpers that could collide with production identifiers (for
  example `findingRuleIDs` rather than `ruleIDs`).
- Use `t.TempDir()` for anything that writes, and `context.Background()` in
  tests: the module targets Go 1.23, so `t.Context()` is unavailable.
- Assert ordering rather than duration values; microsecond assertions are
  flaky.
- New parsers need a fuzz target. Fuzz failures are committed to
  `testdata/fuzz/...` as regression inputs — keep them.
- Any new report field needs a test in `internal/reports` and, if it changes
  the schema, a `CHANGELOG.md` entry.

## Style

- `gofmt` clean, `go vet` clean, no unused code.
- Small interfaces; dependencies point inward (`internal/security` and
  `internal/findings` know nothing about scanners).
- Comments explain *why*, not *what*. Every exported identifier has a doc
  comment.
- Errors carry context (`fmt.Errorf("read configuration: %w", err)`) and are
  surfaced to the user with an actionable message.
- No emoji, no ANSI escapes outside the terminal renderer, no absolute paths in
  output.

## Commit and pull request conventions

- One logical change per commit; subject in the imperative mood
  (`fix: mask short vendor keys`).
- Describe **what changed, why, and how it was verified** — include the
  commands you ran and their exit codes.
- State explicitly anything you could not verify (for example live OSV API
  behaviour or a Windows build) instead of implying it was tested.
- Do not bump versions, tag releases or edit `go.mod` versions as part of an
  unrelated change.
- Never commit binaries, report artifacts, coverage files or editor state.

## Review checklist

- [ ] No secret can reach any output, including errors and verbose logs.
- [ ] Failure, skip and cancellation paths are covered by tests.
- [ ] Exit codes match the documented contract (0/1/2/3).
- [ ] Output is deterministic and repository-relative.
- [ ] New rules are documented and have positive and negative tests.
- [ ] `gofmt`, `go vet`, `go test ./...` and `go test -race ./...` pass.
