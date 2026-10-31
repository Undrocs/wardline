# Architecture

Wardline is a single static binary. It reads a directory, runs four independent
scanners, normalises their output into one finding model, evaluates a policy,
and renders the same report in four formats.

Nothing in the scan path executes project code, writes to the scanned tree, or
talks to the network unless dependency scanning is enabled and not `--offline`.

## Package layout

```
cmd/wardline/            entrypoint: signal handling, exit-code propagation
internal/version/         build metadata (ldflags-injectable)
internal/cli/             argument parsing, command dispatch, output handling
internal/config/          .wardline.yaml schema, validation, defaults
internal/engine/          file collection, scanner orchestration, rule policy
internal/findings/        Severity/Confidence, Finding, dedupe, fingerprints
internal/security/        redaction, verified bounded file reads, path and binary checks
internal/netguard/        outbound destination policy (scheme, host class, dial, redirects)
internal/scanners/        Scanner interface and shared request/result types
internal/scanners/secrets
internal/scanners/dependencies
internal/scanners/workflows
internal/scanners/config
internal/osv/             OSV.dev batch client (retry, cache, size limits)
internal/yamlpos/         line-aware YAML tree used by two scanners
internal/reports/         report model and terminal/JSON/Markdown/SARIF writers
internal/fixtures/        materialises the synthetic fixtures for tests and smoke checks
testdata/                 synthetic fixtures; credential values live in *.tmpl templates
```

Dependencies point inward: scanners depend on `findings`, `security` and shared
scanner types; the CLI depends on engine and reports; nothing depends on the
CLI. `internal/reports` never imports a concrete scanner.

## Data flow

```
main
 └─ cli.Run
     ├─ flag parsing / reordering (positional path may precede flags)
     ├─ config.Discover or config.Load ── invalid → exit 2, no scanning
     ├─ endpoint approval + strict policy (repository config is untrusted)
     ├─ engine.Run(ctx, Options)
     │   ├─ walk: bounded, symlink-aware, exclusion-aware file collection
     │   ├─ for each enabled scanner (bounded worker pool):
     │   │   ├─ secrets.Scan        → findings + skipped checks
     │   │   ├─ dependencies.Scan   → osv.Client → findings + skipped checks
     │   │   ├─ workflows.Scan      → yamlpos → rules → findings
     │   │   └─ config.Scan        → Dockerfile/compose/app-config rules
     │   ├─ per-rule severity overrides, rule disables, suppressions
     │   └─ findings.Dedupe + findings.Sort
     └─ reports.Build → renderer (terminal | json | markdown | sarif)
         └─ exit code: operational failure > policy failure > success
```

### File collection

One walk feeds every scanner so the reported file count, byte count and
exclusions are consistent. The walker:

- refuses to follow symlinks that escape the scan root, and never descends into
  symlinked directories;
- applies default exclusions (VCS directories, dependency caches, build output)
  and user globs, all relative and slash-separated;
- skips binary files (NUL byte in the first 8 KiB) and oversized files;
- enforces `limits.maxFileSize` (oversized files are counted and skipped) and
  `limits.maxFiles` (exceeding it is an operational error: a truncated file list
  would make the scan silently incomplete);
- honours `ctx` cancellation between entries.

Each scanned file carries its `os.FileInfo` from the walk. Scanners re-open the
file with `security.ReadFileLimitedVerified`, which opens with `O_NOFOLLOW` where
the platform supports it and then compares identity and size
(`os.SameFile`, `Size()`) with the walk's snapshot. A file that was replaced,
symlinked or grown between the walk and the read is rejected with
`ErrFileChanged` and reported, so a scan cannot be redirected at a different
file by a concurrent writer.

### Scanner contract

Every scanner implements:

```go
type Scanner interface {
    Name() string
    Scan(ctx context.Context, req *Request) (*Result, error)
}
```

`Result` carries findings, warnings, an optional error message, and
`Skipped []SkippedCheck` — a check that could not run and the reason. A scanner
that cannot complete returns an error; the engine marks it *failed* but keeps
the findings already produced and continues with the remaining scanners.
Scanner status is one of `ran`, `partial`, `skipped`, `failed`, and every
non-`ran` status makes the report `incomplete`. The traversal contributes to the
same signal: if it had to skip oversized files, unreadable paths or directories
nested deeper than 64 levels, `engine.Result.PartialCoverage` is set and the
report is incomplete too — an unexamined file never counts as clean.

A panic inside a scanner is recovered and converted into a failed scanner that
records the panic value and no findings; no stack trace or raw input reaches
the report, and the CLI never crashes on hostile input.

### Concurrency

The four scanners run concurrently: they are independent, and overlapping the
network wait of the dependency scanner with the local scanners shortens
wall-clock time. Each scanner writes its findings into its own slot indexed by
scanner position, so the assembled result does not depend on completion order.

Within a scanner, the secrets scanner — the only one that inspects every byte of
every file — processes files with a fixed-size worker pool sized by
`limits.workers` (default: one worker per CPU, capped at eight). The other
scanners read only the files they own and do it sequentially. Workers write into
indexed slices rather than shared maps, so results are independent of
scheduling. `go test -race ./...` is clean.

### Determinism

Reports are byte-identical for identical inputs and configuration:

- findings are sorted by severity (desc), path, line, rule ID;
- duplicates are removed using a key of rule ID, path and structural locator;
- rule ordering in SARIF follows first appearance after sorting;
- timestamps and durations are the only non-deterministic fields, and tests
  normalise them before comparison.

### Fingerprints

Each finding has an `id` derived from `ruleID|path|locator`. The locator is
structural — a YAML path such as `jobs.release.permissions`, a package
coordinate, a credential file reason, or (for inline secrets) the masked token
itself — so a fingerprint survives unrelated edits and line shifts. Two
consequences are intentional:

- the same credential repeated in one file is reported once, because it has the
  same locator;
- rotating a credential changes its fingerprint, because the masked form
  changes, so a baseline never hides a newly exposed value.

Fingerprints are stable within a schema version and are emitted in SARIF as
`wardlineFindingId/v1`.

## Secrets handling

`internal/security` is the only place allowed to touch raw secret material:

- `MaskSecret` keeps a short prefix for identification and masks the rest.
- `RedactCredentials` masks assignments (`password=`, `api_key:`), URL userinfo,
  HTTP auth schemes (`Authorization: Bearer …`), credentials passed as separate
  command-line arguments (`curl -u user:pass`, `--password …`),
  vendor-prefixed tokens, long random tokens and private key headers. It is
  idempotent, because reporters run it again as a safety net.
- `RedactEvidence` redacts first and truncates second, so a credential can never
  be cut in half and survive as an unrecognised fragment.
- `SanitizeEvidence` strips control characters, collapses whitespace and bounds
  length.
- Scanners never place a raw match into `findings.Finding`; evidence is built by
  the masking helpers only. Finding constructors (`newConfigFinding`,
  `newFinding`, secrets' `buildFinding`) apply `RedactEvidence` themselves, so a
  new rule cannot forget it.
- Reporters redact every string again before rendering.
- No scanner logs match contents. `--verbose` diagnostics name rules, files and
  counts, never values.
- Nothing is written to disk except the report the user asked for (`--output`,
  created with mode `0600`).

## Network

Dependency scanning is the only network user. `internal/netguard` decides what
may be contacted, and it is applied at three levels:

1. **Configuration.** `network.osvEndpoint` comes from the scanned repository, so
   it is validated before a client is built: the default is the official HTTPS
   endpoint, a custom endpoint requires explicit approval
   (`--allow-custom-endpoint`), and plain HTTP, loopback, link-local, private,
   unique-local and cloud-metadata addresses are refused even with approval.
2. **Dial.** Every connection passes through a `net.Dialer` control function that
   re-checks the resolved IP address, which closes the DNS-rebinding gap between
   the URL check and the connection.
3. **Redirects.** Each redirect target is re-validated against the same policy;
   a redirect is the obvious way for a permitted host to reach a forbidden one.

The OSV client:

- posts only `{ecosystem, name, version}` triples in batches of 500;
- sends a fixed `User-Agent` (`wardline/<version>`) that contains no repository,
  path or user information;
- caps response bodies (32 MiB), retries 5xx and transport errors twice more
  (three attempts in total) with backoff, and does not retry 4xx responses;
- distinguishes rate limiting (`429`, surfaced as `osv.ErrRateLimited`) from a
  malformed or rejected request;
- treats a batch response whose result count differs from the query count as an
  error rather than as an empty (apparently clean) result;
- respects the scan context, so cancellation and `--timeout` interrupt requests;
- caches vulnerability detail lookups per run.

A lookup that fails after the first batch keeps the results already obtained,
names the packages that were never queried, and records a skipped check. A
failed advisory detail request keeps its finding (the vulnerability was
detected) and is reported as reduced metadata instead — the two failure modes
are reported separately.

`--offline`, or `network.enabled: false`, prevents construction of an HTTP
client at all. The dependency scanner then reports a skipped check, the report
records `network.enabled: false`, and exit code 0 is accompanied by an
`INCOMPLETE` banner.

## Report model

`schemaVersion` is `1.0`. The JSON document is:

| Field | Contents |
| --- | --- |
| `tool` | Name, version, commit, build date, Go version, platform. |
| `scan` | Target (relative or `.`), mode, timestamps, duration, file/byte counts, offline flag, config file. |
| `network` | Whether network was enabled, destinations contacted, disclosure sentence. |
| `scanners` | One entry per scanner: status, findings count, scope, notes, skipped checks, error. |
| `findings` | Normalised findings, sorted, deduplicated, secrets redacted. |
| `summary` | Counts by severity, suppressed counts, scanner status tallies, `incomplete`, policy outcome. |
| `summary.policy` | The evaluated failure threshold, whether it was met, and why. |
| `policyNotices` | Policy decisions the operator must see, including overrides that `--strict` neutralised. |
| `warnings` / `errors` | Non-fatal diagnostics and scanner failures. |
| `limitations` | Scan-level caveats that always include the working-tree and heuristic-detection statements. |

SARIF maps each rule to a reporting descriptor, each finding to a result with
`ruleIndex`, `level` (`error`/`warning`/`note`), a `partialFingerprints` entry,
and a physical location with a repository-relative URI. Rule help text carries
the remediation. Machine-readable output never includes ANSI escapes or absolute
paths.

## Exit codes

`cli` computes the exit code in this order:

1. `3` — the engine returned an operational failure (I/O, scanner error,
   timeout, cancellation).
2. `2` — usage or configuration error, detected before scanning.
3. `1` — the policy threshold was met.
4. `0` — otherwise.

`--fail-incomplete` adds a third outcome: a scan that did not cover everything
exits `3` even when no finding met the threshold.

The policy is evaluated over every unsuppressed finding in the scan, regardless
of `--severity` or `--min-confidence` filters. Filtering changes what a human
sees, never what fails the build. If a scan is incomplete, the result is never
presented as clean: the terminal renderer prints `INCOMPLETE`, and the JSON
summary sets `"incomplete": true`.

## Extension points

Adding a rule means adding an entry to the relevant rule catalogue
(`WL-SEC-*`, `WL-WF*`, `WL-CFG-*`) with ID, severity, confidence, description,
impact and remediation, plus a test in the scanner's test file. Adding a scanner
means implementing `scanners.Scanner`, registering it in `cli.buildScanners`, and
adding a `SkippedCheck` for every condition under which it cannot run. New rule
IDs must be documented in [docs/rules.md](rules.md).
