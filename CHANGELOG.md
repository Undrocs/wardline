# Changelog

All notable changes to Wardline are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
intends to follow [Semantic Versioning](https://semver.org/) once releases
begin.

No version has been released. There are no tags, binaries or checksums yet;
`wardline version` reports `0.0.0-dev` unless build metadata is injected.

## [Unreleased]

### Added

- **CLI** — `wardline scan [path]`, `wardline audit secrets|dependencies|workflows|config [path]`,
  `wardline version [--format text|json]` and `wardline help [command]`; flags
  `--format`, `--output`, `--severity`, `--fail-on`, `--min-confidence`,
  `--exclude`, `--config`, `--offline`, `--timeout`, `--no-color`, `--verbose`,
  and the audit-policy flags `--strict`, `--fail-incomplete`,
  `--allow-custom-endpoint`, `--quiet` and `--summary`.
  Stable exit codes: `0` clean, `1` policy threshold met, `2` usage or
  configuration error, `3` operational failure.
- **Secrets scanner** — 25 rules (`WL-SEC-001`–`WL-SEC-025`) covering cloud,
  VCS, CI, payment and communication credentials, private key blocks, database
  connection strings, generic credential assignments and committed credential
  files. Keyword gating, vendor validators, entropy and placeholder filters;
  evidence is always masked.
- **Dependency scanner** — Go modules (`go.mod` plus `go.sum` resolution) and npm
  lockfiles (`package-lock.json`/`npm-shrinkwrap.json`, v1/v2/v3) queried against
  OSV.dev in batches of 500 with retries, caching and strict response limits.
  Severity comes from advisory data; missing ratings are reported as `unknown`.
- **Workflow scanner** — structural audit of `.github/workflows/*.yml` with 11
  rules (`WL-WF001`–`WL-WF011`) for token permissions, `pull_request_target`,
  script injection, unpinned actions, artifact trust, self-hosted runners and
  remote script piping. Workflows are parsed, never executed.
- **Configuration scanner** — Dockerfile, Docker Compose and selected YAML/JSON
  application settings, with 19 rules (`WL-CFG-*`) for root users, privileged
  containers, disabled security profiles, embedded credentials, unsafe mounts,
  world-writable permissions, exposed datastore ports and disabled TLS
  verification.
- **Unified findings** — one model across scanners: stable fingerprints from
  rule ID, path and structural locator; deduplication; deterministic sorting;
  severity and confidence metadata; remediation text and references.
- **Reports** — terminal, JSON (`schemaVersion` `1.0`), Markdown and SARIF 2.1.0,
  each recording scanner status, skipped checks, network use, warnings, errors
  and scan-level limitations. A partial or failed scan is marked incomplete and
  never rendered as clean.
- **Configuration** — `.wardline.yaml` with scanner toggles, exclusions, size and
  file limits, worker count, policy and reporting thresholds, network settings,
  timeouts, rule disables, severity overrides and suppressions with a mandatory
  reason and optional expiry. Validation reports every problem before scanning.
- **Fixture materialisation** — the vulnerable fixture stores credential-shaped
  values as `*.tmpl` templates that `internal/fixtures` expands at run time, so
  no committed file matches a vendor credential pattern (GitHub push protection
  rejects such branches even for synthetic values).
- **Fixture coverage test** — `TestVulnerableFixtureExercisesEveryOfflineRule`
  scans the vulnerable fixture and fails if any catalogued rule never fires,
  so an unreachable or regressed rule cannot ship; a companion test asserts no
  planted credential appears in any finding field.
- **Tests** — unit tests for every package (redaction, severity mapping, config
  validation, engine orchestration, report output, SARIF structure, CLI exit
  codes), synthetic fixtures for vulnerable and clean repositories, fuzz targets
  for the secrets scanner and the YAML, workflow, Dockerfile and Compose
  parsers, cancellation and symlink coverage, and a race-detector-clean suite.
- **Documentation** — README, architecture, threat model, rule reference,
  limitations, security policy, contributing guide and third-party notices.
- **CI and release scaffolding** — GitHub Actions workflows for build, test,
  vet, race, fuzz smoke and a release matrix across Linux, macOS and Windows on
  amd64 and arm64 with checksum generation. Actions are pinned to full commit
  SHAs and workflows run with read-only token permissions.
- **Release packaging scripts** — `scripts/build-release-archive.sh` and
  `scripts/verify-release-archive.sh` build one platform archive and verify its
  name, layout, binary name (`wardline.exe` on Windows) and version;
  `scripts/release-smoke.sh` exercises both, including the failure cases, and
  `scripts/check.sh --release` runs it with the rest of the suite.
- **Outbound destination policy** — `internal/netguard` validates the OSV
  endpoint, the dialled address and every redirect against one policy.
- **Supply-chain CI** — a `security` workflow runs CodeQL for Go, `govulncheck`
  (pinned version, outside the module graph) on every push, pull request and
  weekly schedule, and `dependency-review-action` on pull requests. Every action
  is pinned to a full commit SHA and permissions are per job. The self-scan job
  additionally runs `--strict` with command-line exclusions and asserts that the
  ignored configuration is reported. CodeQL runs the `security-extended` pack
  with one documented query exclusion (`.github/codeql/codeql-config.yml`):
  `go/weak-sensitive-data-hashing` fires on the finding fingerprint, which hashes
  an already-masked locator and is never used to protect a credential.
- **Strict CI policy** — `--strict` resolves repository configuration, applies a
  CI floor and reports every override it neutralised.

### Fixed

- `--min-confidence` no longer influences the `--fail-on` policy. It was applied
  before the report was built, so hiding a high-severity, medium-confidence
  finding could turn a failing scan into a passing one. Reporting filters are
  now applied in the report writer, and the policy is always evaluated over
  every unsuppressed finding.
- Reports no longer contain the absolute path of the scanned directory: the
  `scan.target` value echoes the path as supplied and the configuration file is
  shown relative to the target.
- `WL-WF003` no longer reports a job-scoped write permission in a workflow that
  only runs on trusted events. A job-scoped write is the documented
  least-privilege pattern; it is still reported when the workflow can be
  triggered by untrusted events.
- Terminal output aligned the severity column by byte count including ANSI
  escape sequences, which shifted every row when colour was enabled.
- Secret scanning and advisory fetching each started one goroutine per file or
  per advisory. Both now use a fixed-size worker pool, so a large repository or
  an advisory list with many identifiers cannot exhaust memory.
- `WL-CFG-009` reports `seccomp:unconfined` and `apparmor:unconfined` instead of
  reusing the capability rule, whose title and remediation did not describe it.
- Configuration rule identifiers are accepted in any letter case; a lowercase
  rule ID previously disabled nothing and said nothing.
- A property test in `internal/security` could fail intermittently because it
  counted repeated characters in the original rather than visible characters in
  the mask.
- A suppression whose `expires` date was today stayed active for one extra day
  at the boundary; it now lapses at 00:00 UTC on the following day. An
  unparseable expiry is treated as expired and reported instead of being
  silently ignored.
- `rules.disable` filtering reused the input slice as its output buffer; it now
  returns a fresh slice so the caller's findings are never mutated.
- The terminal, Markdown and engine de-duplication helpers were three
  hand-written loops; they now use `slices.Compact` and a single
  `partitionSuppressed` helper shared by the renderers.
- The secrets scanner reported truncated lines and match-limit exhaustion only
  as warnings, so a partially scanned file could still produce a `ran` status.
  Both are now skipped checks and make the report incomplete, together with
  binary and unreadable files.
- `WL-CFG-020` claimed that a `.env` file was "committed to the repository" based
  on its presence in the working tree. Git is never executed, so the rule is now
  titled and worded as "present in the scanned tree" and its remediation explains
  how to check tracking.
- A dependency lookup that failed part-way reported only a count of unchecked
  packages; it now names them. Rate limiting (`429`) is reported as such, a batch
  response with the wrong number of results is rejected instead of being read as
  clean, and failed advisory *detail* requests are reported separately from
  never-queried packages.
- Windows release archives contained `wardline` instead of `wardline.exe`, and
  the macOS/Linux archives were built from whatever commit the runner had
  checked out rather than from the requested tag.

- **Dependency resolution** — Go `replace` and `exclude` directives and `go.work`
  `replace`/`use` entries are applied before lookup, so the versions reported are
  the ones a build would resolve. A module replaced by a local path is reported
  as a skipped check instead of being queried at its published version.
- **npm lockfile validation** — quoted-key and stale-lockfile detection, refusal
  of future `lockfileVersion` formats, and explicit skipping of git, `file:` and
  workspace resolutions.
- **Secret detection** — quoted JSON/TOML keys, YAML block scalars, credentials
  passed as separate command-line arguments (`curl -u user:pass`), `api_token`
  keys, and loopback database credentials (reported at `low` confidence instead
  of suppressed).

### Security

- Secrets are redacted in every output format; no code path writes a raw match.
- **Network destinations are policy-controlled.** A repository-supplied
  `network.osvEndpoint` is refused unless the operator approves it
  (`--allow-custom-endpoint`); plain HTTP, loopback, private, link-local and
  cloud-metadata addresses are refused even then, redirects are re-validated,
  and every connection is checked again at dial time against the resolved IP.
- **Report files are written atomically.** The report is rendered to a temporary
  file, flushed, and renamed over the destination with mode `0600`; a symlink or
  other non-regular destination is refused, and a failed render leaves the
  previous report intact.
- **Evidence is redacted before it is truncated**, so a credential can never be
  cut in half and escape the redaction pattern. `Authorization: Bearer …` and
  command-line credential arguments are now masked too.
- **Repository configuration cannot weaken a CI audit.** Under `--strict`, a
  disabled scanner, a suppression or a lowered threshold is neutralised and
  reported, and every disabled scanner is listed in every format.
- **File reads are verified against the walk.** Scanners re-open with
  `O_NOFOLLOW` where available and compare inode identity and size, so a
  concurrent replacement or symlink swap is detected instead of silently
  scanning a different file.
- **Release publishing is gated.** The requested tag is validated and checked out
  explicitly, the built commit is compared with the tag, a tag must be covered
  by a protection rule, publishing waits for the protected `release` environment,
  and existing release assets are never overwritten (`--clobber` removed).
- **Absolute paths no longer leak into reports.** The scan target is reduced to a
  relative path, its basename, `<home directory>` or `<absolute path>`.
- Scanned repositories are treated as untrusted input: no execution, no
  symlink traversal outside the root, bounded reads, bounded YAML nesting and
  bounded HTTP responses.
- No telemetry, analytics or automatic upload of any kind. `--offline` performs
  no network requests and reports online checks as skipped, never as clean.

### Known limitations

- Working-tree scanning only; Git history is not read.
- No live verification against the OSV.dev API was possible in the build
  environment; OSV behaviour is covered by local HTTP test servers.
- No releases, binaries or version tags exist yet. Release publishing requires
  repository tag protection for `v*` and a `release` environment with required
  reviewers; until those are configured the release job refuses to publish.
- Git history is still not scanned, so `--history` (FEAT-001) remains open.

[Unreleased]: https://github.com/Undrocs/wardline/commits/main
