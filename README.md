# Wardline

Wardline is a security-auditing command-line tool for local repositories. One
command scans a working tree for exposed secrets, known-vulnerable dependencies,
risky GitHub Actions workflows and insecure container/application configuration,
then reports every observation through a single normalised finding model.

Wardline is proprietary, source-available software by Undrocs. See
[License & Intellectual Property](#license--intellectual-property).

> **Status: MVP, pre-release.** There are no published binaries or tagged
> releases yet. Build from source (below). Everything documented here has been
> exercised against the synthetic fixtures in `testdata/`; the sections that
> follow state plainly what is not covered.

## Contents

- [What it checks](#what-it-checks)
- [Build from source](#build-from-source)
- [Usage](#usage)
- [Exit codes](#exit-codes)
- [Configuration](#configuration)
- [Reports](#reports)
- [What Wardline does not do](#what-wardline-does-not-do)
- [Documentation](#documentation)
- [License & Intellectual Property](#license--intellectual-property)

## What it checks

| Scanner | Command | Coverage |
| --- | --- | --- |
| Secrets | `wardline audit secrets` | 25 credential rules (cloud keys, VCS/CI tokens, payment keys, private key blocks, connection strings, committed credential files) with vendor-specific validators, entropy/placeholder filtering and mandatory redaction. Also covers quoted keys in JSON/TOML/YAML, YAML block scalars (`key: |`) and credentials passed as command-line arguments. |
| Dependencies | `wardline audit dependencies` | Go modules (`go.mod` plus `go.sum` hints, `go.work` workspaces, `replace`/`exclude` directives) and npm lockfiles (`package-lock.json` v1/v2/v3, with stale-lockfile and non-registry-source detection) resolved to the versions a build would actually use, then queried against OSV.dev. |
| Workflows | `wardline audit workflows` | Structural audit of `.github/workflows/*.yml`: token permissions, `pull_request_target`, script injection, unpinned actions, artifact trust, self-hosted runners. Workflows are parsed, never executed. |
| Config | `wardline audit config` | Dockerfile, `docker-compose.yml`, and selected application settings: root users, privileged containers, disabled security profiles, embedded credentials, dangerous mounts, world-writable permissions, published sensitive ports, disabled TLS verification. |

Rule identifiers are stable and namespaced (`WL-SEC-*`, `WL-DEP-*`,
`WL-WF*`, `WL-CFG-*`). The full catalogue is in [docs/rules.md](docs/rules.md).

## Build from source

Requires Go 1.23 or newer.

```sh
git clone https://github.com/Undrocs/wardline.git
cd wardline
go build -o wardline ./cmd/wardline
./wardline version
```

Version metadata is injectable at build time:

```sh
go build -ldflags "\
  -X github.com/Undrocs/wardline/internal/version.Version=0.1.0 \
  -X github.com/Undrocs/wardline/internal/version.Commit=$(git rev-parse HEAD) \
  -X github.com/Undrocs/wardline/internal/version.BuildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -o wardline ./cmd/wardline
```

Release archives for all supported platforms are built locally with
`scripts/build-release-archive.sh` and checked with
`scripts/verify-release-archive.sh`; see [docs/releasing.md](docs/releasing.md).

Only one third-party Go module is used (`github.com/goccy/go-yaml`, MIT); every
other dependency is the Go standard library. See
[Third-party notices](docs/limitations.md#third-party-notices).

## Usage

```sh
wardline scan [path]                     # scan a directory (default: .)
wardline audit secrets [path]            # run a single scanner
wardline audit dependencies [path]
wardline audit workflows [path]
wardline audit config [path]
wardline version [--format text|json]
wardline help [command]
```

Flags shared by `scan` and `audit`:

| Flag | Meaning |
| --- | --- |
| `--format terminal\|json\|markdown\|sarif` | Report format (default `terminal`). |
| `--output <path>` | Write the report to a file (mode `0600`) instead of stdout. |
| `--severity <level>` | Hide findings below this severity. Suppressed findings stay visible, flagged. |
| `--fail-on <level>` | Policy threshold for exit code 1 (default `high`). |
| `--min-confidence <low\|medium\|high>` | Hide low-confidence findings from the report. |
| `--exclude <glob>` | Additional exclusion glob (repeatable). |
| `--config <path>` | Explicit configuration file. |
| `--offline` | Perform no network requests; online checks are reported as skipped. |
| `--timeout <duration>` | Overall scan timeout (`90s`, `2m`, …). |
| `--no-color` | Disable ANSI colour. |
| `--quiet` | Print nothing on a clean, complete scan. A scan that found something, or did not finish, is always printed. |
| `--summary` | Print severity counts and skipped checks only, without the per-finding detail. |
| `--fail-incomplete` | Exit `3` when the scan did not cover everything (skipped scanners, partial coverage, skipped checks), even if no finding met the policy threshold. |
| `--strict` | Apply the CI policy: every configured scanner must be enabled, `failOn` may not be weaker than `high`, and repository configuration may not disable or suppress checks that CI requires. Every override is listed in the report. |
| `--allow-custom-endpoint` | Approve a non-official OSV endpoint supplied by configuration. Without it, a repository that points `network.osvEndpoint` anywhere else is refused with exit `2`. |
| `--verbose` | Emit diagnostics to stderr. |

Examples:

```sh
wardline scan . --offline                       # fully local scan
wardline scan . --format sarif --output out.sarif
wardline scan . --fail-on medium --exclude "vendor/**"
wardline audit workflows .github --format markdown
wardline scan . --strict --fail-incomplete       # CI gate
wardline scan . --quiet                          # silent unless something is wrong
```

`--offline` never reports a clean dependency result: the dependency scanner is
reported as *skipped* with its reason, and the report is marked incomplete.

`--strict` resolves the repository's `.wardline.yaml`, applies the CI policy and
then the command-line flags. A repository cannot silently weaken its own audit
by disabling a scanner, adding a suppression or lowering the threshold: those
overrides are neutralised and listed under *Policy* in every report format.

`--fail-incomplete` turns a partial scan into an operational failure (exit `3`).
CI should combine it with `--strict`: together they mean "every check ran, and
anything that did not run fails the build".

`--severity` and `--min-confidence` are reporting filters. The `--fail-on`
policy is always evaluated over every unsuppressed finding, so filtering the
output can never turn a failing scan into a passing one.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Scan completed; no finding met the policy threshold. Check the report for incomplete-coverage warnings. |
| `1` | Scan completed; at least one finding met or exceeded `--fail-on`. |
| `2` | Invalid command, flag or configuration file; the target is a file rather than a directory. |
| `3` | The scan could not complete: the target does not exist, an I/O or report-write error, a scanner failure, cancellation or timeout, or `--fail-incomplete` was set and coverage was partial. |

A scan that fails or is cancelled exits `3`, never `0`. Findings are retained
when a partial scan still has results, and the report records which scanners ran,
were skipped or failed and why.

## Configuration

Wardline reads `.wardline.yaml` from the scan target (or `--config`). Every
setting is optional.

```yaml
version: 1

scanners:
  secrets: true
  dependencies: true
  workflows: true
  config: true

exclude:
  - "vendor/**"
  - "testdata/**"

limits:
  maxFileSize: 2MiB
  maxFiles: 100000
  workers: 8

severity:
  failOn: high

report:
  format: terminal
  minSeverity: info

timeouts:
  scan: 5m
  http: 20s

network:
  enabled: true
  osvEndpoint: https://api.osv.dev

rules:
  disable: ["WL-SEC-008"]
  severity:
    WL-CFG-007: low

suppressions:
  - rule: WL-WF004
    path: ".github/workflows/*.yml"
    reason: "Actions are refreshed by Dependabot; reviewed in the updating pull request."
  - rule: WL-SEC-023
    path: "docs/examples/**"
    expires: "2026-12-31"
    reason: "Documentation examples use obviously fake placeholders."
```

Invalid configuration aborts before any scanner runs and lists every problem
with its field path. Suppressions require a `reason`; expired suppressions are
ignored so the finding reappears.

Because this file lives in the repository being audited, it is treated as
untrusted input:

- a non-official `network.osvEndpoint` is refused unless the operator passes
  `--allow-custom-endpoint`; plain HTTP, loopback, private-range and cloud
  metadata addresses are refused even then;
- under `--strict`, disabling a scanner, suppressing a rule or lowering
  `severity.failOn` below `high` does not take effect, and each attempted
  override is reported;
- every disabled scanner is listed in the report, whatever the mode.

## Reports

- **Terminal** — grouped by severity with locations, evidence and remediation,
  plus an explicit `INCOMPLETE` banner when coverage was partial.
- **JSON** — `schemaVersion` `1.0`; includes tool, scan, network, scanner,
  finding and summary objects.
- **Markdown** — shareable summary with severity counts and a findings table.
- **SARIF 2.1.0** — one rule per rule ID, one result per finding, stable
  partial fingerprints, severity mapped to SARIF levels. Output for the
  synthetic fixtures validates against the official OASIS 2.1.0 schema.

All formats redact secrets. Evidence keeps a recognisable prefix and masks the
remainder (for example `ghp_••••••uG8i`); private key blocks are reported as
the key header only (for example `private key block: -----BEGIN … PRIVATE KEY-----`)
without any key material.

Finding locations are always repository-relative. The scan target is reduced
before it is stored: a relative argument is kept as supplied (`.`,
`testdata/vulnerable`), an absolute path collapses to its final element, and a
path at or above the home directory becomes `<home directory>` (or
`<absolute path>` for a filesystem root). A report committed to CI therefore
does not disclose the directory layout or user name of the machine that produced
it.

`--output` writes atomically: the report is rendered to a temporary file in the
destination directory, flushed, and renamed over the target with mode `0600`.
An existing file keeps its content if rendering fails, a symlink or other
non-regular destination is refused, and a partially written report is never
visible.

## What Wardline does not do

- It does not read Git history — only the working tree. A secret that was
  deleted from a file but remains in history is not detected.
- It does not execute scanned code, install dependencies, run builds or invoke
  project scripts. Scanners are read-only.
- It does not claim completeness. Pattern and rule based detection misses
  things; a clean report is not a security guarantee.
- It does not assign official CVSS scores. Severity ratings are Wardline's own;
  dependency findings quote advisory data when available.
- It does not upload code, secrets or findings anywhere, and has no telemetry.
  Online dependency checks send only `ecosystem`, `name` and `version` to
  OSV.dev, and the report records that destination explicitly.

See [docs/limitations.md](docs/limitations.md) for the detailed list.

## Documentation

| Document | Contents |
| --- | --- |
| [docs/architecture.md](docs/architecture.md) | Package layout, data flow, concurrency, determinism, report schema. |
| [docs/threat-model.md](docs/threat-model.md) | Assets, adversaries, trust boundaries, and the threats Wardline itself must resist. |
| [docs/rules.md](docs/rules.md) | Every rule ID, severity, confidence, rationale and remediation. |
| [docs/limitations.md](docs/limitations.md) | Known gaps, environment assumptions, third-party notices. |
| [SECURITY.md](SECURITY.md) | How to report a vulnerability in Wardline. |
| [docs/releasing.md](docs/releasing.md) | Release preconditions (tag protection, approval), archive layout, verification. |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Build, test, fuzz and review conventions. |
| [CHANGELOG.md](CHANGELOG.md) | Change history. |

## License & Intellectual Property

Copyright © 2026 Undrocs. All rights reserved.

Wardline is proprietary, source-available software developed by Undrocs.

The source code is publicly accessible for transparency, security review, and educational inspection.

No license is granted to modify, redistribute, sublicense, commercially exploit, or repackage this software.

The Wardline and Undrocs names, logos, and branding may not be used to impersonate or misrepresent an official Undrocs product.

All rights not expressly granted are reserved.
