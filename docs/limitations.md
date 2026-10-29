# Limitations

Wardline is a static analysis tool. This page lists what it cannot do, the
assumptions it makes about the environment, and the disclosures that apply to
this MVP build. Read it before relying on a scan result.

## Scope and detection

- **Working tree only.** Wardline does not read Git history, reflogs, stashes,
  remotes, packed objects or deleted branches. A credential removed from a file
  but present in an earlier commit is not detected. Use a history-aware secret
  scanner alongside Wardline if that matters for your repository.
- **Pattern and rule based.** Detection is regular expressions, structural YAML
  inspection and simple heuristics. There is no data-flow or taint analysis, no
  type inference and no symbolic execution. Obfuscated, encoded, split or
  dynamically constructed secrets and vulnerabilities are missed.
- **Local development values are reported at low confidence.** A connection
  string whose host is `localhost`, `127.0.0.1` or a Compose service name is
  reported (the password is still a credential) with confidence `low`, and
  `--min-confidence medium` hides it. `.example`, `.invalid` and documentation
  placeholders (`changeme`, `your-api-key`, `${VAR}`, repeated characters) are
  still skipped, as are values where a placeholder word such as `fake` or
  `dummy` stands alone; a real token that merely contains those letters is
  reported.
- **Some literal shapes are still missed.** Generic key/value detection needs a
  quoted value: `config.password = "…"` is caught, `config.password = variable`
  is not (and cannot be told apart from ordinary code). YAML block scalars whose
  value is not a single line, values assembled at runtime from several literals,
  and credentials in formats with no recognisable key name remain invisible.
- **No exploitability analysis.** A reported dependency vulnerability is a
  version match against an advisory. Wardline does not determine whether the
  vulnerable function is reachable from your code.
- **No vulnerability database of its own.** Dependency findings depend entirely
  on OSV.dev coverage and on the advisory's own metadata, including whether it
  publishes a severity rating.
- **No Kubernetes, Terraform, Helm, CloudFormation or non-GitHub CI support.**
  Kubernetes/Helm YAML is read only by the generic TLS-verification check
  (`WL-CFG-021`); it is not audited for pod security, RBAC or image policy.
- **No container image or runtime scanning.** Wardline inspects Dockerfiles and
  Compose files as text; it never pulls, builds or runs an image.
- **Severity is Wardline's assessment.** For secrets, workflows and
  configuration, severities are editorial judgements about impact, expressed on
  a CVSS-like scale. They are not CVSS scores and must not be presented as
  such. Dependency findings quote advisory data where available, labelled as
  such.
- **A clean scan is not proof of security.** Absence of findings means no rule
  matched. It does not mean the repository is secure.

## Coverage reporting

- Every scanner reports its status: `ran`, `partial`, `skipped` or `failed`.
  A scan is marked incomplete when any scanner failed, was skipped or recorded a
  skipped check. The terminal renderer prints an `INCOMPLETE` banner and the
  JSON summary sets `"incomplete": true`.
- Exit code 0 does not imply complete coverage. Read `summary.incomplete` and
  `scanners[].skipped` in machine-readable output.
- Files larger than `limits.maxFileSize`, binary files and excluded paths are
  not scanned. Exclusions are recorded in the report as configuration, not as a
  per-file decision; skipped oversized files, unreadable paths and directory
  trees deeper than 64 levels additionally mark the scan incomplete, because
  unexamined content must never be reported as clean.
- The secret scanner bounds its work per file: a single line longer than 8 KiB
  is only partially searched, more than 8 matches on one line and more than 100
  findings in one file stop further matching. Each of those cases is recorded as
  a skipped check, so the report says *partial* instead of *clean*.
- `--fail-incomplete` turns any of these conditions into exit code `3`. CI
  should use it together with `--strict`; without it an incomplete scan can
  still exit `0`, and the report is the only place that says so.

## Dependencies

- **Lockfiles are required for exact versions.** `go.mod` supplies module
  requirements and `go.sum` supplies resolved versions; npm requires
  `package-lock.json` or `npm-shrinkwrap.json` (v1/v2/v3 layouts supported).
  Without a lockfile the npm scanner reports a skipped check instead of guessing
  versions from a semver range.
- **Go replacements are resolved, but not always checkable.** `replace`
  directives (version bump, module swap, local path) and `exclude` directives in
  `go.mod`, and `replace`/`use` in `go.work`, are applied before lookup, so the
  versions reported are the ones a build would use. A module replaced by a local
  directory has no published version to query: it is listed as a skipped check
  and its contents are not audited.
- **Newer lockfile formats are refused.** `lockfileVersion` above 3 is reported
  as an error for that file instead of being parsed on a best-effort basis, and
  entries that resolve to git, `file:` or workspace sources are skipped and
  listed. A dependency declared in `package.json` but missing from the lockfile
  is reported as a stale lockfile.
- Vendored directories and `node_modules` are excluded. A committed
  `node_modules` tree is not audited package by package.
- Only Go and npm ecosystems are queried. Python, Ruby, Rust, Java and other
  ecosystems are out of scope for this MVP and are not silently assumed safe:
  they are simply not inventoried, and the scanner scope line states what was
  checked.
- **A failed lookup is not a clean result.** A dependency batch that fails
  part-way keeps the packages already checked, names the packages that were
  never queried and marks the scan incomplete. A failed advisory *detail*
  request keeps the finding (the vulnerability was detected) with reduced
  metadata and is reported separately.
- OSV results are advisory data. Severity is `unknown` when an advisory
  publishes neither a database-specific severity nor a CVSS v3 vector. CVSS v4
  vectors are not converted; such advisories remain `unknown` rather than being
  approximated.

## Network and offline behaviour

- `--offline` performs no HTTP requests at all. Dependency checks then report a
  skipped check and the scan is marked incomplete. Offline scans never claim
  dependencies are clean.
- Online dependency scanning sends package coordinates — ecosystem, package
  name and resolved version — to the OSV endpoint configured in
  `.wardline.yaml`. Nothing else is transmitted: no source, no paths, no
  findings, no identifiers. The destination is recorded in `report.network`.
- Wardline has no telemetry, analytics, crash reporting or auto-upload, and it
  never writes outside the report path you specify.
- The OSV client retries transient failures (two additional attempts with
  backoff). If the service remains unavailable, the scanner is marked `failed`
  and the process exits 3 with the findings collected so far. A dependency
  check never degrades silently into "no vulnerabilities found".

## Environment assumptions

- Go 1.23 or newer to build; no runtime dependency.
- Wardline expects a POSIX-style filesystem. Paths are reported slash-separated
  and relative to the scan root on every platform.
- Symlinks are never followed, including on Windows junctions. A repository
  that stores real content behind symlinks will be partially scanned; this is
  deliberate, to prevent scans from reaching outside the target.
- Case-insensitive filesystems can make exclusion patterns behave differently
  than on Linux; patterns are matched case-sensitively against relative paths.
- `limits.workers` only parallelises the secrets scanner. The other scanners
  read a small, fixed set of files and do not benefit from a pool.
- The scan timeout defaults to 10 minutes. Very large repositories should raise
  `timeouts.scan`; hitting the timeout exits 3 and is never reported as clean.

## Verification disclosures for this MVP

These statements describe what was and was not exercised while building this
version. They are deliberately explicit:

- **No release artifacts exist.** No binaries, archives, checksums or GitHub
  releases have been published. The version string is `0.0.0-dev` unless build
  metadata is injected.
- **The OSV API was not reachable from the build environment.** All dependency
  behaviour was verified against local HTTP test servers (`httptest`) that
  emulate the documented OSV batch and detail endpoints, including retries,
  chunking, partial responses, malformed bodies and 4xx/5xx handling. Live
  end-to-end validation against `api.osv.dev` has **not** been performed.
- **SARIF output was validated against the official OASIS SARIF 2.1.0 JSON
  schema** (draft-04) using the schema published by the SARIF TC, with zero
  validation errors for the synthetic fixture scan. It has not been tested
  against a specific vendor's SARIF consumer.
- **Workflow and configuration detection is verified against synthetic
  fixtures** in `testdata/` and unit tests. No scan of a real third-party
  repository is included, and no benchmark, precision/recall figure or coverage
  percentage is claimed.
- **Go module downloads in the build environment used `GOPROXY=direct` with
  `GOSUMDB=off`** because the public proxy and checksum database were not
  reachable. `go.sum` pins the single dependency, but the checksum database was
  not consulted in that environment.
- **Fuzzing was time-boxed**, not exhaustive. The committed fuzz targets cover
  the secrets scanner, the YAML tree parser, the workflow rules and the
  Dockerfile/Compose parsers. A corpus entry that previously exposed unredacted
  control characters in workflow evidence is committed as a regression test.

## Third-party notices

Wardline is proprietary software (see [LICENSE](../LICENSE)). It is built with
one third-party Go module:

| Module | Version | License | Use |
| --- | --- | --- | --- |
| [`github.com/goccy/go-yaml`](https://github.com/goccy/go-yaml) | v1.19.2 | MIT | YAML parsing for configuration, workflows and Compose files. |

The full MIT license text ships with the module and is reproduced here as
required:

```
MIT License

Copyright (c) 2019 Masaaki Goshima

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

Wardline does not embed the Gitleaks engine or any of its rule data. Secret
detection rules in `internal/scanners/secrets` were written for this project,
informed by publicly documented credential formats. No Gitleaks code, rules
file or license obligation is carried over. The OSV.dev API is consumed as a
public web service; Wardline bundles no OSV data.

If a future change adds a dependency, its license must be recorded here and in
[THIRD-PARTY-NOTICES.md](../THIRD-PARTY-NOTICES.md) before merge.
