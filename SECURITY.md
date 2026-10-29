# Security policy

Wardline is a security tool. A defect in it can expose the secrets it is meant
to protect, hide a real finding, or execute data from a scanned repository.
Reports about Wardline itself are taken seriously.

## Supported versions

Wardline has not published a release yet. There are no tagged versions, no
binaries and no long-term support branches.

| Version | Supported |
| --- | --- |
| `main` branch (pre-release, `0.0.0-dev`) | Security fixes are applied here. |
| Tagged releases | None exist yet. |

Once releases exist, this table will list the supported lines. Until then,
verify against the current `main` branch before reporting.

## Reporting a vulnerability

**Do not open a public issue, pull request, discussion or gist for a security
problem, and do not include real credentials in any report.**

Use GitHub's private vulnerability reporting for the repository:

1. Go to <https://github.com/Undrocs/wardline/security/advisories/new>.
2. Describe the issue, including the affected version or commit, the affected
   command or package, and reproduction steps.
3. Include a proof of concept that uses **synthetic** data. Never paste a live
   token, key or customer data.

If private reporting is unavailable to you, open a minimal public issue that
asks the maintainers to enable a private channel — without technical detail —
and wait for instructions. There is no published security email address; do not
send reports to addresses found elsewhere, and do not guess one.

### What to include

- Commit SHA or version, operating system and architecture.
- The command line and configuration used (redact anything sensitive).
- A minimal repository layout or fixture that reproduces the issue. Synthetic
  secrets only — for example `ghp_` followed by a clearly fake body.
- Impact assessment: for example "scanner writes an unmasked secret into JSON
  output", "crafted workflow file causes a panic", "symlink escapes the scan
  root", "SARIF output contains an absolute path".

### What to expect

- Acknowledgement of the report through the advisory thread.
- An assessment of severity and affected versions.
- A fix on `main` and, once releases exist, a coordinated advisory and patched
  release. Credit is given unless you ask otherwise.
- No bug bounty or payment is offered or implied.

Please allow reasonable time for a fix before public disclosure. We will keep
you informed of progress in the advisory.

## In scope

- Secret leakage: any path where credential material reaches terminal output,
  logs, reports (JSON/Markdown/SARIF), error messages, temporary files or the
  network.
- Outbound transmission of repository content beyond the documented package
  coordinates sent to the OSV endpoint.
- Any way to make Wardline contact a destination other than the approved OSV
  endpoint — a crafted `.wardline.yaml`, a redirect, DNS rebinding, or a
  proxy that the policy does not account for.
- Code execution, command injection or script execution triggered by a scanned
  repository (workflows, Dockerfiles, lockfiles, configuration).
- Path traversal, symlink escape, or reads outside the scan root.
- Crashes, hangs or unbounded resource use caused by crafted input.
- False negatives caused by a logic error (for example a rule that can never
  fire, or a suppression that hides findings beyond its scope).
- Incorrect exit codes that turn a failed or incomplete scan into a success.
- Dependency, build or CI compromise affecting release artifacts.

## Out of scope

- Findings that a scan of some repository produces — those are data, not
  vulnerabilities in Wardline. Report false positives through a normal issue
  with a synthetic fixture.
- The absence of a detection rule (a missing check is a feature request unless
  the documentation claims coverage).
- Rate limiting or availability of the OSV.dev service.
- Social engineering, physical access, or attacks requiring a compromised host.
- Issues in third-party modules; report them upstream, and inform us if
  Wardline's use of the module is affected.

## Security design expectations

Contributors must preserve these properties; a change that breaks one is a
security regression:

1. No secret, in any form, in any output. Evidence is built only through
   `internal/security` masking helpers.
2. No execution of scanned content, ever. No `exec`, no shells, no package
   managers, no container runtime.
3. Read-only access to the target. No writes, deletes or renames inside a
   scanned repository.
4. No network activity except the documented OSV query, and none at all with
   `--offline` or `network.enabled: false`. The destination is decided by
   `internal/netguard`: official HTTPS endpoint by default, custom endpoints only
   with explicit operator approval, never loopback/private/link-local/metadata
   addresses, redirects re-validated, and the dialled IP checked again at connect
   time.
5. No telemetry, no analytics, no crash upload.
6. Failed, partial or skipped checks must never be reported as clean; the
   corresponding exit code and `summary.incomplete` must reflect reality.
7. Report files are created with mode `0600`, written to a temporary file and
   atomically renamed, refuse symlink or non-regular destinations, and contain
   repository-relative paths only (an absolute target is reduced to a basename,
   `<home directory>` or `<absolute path>`).
8. A scanned repository cannot weaken its own audit: `--strict` neutralises
   disabled scanners, suppressions and lowered thresholds and reports every
   override, and `--fail-incomplete` turns partial coverage into exit code `3`.
9. Scanned files are re-validated at read time (`O_NOFOLLOW` where available,
   inode identity and size compared with the walk) so a concurrent replacement
   cannot substitute the file that is scanned.

See [docs/threat-model.md](docs/threat-model.md) for the full model.
