# Threat model

This document states what Wardline protects, what it must never do, and which
threats it explicitly does **not** address. It covers both the threats Wardline
detects in a scanned repository and the threats Wardline itself must resist
while doing so.

## Assets

| Asset | Why it matters |
| --- | --- |
| Credentials found in scanned repositories | A leaked credential is immediately exploitable; Wardline must never make the leak worse. |
| The scanned repository | Wardline is read-only. A scan must not create, modify, delete or reorder any file in the target. |
| The operator's machine | Scanning is performed on developer and CI machines; a hostile repository must not be able to execute code, exhaust memory or write outside the target. |
| The report | Reports are artifacts that may be committed, attached to CI runs or shared; they must not contain secrets or absolute paths. |
| The OSV API and its operators | Wardline sends the minimum data needed, identifies itself, and never floods the service. |

## Attacker model

Wardline assumes the scanned repository content is **untrusted input**. It may
contain deliberately crafted files intended to make the scanner:

- execute code (via workflows, Dockerfiles, Makefiles, lockfiles, `.env`
  files, package metadata);
- follow a path out of the scan root (symlinks, `..` segments, absolute paths
  in Compose volumes or Dockerfile `COPY` sources);
- crash or hang the scanner (deeply nested YAML, giant files, invalid UTF-8,
  pathological regex input, enormous dependency lists);
- reflect a secret into the report in a form the operator cannot recognise as
  a secret;
- cause a false "clean" result that suppresses a real finding.

The operator is trusted to choose the target directory, the configuration file
and the report destination.

## Trust boundaries

```
[operator] --flags/config--> [wardline process]
                                 |  read-only
                                 v
                          [scanned directory]   (untrusted content)
                                 |
                                 | package coordinates only
                                 v
                            [OSV.dev API]       (external, optional)
```

1. **CLI → configuration.** Configuration is parsed and validated before any
   scanning. Unknown fields, bad severities, invalid durations, unsafe
   exclusion patterns (`..`, absolute paths, backslashes) and suppressions
   without a reason are rejected with exit code 2.
2. **Walker → filesystem.** Symlinks are never followed, neither for files nor
   for directories. Exclusion patterns are normalised and must stay inside the
   root. File reads are size-bounded.
3. **Scanners → findings.** A scanner may only produce `findings.Finding`
   values. Evidence is constructed through `internal/security` masking helpers,
   never from a raw match.
4. **Reports → disk/stdout.** Only repository-relative paths and redacted
   evidence are rendered. `--output` files are created with mode `0600`.
5. **Engine → network.** Only the dependency scanner may open a connection, and
   only when `network.enabled` is true and `--offline` is absent. The client
   posts `{ecosystem, name, version}` triples and nothing else.

## Threats Wardline itself must resist

| Threat | Mitigation |
| --- | --- |
| **Code execution from a scanned repository.** A crafted workflow, Dockerfile or lockfile tries to run a command during scanning. | Scanners parse text and structure only. No `exec`, no shell, no package manager, no container runtime is ever invoked. Workflows are parsed with a YAML reader, never run. |
| **Path traversal / symlink escape.** A symlink points at `~/.ssh` or `/etc`. | Symlinks are skipped by the walker; `security.IsWithinRoot` and `security.WithinRootOnce` reject escaping and `..`-bearing paths; Compose and Dockerfile paths are reported as text, never opened. |
| **Memory or CPU exhaustion.** A 5 GiB file, 10⁶ files, deeply nested YAML. | `limits.maxFileSize` (default 2 MiB), `limits.maxFiles` (default 200 000, exceeding it is an error), binary detection, YAML depth limit, bounded response bodies (32 MiB), scan timeout (default 10m) and `--timeout`. |
| **Secret exposure in the report.** A scanner prints the match, a log line, or an error that embeds the secret. | Single masking choke point (`MaskSecret`, `SanitizeEvidence`); every scanner builds evidence via these helpers; tests assert that no fixture secret appears in terminal, JSON, Markdown or SARIF output. |
| **Secret exfiltration.** A covert channel sends content to a third party. | No telemetry, no analytics, no crash reporting, no auto-upload. The only outbound call is the OSV batch query, and the destination is recorded in `report.network`. `--offline` guarantees zero requests. |
| **Silent failure presented as success.** A scanner crashes, a network call fails, a file cannot be read, and the report still says "clean". | Per-scanner status (`ran`/`partial`/`skipped`/`failed`), skipped checks with reasons, `summary.incomplete`, an `INCOMPLETE` banner in the terminal renderer, and exit code 3 for operational failure. |
| **Denial of the scan's credibility by false positives.** Rules fire on placeholders and examples, so operators start ignoring the tool. | Keyword gating, entropy thresholds, placeholder detection (`changeme`, `example`, `xxxx`, repeated-character strings), validator functions for vendor-prefixed keys, and explicit confidence values so uncertain hits are labelled. |
| **Hostile input into the terminal.** ANSI escapes, control characters, very long lines corrupt the operator's terminal. | Evidence is stripped of control characters, whitespace-collapsed and length-bounded before rendering. |
| **Report tampering / non-determinism.** Findings reorder between runs, making diff-based review impossible. | Deterministic ordering, content-derived fingerprints, and tests that assert byte-identical JSON across two runs. |
| **Supply-chain compromise.** A malicious dependency of Wardline itself. | A single third-party module (`goccy/go-yaml`, MIT) pinned in `go.sum`; the standard library for everything else. CI builds with the module cache only. |
| **CI token abuse.** Wardline's own workflows are a target. | `permissions:` is declared per workflow with read-only defaults, actions are pinned to full commit SHAs, no `pull_request_target`, no secrets in workflows that run on forks. |

## Threats Wardline detects (and their limits)

| Category | Detected | Not detected |
| --- | --- | --- |
| Secrets | Known credential formats, assignment patterns, committed key material, credential files. | Secrets created after the scan; secrets in Git history; secrets in binaries, images or remote services; secrets split across lines or encoded in a custom scheme. |
| Dependencies | Vulnerabilities published to OSV for exact versions resolved from lockfiles. | Versions resolved at build time without a lockfile; transitive npm dependencies with no lockfile; vulnerabilities not yet published; malicious packages (OSV `MAL-*` entries are reported only if OSV returns them); reachability of the vulnerable code path. |
| Workflows | Permission scope, dangerous triggers, interpolation of untrusted context, unpinned actions, artifact trust, self-hosted runners, remote script piping. | Runtime behaviour, reusable workflows defined in other repositories, composite action internals, organisation-level settings, branch protection. |
| Configuration | Dockerfile and Compose settings, selected app config keys. | Kubernetes manifests, Terraform, Helm charts, CI systems other than GitHub Actions, runtime hardening, network policy. |

## Out of scope

- Penetration testing or exploit generation.
- Runtime or container-image scanning.
- Guaranteeing that a repository is secure. Wardline reduces uncertainty; it
  does not prove absence.
- Compliance certification. Severity ratings are Wardline's own assessment and
  are **not** official CVSS scores.
- Reading or rewriting Git history, commit metadata or remotes.

## Abuse cases considered and rejected

- **A scanner that "fixes" findings in the working tree.** Rejected: scans are
  strictly read-only; remediation is text, not mutation.
- **Automatic upload of results to a dashboard.** Rejected for the MVP: no
  telemetry, no accounts, no server component.
- **A suppression mechanism that hides findings without justification.**
  Rejected: `suppressions[].reason` is mandatory, suppressions are visible in
  the report, and findings remain listed as suppressed rather than deleted.
- **Downloading rule packs or vulnerability data at scan time.** Rejected:
  rules are compiled in, so a scan cannot be subverted by a network response
  other than OSV data, which is treated as untrusted input.

## Reporting a vulnerability in Wardline

See [SECURITY.md](../SECURITY.md). Wardline's own security posture is part of
its threat model: a scanner that leaks the secrets it finds is worse than no
scanner.
