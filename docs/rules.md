# Rule reference

Every finding cites a stable rule ID. IDs are namespaced by scanner and are
never reused or renumbered:

| Prefix | Scanner |
| --- | --- |
| `WL-SEC-*` | Secrets |
| `WL-DEP-*` | Dependencies |
| `WL-WF*` | GitHub Actions workflows |
| `WL-CFG-*` | Container and application configuration |

Numbering has gaps (for example `WL-CFG-018` and `-019`). Retired or reserved
IDs are not reused, so a rule ID always means the same check.

## Severity and confidence

Severity describes **impact if the condition is real**: `critical` means
immediately exploitable credential or code execution, `high` means direct
compromise path, `medium` means meaningful weakness requiring additional
conditions, `low` means hardening, `info` is informational, and `unknown` is
used when a third-party advisory supplies no rating.

Confidence describes **how certain the detection is**: `high` means the pattern
matched a well-defined format or structural condition, `medium` means the match
depends on context (generic assignments, ambiguous YAML), `low` means a
heuristic that deserves review before action.

Neither value is an official CVSS score. Where a dependency finding quotes a
CVSS vector or score, it comes from the advisory and is labelled as such.

## Secrets (`WL-SEC-*`)

Detection uses keyword-gated regular expressions with optional vendor
validators, entropy checks and placeholder filters. Evidence is always masked;
a matched secret is never written to any output.

| Rule | Title | Severity | Confidence |
| --- | --- | --- | --- |
| `WL-SEC-001` | AWS access key ID | high | high |
| `WL-SEC-002` | AWS secret access key | high | high |
| `WL-SEC-003` | GitHub token | high | high |
| `WL-SEC-004` | GitLab personal access token | high | high |
| `WL-SEC-005` | Slack API token | high | high |
| `WL-SEC-006` | Slack incoming webhook URL | medium | high |
| `WL-SEC-007` | Stripe live secret key | critical | high |
| `WL-SEC-008` | Stripe test secret key | low | high |
| `WL-SEC-009` | Google API key | high | high |
| `WL-SEC-010` | npm access token | high | high |
| `WL-SEC-011` | PyPI API token | critical | high |
| `WL-SEC-012` | SendGrid API key | high | high |
| `WL-SEC-013` | OpenAI API key | high | high |
| `WL-SEC-014` | Discord webhook URL | medium | high |
| `WL-SEC-015` | Azure storage account key | critical | high |
| `WL-SEC-016` | HashiCorp Vault token | high | high |
| `WL-SEC-017` | Twilio API key | medium | medium |
| `WL-SEC-018` | Cloud provider token | high | high |
| `WL-SEC-019` | Square access token | high | high |
| `WL-SEC-020` | Private key material | critical | high |
| `WL-SEC-021` | Database connection string with password | high | high |
| `WL-SEC-022` | Hardcoded password | medium | medium |
| `WL-SEC-023` | Hardcoded API key or token | medium | medium |
| `WL-SEC-024` | JSON Web Token | medium | low |
| `WL-SEC-025` | Credential file committed | high | medium |

Notes:

- `WL-SEC-001` matches AWS key IDs, including long-term (`AKIA`), temporary
  (`ASIA`) and role/session prefixes. The key ID alone is not a working
  credential but identifies a rotation target.
- `WL-SEC-020` reports only the key header (`private key block: -----BEGIN …`)
  and never any base64 key material.
- `WL-SEC-021` reports a database URI with an embedded password. A loopback or
  Compose-service host (`localhost`, `127.0.0.1`, `db`, `redis`, …) lowers the
  confidence to `low` instead of suppressing the finding.
- `WL-SEC-022`/`WL-SEC-023` require a credential-like key name **and** a
  quoted literal value; references to environment variables, template
  placeholders (`${…}`, `{{…}}`), obvious placeholders (`changeme`, `example`,
  `password`), and strings below a minimum entropy are not reported. Both rules
  understand quoted keys (`"password": "…"`, `"api_key" = "…"`) and YAML block
  scalars (`password: |` followed by an indented literal).
- `WL-SEC-025` fires once per credential-bearing filename (for example
  `id_rsa`, `.netrc`, `.aws/credentials`), regardless of content.
- Test and documentation fixtures: find the pattern, not a live credential;
  confirm before rotating anything.

Remediation for every secret rule is the same in substance: revoke or rotate
the credential, purge it from the working tree and history, audit provider logs
for use, and load the value from an environment variable or secret manager.

## Dependencies (`WL-DEP-001`)

| Rule | Title | Severity | Confidence |
| --- | --- | --- | --- |
| `WL-DEP-001` | Known vulnerability in a dependency version | advisory rating | high |

Severity comes from the advisory, in this order of precedence:

1. `database_specific.severity` (for example GHSA `CRITICAL`/`HIGH`/`MODERATE`/`LOW`);
2. a CVSS v3.x base score, converted with the official CVSS v3.1 formula;
3. `unknown` when neither is available. A missing rating is never downgraded to
   `low`.

Each affected package version produces at most one finding per advisory. The
finding records the ecosystem, package name, resolved version, advisory ID,
aliases, the fixed versions when OSV publishes them, and the advisory summary
and details (sanitised and length-bounded).

## GitHub Actions (`WL-WF*`)

Workflows are parsed structurally. Each rule names the YAML path it applies to,
and findings carry a line number from the source document. Workflows are never
executed.

| Rule | Title | Severity | Confidence | Rationale |
| --- | --- | --- | --- | --- |
| `WL-WF001` | Workflow grants write-all token permissions | high | high | `permissions: write-all` gives the token every write scope. |
| `WL-WF002` | Workflow does not restrict token permissions | low | medium | Without a top-level `permissions` block the token inherits repository/organisation defaults. |
| `WL-WF003` | Workflow requests a write permission | medium | medium | A write scope is granted at workflow level, or on a job inside a workflow that untrusted events can trigger. A job-scoped write in a trusted-only workflow is the recommended least-privilege pattern and is not reported. |
| `WL-WF004` | Action is not pinned to a commit SHA | medium | high | Tags and branches are mutable; a compromised upstream can change what runs. |
| `WL-WF005` | Workflow runs on pull_request_target | high | high | Runs with base-repository permissions and secrets in the context of untrusted pull requests. |
| `WL-WF006` | Workflow executes untrusted pull request code with privileged access | critical | high | `pull_request_target` plus a checkout of the PR head executes attacker-controlled code with the base token and secrets. |
| `WL-WF007` | Untrusted input interpolated into a shell command | high | high | `${{ github.event.* }}` inside `run:` allows command injection. |
| `WL-WF008` | Secret may be written to workflow logs | high | medium | Echoing `${{ secrets.* }}` can leak it into logs readable by anyone with repository access. |
| `WL-WF009` | Privileged workflow consumes artifacts from an untrusted run | high | high | `workflow_run` workflows that download artifacts trust data produced by a less privileged run. |
| `WL-WF010` | Self-hosted runner used for untrusted pull requests | medium | medium | Untrusted code on a self-hosted runner can reach its host and other jobs. |
| `WL-WF011` | Remote script piped into a shell | medium | high | `curl … | bash` executes unreviewed remote content. |

Safe patterns that suppress these rules: a top-level `permissions: contents:
read`, per-job `permissions`, actions pinned to a 40-character commit SHA, event
data passed through `env:` (never interpolated directly into `run:`), and
`pull_request` instead of `pull_request_target` for untrusted contributions.

## Container and application configuration (`WL-CFG-*`)

| Rule | Title | Severity | Confidence | Applies to |
| --- | --- | --- | --- | --- |
| `WL-CFG-001` | Container image runs as root | medium | medium | Dockerfile: no `USER` instruction. |
| `WL-CFG-002` | Container explicitly runs as root | medium | high | Dockerfile: `USER root` / `USER 0`. |
| `WL-CFG-003` | Secret baked into image environment | high | high | Dockerfile: `ENV` with a credential-like name and literal value. |
| `WL-CFG-004` | Secret default in build argument | high | high | Dockerfile: `ARG` credential with a literal default. |
| `WL-CFG-005` | Dockerfile adds remote content without verification | medium | medium | Dockerfile: `ADD <url>` or a Git repository. |
| `WL-CFG-006` | Credential file copied into the image | high | high | Dockerfile: `COPY`/`ADD` of a credential-bearing path. |
| `WL-CFG-007` | World-writable file permissions | low | medium | Dockerfile: `chmod 777` / `o+w`. |
| `WL-CFG-008` | Remote script piped into a shell during image build | medium | high | Dockerfile: `RUN` with `curl … | sh`. |
| `WL-CFG-009` | Container security profile disabled | high | high | Compose: `seccomp:unconfined` / `apparmor:unconfined`. |
| `WL-CFG-010` | Privileged container | high | high | Compose: `privileged: true`. |
| `WL-CFG-011` | Docker socket mounted into container | high | high | Compose: `/var/run/docker.sock` bind mount. |
| `WL-CFG-012` | Container uses host networking | medium | medium | Compose: `network_mode: host`. |
| `WL-CFG-013` | Dangerous Linux capability granted | high/medium/low per capability | medium | Compose: `cap_add` of `SYS_ADMIN`, `ALL`, `NET_ADMIN`, … |
| `WL-CFG-014` | Literal secret in Compose environment | high | high | Compose: credential-like environment variable with a literal value. |
| `WL-CFG-015` | Sensitive host path mounted into container | medium | medium | Compose: bind mount of `/`, `/etc`, `/root`, `/home`, `/var/run`, … |
| `WL-CFG-016` | Container explicitly runs as root | low | high | Compose: `user: root` / `user: "0"`. |
| `WL-CFG-017` | Sensitive service port published on all interfaces | medium | medium | Compose: database/cache port published without a host IP. |
| `WL-CFG-020` | Environment file present in the scanned tree | medium | medium | A `.env` file exists in the working tree (templates such as `.env.example` are ignored). Wardline does not run Git, so it cannot tell whether the file is tracked: the remediation tells you how to check. |
| `WL-CFG-021` | TLS certificate verification disabled | medium | medium | YAML/JSON application config: `InsecureSkipVerify`, `verify=False`, `rejectUnauthorized: false`, … |

The configuration scanner only reports what static inspection can establish. It
never builds an image, starts Compose, or evaluates shell expressions.

Evidence in configuration files is excerpted from untrusted build files.
Dockerfile `RUN`, `ADD` and `COPY` arguments, Compose values and workflow
commands are redacted with `security.RedactEvidence` before they are stored, so a
credential in a `curl -H "Authorization: Bearer …"` line never reaches a report.
Truncation happens after redaction for the same reason.

## Overlapping findings

Different scanners can report the same underlying problem from different
angles. A Dockerfile `ENV NPM_TOKEN=…` produces both `WL-SEC-010` (a token is
committed) and `WL-CFG-003` (a secret is baked into the image). Both are
intentional: the first is about the credential, the second about the image.
Deduplication is per scanner, matching rule ID, path and locator.

## Disabling, overriding and suppressing rules

```yaml
rules:
  disable: ["WL-SEC-008"]      # rule never runs
  severity:
    WL-CFG-007: low            # recorded override; reports note the deviation

suppressions:
  - rule: WL-WF004
    path: ".github/workflows/*.yml"
    reason: "Actions are refreshed by Dependabot; reviewed in the updating pull request."
  - rule: WL-SEC-023
    path: "docs/examples/**"
    line: 12
    expires: "2026-12-31"
    reason: "Documentation examples use obviously fake placeholders."
```

- `rules.disable` prevents the rule from firing at all. Prefer a suppression
  when the finding is real but accepted.
- `rules.severity` changes the reported severity and is visible in the report,
  so the deviation from the built-in rating cannot be hidden.
- `suppressions[].reason` is mandatory; a suppression without one is a
  configuration error (exit code 2).
- Suppressed findings remain in the report with `"suppressed": true` and are
  counted separately. They no longer contribute to the policy threshold.
- `expires` (YYYY-MM-DD) keeps the suppression valid through that whole day
  (UTC) and re-enables the finding at 00:00 UTC the next day.

## Adding a rule

1. Add the rule to the scanner's catalogue with a new, never-reused ID.
2. Provide description, impact and remediation text — every rule needs all three.
3. Add a positive fixture and a near-miss fixture in the scanner's test file.
4. Add the rule to this document.
5. Add a synthetic trigger to `testdata/vulnerable`. The test
   `TestVulnerableFixtureExercisesEveryOfflineRule` scans that fixture and fails
   when any catalogue rule never fires, so an unreachable rule cannot ship. If
   the rule can fire on synthetic content, the fixtures stay under `testdata/`,
   which the repository's own `.wardline.yaml` excludes.
6. Keep credential-shaped values in `*.tmpl` files and add them to
   `internal/fixtures`; `go run ./internal/fixtures/cmd/materialize <dir>`
   writes a scannable copy. No committed file may match a vendor credential
   pattern, or push protection rejects the branch.
