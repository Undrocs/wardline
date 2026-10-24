package config

import (
	"fmt"
	"regexp"

	"github.com/Undrocs/wardline/internal/findings"
	"github.com/Undrocs/wardline/internal/security"
)

// rule is the metadata for one configuration check.
type rule struct {
	ID          string
	Title       string
	Description string
	Impact      string
	Remediation string
	References  []string
	Severity    findings.Severity
	Confidence  findings.Confidence
}

var (
	ruleRootUserImplicit = rule{
		ID: "WL-CFG-001", Title: "Container image runs as root",
		Description: "The Dockerfile never sets a USER, so processes start as root inside the container.",
		Impact:      "If the container is compromised, a root process has more capability to escape, mount volumes, or modify anything the container can reach.",
		Remediation: "Create an unprivileged user in the image and add a `USER` instruction before the final entrypoint.",
		References:  []string{"https://docs.docker.com/build/building/best-practices/#user"},
		Severity:    findings.SeverityMedium, Confidence: findings.ConfidenceMedium,
	}
	ruleRootUserExplicit = rule{
		ID: "WL-CFG-002", Title: "Container explicitly runs as root",
		Description: "The Dockerfile sets `USER root` or UID 0.",
		Impact:      "The workload runs with full privileges inside the container, widening the effect of any compromise.",
		Remediation: "Run the process as an unprivileged user and grant only the specific capabilities it needs.",
		References:  []string{"https://docs.docker.com/build/building/best-practices/#user"},
		Severity:    findings.SeverityMedium, Confidence: findings.ConfidenceHigh,
	}
	ruleSecretEnvironment = rule{
		ID: "WL-CFG-003", Title: "Secret baked into image environment",
		Description: "A credential-looking value is set with `ENV` in the Dockerfile.",
		Impact:      "Values in ENV are stored in the image layers and are readable by anyone who can pull the image, even if a later layer unsets them.",
		Remediation: "Remove the value, rebuild the image so the layer is gone, rotate the credential, and inject secrets at run time from the orchestrator or a secrets manager.",
		References:  []string{"https://docs.docker.com/build/building/best-practices/#secrets"},
		Severity:    findings.SeverityHigh, Confidence: findings.ConfidenceHigh,
	}
	ruleSecretBuildArg = rule{
		ID: "WL-CFG-004", Title: "Secret default in build argument",
		Description: "A build argument with a credential-looking name has a literal default value.",
		Impact:      "ARG defaults are recorded in image metadata and build history and should be treated as public.",
		Remediation: "Remove the default, pass the value at build time only when unavoidable, prefer BuildKit secret mounts, and rotate the credential.",
		References:  []string{"https://docs.docker.com/build/building/best-practices/#secrets"},
		Severity:    findings.SeverityHigh, Confidence: findings.ConfidenceHigh,
	}
	ruleRemoteAdd = rule{
		ID: "WL-CFG-005", Title: "Dockerfile adds remote content without verification",
		Description: "`ADD` fetches a remote URL or Git repository directly into the image.",
		Impact:      "The build depends on whatever the remote server returns at build time; there is no checksum or signature check in the Dockerfile.",
		Remediation: "Download the artefact in a separate step, verify a pinned checksum or signature, then copy the verified file.",
		References:  []string{"https://docs.docker.com/reference/dockerfile/#add"},
		Severity:    findings.SeverityMedium, Confidence: findings.ConfidenceMedium,
	}
	ruleCredentialCopy = rule{
		ID: "WL-CFG-006", Title: "Credential file copied into the image",
		Description: "`COPY` or `ADD` places a credential-bearing file into the image.",
		Impact:      "The credential becomes part of an image layer that anyone with pull access can read.",
		Remediation: "Add the file to .dockerignore, remove the COPY step, rotate the credential and mount secrets at run time instead.",
		References:  []string{"https://docs.docker.com/build/building/context/#dockerignore-files"},
		Severity:    findings.SeverityHigh, Confidence: findings.ConfidenceHigh,
	}
	ruleWorldWritable = rule{
		ID: "WL-CFG-007", Title: "World-writable file permissions",
		Description: "The Dockerfile applies world-writable permissions (for example `chmod 777`).",
		Impact:      "Any process in the container can modify the affected files, which weakens integrity guarantees and can enable tampering.",
		Remediation: "Grant the minimum permissions the process needs, typically owned by the application user with mode 0755 or 0644.",
		References:  []string{"https://cwe.mitre.org/data/definitions/732.html"},
		Severity:    findings.SeverityLow, Confidence: findings.ConfidenceMedium,
	}
	ruleRemoteScript = rule{
		ID: "WL-CFG-008", Title: "Remote script piped into a shell during image build",
		Description: "A `RUN` instruction downloads a script and pipes it directly into a shell interpreter.",
		Impact:      "The build executes whatever the remote server returns, with the build context's network access and any build secrets present.",
		Remediation: "Download the script separately, verify a pinned checksum or signature, then execute the verified file.",
		References:  []string{"https://cwe.mitre.org/data/definitions/829.html"},
		Severity:    findings.SeverityMedium, Confidence: findings.ConfidenceHigh,
	}
	rulePrivileged = rule{
		ID: "WL-CFG-010", Title: "Privileged container",
		Description: "A Compose service runs with `privileged: true`.",
		Impact:      "The container receives almost all host capabilities and can often escape to the host, including access to all devices.",
		Remediation: "Remove `privileged` and add only the capabilities the service needs with `cap_add`.",
		References:  []string{"https://docs.docker.com/reference/compose-file/services/#privileged"},
		Severity:    findings.SeverityHigh, Confidence: findings.ConfidenceHigh,
	}
	ruleDockerSocket = rule{
		ID: "WL-CFG-011", Title: "Docker socket mounted into container",
		Description: "A Compose service mounts the host Docker socket.",
		Impact:      "Access to the Docker socket is root-equivalent on the host: the container can start privileged containers and read host secrets.",
		Remediation: "Do not mount the Docker socket. Use a restricted API proxy with an allow-list, or run the workload outside the container.",
		References:  []string{"https://docs.docker.com/reference/compose-file/services/#volumes"},
		Severity:    findings.SeverityHigh, Confidence: findings.ConfidenceHigh,
	}
	ruleHostNetwork = rule{
		ID: "WL-CFG-012", Title: "Container uses host networking",
		Description: "A Compose service sets `network_mode: host`.",
		Impact:      "The container bypasses network isolation, can reach host-only services and binds ports directly on the host.",
		Remediation: "Use a dedicated bridge network and publish only the ports that are required.",
		References:  []string{"https://docs.docker.com/reference/compose-file/services/#network_mode"},
		Severity:    findings.SeverityMedium, Confidence: findings.ConfidenceMedium,
	}
	ruleDangerousCapability = rule{
		ID: "WL-CFG-013", Title: "Dangerous Linux capability granted",
		Description: "A Compose service adds a high-risk capability such as SYS_ADMIN or ALL.",
		Impact:      "These capabilities allow mounting, namespace changes or device access that are effectively equivalent to host compromise.",
		Remediation: "Drop all capabilities (`cap_drop: [ALL]`) and add back only the specific capability the workload requires.",
		References:  []string{"https://docs.docker.com/reference/compose-file/services/#cap_add"},
		Severity:    findings.SeverityHigh, Confidence: findings.ConfidenceMedium,
	}
	ruleUnconfinedProfile = rule{
		ID: "WL-CFG-009", Title: "Container security profile disabled",
		Description: "A Compose service disables a kernel security profile with `seccomp:unconfined` or `apparmor:unconfined`.",
		Impact:      "Without the default seccomp filter or AppArmor profile, a container breakout or exploited service has far more kernel surface available to escalate privileges.",
		Remediation: "Remove the unconfined option. Write a custom profile that allows only the syscalls or file accesses the workload needs.",
		References:  []string{"https://docs.docker.com/reference/compose-file/services/#security_opt"},
		Severity:    findings.SeverityHigh, Confidence: findings.ConfidenceHigh,
	}
	ruleComposeSecretEnv = rule{
		ID: "WL-CFG-014", Title: "Literal secret in Compose environment",
		Description: "A Compose service sets a credential-looking environment variable to a literal value.",
		Impact:      "The credential is stored in the repository, visible to everyone with access to it and to the deployment configuration.",
		Remediation: "Reference an external secret (`secrets:` or a variable read from the environment), rotate the value, and keep the real secret outside the repository.",
		References:  []string{"https://docs.docker.com/reference/compose-file/services/#environment"},
		Severity:    findings.SeverityHigh, Confidence: findings.ConfidenceHigh,
	}
	ruleSensitiveMount = rule{
		ID: "WL-CFG-015", Title: "Sensitive host path mounted into container",
		Description: "A Compose service bind-mounts a sensitive host directory such as /etc, /root or the filesystem root.",
		Impact:      "The container can read or modify host configuration and credentials, which usually allows privilege escalation.",
		Remediation: "Mount only the exact files required, read-only where possible, and keep sensitive host paths out of container filesystems.",
		References:  []string{"https://docs.docker.com/reference/compose-file/services/#volumes"},
		Severity:    findings.SeverityMedium, Confidence: findings.ConfidenceMedium,
	}
	ruleComposeRootUser = rule{
		ID: "WL-CFG-016", Title: "Container explicitly runs as root",
		Description: "A Compose service sets `user: root` or UID 0.",
		Impact:      "The workload runs with full privileges inside the container, widening the effect of any compromise.",
		Remediation: "Set `user` to an unprivileged UID/GID that owns the application files.",
		References:  []string{"https://docs.docker.com/reference/compose-file/services/#user"},
		Severity:    findings.SeverityLow, Confidence: findings.ConfidenceHigh,
	}
	ruleSensitivePort = rule{
		ID: "WL-CFG-017", Title: "Sensitive service port published on all interfaces",
		Description: "A database or cache port is published to the host on 0.0.0.0.",
		Impact:      "If the host is reachable from an untrusted network, the datastore is exposed directly, often with weak or no authentication.",
		Remediation: "Bind published ports to 127.0.0.1 or remove the mapping and keep the datastore on the internal network.",
		References:  []string{"https://docs.docker.com/reference/compose-file/services/#ports"},
		Severity:    findings.SeverityMedium, Confidence: findings.ConfidenceMedium,
	}
	ruleCommittedEnvFile = rule{
		ID: "WL-CFG-020", Title: "Environment file committed to the repository",
		Description: "A .env file is tracked in the repository.",
		Impact:      ".env files commonly hold credentials and are rarely intended for version control; repository access becomes credential access.",
		Remediation: "Remove the file from the repository and its history, add it to .gitignore, keep a sanitised .env.example, and rotate any exposed values.",
		References:  []string{"https://cwe.mitre.org/data/definitions/538.html"},
		Severity:    findings.SeverityMedium, Confidence: findings.ConfidenceMedium,
	}
	ruleInsecureTLS = rule{
		ID: "WL-CFG-021", Title: "TLS certificate verification disabled",
		Description: "An application configuration setting disables TLS certificate verification.",
		Impact:      "Disabling verification removes the only protection against man-in-the-middle attacks on connections made with this configuration.",
		Remediation: "Enable verification, trust the required CA explicitly, and never ship a configuration that disables it to production.",
		References:  []string{"https://cwe.mitre.org/data/definitions/295.html"},
		Severity:    findings.SeverityMedium, Confidence: findings.ConfidenceMedium,
	}
)

var remoteScriptPattern = regexp.MustCompile(`(?i)\b(?:curl|wget)\b[^\n|;]*\|\s*(?:sudo\s+)?(?:ba|z|k)?sh\b`)

func newDockerFinding(r rule, file string, line int, locator, evidence string) findings.Finding {
	return newConfigFinding(r, file, line, locator, evidence, "Dockerfile")
}

func newComposeFinding(r rule, file string, line int, locator, evidence string) findings.Finding {
	return newConfigFinding(r, file, line, locator, evidence, "Docker Compose")
}

func newConfigFinding(r rule, file string, line int, locator, evidence, kind string) findings.Finding {
	description := r.Description
	if kind != "" {
		description = fmt.Sprintf("%s (%s check)", r.Description, kind)
	}
	return findings.New(findings.Finding{
		RuleID:      r.ID,
		Scanner:     findings.ScannerConfig,
		Title:       r.Title,
		Severity:    r.Severity,
		Confidence:  r.Confidence,
		Location:    findings.Location{Path: file, StartLine: line},
		Evidence:    security.SanitizeEvidence(evidence, 200),
		Description: description,
		Impact:      r.Impact,
		Remediation: r.Remediation,
		References:  r.References,
		Locator:     locator,
	})
}

// Catalog exposes rule metadata for documentation and tests.
func Catalog() []rule {
	return []rule{
		ruleRootUserImplicit, ruleRootUserExplicit, ruleSecretEnvironment,
		ruleSecretBuildArg, ruleRemoteAdd, ruleCredentialCopy, ruleWorldWritable, ruleRemoteScript,
		rulePrivileged, ruleDockerSocket, ruleHostNetwork, ruleDangerousCapability,
		ruleUnconfinedProfile, ruleComposeSecretEnv, ruleSensitiveMount, ruleComposeRootUser,
		ruleSensitivePort, ruleCommittedEnvFile, ruleInsecureTLS,
	}
}

// ruleIDs returns the catalog identifiers, used by documentation tests.
func ruleIDs() []string {
	out := make([]string, 0, len(Catalog()))
	for _, r := range Catalog() {
		out = append(out, r.ID)
	}
	return out
}
