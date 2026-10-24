package secrets

import (
	"regexp"
	"strings"

	"github.com/Undrocs/wardline/internal/findings"
)

// Rule is one credential detection pattern.
//
// Rules are intentionally conservative: every rule requires a vendor-specific
// prefix or a keyword anchor, and most additionally require enough entropy to
// reject prose and example strings. Wardline never reports a finding from a rule
// that has no matched, extractable value.
type Rule struct {
	// ID is the stable rule identifier (WL-SEC-NNN).
	ID string
	// Title is a short human readable name.
	Title string
	// Description explains what was detected.
	Description string
	// Impact explains the consequence of exposure.
	Impact string
	// Remediation explains how to fix and rotate.
	Remediation string
	// References are public documentation links.
	References []string
	Severity   findings.Severity
	Confidence findings.Confidence
	// Pattern is the compiled expression.
	Pattern *regexp.Regexp
	// SecretGroup selects the capture group holding the credential (0 = whole match).
	SecretGroup int
	// Keywords prefilters lines cheaply (lower-case substrings). When empty the
	// pattern runs on every line.
	Keywords []string
	// MinEntropy, when non-zero, requires Shannon entropy of the candidate.
	MinEntropy float64
	// MinLength/MaxLength bound the candidate value.
	MinLength int
	MaxLength int
	// AllowPlaceholders permits values such as "example" or "changeme".
	AllowPlaceholders bool
	// PathHints restricts the rule to files whose path contains one of these
	// substrings (lower-case). Empty means any file.
	PathHints []string
	// Validate performs format-specific validation of a candidate value.
	Validate func(string) bool
	// ValidateMatch can inspect the surrounding line and submatch offsets when a
	// decision requires more context than the captured value alone.
	ValidateMatch func(line string, match []int) bool
	// FileLevel rules are evaluated once per file against the path and content
	// instead of line by line.
	FileLevel bool
}

func (r *Rule) appliesToPath(relLower string) bool {
	if len(r.PathHints) == 0 {
		return true
	}
	for _, hint := range r.PathHints {
		if strings.Contains(relLower, hint) {
			return true
		}
	}
	return false
}

func (r *Rule) keywordMatch(lineLower string) bool {
	if len(r.Keywords) == 0 {
		return true
	}
	for _, kw := range r.Keywords {
		if strings.Contains(lineLower, kw) {
			return true
		}
	}
	return false
}

var (
	// Vendor tokens.
	awsAccessKeyID  = regexp.MustCompile(`\b(?:AKIA|ASIA|AIDA|AROA|AIPA|ANPA|ANVA|APKA)[A-Z0-9]{16}\b`)
	awsSecretAssign = regexp.MustCompile(`(?i)aws_?(?:secret_?access_?key|secret)\s*[:=]\s*["']?([A-Za-z0-9/+=]{40,128})["']?`)
	githubToken     = regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{36,251}|github_pat_[A-Za-z0-9_]{60,255})\b`)
	gitlabToken     = regexp.MustCompile(`\bglpat-[A-Za-z0-9_\-]{20}\b`)
	slackToken      = regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,250}\b`)
	slackWebhook    = regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+`)
	stripeLiveKey   = regexp.MustCompile(`\b(sk|rk)_live_[A-Za-z0-9]{20,99}\b`)
	stripeTestKey   = regexp.MustCompile(`\bsk_test_[A-Za-z0-9]{20,99}\b`)
	googleAPIKey    = regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`)
	npmToken        = regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`)
	pypiToken       = regexp.MustCompile(`\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}\b`)
	sendgridKey     = regexp.MustCompile(`\bSG\.[A-Za-z0-9_\-]{22,30}\.[A-Za-z0-9_\-]{43,50}\b`)
	openAIKey       = regexp.MustCompile(`\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,200}T3BlbkFJ[A-Za-z0-9_\-]{20,200}\b|\bsk-proj-[A-Za-z0-9_\-]{80,200}\b`)
	discordWebhook  = regexp.MustCompile(`https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9_\-]{60,90}`)
	azureStorageKey = regexp.MustCompile(`DefaultEndpointsProtocol=https?;AccountName=[A-Za-z0-9._-]{3,24};AccountKey=[A-Za-z0-9+/=]{40,}`)
	vaultToken      = regexp.MustCompile(`\bhv[sbr]\.[A-Za-z0-9_\-]{24,120}\b`)
	twilioAPIKey    = regexp.MustCompile(`\bSK[0-9a-fA-F]{32}\b`)
	doToken         = regexp.MustCompile(`\bdop_v1_[a-f0-9]{64}\b`)
	squareToken     = regexp.MustCompile(`\b(?:sq0atp|sq0csp)-[A-Za-z0-9_\-]{22,43}\b`)
	// Key material.
	privateKeyBlock = regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----`)
	// Connection strings.
	databaseURL = regexp.MustCompile(`(?i)\b(postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis(?:s)?|amqp(?:s)?|mssql|clickhouse)://([^:@/\s"'<>]{1,64}):([^@\s"'<>]{1,256})@([A-Za-z0-9._\-]{1,255})(?::[0-9]{1,5})?`)
	// Generic assignments.
	genericPassword = regexp.MustCompile(`(?i)\b(?:password|passwd|pwd|db_?pass|db_?password)\s*[:=]\s*["']([^"'\s]{8,128})["']`)
	genericAPIKey   = regexp.MustCompile(`(?i)\b(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?token)\s*[:=]\s*["']([A-Za-z0-9_\-./+=]{16,256})["']`)
	jwtToken        = regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b`)
	// Committed credential files.
	sensitiveFilenameRule = regexp.MustCompile(`^.*$`)
)

// Rules is the ordered rule set. Order matters only for reporting stability.
func Rules() []*Rule {
	return []*Rule{
		{
			ID: "WL-SEC-001", Title: "AWS access key ID",
			Description: "An AWS access key ID was found in repository content.",
			Impact:      "Anyone with the matching secret access key can use the AWS identity, potentially reading data, launching resources and incurring cost.",
			Remediation: "Deactivate the access key in AWS IAM, rotate the credentials, audit CloudTrail for unauthorized use, and load credentials from the environment or a secrets manager instead of source code.",
			References:  []string{"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"},
			Severity:    findings.SeverityHigh, Confidence: findings.ConfidenceHigh,
			Pattern: awsAccessKeyID, SecretGroup: 0, MinLength: 20, MaxLength: 20,
			Keywords: []string{"akia", "asia", "aida", "aroa", "aipa", "anpa", "anva", "apka"},
		},
		{
			ID: "WL-SEC-002", Title: "AWS secret access key",
			Description: "A value assigned to an AWS secret access key setting was found.",
			Impact:      "The paired access key ID can be used to authenticate to AWS, giving access to whatever the identity is permitted to do.",
			Remediation: "Rotate the access key pair in AWS IAM, remove the value from source history, and use short-lived credentials from a secrets manager or OIDC role instead.",
			References:  []string{"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"},
			Severity:    findings.SeverityHigh, Confidence: findings.ConfidenceHigh,
			Pattern: awsSecretAssign, SecretGroup: 1, MinLength: 40, MaxLength: 128,
			Keywords:   []string{"aws_secret", "aws-secret", "awssecret", "secret_access_key"},
			MinEntropy: 3.5,
		},
		{
			ID: "WL-SEC-003", Title: "GitHub token",
			Description: "A GitHub access token was found in repository content.",
			Impact:      "The token grants GitHub API access as the token owner, which can include writing code, reading private repositories or modifying workflows.",
			Remediation: "Revoke the token in GitHub settings, issue a replacement with the least scope required, and store it as a repository secret rather than in code.",
			References:  []string{"https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens"},
			Severity:    findings.SeverityHigh, Confidence: findings.ConfidenceHigh,
			Pattern: githubToken, SecretGroup: 0, MinLength: 20, MaxLength: 256,
			Keywords: []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"},
		},
		{
			ID: "WL-SEC-004", Title: "GitLab personal access token",
			Description: "A GitLab personal access token was found in repository content.",
			Impact:      "The token grants GitLab API access with the scopes assigned to it, potentially allowing source modification or data access.",
			Remediation: "Revoke the token in GitLab, issue a scoped replacement, and store it as a CI/CD variable instead of in the repository.",
			References:  []string{"https://docs.gitlab.com/ee/user/profile/personal_access_tokens.html"},
			Severity:    findings.SeverityHigh, Confidence: findings.ConfidenceHigh,
			Pattern: gitlabToken, SecretGroup: 0, MinLength: 26, MaxLength: 26,
			Keywords: []string{"glpat-"},
		},
		{
			ID: "WL-SEC-005", Title: "Slack API token",
			Description: "A Slack API token was found in repository content.",
			Impact:      "The token can read messages, post as the workspace app or access private channels depending on its scopes.",
			Remediation: "Revoke the token in the Slack app configuration, reinstall the app with a new token, and keep tokens in a secret store.",
			References:  []string{"https://api.slack.com/authentication/token-types"},
			Severity:    findings.SeverityHigh, Confidence: findings.ConfidenceHigh,
			Pattern: slackToken, SecretGroup: 0, MinLength: 12, MaxLength: 250,
			Keywords: []string{"xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-"},
		},
		{
			ID: "WL-SEC-006", Title: "Slack incoming webhook URL",
			Description: "A Slack incoming webhook URL was found in repository content.",
			Impact:      "Anyone with the URL can post arbitrary messages into the Slack channel, enabling phishing or disinformation from a trusted workspace app.",
			Remediation: "Regenerate the webhook in the Slack app configuration and store the new URL as a secret.",
			References:  []string{"https://api.slack.com/messaging/webhooks"},
			Severity:    findings.SeverityMedium, Confidence: findings.ConfidenceHigh,
			Pattern: slackWebhook, SecretGroup: 0, MinLength: 40, MaxLength: 300,
			Keywords: []string{"hooks.slack.com"},
		},
		{
			ID: "WL-SEC-007", Title: "Stripe live secret key",
			Description: "A Stripe live-mode secret key was found in repository content.",
			Impact:      "The key permits charges, refunds and access to customer payment data in the live Stripe account.",
			Remediation: "Roll the key in the Stripe dashboard immediately, review recent charges and logs, and keep the replacement in a secrets manager.",
			References:  []string{"https://docs.stripe.com/keys#api-keys"},
			Severity:    findings.SeverityCritical, Confidence: findings.ConfidenceHigh,
			Pattern: stripeLiveKey, SecretGroup: 0, MinLength: 24, MaxLength: 100,
			Keywords: []string{"sk_live_", "rk_live_"},
		},
		{
			ID: "WL-SEC-008", Title: "Stripe test secret key",
			Description: "A Stripe test-mode secret key was found in repository content.",
			Impact:      "Test-mode keys cannot move real money, but they grant access to test data and can be confused with production credentials.",
			Remediation: "Prefer environment variables for test keys as well, and revoke the exposed key if it was ever reused outside tests.",
			References:  []string{"https://docs.stripe.com/keys#api-keys"},
			Severity:    findings.SeverityLow, Confidence: findings.ConfidenceHigh,
			Pattern: stripeTestKey, SecretGroup: 0, MinLength: 24, MaxLength: 100,
			Keywords: []string{"sk_test_"},
		},
		{
			ID: "WL-SEC-009", Title: "Google API key",
			Description: "A Google API key was found in repository content.",
			Impact:      "Depending on enabled APIs and key restrictions, the key can be used to incur billing or access data.",
			Remediation: "Restrict and rotate the key in Google Cloud Console, and serve it from configuration rather than source.",
			References:  []string{"https://cloud.google.com/docs/authentication/api-keys"},
			Severity:    findings.SeverityHigh, Confidence: findings.ConfidenceHigh,
			Pattern: googleAPIKey, SecretGroup: 0, MinLength: 39, MaxLength: 39,
			Keywords: []string{"aiza"},
		},
		{
			ID: "WL-SEC-010", Title: "npm access token",
			Description: "An npm access token was found in repository content.",
			Impact:      "The token can publish packages or read private packages under the token owner's account.",
			Remediation: "Revoke the token in npm, publish with provenance and short-lived CI tokens, and never commit .npmrc credentials.",
			References:  []string{"https://docs.npmjs.com/about-access-tokens"},
			Severity:    findings.SeverityHigh, Confidence: findings.ConfidenceHigh,
			Pattern: npmToken, SecretGroup: 0, MinLength: 40, MaxLength: 40,
			Keywords: []string{"npm_"},
		},
		{
			ID: "WL-SEC-011", Title: "PyPI API token",
			Description: "A PyPI API token was found in repository content.",
			Impact:      "The token can upload releases for the packages it is scoped to, enabling supply-chain compromise.",
			Remediation: "Revoke the token on PyPI, create a project-scoped replacement, and store it as a CI secret.",
			References:  []string{"https://pypi.org/help/#apitoken"},
			Severity:    findings.SeverityCritical, Confidence: findings.ConfidenceHigh,
			Pattern: pypiToken, SecretGroup: 0, MinLength: 60, MaxLength: 300,
			Keywords: []string{"pypi-ag"},
		},
		{
			ID: "WL-SEC-012", Title: "SendGrid API key",
			Description: "A SendGrid API key was found in repository content.",
			Impact:      "The key can send email as the account, damaging sender reputation and enabling phishing.",
			Remediation: "Delete the key in SendGrid, create a restricted replacement, and store it outside the repository.",
			References:  []string{"https://docs.sendgrid.com/ui/account-and-settings/api-keys"},
			Severity:    findings.SeverityHigh, Confidence: findings.ConfidenceHigh,
			Pattern: sendgridKey, SecretGroup: 0, MinLength: 60, MaxLength: 80,
			Keywords: []string{"sg."},
		},
		{
			ID: "WL-SEC-013", Title: "OpenAI API key",
			Description: "An OpenAI API key was found in repository content.",
			Impact:      "The key can consume paid quota and access account resources.",
			Remediation: "Revoke the key in the OpenAI dashboard, create a restricted replacement, and load it from the environment.",
			References:  []string{"https://platform.openai.com/docs/api-reference/authentication"},
			Severity:    findings.SeverityHigh, Confidence: findings.ConfidenceHigh,
			Pattern: openAIKey, SecretGroup: 0, MinLength: 40, MaxLength: 400,
			Keywords: []string{"t3blbkfj", "sk-proj-"},
		},
		{
			ID: "WL-SEC-014", Title: "Discord webhook URL",
			Description: "A Discord webhook URL was found in repository content.",
			Impact:      "Anyone with the URL can post messages to the channel, which is often used for abuse or impersonation.",
			Remediation: "Regenerate the webhook in Discord server settings and store the URL as a secret.",
			References:  []string{"https://support.discord.com/hc/en-us/articles/228383668"},
			Severity:    findings.SeverityMedium, Confidence: findings.ConfidenceHigh,
			Pattern: discordWebhook, SecretGroup: 0, MinLength: 60, MaxLength: 300,
			Keywords: []string{"discord.com/api/webhooks", "discordapp.com/api/webhooks"},
		},
		{
			ID: "WL-SEC-015", Title: "Azure storage account key",
			Description: "An Azure Storage connection string containing an account key was found.",
			Impact:      "The key grants full access to the storage account, including reading, modifying and deleting blobs.",
			Remediation: "Rotate the storage account key in Azure, review access logs, and use managed identities or SAS tokens instead.",
			References:  []string{"https://learn.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage"},
			Severity:    findings.SeverityCritical, Confidence: findings.ConfidenceHigh,
			Pattern: azureStorageKey, SecretGroup: 0, MinLength: 60, MaxLength: 400,
			Keywords: []string{"accountkey="},
		},
		{
			ID: "WL-SEC-016", Title: "HashiCorp Vault token",
			Description: "A HashiCorp Vault token was found in repository content.",
			Impact:      "The token can read or write secrets permitted by its policies.",
			Remediation: "Revoke the token in Vault, issue a short-lived replacement, and never store Vault tokens in source.",
			References:  []string{"https://developer.hashicorp.com/vault/docs/concepts/tokens"},
			Severity:    findings.SeverityHigh, Confidence: findings.ConfidenceHigh,
			Pattern: vaultToken, SecretGroup: 0, MinLength: 27, MaxLength: 125,
			Keywords: []string{"hvs.", "hvb.", "hvr."},
		},
		{
			ID: "WL-SEC-017", Title: "Twilio API key",
			Description: "A Twilio API key was found in repository content.",
			Impact:      "The key can send SMS or voice calls billed to the account.",
			Remediation: "Delete the key in the Twilio console and store the replacement securely.",
			References:  []string{"https://www.twilio.com/docs/iam/api-keys"},
			Severity:    findings.SeverityMedium, Confidence: findings.ConfidenceMedium,
			Pattern: twilioAPIKey, SecretGroup: 0, MinLength: 34, MaxLength: 34,
			Keywords:   []string{"twilio", "sk"},
			MinEntropy: 3.0,
		},
		{
			ID: "WL-SEC-018", Title: "Cloud provider token",
			Description: "A DigitalOcean or Square API token was found in repository content.",
			Impact:      "The token grants API access to the cloud account that owns it.",
			Remediation: "Revoke the token with the provider, create a scoped replacement and store it in a secrets manager.",
			References:  []string{"https://docs.digitalocean.com/reference/api/"},
			Severity:    findings.SeverityHigh, Confidence: findings.ConfidenceHigh,
			Pattern: doToken, SecretGroup: 0, MinLength: 71, MaxLength: 71,
			Keywords: []string{"dop_v1_"},
		},
		{
			ID: "WL-SEC-019", Title: "Square access token",
			Description: "A Square access token was found in repository content.",
			Impact:      "The token can access payment and customer data for the Square account.",
			Remediation: "Revoke the token in the Square developer dashboard and store the replacement securely.",
			References:  []string{"https://developer.squareup.com/docs/build-basics/access-tokens"},
			Severity:    findings.SeverityHigh, Confidence: findings.ConfidenceHigh,
			Pattern: squareToken, SecretGroup: 0, MinLength: 30, MaxLength: 50,
			Keywords: []string{"sq0atp-", "sq0csp-"},
		},
		{
			ID: "WL-SEC-020", Title: "Private key material",
			Description: "A private key block was found in repository content.",
			Impact:      "Possession of the private key allows impersonation of the key holder, decryption of captured traffic or signing of artifacts.",
			Remediation: "Treat the key as compromised: revoke or replace the certificate/key pair, rotate dependent credentials, and store private keys in a secrets manager or hardware token.",
			References:  []string{"https://csrc.nist.gov/glossary/term/private_key"},
			Severity:    findings.SeverityCritical, Confidence: findings.ConfidenceHigh,
			Pattern: privateKeyBlock, SecretGroup: 0, MinLength: 20, MaxLength: 120,
			Keywords: []string{"-----begin"},
		},
		{
			ID: "WL-SEC-021", Title: "Database connection string with password",
			Description: "A database connection URI containing an embedded password was found.",
			Impact:      "The password grants direct access to the database, potentially exposing or corrupting stored data.",
			Remediation: "Rotate the database password, remove the URI from source control and history, and inject it from the environment or a secrets manager.",
			References:  []string{"https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"},
			Severity:    findings.SeverityHigh, Confidence: findings.ConfidenceHigh,
			Pattern: databaseURL, SecretGroup: 3, MinLength: 4, MaxLength: 256,
			ValidateMatch: validateDatabaseURL,
			Keywords:      []string{"postgres://", "postgresql://", "mysql://", "mongodb://", "mongodb+srv://", "redis://", "rediss://", "amqp://", "amqps://", "mssql://", "clickhouse://"},
			// The user part is validated separately so that ${ENV} placeholders
			// and local development defaults are not reported.
			AllowPlaceholders: false,
		},
		{
			ID: "WL-SEC-022", Title: "Hardcoded password",
			Description: "A password-like setting with a literal value was found.",
			Impact:      "Hardcoded passwords are reusable by anyone with repository access and are rarely rotated.",
			Remediation: "Rotate the password, replace the literal with an environment variable or secret reference, and add the file to .gitignore if it holds local credentials.",
			References:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
			Severity:    findings.SeverityMedium, Confidence: findings.ConfidenceMedium,
			Pattern: genericPassword, SecretGroup: 1, MinLength: 8, MaxLength: 128,
			Validate:   validatePassword,
			Keywords:   []string{"password", "passwd", "pwd"},
			MinEntropy: 2.5,
		},
		{
			ID: "WL-SEC-023", Title: "Hardcoded API key or token",
			Description: "An API key, token or client secret setting with a literal value was found.",
			Impact:      "The credential is available to anyone who can read the repository or its history.",
			Remediation: "Rotate the credential, replace the literal with a secret reference, and configure the deployment platform to inject it.",
			References:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
			Severity:    findings.SeverityMedium, Confidence: findings.ConfidenceMedium,
			Pattern: genericAPIKey, SecretGroup: 1, MinLength: 16, MaxLength: 256,
			Validate:   validateGenericToken,
			Keywords:   []string{"api_key", "apikey", "secret_key", "access_token", "auth_token", "client_secret", "private_token", "api-key", "secret-key", "access-token", "auth-token", "client-secret", "private-token"},
			MinEntropy: 3.0,
		},
		{
			ID: "WL-SEC-024", Title: "JSON Web Token",
			Description: "A JSON Web Token was found in repository content.",
			Impact:      "JWTs are bearer credentials while valid; an exposed token may grant access until it expires or is revoked.",
			Remediation: "Confirm whether the token is a live credential. If so, revoke it, shorten its lifetime, and load it at runtime.",
			References:  []string{"https://datatracker.ietf.org/doc/html/rfc8725"},
			Severity:    findings.SeverityMedium, Confidence: findings.ConfidenceLow,
			Pattern: jwtToken, SecretGroup: 0, MinLength: 40, MaxLength: 4096,
			Keywords: []string{"eyj"},
		},
		{
			ID: "WL-SEC-025", Title: "Credential file committed",
			Description: "A file commonly used to store credentials exists in the repository.",
			Impact:      "Credential stores such as private keys, .env files and .npmrc tokens are readable by anyone with repository access, including its history.",
			Remediation: "Remove the file from the repository and its history, rotate every credential it contained, and add the filename to .gitignore.",
			References:  []string{"https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"},
			Severity:    findings.SeverityHigh, Confidence: findings.ConfidenceMedium,
			Pattern: sensitiveFilenameRule, SecretGroup: 0, MinLength: 0, MaxLength: 0, FileLevel: true,
			PathHints: []string{"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".git-credentials", ".netrc", ".pypirc", ".npmrc", ".htpasswd", "service-account.json", "credentials.json"},
		},
	}
}

// RuleByID returns a rule by identifier.
func RuleByID(id string) (*Rule, bool) {
	for _, r := range Rules() {
		if r.ID == id {
			return r, true
		}
	}
	return nil, false
}
