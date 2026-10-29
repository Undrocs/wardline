// Package security holds the defensive primitives Wardline uses when handling
// untrusted repository content: bounded file reads, path normalisation, secret
// masking and text sanitisation.
package security

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// MaskSecret returns a redacted rendering of a credential.
//
// The result never contains the complete value, and the number of visible
// characters is capped so that a masked secret cannot be trivially reconstructed.
// Masked values are safe to print, log, serialise and attach to a report.
func MaskSecret(secret string) string {
	runes := []rune(secret)
	n := len(runes)
	switch {
	case n == 0:
		return "[redacted]"
	case n < 8:
		// Too short to reveal any characters without materially leaking it.
		return strings.Repeat("•", n)
	case n < 16:
		return string(runes[:1]) + strings.Repeat("•", 6) + string(runes[n-1:])
	case n < 24:
		// Four leading characters keep vendor prefixes recognisable (AKIA, ghp_)
		// without exposing enough of a short secret to weaken it.
		return string(runes[:4]) + strings.Repeat("•", 6) + string(runes[n-1:])
	default:
		return string(runes[:4]) + strings.Repeat("•", 6) + string(runes[n-4:])
	}
}

// SanitizeEvidence normalises a code excerpt so it is safe to embed in reports.
//
// It converts control characters to spaces, collapses runs of whitespace,
// truncates to maxRunes and drops invalid UTF-8. It never removes secrets:
// scanners must redact before calling it.
func SanitizeEvidence(s string, maxRunes int) string {
	if maxRunes <= 0 {
		maxRunes = 200
	}
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "")
	}
	var b strings.Builder
	lastSpace := false
	written := 0
	truncated := false
	for _, r := range s {
		if r == '\n' || r == '\r' || unicode.IsControl(r) || r == '\uFFFD' {
			r = ' '
		}
		if unicode.IsSpace(r) {
			if lastSpace {
				continue
			}
			lastSpace, r = true, ' '
		} else {
			lastSpace = false
		}
		if written == maxRunes {
			truncated = true
			break
		}
		b.WriteRune(r)
		written++
	}
	out := strings.TrimSpace(b.String())
	if truncated {
		out += "…"
	}
	return out
}

// RedactEvidence redacts credentials and then normalises/truncates the result
// for storage on a finding.
//
// The order matters: truncating first can cut a credential in half so that the
// redaction pattern no longer recognises it (an e-mail-style password, or the
// userinfo section of a URL whose '@' falls outside the window). Redaction is
// applied to the whole value and only the redacted text is shortened.
func RedactEvidence(s string, maxRunes int) string {
	return SanitizeEvidence(RedactCredentials(s), maxRunes)
}

// credentialKeyPattern matches assignment keys whose value is a credential.
// It is case-insensitive and tolerant of quoting, "=" or ":" separators and
// surrounding shell syntax, because the same pattern has to serve Dockerfile
// instructions, Compose files, YAML and shell scripts.
var credentialKeyPattern = regexp.MustCompile(`(?i)([A-Za-z0-9_.-]*(?:password|passwd|passphrase|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|credential|_auth)[A-Za-z0-9_.-]*)(\s*[:=]\s*)(["']?)([^\s"'\\,;)]+)(["']?)`)

// urlUserinfoPattern matches the password part of scheme://user:password@host.
var urlUserinfoPattern = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://[^:/@\s]+:)([^@\s/]+)(@)`)

// authSchemePattern matches credentials carried by an HTTP authentication
// scheme, such as "Authorization: Bearer <token>". The scheme keyword is kept
// because it is what makes the finding understandable; the credential after it
// is masked. The key/value pattern alone cannot do this: it treats "Bearer" as
// the value and leaves the token visible.
var authSchemePattern = regexp.MustCompile(`(?i)\b(bearer|basic|digest|token|apikey)\s+([A-Za-z0-9._~+/=:-]{8,})`)

// cliFlagPattern matches credentials passed as a separate command-line
// argument, such as "curl -u user:pass" or "mysql --password hunter2".
// Only the value is replaced; the flag stays readable. The flag must start
// with a dash so that ordinary prose is not redacted.
var cliFlagPattern = regexp.MustCompile(`(?i)(^|[\s"'])(-{1,2}(?:password|passwd|token|secret|api[_-]?key|access[_-]?key|client[_-]?secret|auth[_-]?token|u|user))\s+([^\s"'\\;|&]+)`)

// longTokenPattern matches machine-generated tokens in free text.
var longTokenPattern = regexp.MustCompile(`[A-Za-z0-9_\-+/=.]{16,}`)

// credentialPrefixes identify vendor tokens even when they contain no digits.
var credentialPrefixes = []string{
	"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "glpat-",
	"sk_live_", "sk_test_", "sk-proj-", "npm_", "pypi-", "aiza", "akia",
	"asia", "xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-", "sg.", "hvs.",
	"hvb.", "hvr.", "dop_v1_", "sq0atp-", "sq0csp-", "whsec_", "accountkey=",
	"private key-----", "begin rsa", "begin openssh", "begin ec", "begin pgp",
	"begin dsa",
}

// RedactCredentials masks credential material in free text before the text is
// stored in a finding or written to a report.
//
// It handles the shapes that appear in build and CI files:
//
//   - assignments such as PASSWORD=hunter2, api_key: "abc", --token=xyz;
//   - credentials embedded in URLs (scheme://user:password@host);
//   - vendor-prefixed tokens (ghp_, AKIA…, sk_live_…, glpat-…);
//   - long high-entropy tokens in free text;
//   - private key headers.
//
// It never inspects the whole file: callers pass the excerpt they are about to
// store, and the result is safe to print, serialise and attach to a report.
func RedactCredentials(s string) string {
	if s == "" {
		return s
	}
	s = urlUserinfoPattern.ReplaceAllStringFunc(s, func(m string) string {
		sub := urlUserinfoPattern.FindStringSubmatch(m)
		if len(sub) != 4 {
			return m
		}
		return sub[1] + MaskSecret(sub[2]) + sub[3]
	})
	s = credentialKeyPattern.ReplaceAllStringFunc(s, func(m string) string {
		sub := credentialKeyPattern.FindStringSubmatch(m)
		if len(sub) != 6 {
			return m
		}
		key, sep, quote, value, closing := sub[1], sub[2], sub[3], sub[4], sub[5]
		// An interpolation or a documented placeholder is not a credential and
		// masking it would hide what the user wrote. A value that already
		// contains the mask rune was redacted by an earlier pass, which keeps
		// the function idempotent for reports that re-run it.
		if strings.ContainsAny(value, "$%{") || strings.ContainsRune(value, '•') || LooksLikePlaceholder(value) {
			return m
		}
		return key + sep + quote + MaskSecret(value) + closing
	})
	s = authSchemePattern.ReplaceAllStringFunc(s, func(m string) string {
		sub := authSchemePattern.FindStringSubmatch(m)
		if len(sub) != 3 || strings.ContainsRune(sub[2], '•') || LooksLikePlaceholder(sub[2]) {
			return m
		}
		return sub[1] + " " + MaskSecret(sub[2])
	})
	s = cliFlagPattern.ReplaceAllStringFunc(s, func(m string) string {
		sub := cliFlagPattern.FindStringSubmatch(m)
		if len(sub) != 4 {
			return m
		}
		prefix, flag, value := sub[1], sub[2], sub[3]
		if strings.ContainsRune(value, '•') || LooksLikePlaceholder(value) || strings.ContainsAny(value, "$%{") {
			return m
		}
		// For credential flags whose value is "user:password" or "user:password"
		// inside a URL, keep the user name and mask only the password.
		if idx := strings.Index(value, ":"); idx > 0 && idx < len(value)-1 {
			value = value[:idx] + ":" + MaskSecret(value[idx+1:])
		} else {
			value = MaskSecret(value)
		}
		return prefix + flag + " " + value
	})
	s = longTokenPattern.ReplaceAllStringFunc(s, func(token string) string {
		if LooksLikePlaceholder(token) || strings.ContainsRune(token, '•') {
			return token
		}
		lower := strings.ToLower(token)
		for _, prefix := range credentialPrefixes {
			if strings.HasPrefix(lower, prefix) || strings.Contains(lower, prefix) {
				return MaskSecret(token)
			}
		}
		// Long mixed-alphabet tokens are treated as credentials; ordinary
		// identifiers such as AWS_SECRET_ACCESS_KEY are left readable.
		if len(token) >= 32 && LooksRandom(token, 3.0) {
			return MaskSecret(token)
		}
		return token
	})
	return s
}
