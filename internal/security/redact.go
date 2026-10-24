// Package security holds the defensive primitives Wardline uses when handling
// untrusted repository content: bounded file reads, path normalisation, secret
// masking and text sanitisation.
package security

import (
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
