package secrets

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Undrocs/wardline/internal/security"
)

// localHosts are hostnames that indicate a local development connection string.
// A credential for localhost is still a secret, but it is not evidence of a
// production credential leak, and reporting every docker-compose default would
// bury real findings.
var localHosts = []string{
	"localhost", "127.0.0.1", "0.0.0.0", "::1", "host.docker.internal",
	"db", "database", "postgres", "mysql", "redis", "mongo", "mongodb", "cache",
}

// interpolationMarkers indicate that a value is resolved at runtime rather than
// hardcoded.
var interpolationMarkers = []string{
	"${", "{{", "$(", "%(", "<%", "os.environ", "process.env", "getenv",
	"System.getenv", "env[", "vault:", "sops:", "secretref", "*****", "xxxxx",
	"...", "redacted", "placeholder",
}

func containsInterpolation(value string) bool {
	lower := strings.ToLower(value)
	for _, marker := range interpolationMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// validateDatabaseURL inspects the full match so that host and username can be
// considered, not just the password.
func validateDatabaseURL(line string, match []int) bool {
	group := func(i int) string {
		if 2*i+1 >= len(match) || match[2*i] < 0 {
			return ""
		}
		return line[match[2*i]:match[2*i+1]]
	}
	user := group(2)
	password := group(3)
	host := strings.ToLower(group(4))

	if password == "" || user == "" {
		return false
	}
	if containsInterpolation(password) || containsInterpolation(user) {
		return false
	}
	if security.LooksLikePlaceholder(password) || security.LooksLikePlaceholder(user) {
		return false
	}
	if !utf8.ValidString(password) {
		return false
	}
	hostname := host
	if idx := strings.LastIndex(hostname, ":"); idx >= 0 {
		hostname = hostname[:idx]
	}
	for _, local := range localHosts {
		if hostname == local || strings.HasPrefix(hostname, local+".") {
			return false
		}
	}
	if strings.HasSuffix(hostname, ".example") || strings.HasSuffix(hostname, ".invalid") {
		return false
	}
	if len(password) < 4 {
		return false
	}
	if len(password) < 8 && security.ShannonEntropy(password) < 2.0 {
		return false
	}
	return true
}

// validatePassword rejects literals that are configuration indirection,
// documentation placeholders or obviously non-secret words.
func validatePassword(value string) bool {
	if containsInterpolation(value) {
		return false
	}
	lower := strings.ToLower(value)
	switch lower {
	case "password", "passwd", "secret", "changeme", "changeit", "admin",
		"root", "letmein", "test", "testing", "default", "example",
		"password1", "qwerty", "12345678":
		return false
	}
	if strings.HasPrefix(value, "!") && len(value) < 12 {
		// CI variable negation such as "!password".
		return false
	}
	classes := charClasses(value)
	if classes < 2 && security.ShannonEntropy(value) < 2.5 {
		return false
	}
	return true
}

// validateGenericToken rejects values that are clearly configuration paths,
// URLs or natural language rather than credentials.
func validateGenericToken(value string) bool {
	if containsInterpolation(value) {
		return false
	}
	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return false
	}
	if charClasses(value) < 2 {
		return false
	}
	// A dotted path such as "some.config.value" is not a credential.
	if strings.Count(value, ".") >= 2 && !strings.ContainsAny(value, "0123456789-_") {
		return false
	}
	return true
}

func charClasses(s string) int {
	var lower, upper, digit, symbol bool
	for _, r := range s {
		switch {
		case unicode.IsLower(r):
			lower = true
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsDigit(r):
			digit = true
		default:
			symbol = true
		}
	}
	n := 0
	for _, ok := range []bool{lower, upper, digit, symbol} {
		if ok {
			n++
		}
	}
	return n
}
