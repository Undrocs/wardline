// Package fixtures materialises the synthetic vulnerable repository that the
// tests and scripts/smoke.sh scan.
//
// The credential-shaped values are assembled from fragments at run time instead
// of being stored verbatim. A repository holding a string that matches, say, a
// Slack webhook URL cannot be distinguished from one that leaks a real
// credential: hosting providers block such pushes and secret scanners raise
// alarms. The templates under testdata hold a {{PLACEHOLDER}} where the value
// belongs, and Materialize replaces it.
package fixtures

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// Template files carry this suffix; it is removed when the fixture is
// materialised.
const templateSuffix = ".tmpl"

// Vulnerable returns the path of the vulnerable fixture inside the repository.
func Vulnerable() (string, error) {
	root, err := Root()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "testdata", "vulnerable"), nil
}

// Clean returns the path of the clean fixture inside the repository.
func Clean() (string, error) {
	root, err := Root()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "testdata", "clean"), nil
}

// Root returns the module root directory, derived from the location of this
// file rather than from the working directory so that it works from any test.
func Root() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("cannot locate the fixture package source")
	}
	root := filepath.Dir(filepath.Dir(filepath.Dir(file)))
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		return "", fmt.Errorf("cannot locate the module root from %s: %w", file, err)
	}
	return root, nil
}

// CredentialValues returns the synthetic secrets planted in the vulnerable
// fixture. Tests assert that none of them reaches a report.
func CredentialValues() []string {
	values := make([]string, 0, len(credentials))
	for _, v := range credentials {
		values = append(values, v)
	}
	sort.Strings(values)
	return values
}

// credentials holds the synthetic values, keyed by the placeholder used in the
// fixture templates. Every fragment split below exists so that no complete
// credential-shaped string appears in the repository.
var credentials = map[string]string{
	"AWS_ACCESS_KEY_ID": "AKIA" + "Q7X4R2ZP5RTMNW3V",
	"AWS_SECRET_KEY":    "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYzq7pLm2Kd9Rt",
	"GITLAB_TOKEN":      "glpat-" + "Q7mXr4Tz9KpL2WcV8bN3",
	"SLACK_TOKEN":       "xoxb-" + "123456789012-abcdefghijklmnop",
	"SLACK_WEBHOOK":     "https://hooks.slack.com/" + "services/T00000000/B00000000/" + "Q7mXr4Tz9KpL2WcV8bN3jH6yF5dS1aE0uG8iQ7mXr4Tz9KpL2WcV8bN3jH6yF5dS1",
	"STRIPE_LIVE":       "sk_live_" + "Q7mXr4Tz9KpL2WcV8bN3jH6y",
	"STRIPE_TEST":       "sk_test_" + "Q7mXr4Tz9KpL2WcV8bN3jH6y",
	"GOOGLE_API_KEY":    "AIza" + "Q7X4R2ZP5RTMNW3Vq7pLm2Kd9Rt4Wx1AaBc",
	"PYPI_TOKEN":        "pypi-AgEIcHlwaS5vcmcQ" + "7mXr4Tz9KpL2WcV8bN3jH6yF5dS1aE0uG8iQ7mXr4Tz9AbCdE",
	"SENDGRID_KEY":      "SG.Q7mXr4Tz9KpL2WcV8bN3jH." + "Q7mXr4Tz9KpL2WcV8bN3jH6yF5dS1aE0uG8iQ7mXr4Tz9",
	"OPENAI_KEY":        "sk-proj-" + "Q7mXr4Tz9KpL2WcV8bN3jH6yF5dS1aE0uG8iQ7mXr4Tz9KpL2WcV8bN3jH6yF5dS1aE0uG8iQ7mXr4Tz9KpL2WcV8bN3jH6yF5dS1aE0uG8i",
	"DISCORD_WEBHOOK":   "https://discord.com/api/webhooks/" + "123456789012345678/" + "Q7mXr4Tz9KpL2WcV8bN3jH6yF5dS1aE0uG8iQ7mXr4Tz9KpL2WcV8bN3jH6yF5dS1",
	"AZURE_STORAGE":     "DefaultEndpointsProtocol=https;AccountName=examplestorage;AccountKey=" + "Q7mXr4Tz9KpL2WcV8bN3jH6yF5dS1aE0uG8iQ7mXr4Tz9KpL2WcV8bN3jH6yF5dS1aE0uG8iQ7mXr4Tz9KpL2==",
	"VAULT_TOKEN":       "hvs." + "CAESIJQ7mXr4Tz9KpL2WcV8bN3jH6yF5dS1aE0uG8iQ7mXr4",
	"TWILIO_KEY":        "SK" + "0123456789abcdef0123456789abcdef",
	"DIGITALOCEAN":      "dop_v1_" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	"SQUARE_TOKEN":      "sq0atp-" + "Q7mXr4Tz9KpL2WcV8bN3jH6y",
	"SESSION_JWT":       "eyJhbGciOiJIUzI1NiJ9." + "eyJzdWIiOiIxMjM0NTY3ODkwIn0." + "dQw4w9WgXcQ7mXr4Tz9KpL2",
	"GITHUB_TOKEN":      "ghp_" + "Q7mXr4Tz9KpL2WcV8bN3jH6yF5dS1aE0uG8i",
	"NPM_TOKEN":         "npm_" + "Q7mXr4Tz9KpL2WcV8bN3jH6yF5dS1aE0uG8i",
	"DATABASE_URL":      "postgres://reportsvc:" + "Yk4mPz9Qw2Er7Tt5" + "@db-prod.internal:5432/reports",
	// Split so that no single Go literal follows the key as a complete value:
	// the quoted-key rule (WL-SEC-022) would otherwise report this generator.
	"DB_PASSWORD":     "Zq7" + "pLm2Kd9Rt" + "4Wx1",
	"APP_PASSWORD":    "Lm4Qp9Zx2Tr7" + "Wc5V",
	"API_KEY":         "b7f3c9d1e5a8" + "b2c4d6f8a0b1c3d5e7f9",
	"SERVICE_API_KEY": "9c1f7b3a5d2e" + "8c4f6a0b9d7e3c5f1a2b",
	// The PEM header is split for the same reason, and the raw separator keeps the
	// block on one line exactly as the committed fixture always had it.
	"PRIVATE_KEY_BLOCK": strings.Join([]string{
		"-----BEGIN " + "RSA PRIVATE KEY-----",
		"MIIEowIBAAKCAQEA0000000000000000000000000000000000000000",
		"SyntheticFixtureOnlyNotARealKey0000000000000000000000000000",
		"-----END " + "RSA PRIVATE KEY-----",
	}, `\n`),
}

// Materialize copies the vulnerable fixture tree into dst, replacing
// {{PLACEHOLDER}} markers in template files and removing the template suffix.
// dst is created if necessary; it must be empty or absent.
func Materialize(dst string) error {
	src, err := Vulnerable()
	if err != nil {
		return err
	}
	return materializeTree(src, dst)
}

func materializeTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)

		if entry.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.HasSuffix(entry.Name(), templateSuffix) {
			target = strings.TrimSuffix(target, templateSuffix)
			if data, err = expand(data); err != nil {
				return fmt.Errorf("%s: %w", rel, err)
			}
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		return os.WriteFile(target, data, info.Mode().Perm())
	})
}

// expand replaces every known placeholder and rejects unknown ones, so a typo
// in a template cannot silently ship a fixture without its credential.
func expand(template []byte) ([]byte, error) {
	out := string(template)
	for name, value := range credentials {
		out = strings.ReplaceAll(out, "{{"+name+"}}", value)
	}
	if idx := strings.Index(out, "{{"); idx >= 0 {
		end := strings.Index(out[idx:], "}}")
		if end < 0 {
			return nil, fmt.Errorf("unterminated placeholder at byte %d", idx)
		}
		return nil, fmt.Errorf("unknown placeholder %s", out[idx:idx+end+2])
	}
	return []byte(out), nil
}
