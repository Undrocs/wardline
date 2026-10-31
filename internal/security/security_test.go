package security

import (
	"strings"
	"testing"
	"testing/quick"
)

func TestMaskSecretNeverRevealsValue(t *testing.T) {
	cases := []string{
		"a",
		"short",
		"AKIA" + "IOSFODNN7EXAMPLE",
		"ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz012345",
		"wJalrXUtnFEMI/K7MDENG/bPxRfiCYzq7pLm2Kd9Rt",
		strings.Repeat("x", 200),
	}
	for _, secret := range cases {
		masked := MaskSecret(secret)
		if masked == secret && len(secret) > 0 {
			t.Fatalf("MaskSecret(%q) returned the original value", secret)
		}
		if len(secret) >= 8 && strings.Contains(masked, secret[1:len(secret)-1]) {
			t.Fatalf("MaskSecret(%q) leaked a substring: %q", secret, masked)
		}
		if len(secret) > 8 && strings.Contains(masked, secret) {
			t.Fatalf("MaskSecret(%q) contains the original value", secret)
		}
	}
}

func TestMaskSecretKeepsUsefulContext(t *testing.T) {
	masked := MaskSecret("AKIA" + "Q7X4R2ZP5RTMNW3V")
	if !strings.HasPrefix(masked, "AKIA") {
		t.Fatalf("expected the vendor prefix to remain visible, got %q", masked)
	}
	if strings.Contains(masked, "Q7X4R2") {
		t.Fatalf("expected the middle of the secret to be hidden, got %q", masked)
	}
}

func TestMaskSecretProperty(t *testing.T) {
	property := func(s string) bool {
		runes := []rune(s)
		masked := MaskSecret(s)
		if len(runes) == 0 {
			return masked == "[redacted]"
		}
		if masked == s {
			return false
		}
		// At most 8 original characters may survive, and the hidden middle is
		// always replaced by mask runes.
		visible, maskedRunes := 0, 0
		for _, r := range masked {
			if r == '•' {
				maskedRunes++
				continue
			}
			visible++
		}
		if len(runes) >= 8 {
			return visible <= 8 && maskedRunes >= 6
		}
		return visible == 0
	}
	if err := quick.Check(property, &quick.Config{MaxCount: 500}); err != nil {
		t.Fatalf("mask property violated: %v", err)
	}
}

func FuzzMaskSecret(f *testing.F) {
	f.Add("AKIA" + "Q7X4R2ZP5RTMNW3V")
	f.Add("")
	f.Add("-----BEGIN" + " RSA PRIVATE KEY-----")
	f.Fuzz(func(t *testing.T, s string) {
		masked := MaskSecret(s)
		if s != "" && masked == s {
			t.Fatalf("masked value equals input")
		}
		if len(s) > 64 && strings.Contains(masked, s) {
			t.Fatalf("masked value contains input")
		}
	})
}

func TestSanitizeEvidence(t *testing.T) {
	got := SanitizeEvidence("key\x00 = \"value\"\n\n\tnext", 100)
	if strings.ContainsAny(got, "\x00\n\t") {
		t.Fatalf("control characters were not removed: %q", got)
	}
	if got != "key = \"value\" next" {
		t.Fatalf("unexpected sanitised output: %q", got)
	}
	long := SanitizeEvidence(strings.Repeat("a", 500), 20)
	if len([]rune(long)) > 21 {
		t.Fatalf("truncation failed: %d runes", len([]rune(long)))
	}
	invalid := SanitizeEvidence(string([]byte{0xff, 0xfe, 'a', 'b'}), 50)
	if !strings.Contains(invalid, "ab") {
		t.Fatalf("valid runes were lost: %q", invalid)
	}
}

func TestShannonEntropy(t *testing.T) {
	if e := ShannonEntropy(""); e != 0 {
		t.Fatalf("empty entropy = %v", e)
	}
	if e := ShannonEntropy("aaaaaaaa"); e != 0 {
		t.Fatalf("repeated character entropy = %v", e)
	}
	if e := ShannonEntropy("aB3$xY9!"); e < 2.5 {
		t.Fatalf("mixed string entropy too low: %v", e)
	}
}

func TestLooksLikePlaceholder(t *testing.T) {
	placeholders := []string{
		"", "changeme", "your-api-key-here", "REPLACE_ME", "xxxxxxxx",
		"${DB_PASSWORD}", "{{ .Values.password }}", "<your-token>",
		"example", "not-a-real-secret", "password", "0000", "...",
	}
	for _, p := range placeholders {
		if !LooksLikePlaceholder(p) {
			t.Errorf("expected %q to be treated as a placeholder", p)
		}
	}
	real := []string{"Zq7pLm2Kd9Rt4Wx1", "AKIA" + "Q7X4R2ZP5RTMNW3V", "hunter2hunter2"}
	for _, r := range real {
		if LooksLikePlaceholder(r) {
			t.Errorf("expected %q to be treated as a real value", r)
		}
	}
}

func TestLooksRandom(t *testing.T) {
	if LooksRandom("AWS_SECRET_ACCESS_KEY", 3.0) {
		t.Error("identifier with no digits was considered random")
	}
	if !LooksRandom("Zq7pLm2Kd9Rt4Wx1", 3.0) {
		t.Error("mixed value was not considered random")
	}
	if LooksRandom("short1", 3.0) {
		t.Error("short value was considered random")
	}
}

func TestRedactCredentialsMasksEveryShape(t *testing.T) {
	cases := []struct {
		name string
		in   string
		// wantAbsent are substrings that must not survive redaction.
		wantAbsent []string
		// wantPresent are substrings that must survive, proving the surrounding
		// context is still useful.
		wantPresent []string
	}{
		{
			name:        "dockerfile env assignment",
			in:          "ENV DB_PASSWORD=hunter2 API_TOKEN=abc123",
			wantAbsent:  []string{"hunter2", "abc123"},
			wantPresent: []string{"DB_PASSWORD", "API_TOKEN"},
		},
		{
			name:        "short password in a run command",
			in:          "RUN mysql --password=Secr3t99 -e 'select 1'",
			wantAbsent:  []string{"Secr3t99"},
			wantPresent: []string{"mysql"},
		},
		{
			name:        "multiple credentials on one line",
			in:          "curl -H 'Authorization: token ghp_Q7mXr4Tz9KpL2WcV8bN3jH6yF5dS1aE0uG8i' https://x?api_key=AKIAQ7X4R2ZP5RTMNW3V",
			wantAbsent:  []string{"ghp_Q7mXr4Tz9KpL2WcV8bN3jH6yF5dS1aE0uG8i", "AKIAQ7X4R2ZP5RTMNW3V"},
			wantPresent: []string{"curl", "https://x"},
		},
		{
			name:        "http auth scheme keeps the token intact",
			in:          "curl -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl' https://api.example.com",
			wantAbsent:  []string{"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl"},
			wantPresent: []string{"Bearer", "https://api.example.com"},
		},
		{
			name:        "curl user flag",
			in:          "RUN curl -u deploy:hunter2 https://artifacts.internal/pkg.tgz",
			wantAbsent:  []string{"hunter2"},
			wantPresent: []string{"-u", "deploy:", "https://artifacts.internal"},
		},
		{
			name:        "separate password argument",
			in:          "RUN mysql --password Secr3t99 -e 'select 1'",
			wantAbsent:  []string{"Secr3t99"},
			wantPresent: []string{"--password", "mysql"},
		},
		{
			name:        "url userinfo",
			in:          "RUN psql postgres://svc:hunter2@db.internal:5432/app",
			wantAbsent:  []string{"hunter2"},
			wantPresent: []string{"postgres://svc", "db.internal"},
		},
		{
			name:        "yaml style",
			in:          "password: \"Lm4Qp9Zx2Tr7Wc5V\"\nuser: app",
			wantAbsent:  []string{"Lm4Qp9Zx2Tr7Wc5V"},
			wantPresent: []string{"password:", "user: app"},
		},
		{
			// The header is structural and is what a reader needs to identify
			// the finding; the key material below it is what must be masked.
			name:        "private key body",
			in:          "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0000000000000000abcdefghij\n-----END RSA PRIVATE KEY-----",
			wantAbsent:  []string{"MIIEowIBAAKCAQEA0000000000000000abcdefghij"},
			wantPresent: []string{"BEGIN RSA PRIVATE KEY"},
		},
		{
			name:        "placeholder is preserved",
			in:          "ENV DB_PASSWORD=${DB_PASSWORD}",
			wantPresent: []string{"${DB_PASSWORD}"},
		},
		{
			name:        "empty input",
			in:          "",
			wantPresent: []string{""},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := RedactCredentials(c.in)
			for _, absent := range c.wantAbsent {
				if strings.Contains(got, absent) {
					t.Fatalf("redacted text still contains %q: %q", absent, got)
				}
			}
			for _, present := range c.wantPresent {
				if !strings.Contains(got, present) {
					t.Fatalf("redacted text lost %q: %q", present, got)
				}
			}
		})
	}
}

func TestRedactCredentialsIsIdempotent(t *testing.T) {
	// Reports re-run redaction as a safety net, so running it twice must not
	// keep changing the text.
	in := "ENV API_KEY=abcd1234efgh RUN curl https://x?token=ghp_Q7mXr4Tz9KpL2WcV8bN3jH6yF5dS1aE0uG8i"
	once := RedactCredentials(in)
	twice := RedactCredentials(once)
	if once != twice {
		t.Fatalf("redaction is not idempotent:\n once: %q\ntwice: %q", once, twice)
	}
	if strings.Contains(once, "abcd1234efgh") {
		t.Fatalf("short credential survived: %q", once)
	}
}

func FuzzRedactCredentials(f *testing.F) {
	f.Add("password=hunter2")
	f.Add("postgres://user:pass@host/db")
	f.Add("AKIAIOSFODNN7EXAMPLE")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		got := RedactCredentials(s)
		if got != RedactCredentials(got) {
			t.Fatalf("not idempotent for %q", s)
		}
	})
}
