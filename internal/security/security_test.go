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
