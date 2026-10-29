package netguard

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestCheckAcceptsTheOfficialEndpoint(t *testing.T) {
	got, err := Check("HTTPS://API.OSV.DEV/", Policy{})
	if err != nil {
		t.Fatalf("official endpoint rejected: %v", err)
	}
	if got != "https://api.osv.dev" {
		t.Fatalf("normalisation failed: %q", got)
	}
}

func TestCheckRejectsUntrustedDestinations(t *testing.T) {
	cases := []struct {
		name    string
		url     string
		policy  Policy
		wantErr error
	}{
		{"plain http to a public host", "http://osv.example.com", Policy{AllowCustomEndpoint: true}, ErrInsecureScheme},
		{"custom endpoint without approval", "https://osv.example.com", Policy{}, ErrCustomEndpoint},
		{"loopback without approval", "https://127.0.0.1:8080", Policy{}, ErrCustomEndpoint},
		{"private network without approval", "https://10.1.2.3", Policy{}, ErrCustomEndpoint},
		{"metadata IPv4", "https://169.254.169.254", Policy{AllowCustomEndpoint: true}, ErrMetadataService},
		{"metadata IPv6", "https://[fd00:ec2::254]", Policy{AllowCustomEndpoint: true}, ErrMetadataService},
		{"metadata host name", "https://metadata.google.internal", Policy{AllowCustomEndpoint: true}, ErrMetadataService},
		{"ECS credentials endpoint", "http://169.254.170.2/v2/credentials", Policy{AllowCustomEndpoint: true}, ErrUnsafeURL},
		{"embedded credentials", "https://user:pass@osv.dev", Policy{AllowCustomEndpoint: true}, ErrUnsafeURL},
		{"query string", "https://osv.example.com/?proxy=1", Policy{AllowCustomEndpoint: true}, ErrUnsafeURL},
		{"path smuggling", "https://osv.example.com/../../v1", Policy{AllowCustomEndpoint: true}, ErrUnsafeURL},
		{"file scheme", "file:///etc/passwd", Policy{AllowCustomEndpoint: true}, ErrUnsafeURL},
		{"empty host", "https:///v1", Policy{AllowCustomEndpoint: true}, ErrUnsafeURL},
		{"gopher scheme", "gopher://osv.dev", Policy{AllowCustomEndpoint: true}, ErrUnsafeURL},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Check(c.url, c.policy)
			if err == nil {
				t.Fatalf("%s was accepted", c.url)
			}
			if !errors.Is(err, c.wantErr) {
				t.Fatalf("error %v does not wrap %v", err, c.wantErr)
			}
		})
	}
}

func TestCheckAcceptsAnApprovedPrivateEndpoint(t *testing.T) {
	// A local OSV mirror is a legitimate use case, but it must never be reached
	// without explicit approval.
	if _, err := Check("http://127.0.0.1:9000", Policy{AllowCustomEndpoint: true}); err != nil {
		t.Fatalf("approved loopback endpoint rejected: %v", err)
	}
	if _, err := Check("http://127.0.0.1:9000", Policy{}); err == nil {
		t.Fatal("unapproved loopback endpoint accepted")
	}
}

func TestCheckDialHostBlocksMetadataEvenWhenApproved(t *testing.T) {
	approved := Policy{AllowCustomEndpoint: true}
	if err := CheckDialHost("169.254.169.254", approved); !errors.Is(err, ErrMetadataService) {
		t.Fatalf("metadata address allowed: %v", err)
	}
	if err := CheckDialHost("::ffff:169.254.169.254", approved); !errors.Is(err, ErrMetadataService) {
		t.Fatalf("IPv4-mapped metadata address allowed: %v", err)
	}
	if err := CheckDialHost("10.0.0.7", Policy{}); !errors.Is(err, ErrPrivateNetwork) {
		t.Fatalf("private address allowed without approval: %v", err)
	}
	if err := CheckDialHost("10.0.0.7", approved); err != nil {
		t.Fatalf("approved private address rejected: %v", err)
	}
	if err := CheckDialHost("93.184.216.34", Policy{}); err != nil {
		t.Fatalf("public address rejected: %v", err)
	}
}

func TestClassifyAddr(t *testing.T) {
	cases := map[string]Class{
		"8.8.8.8":         ClassPublic,
		"127.0.0.1":       ClassPrivate,
		"10.0.0.1":        ClassPrivate,
		"192.168.1.1":     ClassPrivate,
		"172.16.0.1":      ClassPrivate,
		"169.254.1.1":     ClassPrivate,
		"0.0.0.0":         ClassPrivate,
		"::1":             ClassPrivate,
		"fd12:3456::1":    ClassPrivate,
		"169.254.169.254": ClassMetadata,
		"100.100.100.200": ClassMetadata,
		"192.0.0.192":     ClassMetadata,
		"2606:4700::1111": ClassPublic,
	}
	for raw, want := range cases {
		t.Run(raw, func(t *testing.T) {
			if got := ClassifyAddr(netip.MustParseAddr(raw)); got != want {
				t.Fatalf("ClassifyAddr(%s) = %v, want %v", raw, got, want)
			}
		})
	}
}

func TestCheckRedirectRejectsHostAndSchemeChanges(t *testing.T) {
	mustParse := func(raw string) *url.URL {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	first := mustParse("https://api.osv.dev/v1/querybatch")

	evil := mustParse("https://evil.example.com/collect")
	if err := CheckRedirect(evil, first, Policy{}); err == nil {
		t.Fatal("cross-host redirect allowed")
	}

	metadata := mustParse("https://169.254.169.254/latest/meta-data/")
	if err := CheckRedirect(metadata, first, Policy{AllowCustomEndpoint: true}); !errors.Is(err, ErrMetadataService) && !errors.Is(err, ErrUnsafeURL) {
		t.Fatalf("metadata redirect allowed: %v", err)
	}

	downgrade := mustParse("http://api.osv.dev/v1/querybatch")
	if err := CheckRedirect(downgrade, first, Policy{}); err == nil {
		t.Fatal("scheme downgrade allowed")
	}

	same := mustParse("https://api.osv.dev/v1/vulns/GHSA-x")
	if err := CheckRedirect(same, first, Policy{}); err != nil {
		t.Fatalf("same-host redirect rejected: %v", err)
	}
}

func TestClientRefusesRedirectToAnotherHost(t *testing.T) {
	// The redirect target is a second test server, so this exercises the real
	// client rather than the helper.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("request reached the redirect target")
	}))
	t.Cleanup(target.Close)

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	t.Cleanup(origin.Close)

	client := NewHTTPClient(Policy{AllowCustomEndpoint: true}, 2*time.Second, true)
	resp, err := client.Get(origin.URL)
	if err == nil {
		resp.Body.Close()
		t.Fatal("cross-host redirect was followed")
	}
	if !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestClientRefusesLoopbackDialWithoutApproval(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("request reached a loopback server without approval")
	}))
	t.Cleanup(server.Close)

	client := NewHTTPClient(Policy{}, 2*time.Second, false)
	resp, err := client.Get(server.URL)
	if err == nil {
		resp.Body.Close()
		t.Fatal("loopback connection allowed without approval")
	}
	if !errors.Is(err, ErrPrivateNetwork) && !strings.Contains(err.Error(), "private") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestClientAllowsApprovedLoopback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	client := NewHTTPClient(Policy{AllowCustomEndpoint: true}, 2*time.Second, false)
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("approved loopback request failed: %v", err)
	}
	resp.Body.Close()
}

func TestIsProxyConfigured(t *testing.T) {
	env := func(values map[string]string) func(string) string {
		return func(k string) string { return values[k] }
	}
	if IsProxyConfigured(env(map[string]string{})) {
		t.Fatal("no proxy reported when none is configured")
	}
	if !IsProxyConfigured(env(map[string]string{"HTTPS_PROXY": "http://proxy:3128"})) {
		t.Fatal("proxy not detected")
	}
	if !IsProxyConfigured(env(map[string]string{"http_proxy": "http://proxy:3128"})) {
		t.Fatal("lower-case proxy not detected")
	}
}
