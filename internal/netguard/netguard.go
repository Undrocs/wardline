// Package netguard constrains where Wardline is allowed to send HTTP requests.
//
// The OSV endpoint can come from a repository's .wardline.yaml, which is
// untrusted input: a scanned repository must not be able to make the scanner
// contact an arbitrary host, a private-network service or a cloud metadata
// endpoint. The policy in this package is applied in three places:
//
//   - statically, when the endpoint URL is validated (scheme, host, address
//     class, known metadata host names);
//   - at connect time, through a dialer that inspects the address actually
//     being connected to, which also covers DNS answers that point somewhere
//     unexpected;
//   - on every redirect, so a permitted host cannot bounce the request to a
//     forbidden one.
//
// Metadata service addresses are never permitted, even with approval for a
// custom endpoint: no legitimate OSV mirror lives on a link-local metadata
// address.
package netguard

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// OfficialEndpoint is the only endpoint used without explicit approval.
const OfficialEndpoint = "https://api.osv.dev"

// maxRedirects bounds redirect chains. OSV does not redirect; a chain longer
// than this is treated as hostile.
const maxRedirects = 3

// Sentinel errors, so callers and tests can distinguish the failure classes.
var (
	// ErrInsecureScheme means the endpoint is not HTTPS (plain HTTP is only
	// tolerated for an approved loopback or private endpoint).
	ErrInsecureScheme = errors.New("endpoint must use https")
	// ErrCustomEndpoint means the endpoint is not the official one and approval
	// was not granted.
	ErrCustomEndpoint = errors.New("custom endpoint requires explicit approval")
	// ErrPrivateNetwork means the endpoint resolves to a loopback, private or
	// link-local address and approval was not granted.
	ErrPrivateNetwork = errors.New("endpoint targets a private or loopback address")
	// ErrMetadataService means the endpoint targets a cloud metadata service.
	ErrMetadataService = errors.New("endpoint targets a cloud metadata service")
	// ErrUnsafeURL means the URL is structurally unusable (userinfo, query,
	// fragment, missing host).
	ErrUnsafeURL = errors.New("unsafe endpoint URL")
)

// Policy describes what the operator has approved.
type Policy struct {
	// AllowCustomEndpoint permits an endpoint other than OfficialEndpoint, and
	// permits that endpoint to resolve to a private or loopback address. It is
	// only ever set from trusted input: a command line flag or the API, never
	// from a scanned repository's configuration.
	AllowCustomEndpoint bool
}

// Normalize returns the canonical form of an endpoint: trimmed, without a
// trailing slash, with a lower-case scheme and host.
func Normalize(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return strings.TrimRight(strings.TrimSpace(raw), "/")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	return strings.TrimRight(u.String(), "/")
}

// IsOfficial reports whether raw resolves to the official OSV endpoint.
func IsOfficial(raw string) bool {
	return Normalize(raw) == Normalize(OfficialEndpoint)
}

// Check validates an endpoint URL against the policy and returns its
// normalised form.
//
// It performs no DNS lookup: resolution happens later, and the dial guard is
// what enforces the address class at that point.
func Check(raw string, p Policy) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("%w: endpoint is empty", ErrUnsafeURL)
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrUnsafeURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("%w: %q must be an http(s) URL", ErrUnsafeURL, raw)
	}
	if u.Host == "" {
		return "", fmt.Errorf("%w: %q has no host", ErrUnsafeURL, raw)
	}
	if u.User != nil {
		return "", fmt.Errorf("%w: %q must not embed credentials", ErrUnsafeURL, raw)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("%w: %q must not contain a query or fragment", ErrUnsafeURL, raw)
	}
	if u.Path != "" && u.Path != "/" {
		return "", fmt.Errorf("%w: %q must not contain a path", ErrUnsafeURL, raw)
	}

	host := u.Hostname()
	class, err := ClassifyHost(host)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrUnsafeURL, err)
	}
	if class == ClassMetadata {
		return "", fmt.Errorf("%w: %s", ErrMetadataService, host)
	}
	official := IsOfficial(trimmed)
	if !official && !p.AllowCustomEndpoint {
		return "", fmt.Errorf("%w: %s is not %s; pass --allow-custom-endpoint to approve it",
			ErrCustomEndpoint, Normalize(trimmed), OfficialEndpoint)
	}
	if class == ClassPrivate && !p.AllowCustomEndpoint {
		return "", fmt.Errorf("%w: %s", ErrPrivateNetwork, host)
	}
	if u.Scheme == "http" && class == ClassPublic {
		return "", fmt.Errorf("%w: %s is a public host and must use https", ErrInsecureScheme, host)
	}
	if u.Scheme == "http" && !p.AllowCustomEndpoint {
		return "", fmt.Errorf("%w: %s", ErrInsecureScheme, host)
	}
	return Normalize(trimmed), nil
}

// Class is the network class of an endpoint host.
type Class int

const (
	// ClassPublic is a routable address on the public internet.
	ClassPublic Class = iota
	// ClassPrivate is loopback, RFC1918, link-local, unique-local or an
	// unspecified address.
	ClassPrivate
	// ClassMetadata is a cloud instance metadata service.
	ClassMetadata
)

// metadataHosts are host names that resolve to instance metadata services.
// The list is deliberately explicit rather than heuristic.
var metadataHosts = []string{
	"metadata.google.internal",
	"metadata.goog",
	"instance-data",
	"instance-data.ec2.internal",
	"metadata",
	"metadata.azure.com",
	"metadata.public.ctr",
}

// metadataPrefixes match provider-specific metadata names.
var metadataPrefixes = []string{
	"metadata.google.internal.",
	"metadata.azure.",
}

// metadataAddrs are the link-local and private addresses used by cloud
// metadata services, including container credential endpoints.
var metadataAddrs = []netip.Addr{
	netip.MustParseAddr("169.254.169.254"), // AWS, GCP, Azure, DigitalOcean
	netip.MustParseAddr("169.254.170.2"),   // AWS ECS task credentials
	netip.MustParseAddr("100.100.100.200"), // Alibaba Cloud
	netip.MustParseAddr("192.0.0.192"),     // Oracle Cloud
	netip.MustParseAddr("fd00:ec2::254"),   // AWS IPv6
}

// ClassifyHost classifies a host name or IP literal without doing DNS lookups.
// Host names other than known metadata names are treated as public; the dial
// guard classifies the resolved address again.
func ClassifyHost(host string) (Class, error) {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" {
		return ClassPublic, errors.New("empty host")
	}
	for _, m := range metadataHosts {
		if host == m {
			return ClassMetadata, nil
		}
	}
	for _, p := range metadataPrefixes {
		if strings.HasPrefix(host, p) {
			return ClassMetadata, nil
		}
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return ClassPrivate, nil
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = strings.Trim(host, "[]")
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return ClassifyAddr(addr), nil
	}
	return ClassPublic, nil
}

// ClassifyAddr classifies an IP address.
func ClassifyAddr(addr netip.Addr) Class {
	addr = addr.Unmap()
	for _, m := range metadataAddrs {
		if addr == m {
			return ClassMetadata
		}
	}
	switch {
	case addr.IsLoopback(), addr.IsPrivate(), addr.IsLinkLocalUnicast(),
		addr.IsLinkLocalMulticast(), addr.IsInterfaceLocalMulticast(),
		addr.IsUnspecified(), addr.IsMulticast():
		return ClassPrivate
	}
	// IPv4-mapped and 6to4/Teredo forms of a metadata address are covered by the
	// explicit list above after Unmap; anything else is treated as public.
	return ClassPublic
}

// DialControl returns a net.Dialer.Control hook that rejects connections to
// address classes the policy does not permit. The hook receives the address the
// socket is about to connect to, so a host name that resolves to a forbidden
// address is refused after resolution.
func DialControl(p Policy) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		return CheckDialHost(host, p)
	}
}

// CheckDialHost validates a host that is about to be dialled.
func CheckDialHost(host string, p Policy) error {
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = strings.Trim(host, "[]")
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		// Not an IP literal: the net package resolves names before dialling, so
		// this only happens for unusual networks. Classify by name.
		class, classErr := ClassifyHost(host)
		if classErr != nil {
			return classErr
		}
		if class == ClassMetadata {
			return fmt.Errorf("%w: %s", ErrMetadataService, host)
		}
		return nil
	}
	switch ClassifyAddr(addr) {
	case ClassMetadata:
		return fmt.Errorf("%w: %s", ErrMetadataService, addr)
	case ClassPrivate:
		if !p.AllowCustomEndpoint {
			return fmt.Errorf("%w: %s", ErrPrivateNetwork, addr)
		}
	}
	return nil
}

// CheckRedirect validates a redirect hop against the original endpoint.
//
// Cross-host redirects are refused outright: an OSV endpoint has no reason to
// send the client to a different host, and allowing it would let a compromised
// or misconfigured mirror reach any destination the policy permits.
func CheckRedirect(dst, first *url.URL, p Policy) error {
	if dst == nil || first == nil {
		return errors.New("redirect without a target")
	}
	if !strings.EqualFold(dst.Scheme, first.Scheme) {
		return fmt.Errorf("%w: redirect changed scheme from %s to %s", ErrUnsafeURL, first.Scheme, dst.Scheme)
	}
	if !strings.EqualFold(dst.Host, first.Host) {
		return fmt.Errorf("%w: redirect changed host from %s to %s", ErrUnsafeURL, first.Host, dst.Host)
	}
	class, err := ClassifyHost(dst.Hostname())
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnsafeURL, err)
	}
	if class == ClassMetadata {
		return fmt.Errorf("%w: %s", ErrMetadataService, dst.Hostname())
	}
	if class == ClassPrivate && !p.AllowCustomEndpoint {
		return fmt.Errorf("%w: %s", ErrPrivateNetwork, dst.Hostname())
	}
	return nil
}

// IsProxyConfigured reports whether the environment supplies an HTTP proxy.
// When it does, the dial guard is not installed: the proxy is operator-owned
// configuration, and the proxy address (often a private one) is not the
// destination being audited.
func IsProxyConfigured(getenv func(string) string) bool {
	if getenv == nil {
		return false
	}
	for _, name := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		if strings.TrimSpace(getenv(name)) != "" {
			return true
		}
	}
	return false
}

// NewHTTPClient builds an HTTP client with the policy applied to redirects and,
// unless allowUnrestrictedDial is set (a configured proxy owns the connection),
// to the addresses actually dialled.
func NewHTTPClient(p Policy, timeout time.Duration, allowUnrestrictedDial bool) *http.Client {
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	if !allowUnrestrictedDial {
		dialer.Control = DialControl(p)
	}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		MaxIdleConns:          8,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: 2 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return fmt.Errorf("stopped after %d redirects", maxRedirects)
		}
		first := req.URL
		if len(via) > 0 {
			first = via[0].URL
		}
		return CheckRedirect(req.URL, first, p)
	}
	return client
}
