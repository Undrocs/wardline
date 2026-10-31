// Package osv is a small, defensive client for the OSV.dev vulnerability API.
//
// Only package coordinates (ecosystem, name, version) are transmitted. Wardline
// never sends file content, source code or discovered secrets to this or any
// other service.
//
// The client enforces request timeouts, response-size limits, bounded
// concurrency and retries with backoff, and it never converts a failed request
// into an empty (apparently clean) result.
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Undrocs/wardline/internal/netguard"
)

// DefaultEndpoint is the official OSV API endpoint.
const DefaultEndpoint = "https://api.osv.dev"

const (
	// maxResponseBytes caps a single API response body (32 MiB).
	maxResponseBytes = 32 << 20
	// batchSize is the number of queries sent per batch request. OSV accepts
	// larger batches; 500 keeps request bodies and failure blasts small.
	batchSize = 500
	// detailWorkers bounds concurrent advisory detail requests.
	detailWorkers = 4
	// maxRetries is the number of additional attempts for retryable failures.
	maxRetries = 2
)

// ErrRateLimited marks a response that the endpoint refused because of rate
// limiting. Callers can distinguish it from a malformed or rejected request.
var ErrRateLimited = errors.New("OSV endpoint rate limited the request")

// Package identifies a package coordinate.
type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

// Query is a single vulnerability lookup.
type Query struct {
	Package Package `json:"package"`
	Version string  `json:"version,omitempty"`
}

// Vulnerability is the subset of the OSV schema Wardline consumes.
type Vulnerability struct {
	ID        string   `json:"id"`
	Summary   string   `json:"summary"`
	Details   string   `json:"details"`
	Aliases   []string `json:"aliases"`
	Modified  string   `json:"modified"`
	Published string   `json:"published"`
	Severity  []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected   []Affected `json:"affected"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
		CWE      []any  `json:"cwe_ids"`
	} `json:"database_specific"`
}

// Affected describes the affected ranges for one package.
type Affected struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	Ranges []struct {
		Type   string `json:"type"`
		Events []struct {
			Introduced   string `json:"introduced"`
			Fixed        string `json:"fixed"`
			LastAffected string `json:"last_affected"`
			Limit        string `json:"limit"`
		} `json:"events"`
	} `json:"ranges"`
	Versions []string `json:"versions"`
}

// QueryResult is the minimal batch response entry for one query.
type QueryResult struct {
	Vulns []struct {
		ID       string `json:"id"`
		Modified string `json:"modified"`
	} `json:"vulns"`
}

// Client talks to an OSV-compatible endpoint.
type Client struct {
	baseURL   string
	http      *http.Client
	policy    netguard.Policy
	userAgent string
	logf      func(string, ...any)

	mu    sync.Mutex
	cache map[string]*Vulnerability
}

// Option customises a Client.
type Option func(*Client)

// WithUserAgent sets the HTTP User-Agent.
func WithUserAgent(ua string) Option { return func(c *Client) { c.userAgent = ua } }

// WithLogger sets a verbose logger.
func WithLogger(logf func(string, ...any)) Option { return func(c *Client) { c.logf = logf } }

// WithPolicy sets the outbound network policy. The default policy permits only
// the official endpoint; a custom endpoint (an internal mirror, a test server)
// has to be approved explicitly by the caller.
func WithPolicy(p netguard.Policy) Option { return func(c *Client) { c.policy = p } }

// New creates a client. When httpClient is nil a policy-enforcing default is
// used.
//
// The endpoint is validated against the client policy before any request is
// made, so an endpoint that reached this function from configuration cannot be
// used unless the caller approved it.
func New(baseURL string, httpClient *http.Client, opts ...Option) (*Client, error) {
	c := &Client{
		userAgent: "wardline",
		cache:     map[string]*Vulnerability{},
	}
	for _, opt := range opts {
		if opt != nil {
			opt(c)
		}
	}
	if strings.TrimSpace(baseURL) == "" {
		baseURL = DefaultEndpoint
	}
	endpoint, err := netguard.Check(baseURL, c.policy)
	if err != nil {
		return nil, fmt.Errorf("invalid OSV endpoint: %w", err)
	}
	c.baseURL = endpoint
	if httpClient == nil {
		httpClient = netguard.NewHTTPClient(c.policy, 20*time.Second, false)
	} else {
		// Honour the caller's transport, timeouts and proxy, but never their
		// redirect policy: a redirect is how a permitted host would reach a
		// forbidden one.
		clone := *httpClient
		clone.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			first := req.URL
			if len(via) > 0 {
				first = via[0].URL
			}
			return netguard.CheckRedirect(req.URL, first, c.policy)
		}
		httpClient = &clone
	}
	c.http = httpClient
	return c, nil
}

// Endpoint returns the configured base URL.
func (c *Client) Endpoint() string { return c.baseURL }

// QueryBatch queries OSV for every package coordinate.
//
// Responses are returned in the same order as the input. When a chunk fails,
// the results collected so far are returned together with the error so callers
// can report a partial scan instead of pretending the unchecked packages are
// clean.
func (c *Client) QueryBatch(ctx context.Context, queries []Query) ([]QueryResult, error) {
	out := make([]QueryResult, len(queries))
	for start := 0; start < len(queries); start += batchSize {
		end := start + batchSize
		if end > len(queries) {
			end = len(queries)
		}
		chunk := queries[start:end]
		results, err := c.queryChunk(ctx, chunk)
		if err != nil {
			return out[:start], err
		}
		copy(out[start:end], results)
	}
	return out, nil
}

func (c *Client) queryChunk(ctx context.Context, chunk []Query) ([]QueryResult, error) {
	body := struct {
		Queries []Query `json:"queries"`
	}{Queries: chunk}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("encode OSV request: %w", err)
	}
	var parsed struct {
		Results []QueryResult `json:"results"`
	}
	if err := c.do(ctx, http.MethodPost, "/v1/querybatch", payload, &parsed); err != nil {
		return nil, err
	}
	if len(parsed.Results) != len(chunk) {
		return nil, fmt.Errorf("OSV returned %d results for %d queries; a partial response cannot be trusted", len(parsed.Results), len(chunk))
	}
	return parsed.Results, nil
}

// Fetch retrieves advisory details, caching responses per ID.
func (c *Client) Fetch(ctx context.Context, id string) (*Vulnerability, error) {
	if id == "" {
		return nil, errors.New("empty advisory id")
	}
	c.mu.Lock()
	if v, ok := c.cache[id]; ok {
		c.mu.Unlock()
		return v, nil
	}
	c.mu.Unlock()

	var vuln Vulnerability
	if err := c.do(ctx, http.MethodGet, "/v1/vulns/"+url.PathEscape(id), nil, &vuln); err != nil {
		return nil, err
	}
	if vuln.ID == "" {
		return nil, fmt.Errorf("OSV returned an advisory without an id for %s", id)
	}
	c.mu.Lock()
	c.cache[id] = &vuln
	c.mu.Unlock()
	return &vuln, nil
}

// FetchMany retrieves advisory details concurrently with bounded workers.
// Individual failures are returned per ID and never abort the whole fetch.
func (c *Client) FetchMany(ctx context.Context, ids []string) (map[string]*Vulnerability, map[string]error) {
	unique := make([]string, 0, len(ids))
	seen := map[string]bool{}
	for _, id := range ids {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		unique = append(unique, id)
	}
	out := make(map[string]*Vulnerability, len(unique))
	errs := make(map[string]error)
	if len(unique) == 0 {
		return out, errs
	}
	// Bounded worker pool: an advisory list is attacker-influenced input, so the
	// number of concurrent requests must not scale with it.
	workers := detailWorkers
	if workers > len(unique) {
		workers = len(unique)
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	jobs := make(chan string)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range jobs {
				v, err := c.Fetch(ctx, id)
				mu.Lock()
				if err != nil {
					errs[id] = err
				} else {
					out[id] = v
				}
				mu.Unlock()
			}
		}()
	}
	for _, id := range unique {
		if err := ctx.Err(); err != nil {
			mu.Lock()
			errs[id] = err
			mu.Unlock()
			continue
		}
		jobs <- id
	}
	close(jobs)
	wg.Wait()
	return out, errs
}

// do performs one request with retries for transient failures.
func (c *Client) do(ctx context.Context, method, path string, payload []byte, into any) error {
	endpoint := c.baseURL + path
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			delay := time.Duration(250*(1<<(attempt-1))) * time.Millisecond
			// Add jitter so parallel clients do not retry in lockstep.
			delay += time.Duration(rand.Int63n(int64(100 * time.Millisecond)))
			if c.logf != nil {
				c.logf("osv: retrying %s in %s after: %v", path, delay, lastErr)
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
		}
		retryable, err := c.once(ctx, method, endpoint, payload, into)
		if err == nil {
			return nil
		}
		lastErr = err
		if !retryable {
			return err
		}
	}
	return lastErr
}

func (c *Client) once(ctx context.Context, method, endpoint string, payload []byte, into any) (retryable bool, err error) {
	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return false, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		return true, fmt.Errorf("request to %s failed: %w", sanitizeURL(endpoint), err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		msg := readLimited(resp.Body, 512)
		switch {
		case resp.StatusCode == http.StatusTooManyRequests:
			return true, fmt.Errorf("%w: %s returned HTTP 429 after %d attempt(s)%s", ErrRateLimited, sanitizeURL(endpoint), maxRetries+1, detailSuffix(msg))
		case resp.StatusCode >= 500:
			return true, fmt.Errorf("%s returned HTTP %d%s", sanitizeURL(endpoint), resp.StatusCode, detailSuffix(msg))
		case resp.StatusCode == http.StatusNotFound:
			return false, fmt.Errorf("%s returned HTTP 404: advisory not found", sanitizeURL(endpoint))
		default:
			return false, fmt.Errorf("%s returned HTTP %d%s", sanitizeURL(endpoint), resp.StatusCode, detailSuffix(msg))
		}
	}
	limited := io.LimitReader(resp.Body, maxResponseBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return true, fmt.Errorf("read response from %s: %w", sanitizeURL(endpoint), err)
	}
	if int64(len(data)) > maxResponseBytes {
		return false, fmt.Errorf("response from %s exceeded the %d byte limit", sanitizeURL(endpoint), maxResponseBytes)
	}
	// Unknown fields are ignored on purpose: OSV adds advisory fields over time
	// and an unrecognised field must never fail a scan.
	if err := json.Unmarshal(data, into); err != nil {
		return false, fmt.Errorf("decode response from %s: %w", sanitizeURL(endpoint), err)
	}
	return false, nil
}

func detailSuffix(msg string) string {
	msg = strings.TrimSpace(msg)
	if msg == "" {
		return ""
	}
	if len(msg) > 120 {
		msg = msg[:120] + "…"
	}
	return ": " + msg
}

func sanitizeURL(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "OSV endpoint"
	}
	u.RawQuery, u.Fragment, u.User = "", "", nil
	return u.String()
}

func readLimited(r io.Reader, n int64) string {
	b, err := io.ReadAll(io.LimitReader(r, n))
	if err != nil {
		return ""
	}
	return string(b)
}

// AffectedFixedVersion extracts the lowest "fixed" version for the package
// matching the query from an advisory.
func (v *Vulnerability) AffectedFixedVersion(ecosystem, name string) string {
	if v == nil {
		return ""
	}
	for _, aff := range v.Affected {
		if !strings.EqualFold(aff.Package.Ecosystem, ecosystem) || aff.Package.Name != name {
			continue
		}
		for _, rng := range aff.Ranges {
			for _, ev := range rng.Events {
				if ev.Fixed != "" {
					return ev.Fixed
				}
			}
		}
	}
	return ""
}

// AffectedRange renders the affected versions/ranges for reports.
func (v *Vulnerability) AffectedRange(ecosystem, name string) string {
	if v == nil {
		return ""
	}
	for _, aff := range v.Affected {
		if !strings.EqualFold(aff.Package.Ecosystem, ecosystem) || aff.Package.Name != name {
			continue
		}
		var parts []string
		for _, rng := range aff.Ranges {
			var intro, fixed, last string
			for _, ev := range rng.Events {
				if ev.Introduced != "" {
					intro = ev.Introduced
				}
				if ev.Fixed != "" {
					fixed = ev.Fixed
				}
				if ev.LastAffected != "" {
					last = ev.LastAffected
				}
			}
			switch {
			case intro != "" && fixed != "":
				parts = append(parts, fmt.Sprintf(">= %s, < %s", intro, fixed))
			case intro != "" && last != "":
				parts = append(parts, fmt.Sprintf(">= %s, <= %s", intro, last))
			case intro != "":
				parts = append(parts, fmt.Sprintf(">= %s", intro))
			}
		}
		if len(aff.Versions) > 0 {
			shown := aff.Versions
			if len(shown) > 5 {
				shown = shown[:5]
			}
			parts = append(parts, "versions: "+strings.Join(shown, ", "))
		}
		return strings.Join(parts, "; ")
	}
	return ""
}
