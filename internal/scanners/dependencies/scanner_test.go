package dependencies

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Undrocs/wardline/internal/config"
	"github.com/Undrocs/wardline/internal/findings"
	"github.com/Undrocs/wardline/internal/scanners"
)

// osvMock is a deterministic stand-in for the OSV.dev API.
type osvMock struct {
	t            *testing.T
	server       *httptest.Server
	batchCalls   int32
	detailCalls  int32
	failBatch    int32 // number of remaining batch requests to fail
	failDetail   bool
	queryCount   int
	lastQueries  []map[string]any
	userAgents   []string
	vulns        map[string]map[string]any
	queryResults map[string][]string // "ecosystem/name@version" -> vuln ids
}

func newOSVMock(t *testing.T) *osvMock {
	m := &osvMock{
		t:            t,
		vulns:        map[string]map[string]any{},
		queryResults: map[string][]string{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/querybatch", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&m.batchCalls, 1)
		m.userAgents = append(m.userAgents, r.Header.Get("User-Agent"))
		if atomic.AddInt32(&m.failBatch, -1) >= 0 {
			http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			Queries []struct {
				Package struct {
					Ecosystem string `json:"ecosystem"`
					Name      string `json:"name"`
				} `json:"package"`
				Version string `json:"version"`
			} `json:"queries"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		m.queryCount += len(body.Queries)
		results := make([]map[string]any, 0, len(body.Queries))
		for _, q := range body.Queries {
			key := q.Package.Ecosystem + "/" + q.Package.Name + "@" + q.Version
			ids := m.queryResults[key]
			entry := map[string]any{}
			if len(ids) > 0 {
				var vulns []map[string]any
				for _, id := range ids {
					vulns = append(vulns, map[string]any{"id": id, "modified": "2026-01-01T00:00:00Z"})
				}
				entry["vulns"] = vulns
			}
			results = append(results, entry)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
	})
	mux.HandleFunc("/v1/vulns/", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&m.detailCalls, 1)
		if m.failDetail {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/v1/vulns/")
		vuln, ok := m.vulns[id]
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(vuln)
	})
	m.server = httptest.NewServer(mux)
	t.Cleanup(m.server.Close)
	return m
}

func (m *osvMock) addVuln(id string, vuln map[string]any) { m.vulns[id] = vuln }

func (m *osvMock) endpoint() string { return m.server.URL }

func writeDependencyFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func scanDependencies(t *testing.T, dir, endpoint string, offline bool) *scanners.Result {
	t.Helper()
	cfg := config.Default()
	cfg.Network.OSVEndpoint = endpoint
	var files []scanners.File
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		info, infoErr := d.Info()
		if infoErr != nil {
			return infoErr
		}
		rel, relErr := filepath.Rel(dir, path)
		if relErr != nil {
			return relErr
		}
		files = append(files, scanners.File{Rel: filepath.ToSlash(rel), Abs: path, Size: info.Size()})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	req := &scanners.Request{
		Root: dir, Files: files, Config: cfg, Offline: offline,
		Now:        time.Unix(1700000000, 0),
		HTTPClient: &http.Client{Timeout: 5 * time.Second},
	}
	res, err := New().Scan(context.Background(), req)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	return res
}

// TestUserAgentIdentifiesWardline verifies the scanner identifies itself to the
// OSV API with the tool name and version.
func TestUserAgentIdentifiesWardline(t *testing.T) {
	mock := newOSVMock(t)
	dir := t.TempDir()
	writeDependencyFile(t, dir, "go.mod", goModFixture)
	writeDependencyFile(t, dir, "go.sum", goSumFixture)
	scanDependencies(t, dir, mock.endpoint(), false)

	if len(mock.userAgents) == 0 {
		t.Fatal("no batch request was made")
	}
	got := mock.userAgents[0]
	if !strings.HasPrefix(got, "wardline/") {
		t.Fatalf("unexpected user agent %q", got)
	}
	if strings.Contains(got, dir) || strings.Contains(got, "example.com/app") {
		t.Fatalf("user agent leaks scan details: %q", got)
	}
}

const goModFixture = `module example.com/app

go 1.21

require (
	github.com/golang-jwt/jwt v3.2.1+incompatible
	golang.org/x/crypto v0.11.0 // indirect
)
`

const goSumFixture = `github.com/golang-jwt/jwt v3.2.1+incompatible h1:abc=
golang.org/x/crypto v0.11.0 h1:def=
`

func TestScanFindsVulnerabilities(t *testing.T) {
	mock := newOSVMock(t)
	mock.queryResults["Go/github.com/golang-jwt/jwt@v3.2.1+incompatible"] = []string{"GHSA-jf5w-j5fh-9h5m"}
	mock.addVuln("GHSA-jf5w-j5fh-9h5m", map[string]any{
		"id":      "GHSA-jf5w-j5fh-9h5m",
		"summary": "JWT library allows alg=none tokens",
		"details": "A token with alg=none is accepted when the key function returns an error.",
		"aliases": []string{"CVE-2020-26160"},
		"severity": []map[string]any{
			{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
		},
		"affected": []map[string]any{{
			"package": map[string]any{"ecosystem": "Go", "name": "github.com/golang-jwt/jwt"},
			"ranges": []map[string]any{{
				"type":   "SEMVER",
				"events": []map[string]any{{"introduced": "0"}, {"fixed": "4.0.0"}},
			}},
		}},
		"references": []map[string]any{{"type": "ADVISORY", "url": "https://example.com/advisory"}},
		"published":  "2020-10-06T00:00:00Z",
	})

	dir := t.TempDir()
	writeDependencyFile(t, dir, "go.mod", goModFixture)
	writeDependencyFile(t, dir, "go.sum", goSumFixture)

	res := scanDependencies(t, dir, mock.endpoint(), false)
	if len(res.Findings) != 1 {
		t.Fatalf("expected one finding, got %d: %+v", len(res.Findings), res.Findings)
	}
	f := res.Findings[0]
	if f.RuleID != RuleVulnerableDependency {
		t.Errorf("unexpected rule %s", f.RuleID)
	}
	if f.Severity != findings.SeverityHigh {
		t.Errorf("expected high severity from CVSS 7.5, got %s", f.Severity)
	}
	if f.Package == nil || f.Package.Name != "github.com/golang-jwt/jwt" || !f.Package.Direct {
		t.Errorf("package metadata wrong: %+v", f.Package)
	}
	if f.Vulnerability == nil || f.Vulnerability.FixedVersion != "4.0.0" {
		t.Errorf("fixed version not carried: %+v", f.Vulnerability)
	}
	if f.Vulnerability.CVSSScore == nil || *f.Vulnerability.CVSSScore != 7.5 {
		t.Errorf("CVSS score not computed: %+v", f.Vulnerability)
	}
	if f.Location.Path != "go.mod" || f.Location.StartLine != 6 {
		t.Errorf("location wrong: %+v", f.Location)
	}
	if len(f.References) < 2 {
		t.Errorf("expected OSV and advisory references, got %v", f.References)
	}
	if len(res.Network) != 1 || res.Network[0] != mock.endpoint() {
		t.Errorf("network destination not recorded: %v", res.Network)
	}
	if len(res.Notes) == 0 || !strings.Contains(strings.Join(res.Notes, " "), "sent to") {
		t.Errorf("network disclosure missing: %v", res.Notes)
	}
	if len(res.Skipped) != 0 {
		t.Errorf("unexpected skipped checks: %+v", res.Skipped)
	}
}

func TestScanNPMWithLockfile(t *testing.T) {
	mock := newOSVMock(t)
	mock.queryResults["npm/lodash@4.17.15"] = []string{"GHSA-xxxx-yyyy-zzzz"}
	mock.addVuln("GHSA-xxxx-yyyy-zzzz", map[string]any{
		"id": "GHSA-xxxx-yyyy-zzzz", "summary": "Prototype pollution",
		"database_specific": map[string]any{"severity": "MODERATE"},
		"affected": []map[string]any{{
			"package": map[string]any{"ecosystem": "npm", "name": "lodash"},
			"ranges":  []map[string]any{{"events": []map[string]any{{"introduced": "0"}, {"fixed": "4.17.19"}}}},
		}},
	})
	dir := t.TempDir()
	writeDependencyFile(t, dir, "web/package.json", `{"dependencies": {"lodash": "4.17.15"}}`)
	writeDependencyFile(t, dir, "web/package-lock.json", `{
	  "lockfileVersion": 3,
	  "packages": {
	    "": {"dependencies": {"lodash": "4.17.15"}},
	    "node_modules/lodash": {"version": "4.17.15"},
	    "node_modules/dev-only": {"version": "1.0.0", "dev": true}
	  }
	}`)

	res := scanDependencies(t, dir, mock.endpoint(), false)
	if len(res.Findings) != 1 {
		t.Fatalf("expected one finding, got %+v", res.Findings)
	}
	if res.Findings[0].Severity != findings.SeverityMedium {
		t.Errorf("expected medium severity, got %s", res.Findings[0].Severity)
	}
	if res.Findings[0].Location.Path != "web/package-lock.json" {
		t.Errorf("unexpected manifest path %s", res.Findings[0].Location.Path)
	}
}

func TestScanWithoutLockfileIsPartialNotClean(t *testing.T) {
	dir := t.TempDir()
	writeDependencyFile(t, dir, "web/package.json", `{"dependencies": {"lodash": "^4.0.0"}}`)
	res := scanDependencies(t, dir, "http://127.0.0.1:1", false)
	if len(res.Findings) != 0 {
		t.Fatalf("expected no findings, got %+v", res.Findings)
	}
	if len(res.Skipped) == 0 {
		t.Fatal("a missing lockfile must be reported as a skipped check")
	}
	if !strings.Contains(strings.Join(skippedReasons(res), " "), "no package-lock.json") {
		t.Fatalf("unexpected skip reasons: %v", skippedReasons(res))
	}
}

func TestScanWithoutManifests(t *testing.T) {
	dir := t.TempDir()
	writeDependencyFile(t, dir, "README.md", "hello")
	res := scanDependencies(t, dir, "http://127.0.0.1:1", false)
	if len(res.Skipped) != 1 {
		t.Fatalf("expected one skipped check, got %+v", res.Skipped)
	}
}

func TestOfflineModeDisclosesSkippedChecks(t *testing.T) {
	dir := t.TempDir()
	writeDependencyFile(t, dir, "go.mod", goModFixture)
	writeDependencyFile(t, dir, "go.sum", goSumFixture)
	res := scanDependencies(t, dir, "http://127.0.0.1:1", true)
	if len(res.Findings) != 0 {
		t.Fatalf("offline scan produced findings: %+v", res.Findings)
	}
	if len(res.Skipped) == 0 || !strings.Contains(strings.Join(skippedReasons(res), " "), "offline") {
		t.Fatalf("offline skip not reported: %+v", res.Skipped)
	}
	if !strings.Contains(strings.Join(res.Notes, " "), "free of known vulnerabilities") {
		t.Fatalf("offline note missing: %v", res.Notes)
	}
}

func TestGoSumMissingIsReported(t *testing.T) {
	mock := newOSVMock(t)
	dir := t.TempDir()
	writeDependencyFile(t, dir, "go.mod", goModFixture)
	res := scanDependencies(t, dir, mock.endpoint(), false)
	if len(res.Skipped) == 0 {
		t.Fatal("missing go.sum must be reported")
	}
	if !strings.Contains(strings.Join(skippedReasons(res), " "), "go.sum") {
		t.Fatalf("unexpected skip reasons: %v", skippedReasons(res))
	}
}

func TestBatchFailureIsAnError(t *testing.T) {
	mock := newOSVMock(t)
	atomic.StoreInt32(&mock.failBatch, 10)
	dir := t.TempDir()
	writeDependencyFile(t, dir, "go.mod", goModFixture)
	writeDependencyFile(t, dir, "go.sum", goSumFixture)
	cfg := config.Default()
	cfg.Network.OSVEndpoint = mock.endpoint()
	path := filepath.Join(dir, "go.mod")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	req := &scanners.Request{
		Root: dir, Config: cfg, Now: time.Unix(1700000000, 0),
		Files:      []scanners.File{{Rel: "go.mod", Abs: path, Size: info.Size()}},
		HTTPClient: &http.Client{Timeout: 2 * time.Second},
	}
	res, err := New().Scan(context.Background(), req)
	if err == nil {
		t.Fatalf("expected an error when OSV is unreachable, got result %+v", res)
	}
	if !strings.Contains(err.Error(), "not checked") {
		t.Errorf("error should state that dependencies were not checked: %v", err)
	}
}

func TestDetailFetchFailureKeepsFinding(t *testing.T) {
	mock := newOSVMock(t)
	mock.failDetail = true
	mock.queryResults["Go/github.com/golang-jwt/jwt@v3.2.1+incompatible"] = []string{"GHSA-jf5w-j5fh-9h5m"}
	dir := t.TempDir()
	writeDependencyFile(t, dir, "go.mod", goModFixture)
	writeDependencyFile(t, dir, "go.sum", goSumFixture)
	res := scanDependencies(t, dir, mock.endpoint(), false)
	if len(res.Findings) != 1 {
		t.Fatalf("expected the finding to be kept with reduced metadata, got %+v", res.Findings)
	}
	if res.Findings[0].Severity != findings.SeverityUnknown {
		t.Errorf("severity should be unknown without advisory data, got %s", res.Findings[0].Severity)
	}
	if len(res.Warnings) == 0 {
		t.Error("expected a warning about failed detail requests")
	}
}

func TestBatchChunking(t *testing.T) {
	mock := newOSVMock(t)
	dir := t.TempDir()
	var b strings.Builder
	b.WriteString("module example.com/app\n\ngo 1.21\n\nrequire (\n")
	var sum strings.Builder
	for i := 0; i < 1200; i++ {
		name := fmt.Sprintf("example.com/dep%04d", i)
		b.WriteString("\t" + name + " v1.0." + fmt.Sprint(i%10) + "\n")
		sum.WriteString(name + " v1.0." + fmt.Sprint(i%10) + " h1:x=\n")
	}
	b.WriteString(")\n")
	writeDependencyFile(t, dir, "go.mod", b.String())
	writeDependencyFile(t, dir, "go.sum", sum.String())

	res := scanDependencies(t, dir, mock.endpoint(), false)
	if len(res.Findings) != 0 {
		t.Fatalf("unexpected findings: %+v", res.Findings)
	}
	if mock.queryCount != 1200 {
		t.Fatalf("expected 1200 queries, got %d", mock.queryCount)
	}
	if got := atomic.LoadInt32(&mock.batchCalls); got != 3 {
		t.Fatalf("expected 3 batch requests (chunks of 500), got %d", got)
	}
}

func TestAdvisoryDeduplication(t *testing.T) {
	mock := newOSVMock(t)
	// Two aliases of the same advisory reported for the same package version.
	mock.queryResults["Go/github.com/golang-jwt/jwt@v3.2.1+incompatible"] = []string{"GHSA-aaa", "GHSA-aaa"}
	mock.addVuln("GHSA-aaa", map[string]any{
		"id": "GHSA-aaa", "summary": "dup", "database_specific": map[string]any{"severity": "HIGH"},
	})
	dir := t.TempDir()
	writeDependencyFile(t, dir, "go.mod", goModFixture)
	writeDependencyFile(t, dir, "go.sum", goSumFixture)
	res := scanDependencies(t, dir, mock.endpoint(), false)
	if len(res.Findings) != 1 {
		t.Fatalf("duplicate advisories must be deduplicated, got %d", len(res.Findings))
	}
}

func TestUnsupportedEcosystemsAreNoted(t *testing.T) {
	mock := newOSVMock(t)
	dir := t.TempDir()
	writeDependencyFile(t, dir, "requirements.txt", "flask==2.0.1\n")
	writeDependencyFile(t, dir, "Cargo.toml", "[package]\nname='x'\n")
	res := scanDependencies(t, dir, mock.endpoint(), false)
	joined := strings.Join(res.Notes, " ")
	if !strings.Contains(joined, "not supported yet") {
		t.Fatalf("expected an unsupported-ecosystem note, got %v", res.Notes)
	}
	if strings.Contains(joined, "Rust") && !strings.Contains(joined, "Python") {
		t.Fatalf("all unsupported ecosystems should be listed: %v", res.Notes)
	}
}

func TestCancellationIsPropagated(t *testing.T) {
	dir := t.TempDir()
	writeDependencyFile(t, dir, "go.mod", goModFixture)
	writeDependencyFile(t, dir, "go.sum", goSumFixture)
	cfg := config.Default()
	cfg.Network.OSVEndpoint = "http://127.0.0.1:1"
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	path := filepath.Join(dir, "go.mod")
	info, _ := os.Stat(path)
	req := &scanners.Request{
		Root: dir, Config: cfg, Now: time.Unix(1700000000, 0), Files: []scanners.File{{Rel: "go.mod", Abs: path, Size: info.Size()}},
	}
	if _, err := New().Scan(ctx, req); err == nil {
		t.Fatal("expected a cancellation error")
	}
}

func skippedReasons(res *scanners.Result) []string {
	out := make([]string, 0, len(res.Skipped))
	for _, s := range res.Skipped {
		out = append(out, s.Check+": "+s.Reason)
	}
	return out
}
