package osv

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func newTestClient(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client, err := New(server.URL, &http.Client{Timeout: 2 * time.Second}, WithUserAgent("wardline-test"))
	if err != nil {
		t.Fatal(err)
	}
	return client, server
}

func TestQueryBatch(t *testing.T) {
	var requests int32
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method %s", r.Method)
		}
		if got := r.Header.Get("User-Agent"); got != "wardline-test" {
			t.Errorf("unexpected user agent %q", got)
		}
		var body struct {
			Queries []Query `json:"queries"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode: %v", err)
		}
		results := make([]map[string]any, len(body.Queries))
		for i, q := range body.Queries {
			if q.Package.Name == "github.com/golang-jwt/jwt" {
				results[i] = map[string]any{"vulns": []map[string]string{{"id": "GHSA-1", "modified": "2026-01-01T00:00:00Z"}}}
			} else {
				results[i] = map[string]any{}
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
	})

	queries := []Query{
		{Package: Package{Ecosystem: "Go", Name: "github.com/golang-jwt/jwt"}, Version: "v3.2.1"},
		{Package: Package{Ecosystem: "Go", Name: "golang.org/x/crypto"}, Version: "v0.11.0"},
	}
	results, err := client.QueryBatch(context.Background(), queries)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if len(results[0].Vulns) != 1 || results[0].Vulns[0].ID != "GHSA-1" {
		t.Fatalf("unexpected first result: %+v", results[0])
	}
	if len(results[1].Vulns) != 0 {
		t.Fatalf("unexpected second result: %+v", results[1])
	}
	if atomic.LoadInt32(&requests) != 1 {
		t.Errorf("expected a single request, got %d", requests)
	}
}

func TestQueryBatchChunking(t *testing.T) {
	var calls int32
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		var body struct {
			Queries []Query `json:"queries"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		results := make([]map[string]any, len(body.Queries))
		for i := range results {
			results[i] = map[string]any{}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
	})
	queries := make([]Query, 1201)
	for i := range queries {
		queries[i] = Query{Package: Package{Ecosystem: "npm", Name: fmt.Sprintf("pkg%d", i)}, Version: "1.0.0"}
	}
	if _, err := client.QueryBatch(context.Background(), queries); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Fatalf("expected 3 chunked requests, got %d", got)
	}
}

func TestQueryBatchPartialResponseIsRejected(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"results":[]}`))
	})
	_, err := client.QueryBatch(context.Background(), []Query{{Package: Package{Ecosystem: "Go", Name: "x"}, Version: "v1.0.0"}})
	if err == nil || !strings.Contains(err.Error(), "partial response") {
		t.Fatalf("expected a partial-response error, got %v", err)
	}
}

func TestRetriesOnServerError(t *testing.T) {
	var attempts int32
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&attempts, 1) < 3 {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{"results":[{}]}`))
	})
	results, err := client.QueryBatch(context.Background(), []Query{{Package: Package{Ecosystem: "Go", Name: "x"}, Version: "v1.0.0"}})
	if err != nil {
		t.Fatalf("expected the retry to succeed, got %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("unexpected results: %+v", results)
	}
	if got := atomic.LoadInt32(&attempts); got != 3 {
		t.Fatalf("expected 3 attempts, got %d", got)
	}
}

func TestDoesNotRetryClientErrors(t *testing.T) {
	var attempts int32
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		http.Error(w, "bad request", http.StatusBadRequest)
	})
	_, err := client.QueryBatch(context.Background(), []Query{{Package: Package{Ecosystem: "Go", Name: "x"}, Version: "v1.0.0"}})
	if err == nil {
		t.Fatal("expected an error")
	}
	if got := atomic.LoadInt32(&attempts); got != 1 {
		t.Fatalf("client errors must not be retried, got %d attempts", got)
	}
}

func TestFetchCachesAndParses(t *testing.T) {
	var calls int32
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		if !strings.HasPrefix(r.URL.Path, "/v1/vulns/") {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":      "GHSA-1",
			"summary": "summary",
			"aliases": []string{"CVE-1"},
			"severity": []map[string]string{
				{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
			},
			"affected": []map[string]any{{
				"package": map[string]any{"ecosystem": "Go", "name": "github.com/x/y"},
				"ranges": []map[string]any{{"events": []map[string]any{
					{"introduced": "0"}, {"fixed": "1.2.3"},
				}}},
			}},
			"database_specific": map[string]any{"severity": "HIGH"},
		})
	})
	v, err := client.Fetch(context.Background(), "GHSA-1")
	if err != nil {
		t.Fatal(err)
	}
	if v.ID != "GHSA-1" || v.Summary != "summary" {
		t.Fatalf("unexpected advisory: %+v", v)
	}
	if fixed := v.AffectedFixedVersion("Go", "github.com/x/y"); fixed != "1.2.3" {
		t.Errorf("unexpected fixed version %q", fixed)
	}
	if rng := v.AffectedRange("Go", "github.com/x/y"); !strings.Contains(rng, ">= 0") || !strings.Contains(rng, "< 1.2.3") {
		t.Errorf("unexpected range %q", rng)
	}
	if _, err := client.Fetch(context.Background(), "GHSA-1"); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("advisory should be cached, got %d requests", got)
	}
}

func TestFetchErrors(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	if _, err := client.Fetch(context.Background(), "GHSA-missing"); err == nil {
		t.Fatal("expected an error for a 404")
	}
	if _, err := client.Fetch(context.Background(), ""); err == nil {
		t.Fatal("expected an error for an empty id")
	}
}

func TestFetchRejectsOversizedResponses(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"x","summary":"`))
		chunk := strings.Repeat("a", 1<<20)
		for i := 0; i < 40; i++ {
			if _, err := w.Write([]byte(chunk)); err != nil {
				return
			}
		}
	})
	if _, err := client.Fetch(context.Background(), "big"); err == nil {
		t.Fatal("expected an error for an oversized response")
	}
}

func TestFetchManyPartialFailure(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/v1/vulns/")
		if id == "bad" {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": id})
	})
	details, errs := client.FetchMany(context.Background(), []string{"good", "bad", "good"})
	if len(details) != 1 || details["good"] == nil {
		t.Fatalf("unexpected details: %+v", details)
	}
	if len(errs) != 1 || errs["bad"] == nil {
		t.Fatalf("unexpected errors: %+v", errs)
	}
}

func TestTolerantDecoding(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		// An unknown field must not fail the scan.
		_, _ = w.Write([]byte(`{"id":"GHSA-1","future_field":{"a":1}}`))
	})
	v, err := client.Fetch(context.Background(), "GHSA-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.ID != "GHSA-1" {
		t.Fatalf("unexpected advisory: %+v", v)
	}
}

func TestContextCancellation(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		// Sleep briefly: the client's context expires long before this returns,
		// so the request must be abandoned without waiting for the body.
		time.Sleep(300 * time.Millisecond)
		_, _ = w.Write([]byte(`{"results":[{}]}`))
	})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := client.QueryBatch(ctx, []Query{{Package: Package{Ecosystem: "Go", Name: "x"}, Version: "v1"}})
	if err == nil {
		t.Fatal("expected a context error")
	}
}

func TestNewValidatesEndpoint(t *testing.T) {
	for _, endpoint := range []string{"ftp://example.com", "not-a-url"} {
		if _, err := New(endpoint, nil); err == nil {
			t.Errorf("expected an error for endpoint %q", endpoint)
		}
	}
	client, err := New("", nil)
	if err != nil {
		t.Fatal(err)
	}
	if client.Endpoint() != DefaultEndpoint {
		t.Fatalf("unexpected default endpoint %q", client.Endpoint())
	}
}

func TestAffectedRangeWithoutData(t *testing.T) {
	v := &Vulnerability{ID: "X"}
	if got := v.AffectedRange("Go", "missing"); got != "" {
		t.Errorf("unexpected range %q", got)
	}
	if got := v.AffectedFixedVersion("Go", "missing"); got != "" {
		t.Errorf("unexpected fixed version %q", got)
	}
	var nilVuln *Vulnerability
	if got := nilVuln.AffectedRange("Go", "x"); got != "" {
		t.Errorf("nil advisory returned %q", got)
	}
}
