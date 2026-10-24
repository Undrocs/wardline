package config

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Undrocs/wardline/internal/config"
	"github.com/Undrocs/wardline/internal/findings"
	"github.com/Undrocs/wardline/internal/scanners"
)

func scanFile(t *testing.T, rel, content string) *scanners.Result {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	req := &scanners.Request{
		Root: dir, Config: config.Default(), Now: time.Unix(1700000000, 0), Offline: true,
		Files: []scanners.File{{Rel: rel, Abs: path, Size: info.Size()}},
	}
	res, err := New().Scan(context.Background(), req)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	return res
}

func hasRule(res *scanners.Result, rule string) bool {
	for _, f := range res.Findings {
		if f.RuleID == rule {
			return true
		}
	}
	return false
}

func TestDockerfileRules(t *testing.T) {
	cases := []struct {
		name    string
		content string
		rule    string
	}{
		{
			name:    "implicit root",
			content: "FROM node:20\nCMD [\"node\", \"server.js\"]\n",
			rule:    "WL-CFG-001",
		},
		{
			name:    "explicit root",
			content: "FROM alpine:3.20\nUSER root\nCMD [\"sh\"]\n",
			rule:    "WL-CFG-002",
		},
		{
			name:    "secret env",
			content: "FROM alpine:3.20\nUSER app\nENV API_TOKEN=Zq7pLm2Kd9Rt4Wx1\n",
			rule:    "WL-CFG-003",
		},
		{
			name:    "secret arg",
			content: "FROM alpine:3.20\nUSER app\nARG DB_PASSWORD=Zq7pLm2Kd9Rt4Wx1\n",
			rule:    "WL-CFG-004",
		},
		{
			name:    "remote add",
			content: "FROM alpine:3.20\nUSER app\nADD https://example.com/tool.tar.gz /tmp/\n",
			rule:    "WL-CFG-005",
		},
		{
			name:    "credential copy",
			content: "FROM alpine:3.20\nUSER app\nCOPY .npmrc /root/.npmrc\n",
			rule:    "WL-CFG-006",
		},
		{
			name:    "world writable",
			content: "FROM alpine:3.20\nUSER app\nRUN chmod -R 777 /app\n",
			rule:    "WL-CFG-007",
		},
		{
			name:    "remote script",
			content: "FROM alpine:3.20\nUSER app\nRUN wget -qO- https://example.com/i.sh | sh\n",
			rule:    "WL-CFG-008",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := scanFile(t, "Dockerfile", c.content)
			if !hasRule(res, c.rule) {
				t.Fatalf("expected %s, got %v", c.rule, findingRuleIDs(res))
			}
		})
	}
}

func findingRuleIDs(res *scanners.Result) []string {
	out := make([]string, 0, len(res.Findings))
	for _, f := range res.Findings {
		out = append(out, f.RuleID)
	}
	return out
}

func TestSafeDockerfile(t *testing.T) {
	content := `FROM golang:1.23 AS build
WORKDIR /src
COPY go.mod ./
RUN go build -o /out/app ./cmd/app

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/app /app
USER nonroot:nonroot
ENTRYPOINT ["/app"]
`
	res := scanFile(t, "Dockerfile", content)
	if len(res.Findings) != 0 {
		for _, f := range res.Findings {
			t.Logf("unexpected: %s %s %s", f.RuleID, f.LocationString(), f.Evidence)
		}
		t.Fatalf("expected no findings, got %v", findingRuleIDs(res))
	}
}

func TestDockerfileSecretRedaction(t *testing.T) {
	res := scanFile(t, "Dockerfile", "FROM alpine:3.20\nUSER app\nENV API_TOKEN=Zq7pLm2Kd9Rt4Wx1\n")
	if len(res.Findings) == 0 {
		t.Fatal("expected a finding")
	}
	for _, f := range res.Findings {
		if strings.Contains(f.Evidence, "Zq7pLm2Kd9Rt4Wx1") {
			t.Fatalf("secret leaked in evidence: %q", f.Evidence)
		}
	}
}

func TestComposeRules(t *testing.T) {
	content := `services:
  api:
    image: example/api:1.0.0
    privileged: true
    network_mode: host
    user: "0"
    cap_add:
      - SYS_ADMIN
    security_opt:
      - seccomp:unconfined
    environment:
      DB_PASSWORD: Zq7pLm2Kd9Rt4Wx1
      SAFE_VALUE: hello
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /etc:/host-etc
    ports:
      - "5432:5432"
      - "127.0.0.1:6379:6379"
`
	res := scanFile(t, "docker-compose.yml", content)
	want := []string{
		"WL-CFG-009", "WL-CFG-010", "WL-CFG-011", "WL-CFG-012", "WL-CFG-013",
		"WL-CFG-014", "WL-CFG-015", "WL-CFG-016", "WL-CFG-017",
	}
	for _, rule := range want {
		if !hasRule(res, rule) {
			t.Errorf("expected %s, got %v", rule, findingRuleIDs(res))
		}
	}
	for _, f := range res.Findings {
		if strings.Contains(f.Evidence, "Zq7pLm2Kd9Rt4Wx1") {
			t.Fatalf("secret leaked in compose evidence: %q", f.Evidence)
		}
	}
	// The 6379 mapping binds to localhost and must not be reported.
	for _, f := range res.Findings {
		if f.RuleID == "WL-CFG-017" && strings.Contains(f.Evidence, "6379") {
			t.Errorf("loopback-bound port was reported as exposed: %s", f.Evidence)
		}
	}
}

func TestSafeCompose(t *testing.T) {
	content := `services:
  api:
    image: example/api:1.0.0
    user: "1000:1000"
    read_only: true
    cap_drop:
      - ALL
    environment:
      DB_PASSWORD: ${DB_PASSWORD}
    volumes:
      - ./data:/data:ro
    ports:
      - "127.0.0.1:8080:8080"
`
	res := scanFile(t, "docker-compose.yml", content)
	if len(res.Findings) != 0 {
		for _, f := range res.Findings {
			t.Logf("unexpected: %s %s", f.RuleID, f.Evidence)
		}
		t.Fatalf("expected no findings, got %v", findingRuleIDs(res))
	}
}

func TestComposeListEnvironmentAndLongSyntax(t *testing.T) {
	content := `services:
  api:
    image: example/api:1.0.0
    environment:
      - API_KEY=Q7mXr4Tz9KpL2WcV8bN3
    volumes:
      - type: bind
        source: /var/run/docker.sock
        target: /var/run/docker.sock
    ports:
      - target: 6379
        published: 6379
        host_ip: 0.0.0.0
`
	res := scanFile(t, "compose.yaml", content)
	if !hasRule(res, "WL-CFG-014") {
		t.Errorf("list-style environment secret not detected: %v", findingRuleIDs(res))
	}
	if !hasRule(res, "WL-CFG-011") {
		t.Errorf("long-syntax docker socket mount not detected: %v", findingRuleIDs(res))
	}
	if !hasRule(res, "WL-CFG-017") {
		t.Errorf("long-syntax exposed port not detected: %v", findingRuleIDs(res))
	}
}

func TestMalformedComposeIsSkipped(t *testing.T) {
	res := scanFile(t, "docker-compose.yml", "services: [\n")
	if len(res.Skipped) == 0 {
		t.Fatal("unparseable compose file must be reported as skipped")
	}
	if len(res.Findings) != 0 {
		t.Fatalf("unexpected findings: %v", findingRuleIDs(res))
	}
}

func TestCommittedEnvFile(t *testing.T) {
	res := scanFile(t, "deploy/.env.production", "DB_HOST=db.internal\n")
	if !hasRule(res, "WL-CFG-020") {
		t.Fatalf("expected WL-CFG-020, got %v", findingRuleIDs(res))
	}
	res = scanFile(t, ".env.example", "DB_HOST=db.internal\n")
	if hasRule(res, "WL-CFG-020") {
		t.Fatal("example env files must not be reported")
	}
}

func TestInsecureTLSConfig(t *testing.T) {
	res := scanFile(t, "config/app.yaml", "tls:\n  verify: false\n  insecure_skip_verify: true\n")
	if count := len(res.Findings); count != 2 {
		t.Fatalf("expected 2 TLS findings, got %d: %v", count, findingRuleIDs(res))
	}
	res = scanFile(t, "config/app.json", `{"client": {"rejectUnauthorized": false}}`)
	if !hasRule(res, "WL-CFG-021") {
		t.Fatalf("expected WL-CFG-021 for JSON config, got %v", findingRuleIDs(res))
	}
	res = scanFile(t, "config/app.yaml", "tls:\n  verify: true\n")
	if len(res.Findings) != 0 {
		t.Fatalf("expected no findings, got %v", findingRuleIDs(res))
	}
}

func TestIgnoredPaths(t *testing.T) {
	for _, rel := range []string{"package.json", "package-lock.json", ".github/workflows/ci.yml", "node_modules/x/app.yaml"} {
		res := scanFile(t, rel, `{"verify": false, "insecure_skip_verify": true}`)
		if len(res.Findings) != 0 {
			t.Errorf("%s should not be treated as application config: %v", rel, findingRuleIDs(res))
		}
	}
}

func TestCatalogComplete(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range Catalog() {
		if r.ID == "" || r.Title == "" || r.Remediation == "" || r.Impact == "" || len(r.References) == 0 {
			t.Errorf("rule %q has incomplete metadata", r.ID)
		}
		if seen[r.ID] {
			t.Errorf("duplicate rule id %q", r.ID)
		}
		seen[r.ID] = true
	}
	if len(ruleIDs()) != len(Catalog()) {
		t.Errorf("rule ids mismatch")
	}
	for _, id := range ruleIDs() {
		if !strings.HasPrefix(id, "WL-CFG-") {
			t.Errorf("unexpected rule id %q", id)
		}
	}
}

func TestDockerfileContinuations(t *testing.T) {
	content := "FROM alpine:3.20\nUSER app\nRUN apk add --no-cache \\\n  curl \\\n  bash \\\n  && curl -s https://example.com/x | bash\n"
	res := scanFile(t, "Dockerfile", content)
	if !hasRule(res, "WL-CFG-008") {
		t.Fatalf("multi-line RUN was not inspected: %v", findingRuleIDs(res))
	}
	for _, f := range res.Findings {
		if f.RuleID == "WL-CFG-008" && f.Location.StartLine != 3 {
			t.Errorf("expected the finding on the instruction's first line (3), got %d", f.Location.StartLine)
		}
	}
}

func TestFindingsCarryGuidance(t *testing.T) {
	res := scanFile(t, "Dockerfile", "FROM node:20\nENV API_TOKEN=Zq7pLm2Kd9Rt4Wx1\n")
	if len(res.Findings) == 0 {
		t.Fatal("expected findings")
	}
	for _, f := range res.Findings {
		if f.Remediation == "" || f.Impact == "" || f.Description == "" {
			t.Errorf("%s is missing guidance", f.RuleID)
		}
		if f.Confidence == "" {
			t.Errorf("%s has no confidence", f.RuleID)
		}
		if f.Severity == findings.SeverityUnknown {
			t.Errorf("%s has unknown severity", f.RuleID)
		}
	}
}
