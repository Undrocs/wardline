package config

import (
	"strings"
	"testing"

	"github.com/Undrocs/wardline/internal/findings"
)

func assertFindingsWellFormed(t *testing.T, path string, found []findings.Finding) {
	t.Helper()
	for _, item := range found {
		if item.RuleID == "" {
			t.Fatalf("finding without a rule id: %+v", item)
		}
		if !strings.HasPrefix(item.RuleID, "WL-CFG-") {
			t.Fatalf("finding %s is outside the config rule namespace", item.RuleID)
		}
		if item.Title == "" || item.Description == "" || item.Remediation == "" {
			t.Fatalf("finding %s is missing descriptive fields", item.RuleID)
		}
		if item.Location.Path != path {
			t.Fatalf("finding %s has an unexpected path %q", item.RuleID, item.Location.Path)
		}
		if item.Location.StartLine < 0 || item.Location.EndLine < 0 {
			t.Fatalf("finding %s has a negative line number", item.RuleID)
		}
		if strings.ContainsRune(item.Evidence, '\x00') {
			t.Fatalf("finding %s carries a NUL byte in evidence", item.RuleID)
		}
	}
}

// FuzzCheckDockerfile exercises the Dockerfile parser and rules with arbitrary
// bytes. It must never panic and must never emit a malformed finding.
func FuzzCheckDockerfile(f *testing.F) {
	seeds := []string{
		"FROM alpine:3.20\nUSER app\n",
		"FROM ubuntu\nUSER root\nRUN apt-get update\nENV API_TOKEN=abc123\n",
		"FROM scratch\nCOPY id_rsa /root/.ssh/id_rsa\nADD https://example.invalid/x.tar.gz /tmp/\n",
		"FROM node AS build\nRUN --mount=type=secret,id=npm token=foo\n",
		"FROM alpine\nRUN curl -fsSL https://x.invalid/i.sh | sh\nHEALTHCHECK CMD true\n",
		"FROM alpine\\\n  AS runner\nEXPOSE 22\n",
		"",
		"   \n# comment only\n",
	}
	for _, seed := range seeds {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		found := checkDockerfile("Dockerfile", data)
		assertFindingsWellFormed(t, "Dockerfile", found)
	})
}

// FuzzCheckCompose exercises the compose parser, including its YAML error path.
func FuzzCheckCompose(f *testing.F) {
	seeds := []string{
		"services:\n  app:\n    image: nginx\n",
		"services:\n  db:\n    image: postgres\n    privileged: true\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n",
		"services:\n  app:\n    environment:\n      - API_KEY=abc\n    ports:\n      - \"5432:5432\"\n",
		"services:\n  app:\n    user: root\n    cap_add: [ALL]\n    network_mode: host\n",
		"",
		"services: [\n",
		"version: \"3\"\nservices:\n  app:\n    volumes: [\"/:/host\"]\n",
	}
	for _, seed := range seeds {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		found, err := checkCompose("docker-compose.yml", data)
		if err != nil {
			return
		}
		assertFindingsWellFormed(t, "docker-compose.yml", found)
	})
}
