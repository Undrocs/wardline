// Package config audits Dockerfiles, Docker Compose files and selected
// application configuration for static misconfigurations.
//
// Only issues that static inspection can establish are reported. Wardline never
// builds an image, runs Compose, or executes repository code.
package config

import (
	"context"
	"fmt"
	"path"
	"strings"

	"github.com/Undrocs/wardline/internal/findings"
	"github.com/Undrocs/wardline/internal/scanners"
	"github.com/Undrocs/wardline/internal/security"
	"github.com/Undrocs/wardline/internal/yamlpos"
)

// Scanner audits configuration files.
type Scanner struct{}

// New returns a configuration scanner.
func New() *Scanner { return &Scanner{} }

// Name implements scanners.Scanner.
func (s *Scanner) Name() string { return findings.ScannerConfig }

// Scan implements scanners.Scanner.
func (s *Scanner) Scan(ctx context.Context, req *scanners.Request) (*scanners.Result, error) {
	res := &scanners.Result{}
	counts := struct{ docker, compose, env, app int }{}

	for _, file := range req.Files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		switch {
		case isDockerfile(file.Rel):
			data, err := security.ReadFileLimited(file.Abs, req.Config.Limits.MaxFileSize)
			if err != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("%s: could not be read: %v", file.Rel, err))
				continue
			}
			res.Findings = append(res.Findings, checkDockerfile(file.Rel, data)...)
			counts.docker++
		case isComposeFile(file.Rel):
			data, err := security.ReadFileLimited(file.Abs, req.Config.Limits.MaxFileSize)
			if err != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("%s: could not be read: %v", file.Rel, err))
				continue
			}
			found, err := checkCompose(file.Rel, data)
			if err != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("%s: %v", file.Rel, err))
				res.Skipped = append(res.Skipped, scanners.SkippedCheck{
					Check:  "compose audit: " + file.Rel,
					Reason: "file could not be parsed: " + err.Error(),
				})
				continue
			}
			res.Findings = append(res.Findings, found...)
			counts.compose++
		case isCommittedEnvFile(file.Rel):
			res.Findings = append(res.Findings, newConfigFinding(ruleCommittedEnvFile, file.Rel, 1,
				"file:.env", "tracked environment file: "+path.Base(file.Rel), "Application configuration"))
			counts.env++
		case isApplicationConfig(file.Rel):
			data, err := security.ReadFileLimited(file.Abs, req.Config.Limits.MaxFileSize)
			if err != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("%s: could not be read: %v", file.Rel, err))
				continue
			}
			if found, err := checkInsecureTLS(file.Rel, data); err != nil {
				res.Skipped = append(res.Skipped, scanners.SkippedCheck{
					Check:  "application config: " + file.Rel,
					Reason: "file could not be parsed: " + err.Error(),
				})
			} else if len(found) > 0 {
				res.Findings = append(res.Findings, found...)
				counts.app++
			}
		}
	}

	res.Scope = fmt.Sprintf("%d Dockerfile(s), %d Compose file(s), %d env file(s), %d application config(s)",
		counts.docker, counts.compose, counts.env, counts.app)
	return res, nil
}

// isDockerfile matches Dockerfile, Dockerfile.dev, app.Dockerfile and similar.
func isDockerfile(rel string) bool {
	base := strings.ToLower(path.Base(rel))
	return base == "dockerfile" ||
		strings.HasPrefix(base, "dockerfile.") ||
		strings.HasSuffix(base, ".dockerfile") ||
		strings.HasPrefix(base, "containerfile")
}

// isComposeFile matches the conventional Compose file names.
func isComposeFile(rel string) bool {
	base := strings.ToLower(path.Base(rel))
	switch base {
	case "docker-compose.yml", "docker-compose.yaml",
		"compose.yml", "compose.yaml",
		"docker-compose.override.yml", "docker-compose.override.yaml",
		"compose.override.yml", "compose.override.yaml",
		"docker-compose.prod.yml", "docker-compose.prod.yaml",
		"docker-compose.dev.yml", "docker-compose.dev.yaml":
		return true
	}
	return false
}

// isCommittedEnvFile matches real environment files, excluding the sanitised
// examples that projects are expected to commit.
func isCommittedEnvFile(rel string) bool {
	base := strings.ToLower(path.Base(rel))
	if !strings.HasPrefix(base, ".env") {
		return false
	}
	switch base {
	case ".env.example", ".env.sample", ".env.template", ".env.dist", ".env.example.local":
		return false
	}
	return true
}

// isApplicationConfig selects YAML/JSON configuration files for the TLS check.
// Dependency manifests and workflows are excluded to keep the rule scoped.
func isApplicationConfig(rel string) bool {
	base := strings.ToLower(path.Base(rel))
	switch base {
	case "package.json", "package-lock.json", "npm-shrinkwrap.json", "tsconfig.json",
		"go.mod", "go.sum", "composer.json", "composer.lock", "renovate.json",
		"dependabot.yml", "dependabot.yaml":
		return false
	}
	if strings.HasPrefix(strings.ToLower(rel), ".github/") {
		return false
	}
	if security.IsGeneratedPath(rel) {
		return false
	}
	switch strings.ToLower(path.Ext(base)) {
	case ".yml", ".yaml", ".json":
		return true
	}
	return false
}

// insecureTLSKeys maps a configuration key to the value that disables
// verification.
var insecureTLSKeys = map[string]string{
	"insecure_skip_verify": "true",
	"insecure":             "true",
	"skip_tls_verify":      "true",
	"tls_verify":           "false",
	"verify_ssl":           "false",
	"ssl_verify":           "false",
	"verify_tls":           "false",
	"rejectunauthorized":   "false",
	"verify":               "false",
}

// checkInsecureTLS walks a configuration document for settings that disable TLS
// certificate verification.
func checkInsecureTLS(rel string, data []byte) ([]findings.Finding, error) {
	root, err := yamlpos.Parse(data)
	if err != nil {
		return nil, err
	}
	var out []findings.Finding
	var walk func(n *yamlpos.Node, pathParts []string)
	walk = func(n *yamlpos.Node, pathParts []string) {
		if n == nil {
			return
		}
		switch n.Kind {
		case yamlpos.KindMapping:
			for _, p := range n.Pairs {
				key := strings.ToLower(p.Key)
				if p.Value != nil {
					if v, ok := p.Value.Scalar(); ok {
						if want, interesting := insecureTLSKeys[key]; interesting && strings.EqualFold(strings.TrimSpace(v), want) {
							locator := "config." + strings.Join(append(pathParts, p.Key), ".")
							out = append(out, newConfigFinding(ruleInsecureTLS, rel, p.KeyLine, locator,
								fmt.Sprintf("%s: %s", strings.Join(append(pathParts, p.Key), "."), v),
								"Application configuration"))
							continue
						}
					}
				}
				walk(p.Value, append(pathParts, p.Key))
			}
		case yamlpos.KindSequence:
			for i, item := range n.Items {
				walk(item, append(pathParts, fmt.Sprintf("[%d]", i)))
			}
		}
	}
	walk(root, nil)
	return out, nil
}
