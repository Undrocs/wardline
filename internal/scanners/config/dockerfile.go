package config

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Undrocs/wardline/internal/findings"
	"github.com/Undrocs/wardline/internal/security"
)

// instruction is one logical Dockerfile instruction (continuations joined).
type instruction struct {
	Keyword string
	Args    string
	Line    int
}

// parseDockerfile splits a Dockerfile into logical instructions, joining
// backslash continuations and dropping comments and parser directives.
func parseDockerfile(data []byte) []instruction {
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	var out []instruction
	var current strings.Builder
	startLine := 0
	flush := func() {
		text := strings.TrimSpace(current.String())
		current.Reset()
		if text == "" {
			return
		}
		fields := strings.Fields(text)
		if len(fields) == 0 {
			return
		}
		out = append(out, instruction{
			Keyword: strings.ToUpper(fields[0]),
			Args:    strings.TrimSpace(strings.TrimPrefix(text, fields[0])),
			Line:    startLine,
		})
	}
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if current.Len() == 0 {
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			startLine = i + 1
		}
		if strings.HasSuffix(trimmed, "\\") {
			current.WriteString(strings.TrimSuffix(trimmed, "\\"))
			current.WriteString(" ")
			continue
		}
		current.WriteString(trimmed)
		flush()
	}
	flush()
	return out
}

// secretKeyPattern matches environment variable names that should never carry a
// literal credential.
var secretKeyPattern = regexp.MustCompile(`(?i)(^|_)(password|passwd|pwd|secret|token|api_?key|apikey|access_?key|private_?key|client_?secret|credential|auth)($|_)`)

// credentialCopyPattern matches source paths that would embed credentials in an
// image layer.
var credentialCopyPattern = regexp.MustCompile(`(?i)(^|/)(\.env(\.[\w.-]+)?|\.npmrc|\.netrc|\.pypirc|\.git-credentials|id_rsa|id_dsa|id_ecdsa|id_ed25519|[\w.-]+\.(pem|key|p12|pfx|jks)|credentials\.json|service-account\.json)$`)

var chmodWorldWritable = regexp.MustCompile(`(?i)\bchmod\s+(?:-R\s+)?(?:0?777|a\+rwx|o\+w)\b`)

// dockerfileContext tracks the state that decides whether the final image runs
// as an unprivileged user: the current build stage and whether it set USER.
type dockerfileContext struct {
	file     string
	userSet  bool
	riskBase bool
}

// checkDockerfile audits one Dockerfile.
func checkDockerfile(rel string, data []byte) []findings.Finding {
	instructions := parseDockerfile(data)
	ctx := &dockerfileContext{file: rel}
	var out []findings.Finding
	lastFromLine := 1

	for _, ins := range instructions {
		switch ins.Keyword {
		case "FROM":
			base := ""
			for _, field := range strings.Fields(ins.Args) {
				// Skip build flags such as --platform=linux/arm64.
				if strings.HasPrefix(field, "--") {
					continue
				}
				base = strings.ToLower(field)
				break
			}
			ctx.riskBase = !(strings.Contains(base, "distroless") || base == "scratch")
			// A new stage resets the effective user for that stage.
			ctx.userSet = false
			lastFromLine = ins.Line
		case "USER":
			user := strings.TrimSpace(ins.Args)
			ctx.userSet = true
			if user == "root" || user == "0" || strings.HasPrefix(user, "0:") || strings.HasPrefix(user, "root:") {
				out = append(out, newDockerFinding(ruleRootUserExplicit, rel, ins.Line,
					fmt.Sprintf("instructions.USER[%d]", ins.Line),
					"USER "+security.SanitizeEvidence(user, 40)))
			}
		case "ENV", "ARG":
			for _, kv := range parseKeyValues(ins.Args) {
				if !secretKeyPattern.MatchString(kv.key) {
					continue
				}
				if !isLiteralValue(kv.value) {
					continue
				}
				rule := ruleSecretEnvironment
				if ins.Keyword == "ARG" {
					rule = ruleSecretBuildArg
				}
				out = append(out, newDockerFinding(rule, rel, ins.Line,
					fmt.Sprintf("instructions.%s[%d].%s", ins.Keyword, ins.Line, kv.key),
					fmt.Sprintf("%s %s=%s", ins.Keyword, kv.key, security.MaskSecret(kv.value))))
			}
		case "ADD":
			fields := strings.Fields(ins.Args)
			if len(fields) > 0 {
				src := fields[0]
				lower := strings.ToLower(src)
				if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") || strings.HasPrefix(lower, "git@") || strings.HasSuffix(lower, ".git") {
					out = append(out, newDockerFinding(ruleRemoteAdd, rel, ins.Line,
						fmt.Sprintf("instructions.ADD[%d]", ins.Line),
						"ADD "+security.SanitizeEvidence(src, 100)))
				}
			}
			out = append(out, checkCopiedCredentials(rel, ins)...)
		case "COPY":
			out = append(out, checkCopiedCredentials(rel, ins)...)
		case "RUN":
			if match := remoteScriptPattern.FindString(ins.Args); match != "" {
				out = append(out, newDockerFinding(ruleRemoteScript, rel, ins.Line,
					fmt.Sprintf("instructions.RUN[%d]", ins.Line),
					"RUN "+security.SanitizeEvidence(match, 100)))
			}
			if chmodWorldWritable.MatchString(ins.Args) {
				out = append(out, newDockerFinding(ruleWorldWritable, rel, ins.Line,
					fmt.Sprintf("instructions.RUN[%d].chmod", ins.Line),
					"RUN "+security.SanitizeEvidence(ins.Args, 100)))
			}
		}
	}

	// A final image that never sets USER runs as root unless the base image
	// changes the default user.
	lastStageRisk := ctx.riskBase
	if !ctx.userSet && lastStageRisk {
		out = append(out, newDockerFinding(ruleRootUserImplicit, rel, lastFromLine,
			"instructions.USER.missing",
			"No USER instruction; the image runs as root by default"))
	}
	return out
}

func checkCopiedCredentials(rel string, ins instruction) []findings.Finding {
	fields := strings.Fields(ins.Args)
	if len(fields) < 2 {
		return nil
	}
	var out []findings.Finding
	sources := fields[:len(fields)-1]
	for _, src := range sources {
		clean := strings.TrimPrefix(strings.TrimSuffix(src, "/"), "./")
		if !credentialCopyPattern.MatchString(clean) {
			continue
		}
		out = append(out, newDockerFinding(ruleCredentialCopy, rel, ins.Line,
			fmt.Sprintf("instructions.%s[%d].%s", ins.Keyword, ins.Line, clean),
			ins.Keyword+" "+security.SanitizeEvidence(src, 100)))
	}
	return out
}

type keyValue struct {
	key   string
	value string
}

// parseKeyValues handles both `KEY=value KEY2=value2` and legacy `KEY value`.
func parseKeyValues(args string) []keyValue {
	args = strings.TrimSpace(args)
	if args == "" {
		return nil
	}
	if !strings.Contains(args, "=") {
		fields := strings.SplitN(args, " ", 2)
		if len(fields) == 2 {
			return []keyValue{{key: fields[0], value: strings.TrimSpace(fields[1])}}
		}
		return []keyValue{{key: args, value: ""}}
	}
	var out []keyValue
	for _, field := range splitRespectingQuotes(args) {
		kv := strings.SplitN(field, "=", 2)
		if len(kv) != 2 {
			continue
		}
		out = append(out, keyValue{
			key:   strings.TrimSpace(kv[0]),
			value: strings.Trim(strings.TrimSpace(kv[1]), `"'`),
		})
	}
	return out
}

func splitRespectingQuotes(s string) []string {
	var out []string
	var current strings.Builder
	var quote rune
	for _, r := range s {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			}
			current.WriteRune(r)
		case r == '"' || r == '\'':
			quote = r
			current.WriteRune(r)
		case r == ' ' || r == '\t':
			if current.Len() > 0 {
				out = append(out, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(r)
		}
	}
	if current.Len() > 0 {
		out = append(out, current.String())
	}
	return out
}

// isLiteralValue reports whether a value is an actual literal rather than an
// interpolation, an empty string or a known placeholder.
func isLiteralValue(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" {
		return false
	}
	if strings.HasPrefix(v, "$") || strings.HasPrefix(v, "%") || strings.Contains(v, "${") {
		return false
	}
	return !security.LooksLikePlaceholder(v)
}
