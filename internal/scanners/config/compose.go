package config

import (
	"fmt"
	"strings"

	"github.com/Undrocs/wardline/internal/findings"
	"github.com/Undrocs/wardline/internal/security"
	"github.com/Undrocs/wardline/internal/yamlpos"
)

// dangerousCapabilities are capabilities that amount to host control.
var dangerousCapabilities = map[string]findings.Severity{
	"ALL":             findings.SeverityHigh,
	"SYS_ADMIN":       findings.SeverityHigh,
	"SYS_PTRACE":      findings.SeverityHigh,
	"SYS_MODULE":      findings.SeverityHigh,
	"DAC_READ_SEARCH": findings.SeverityHigh,
	"NET_ADMIN":       findings.SeverityMedium,
	"NET_RAW":         findings.SeverityLow,
	"SYS_RAWIO":       findings.SeverityHigh,
	"BPF":             findings.SeverityHigh,
	"PERFMON":         findings.SeverityMedium,
}

// sensitiveHostPaths are bind-mount sources that expose the host.
var sensitiveHostPaths = []string{
	"/", "/etc", "/root", "/home", "/var/run", "/var/lib/docker", "/boot", "/proc", "/sys", "/dev",
}

// sensitiveServicePorts are datastore ports that should not be published on all
// interfaces.
var sensitiveServicePorts = map[string]string{
	"5432":  "PostgreSQL",
	"3306":  "MySQL/MariaDB",
	"27017": "MongoDB",
	"6379":  "Redis",
	"9200":  "Elasticsearch",
	"9300":  "Elasticsearch",
	"11211": "Memcached",
	"5984":  "CouchDB",
	"2375":  "Docker daemon",
	"2376":  "Docker daemon",
	"8500":  "Consul",
	"8200":  "Vault",
	"8123":  "ClickHouse",
	"9092":  "Kafka",
	"5672":  "RabbitMQ",
	"15672": "RabbitMQ management",
	"8086":  "InfluxDB",
	"9042":  "Cassandra",
}

// checkCompose audits a Docker Compose file.
func checkCompose(rel string, data []byte) ([]findings.Finding, error) {
	root, err := yamlpos.ParseMapping(data)
	if err != nil {
		return nil, err
	}
	services, ok := root.Get("services")
	if !ok || services.Kind != yamlpos.KindMapping {
		// Every Compose layout (v1 as well as the v2/v3 schemas) puts services
		// under a top-level `services` mapping. Anything else is not a Compose
		// file we can audit; the caller records a skipped check only for files
		// it selected by name, so this is a silent no-op.
		return nil, nil
	}
	var out []findings.Finding
	for _, svc := range services.Pairs {
		body := svc.Value
		if body == nil || body.Kind != yamlpos.KindMapping {
			continue
		}
		loc := func(key string) string { return fmt.Sprintf("services.%s.%s", svc.Key, key) }

		if v, ok := body.Get("privileged"); ok {
			if s, ok := v.Scalar(); ok && strings.EqualFold(strings.TrimSpace(s), "true") {
				out = append(out, newComposeFinding(rulePrivileged, rel, v.Line, loc("privileged"),
					fmt.Sprintf("service %s: privileged: true", svc.Key)))
			}
		}
		if v, ok := body.Get("network_mode"); ok {
			if s, ok := v.Scalar(); ok && strings.EqualFold(strings.TrimSpace(s), "host") {
				out = append(out, newComposeFinding(ruleHostNetwork, rel, v.Line, loc("network_mode"),
					fmt.Sprintf("service %s: network_mode: host", svc.Key)))
			}
		}
		if v, ok := body.Get("user"); ok {
			if s, ok := v.Scalar(); ok {
				user := strings.TrimSpace(s)
				if user == "root" || user == "0" || strings.HasPrefix(user, "0:") || strings.HasPrefix(user, "root:") {
					out = append(out, newComposeFinding(ruleComposeRootUser, rel, v.Line, loc("user"),
						fmt.Sprintf("service %s: user: %s", svc.Key, security.RedactEvidence(user, 20))))
				}
			}
		}
		if v, ok := body.Get("cap_add"); ok {
			for _, item := range v.Seq() {
				capability := strings.TrimSpace(item.Value)
				if capability == "" {
					continue
				}
				severity, dangerous := dangerousCapabilities[strings.ToUpper(capability)]
				if !dangerous {
					continue
				}
				f := newComposeFinding(ruleDangerousCapability, rel, item.Line,
					loc("cap_add."+strings.ToUpper(capability)),
					fmt.Sprintf("service %s: cap_add: %s", svc.Key, capability))
				f.Severity = severity
				out = append(out, f)
			}
		}
		if v, ok := body.Get("security_opt"); ok {
			for _, item := range v.Seq() {
				opt := strings.ToLower(strings.TrimSpace(item.Value))
				if strings.HasPrefix(opt, "seccomp:unconfined") || strings.HasPrefix(opt, "apparmor:unconfined") ||
					strings.HasPrefix(opt, "seccomp=unconfined") || strings.HasPrefix(opt, "apparmor=unconfined") {
					out = append(out, newComposeFinding(ruleUnconfinedProfile, rel, item.Line,
						loc("security_opt."+opt), fmt.Sprintf("service %s: security_opt: %s", svc.Key, opt)))
				}
			}
		}
		out = append(out, checkComposeVolumes(rel, svc.Key, body)...)
		out = append(out, checkComposeEnvironment(rel, svc.Key, body)...)
		out = append(out, checkComposePorts(rel, svc.Key, body)...)
	}
	return out, nil
}

func checkComposeVolumes(rel, service string, body *yamlpos.Node) []findings.Finding {
	volumes, ok := body.Get("volumes")
	if !ok {
		return nil
	}
	var out []findings.Finding
	handle := func(source, target string, line int, locatorSuffix string) {
		src := strings.TrimSpace(source)
		if src == "" {
			return
		}
		lower := strings.ToLower(src)
		if strings.Contains(lower, "docker.sock") {
			out = append(out, newComposeFinding(ruleDockerSocket, rel, line,
				fmt.Sprintf("services.%s.volumes%s.dockerSock", service, locatorSuffix),
				fmt.Sprintf("service %s mounts %s", service, security.RedactEvidence(src, 80))))
			return
		}
		if isSensitiveHostPath(lower) {
			out = append(out, newComposeFinding(ruleSensitiveMount, rel, line,
				fmt.Sprintf("services.%s.volumes%s.%s", service, locatorSuffix, security.RedactEvidence(src, 40)),
				fmt.Sprintf("service %s mounts %s", service, security.RedactEvidence(src, 80))))
		}
	}
	for i, item := range volumes.Seq() {
		if item.Kind == yamlpos.KindScalar || item.Kind == yamlpos.KindBlock {
			parts := strings.Split(item.Value, ":")
			handle(parts[0], "", item.Line, fmt.Sprintf("[%d]", i))
			continue
		}
		if item.Kind == yamlpos.KindMapping {
			// Long syntax: only `source` can expose the host; a named volume has
			// no leading slash and is therefore never reported.
			source, _ := item.Get("source")
			src, _ := source.Scalar()
			line := item.Line
			if source != nil {
				line = source.Line
			}
			handle(src, "", line, fmt.Sprintf("[%d]", i))
		}
	}
	return out
}

func isSensitiveHostPath(p string) bool {
	if p == "/" {
		return true
	}
	for _, prefix := range sensitiveHostPaths {
		if prefix == "/" {
			continue
		}
		if p == prefix || strings.HasPrefix(p, prefix+"/") {
			return true
		}
	}
	return false
}

func checkComposeEnvironment(rel, service string, body *yamlpos.Node) []findings.Finding {
	env, ok := body.Get("environment")
	if !ok {
		return nil
	}
	var out []findings.Finding
	report := func(key, value string, line int, suffix string) {
		if !secretKeyPattern.MatchString(key) {
			return
		}
		if !isLiteralValue(value) {
			return
		}
		out = append(out, newComposeFinding(ruleComposeSecretEnv, rel, line,
			fmt.Sprintf("services.%s.environment.%s%s", service, key, suffix),
			fmt.Sprintf("service %s: %s=%s", service, key, security.MaskSecret(value))))
	}
	switch env.Kind {
	case yamlpos.KindMapping:
		for _, p := range env.Pairs {
			value, ok := p.Value.Scalar()
			if !ok {
				continue
			}
			report(p.Key, value, p.KeyLine, "")
		}
	case yamlpos.KindSequence:
		for i, item := range env.Seq() {
			value, ok := item.Scalar()
			if !ok {
				continue
			}
			kv := strings.SplitN(value, "=", 2)
			if len(kv) != 2 {
				continue
			}
			report(strings.TrimSpace(kv[0]), strings.TrimSpace(kv[1]), item.Line, fmt.Sprintf("[%d]", i))
		}
	}
	return out
}

func checkComposePorts(rel, service string, body *yamlpos.Node) []findings.Finding {
	ports, ok := body.Get("ports")
	if !ok {
		return nil
	}
	var out []findings.Finding
	for i, item := range ports.Seq() {
		spec, ok := item.Scalar()
		if !ok {
			// Long syntax: {target: 5432, published: 5432, host_ip: 0.0.0.0}
			if item.Kind == yamlpos.KindMapping {
				target, _ := item.Get("target")
				hostIP, _ := item.Get("host_ip")
				port, _ := target.Scalar()
				ip, _ := hostIP.Scalar()
				if name, sensitive := sensitiveServicePorts[strings.TrimSpace(port)]; sensitive && (ip == "" || ip == "0.0.0.0") {
					out = append(out, newComposeFinding(ruleSensitivePort, rel, item.Line,
						fmt.Sprintf("services.%s.ports[%d]", service, i),
						fmt.Sprintf("service %s publishes %s port %s", service, name, port)))
				}
			}
			continue
		}
		host, port := splitPortSpec(spec)
		name, sensitive := sensitiveServicePorts[port]
		if !sensitive {
			continue
		}
		if host != "" && host != "0.0.0.0" && host != "::" && host != "0:0:0:0:0:0:0:0" {
			// Bound to a specific interface such as 127.0.0.1: not exposed.
			continue
		}
		out = append(out, newComposeFinding(ruleSensitivePort, rel, item.Line,
			fmt.Sprintf("services.%s.ports[%d]", service, i),
			fmt.Sprintf("service %s publishes %s port %s", service, name, port)))
	}
	return out
}

// splitPortSpec extracts the host binding and container port from a short
// Compose port specification.
func splitPortSpec(spec string) (host, containerPort string) {
	spec = strings.TrimSpace(strings.Trim(spec, `"'`))
	// Strip protocol suffix: "5432:5432/tcp".
	if idx := strings.Index(spec, "/"); idx >= 0 {
		spec = spec[:idx]
	}
	parts := strings.Split(spec, ":")
	switch len(parts) {
	case 1:
		return "", parts[0]
	case 2:
		return "", parts[1]
	default:
		// IPv6 bindings appear as "[::1]:5432:5432".
		host := strings.Join(parts[:len(parts)-1], ":")
		host = strings.Trim(host, "[]")
		return host, parts[len(parts)-1]
	}
}
