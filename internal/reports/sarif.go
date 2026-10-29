package reports

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"

	"github.com/Undrocs/wardline/internal/findings"
)

// sarifVersion and sarifSchema identify the emitted document.
const (
	sarifVersion = "2.1.0"
	sarifSchema  = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/schemas/sarif-schema-2.1.0.json"
)

// sarifLog is the SARIF 2.1.0 root object.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Invocations []sarifInvocation `json:"invocations"`
	Results     []sarifResult     `json:"results"`
	// Properties carries Wardline specific scan metadata that has no SARIF
	// equivalent.
	Properties map[string]any `json:"properties,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name            string      `json:"name"`
	FullName        string      `json:"fullName,omitempty"`
	Version         string      `json:"version"`
	InformationURI  string      `json:"informationUri"`
	SemanticVersion string      `json:"semanticVersion,omitempty"`
	Rules           []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string             `json:"id"`
	Name                 string             `json:"name,omitempty"`
	ShortDescription     sarifMessage       `json:"shortDescription"`
	FullDescription      *sarifMessage      `json:"fullDescription,omitempty"`
	HelpURI              string             `json:"helpUri,omitempty"`
	DefaultConfiguration sarifDefaultConfig `json:"defaultConfiguration"`
	Properties           map[string]any     `json:"properties,omitempty"`
}

type sarifDefaultConfig struct {
	Level string `json:"level"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string             `json:"ruleId"`
	RuleIndex           int                `json:"ruleIndex"`
	Level               string             `json:"level"`
	Message             sarifMessage       `json:"message"`
	Locations           []sarifLocation    `json:"locations,omitempty"`
	PartialFingerprints map[string]string  `json:"partialFingerprints"`
	Properties          map[string]any     `json:"properties,omitempty"`
	Suppressions        []sarifSuppression `json:"suppressions,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
	EndLine     int `json:"endLine,omitempty"`
	EndColumn   int `json:"endColumn,omitempty"`
}

type sarifSuppression struct {
	Kind          string `json:"kind"`
	Justification string `json:"justification,omitempty"`
}

type sarifInvocation struct {
	ExecutionSuccessful        bool                `json:"executionSuccessful"`
	CommandLine                string              `json:"commandLine,omitempty"`
	ToolExecutionNotifications []sarifNotification `json:"toolExecutionNotifications,omitempty"`
}

type sarifNotification struct {
	Level   string       `json:"level"`
	Message sarifMessage `json:"message"`
}

// sarifLevel maps Wardline severities to SARIF result levels.
func sarifLevel(s findings.Severity) string {
	switch s {
	case findings.SeverityCritical, findings.SeverityHigh:
		return "error"
	case findings.SeverityMedium, findings.SeverityUnknown:
		return "warning"
	case findings.SeverityLow:
		return "note"
	default:
		return "note"
	}
}

// WriteSARIF writes a SARIF 2.1.0 document that GitHub code scanning accepts.
//
// Only relative, percent-encoded repository paths are emitted, so reports do not
// disclose the absolute path of the machine that produced them.
func WriteSARIF(w io.Writer, rep *Report) error {
	if rep == nil {
		return fmt.Errorf("no report")
	}
	run := sarifRun{
		Tool: sarifTool{Driver: sarifDriver{
			Name:            "Wardline",
			FullName:        "Wardline security scanner",
			Version:         rep.Tool.Version,
			SemanticVersion: semanticVersion(rep.Tool.Version),
			InformationURI:  "https://github.com/Undrocs/wardline",
			Rules:           []sarifRule{},
		}},
		Results: []sarifResult{},
		Properties: map[string]any{
			"scanMode":            rep.Scan.Mode,
			"target":              rep.Scan.Target,
			"filesScanned":        rep.Scan.Files,
			"configFile":          rep.Scan.ConfigFile,
			"incomplete":          rep.Summary.Incomplete,
			"policyNotices":       rep.PolicyNotices,
			"networkDestinations": rep.Network.Destinations,
		},
	}

	// Rule metadata, deduplicated and sorted by ID for deterministic output.
	metaByID := map[string]findings.Finding{}
	for _, f := range rep.Findings {
		if _, ok := metaByID[f.RuleID]; ok {
			continue
		}
		metaByID[f.RuleID] = f
	}
	ruleIDs := make([]string, 0, len(metaByID))
	for id := range metaByID {
		ruleIDs = append(ruleIDs, id)
	}
	sort.Strings(ruleIDs)
	index := make(map[string]int, len(ruleIDs))
	for i, id := range ruleIDs {
		f := metaByID[id]
		helpURI := ""
		if len(f.References) > 0 {
			helpURI = f.References[0]
		}
		run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, sarifRule{
			ID:               id,
			Name:             sarifName(f.Title),
			ShortDescription: sarifMessage{Text: f.Title},
			FullDescription:  &sarifMessage{Text: orDefault(f.Description, f.Title)},
			HelpURI:          helpURI,
			DefaultConfiguration: sarifDefaultConfig{
				Level: sarifLevel(f.Severity),
			},
		})
		index[id] = i
	}

	for _, f := range rep.Findings {
		result := sarifResult{
			RuleID:    f.RuleID,
			RuleIndex: index[f.RuleID],
			Level:     sarifLevel(f.Severity),
			Message:   sarifMessage{Text: sarifText(f)},
			PartialFingerprints: map[string]string{
				"wardlineFindingId/v1": f.ID,
			},
			Properties: map[string]any{
				"severity":   f.Severity.String(),
				"confidence": string(f.Confidence),
				"scanner":    f.Scanner,
			},
		}
		if f.Evidence != "" {
			result.Properties["evidence"] = f.Evidence
		}
		if f.Vulnerability != nil {
			if len(f.Vulnerability.IDs) > 0 {
				result.Properties["advisoryIds"] = f.Vulnerability.IDs
			}
			if f.Vulnerability.FixedVersion != "" {
				result.Properties["fixedVersion"] = f.Vulnerability.FixedVersion
			}
			if f.Vulnerability.CVSSScore != nil {
				result.Properties["cvssV3BaseScore"] = *f.Vulnerability.CVSSScore
			}
		}
		if f.Package != nil {
			result.Properties["package"] = f.Package.Name
			result.Properties["packageVersion"] = f.Package.Version
			result.Properties["ecosystem"] = f.Package.Ecosystem
		}
		if f.Suppressed {
			// Suppressions come from .wardline.yaml, not from an inline
			// annotation, so SARIF classifies them as external.
			result.Suppressions = []sarifSuppression{{
				Kind:          "external",
				Justification: f.SuppressionReason,
			}}
		}
		loc := sarifLocation{PhysicalLocation: sarifPhysicalLocation{
			ArtifactLocation: sarifArtifactLocation{URI: sarifURI(f.Location.Path), URIBaseID: "SRCROOT"},
		}}
		if f.Location.StartLine > 0 {
			loc.PhysicalLocation.Region = &sarifRegion{
				StartLine:   f.Location.StartLine,
				StartColumn: f.Location.StartColumn,
				EndLine:     f.Location.EndLine,
				EndColumn:   f.Location.EndColumn,
			}
		}
		result.Locations = []sarifLocation{loc}
		run.Results = append(run.Results, result)
	}

	invocation := sarifInvocation{ExecutionSuccessful: len(rep.Errors) == 0}
	for _, notice := range rep.PolicyNotices {
		invocation.ToolExecutionNotifications = append(invocation.ToolExecutionNotifications, sarifNotification{
			Level:   "note",
			Message: sarifMessage{Text: notice},
		})
	}
	for _, e := range rep.Errors {
		invocation.ToolExecutionNotifications = append(invocation.ToolExecutionNotifications, sarifNotification{
			Level:   "error",
			Message: sarifMessage{Text: e},
		})
	}
	for _, runInfo := range rep.Scanners {
		if runInfo.Disabled {
			invocation.ToolExecutionNotifications = append(invocation.ToolExecutionNotifications, sarifNotification{
				Level:   "note",
				Message: sarifMessage{Text: runInfo.Name + " scanner disabled: it did not run for this scan"},
			})
			continue
		}
		if runInfo.Status == "skipped" || runInfo.Status == "partial" || runInfo.Status == "failed" {
			notifications := make([]string, 0, len(runInfo.Skipped))
			for _, sk := range runInfo.Skipped {
				notifications = append(notifications, sk.Check+": "+sk.Reason)
			}
			if runInfo.Error != "" {
				notifications = append(notifications, runInfo.Error)
			}
			if len(notifications) == 0 {
				notifications = append(notifications, "scanner did not complete all checks")
			}
			invocation.ToolExecutionNotifications = append(invocation.ToolExecutionNotifications, sarifNotification{
				Level:   "warning",
				Message: sarifMessage{Text: runInfo.Name + " scanner " + string(runInfo.Status) + ": " + strings.Join(notifications, "; ")},
			})
		}
	}
	run.Invocations = []sarifInvocation{invocation}

	doc := sarifLog{Schema: sarifSchema, Version: sarifVersion, Runs: []sarifRun{run}}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("encode SARIF report: %w", err)
	}
	return nil
}

// sarifText builds the result message. It contains no raw credentials.
func sarifText(f findings.Finding) string {
	var b strings.Builder
	b.WriteString(f.Title)
	if f.Location.Path != "" {
		b.WriteString(" (")
		b.WriteString(f.Location.String())
		b.WriteString(")")
	}
	if f.Evidence != "" {
		b.WriteString(": ")
		b.WriteString(f.Evidence)
	}
	if f.Remediation != "" {
		b.WriteString(" Remediation: ")
		b.WriteString(oneLine(strings.TrimSpace(f.Remediation)))
	}
	return b.String()
}

// sarifURI converts a repository-relative path into a URI reference. Absolute
// paths are never emitted.
func sarifURI(rel string) string {
	rel = strings.TrimPrefix(strings.ReplaceAll(rel, "\\", "/"), "/")
	segments := strings.Split(rel, "/")
	encoded := make([]string, 0, len(segments))
	for _, seg := range segments {
		encoded = append(encoded, url.PathEscape(seg))
	}
	return strings.Join(encoded, "/")
}

// sarifName produces a rule name suitable for SARIF (alphanumeric and dashes).
func sarifName(title string) string {
	var b strings.Builder
	for _, r := range title {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ' || r == '-' || r == '_':
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

// semanticVersion keeps only a leading x.y.z when the build version is a clean
// semantic version; development builds omit the field.
func semanticVersion(v string) string {
	parts := strings.SplitN(v, "-", 2)
	core := parts[0]
	fields := strings.Split(core, ".")
	if len(fields) != 3 {
		return ""
	}
	for _, f := range fields {
		if f == "" {
			return ""
		}
		for _, r := range f {
			if r < '0' || r > '9' {
				return ""
			}
		}
	}
	return core
}
