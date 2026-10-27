package node

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"samuh/internal/analyzer"
	"samuh/internal/rules"
)

func init() {
	analyzer.RegisterDefault(NewAnalyzer())
}

// NodeAnalyzer implements the analyzer.Analyzer interface for Node.js projects.
type NodeAnalyzer struct {
	nodeIndicator *regexp.Regexp
}

// NewAnalyzer creates a new instance of NodeAnalyzer.
func NewAnalyzer() *NodeAnalyzer {
	return &NodeAnalyzer{
		nodeIndicator: regexp.MustCompile(`(?i)(require\(|module\.exports|process\.|Buffer\.|__dirname|__filename|express\(|import\s+.*['"](node:|fs|path|http|crypto|child_process|os)['"])`),
	}
}

// Name returns the name of the analyzer.
func (a *NodeAnalyzer) Name() string {
	return "Node.js"
}

// Extensions returns the file extensions supported by this analyzer.
func (a *NodeAnalyzer) Extensions() []string {
	return []string{".js", ".mjs", ".cjs"}
}

// Analyze scans a single file for Node.js vulnerabilities.
func (a *NodeAnalyzer) Analyze(ctx context.Context, file analyzer.FileContext) ([]rules.Finding, error) {
	var findings []rules.Finding

	/*
		Skip browser-only files (the JS/TS analyzer covers them). Lines is used
		instead of Content because not every scanner populates Content.
	*/
	contentStr := strings.Join(file.Lines, "\n")
	if !a.nodeIndicator.MatchString(contentStr) {
		return findings, nil
	}

	for i, line := range file.Lines {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		for _, pat := range nodePatterns {
			if pat.regex.MatchString(line) {
				finding := rules.Finding{
					RuleID:      pat.rule.ID,
					Title:       pat.rule.Title,
					Description: pat.rule.Description,
					Severity:    pat.rule.Severity,
					Confidence:  pat.rule.Confidence,
					FilePath:    file.Path,
					Line:        i + 1,
					Column:      0,
					Snippet:     strings.TrimSpace(line),
					OWASP:       pat.rule.OWASP,
					NIST:        pat.rule.NIST,
					CWE:         pat.rule.CWE,
					Remediation: pat.rule.Remediation,
					References:  pat.rule.References,
					Language:    "Node.js",
				}
				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

// packageJSON models the relevant parts of a package.json file.
type packageJSON struct {
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

// AnalyzeProject checks package.json and package-lock.json for supply chain issues.
func (a *NodeAnalyzer) AnalyzeProject(ctx context.Context, projectRoot string) ([]rules.Finding, error) {
	var findings []rules.Finding

	packageJSONPath := filepath.Join(projectRoot, "package.json")
	lockfilePath := filepath.Join(projectRoot, "package-lock.json")

	data, err := os.ReadFile(packageJSONPath)
	if err != nil {
		if os.IsNotExist(err) {
			return findings, nil // Not a Node.js project
		}
		return findings, err
	}

	if _, err := os.Stat(lockfilePath); os.IsNotExist(err) {
		findings = append(findings, rules.Finding{
			RuleID:      "NODE-A03-001",
			Title:       "Missing package-lock.json",
			Description: "The project lacks a package-lock.json file, meaning dependencies are not pinned. This can lead to uncontrolled dependency updates and supply chain attacks.",
			Severity:    rules.SeverityMedium,
			Confidence:  rules.ConfidenceHigh,
			FilePath:    packageJSONPath,
			Line:        1,
			OWASP:       rules.OWASPA03,
			NIST:        []rules.NISTFunction{rules.NISTProtect},
			CWE:         "CWE-1104",
			Remediation: "Run 'npm install' to generate a package-lock.json file and commit it to version control.",
			Language:    "Node.js",
		})
	}

	var pkg packageJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		return findings, nil // Malformed package.json is not reported
	}

	checkDeps := func(deps map[string]string) {
		for name, version := range deps {
			if name == "node-serialize" {
				findings = append(findings, rules.Finding{
					RuleID:       "NODE-A03-002",
					Title:        "Known Vulnerable Dependency (node-serialize)",
					Description:  "The project depends on node-serialize, which is known to be vulnerable to remote code execution (RCE) via unsafe deserialization.",
					Severity:     rules.SeverityCritical,
					Confidence:   rules.ConfidenceHigh,
					FilePath:     packageJSONPath,
					Line:         1,
					MatchContent: "node-serialize: " + version,
					OWASP:        rules.OWASPA03,
					NIST:         []rules.NISTFunction{rules.NISTProtect},
					CWE:          "CWE-502",
					Remediation:  "Remove node-serialize and use secure serialization alternatives like JSON.parse/stringify.",
					Language:     "Node.js",
				})
			}

			if version == "*" || version == "latest" || version == ">0.0.0" {
				findings = append(findings, rules.Finding{
					RuleID:       "NODE-A03-003",
					Title:        "Wildcard Dependency Version",
					Description:  "A dependency (" + name + ") is configured to use a wildcard ('*') or 'latest' version. This pulls the newest version automatically, which is a supply chain risk.",
					Severity:     rules.SeverityHigh,
					Confidence:   rules.ConfidenceHigh,
					FilePath:     packageJSONPath,
					Line:         1,
					MatchContent: name + ": " + version,
					OWASP:        rules.OWASPA03,
					NIST:         []rules.NISTFunction{rules.NISTProtect},
					CWE:          "CWE-1104",
					Remediation:  "Pin the dependency to a specific version or a narrow semver range.",
					Language:     "Node.js",
				})
			}
		}
	}

	checkDeps(pkg.Dependencies)
	checkDeps(pkg.DevDependencies)

	return findings, nil
}
