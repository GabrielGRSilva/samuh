// Helper functions to parse command line flags, used in scan.go
package cmd

import (
	"fmt"
	"samuh/internal/reporter"
	"samuh/internal/rules"
	"strings"
)

// Converts a scope string to the ScanScope type.
func parseScope(s string) (rules.ScanScope, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "project":
		return rules.ScanScopeProject, nil
	case "folder":
		return rules.ScanScopeFolder, nil
	default:
		return rules.ScanScopeProject, fmt.Errorf("invalid scope: %s", s)
	}
}

// ParseFormat converts a string to a Format, returning an error for unknown formats.
func parseFormat(s string) reporter.Format {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "json":
		return reporter.FormatJSON
	case "html":
		return reporter.FormatHTML
	case "markdown", "md":
		return reporter.FormatMarkdown
	case "sarif":
		return reporter.FormatSARIF
	default:
		return reporter.FormatMarkdown
	}
}

// Converts a severity string to the Severity type.
func parseSeverity(s string) rules.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return rules.SeverityCritical
	case "high":
		return rules.SeverityHigh
	case "medium":
		return rules.SeverityMedium
	case "low":
		return rules.SeverityLow
	case "info":
		return rules.SeverityInfo
	default:
		return rules.SeverityLow
	}
}
