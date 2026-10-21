/*
Package rules defines the core types for security rules, findings, and
compliance framework mappings used throughout SAMUH.
*/
package rules

import "fmt"

// Severity represents the impact level of a security finding.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// Rank returns a numeric rank for sorting (higher = more severe).
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// IsAtLeast returns true if this severity is at least as severe as other.
func (s Severity) IsAtLeast(other Severity) bool {
	return s.Rank() >= other.Rank()
}

// OWASPCategory represents an OWASP Top 10:2025 category.
type OWASPCategory string

const (
	OWASPA01 OWASPCategory = "A01:2025-Broken Access Control"
	OWASPA02 OWASPCategory = "A02:2025-Security Misconfiguration"
	OWASPA03 OWASPCategory = "A03:2025-Software Supply Chain Failures"
	OWASPA04 OWASPCategory = "A04:2025-Cryptographic Failures"
	OWASPA05 OWASPCategory = "A05:2025-Injection"
	OWASPA06 OWASPCategory = "A06:2025-Insecure Design"
	OWASPA07 OWASPCategory = "A07:2025-Authentication Failures"
	OWASPA08 OWASPCategory = "A08:2025-Software or Data Integrity Failures"
	OWASPA09 OWASPCategory = "A09:2025-Security Logging and Monitoring Failures"
	OWASPA10 OWASPCategory = "A10:2025-Mishandling of Exceptional Conditions"
)

// NISTFunction represents a NIST CSF 2.0 function.
type NISTFunction string

const (
	NISTGovern   NISTFunction = "GV-Govern"
	NISTIdentify NISTFunction = "ID-Identify"
	NISTProtect  NISTFunction = "PR-Protect"
	NISTDetect   NISTFunction = "DE-Detect"
	NISTRespond  NISTFunction = "RS-Respond"
	NISTRecover  NISTFunction = "RC-Recover"
)

// Confidence indicates how confident the scanner is about a finding.
type Confidence string

const (
	ConfidenceHigh   Confidence = "HIGH"
	ConfidenceMedium Confidence = "MEDIUM"
	ConfidenceLow    Confidence = "LOW"
)

// ScanScope selects what is scanned; project-level checks run only for ScanScopeProject.
type ScanScope string

const (
	ScanScopeProject ScanScope = "PROJECT"
	ScanScopeFolder  ScanScope = "FOLDER"
)

// Rule defines a security check that an analyzer can perform.
type Rule struct {
	ID          string // e.g., "PHP-INJ-001"
	Title       string
	Description string
	Severity    Severity   // default severity for findings from this rule
	Confidence  Confidence // likelihood that a match is a true positive
	OWASP       OWASPCategory
	NIST        []NISTFunction
	CWE         string // e.g., "CWE-89"
	Remediation string
	References  []string // documentation URLs
	Languages   []string // empty means all languages
}

// Finding represents a single vulnerability instance detected during scanning.
type Finding struct {
	RuleID       string
	Title        string
	Description  string
	Severity     Severity // may differ from the rule default
	Confidence   Confidence
	FilePath     string
	Line         int // 1-based
	Column       int // 1-based; 0 if unknown
	EndLine      int // 0 if single-line
	Snippet      string
	MatchContent string // text that triggered the finding
	OWASP        OWASPCategory
	NIST         []NISTFunction
	CWE          string
	Remediation  string
	References   []string // documentation URLs
	Language     string
}

// String returns a human-readable representation of the finding.
func (f Finding) String() string {
	return fmt.Sprintf("[%s] %s: %s (at %s:%d)", f.Severity, f.RuleID, f.Title, f.FilePath, f.Line)
}

// ScanReport holds the complete results of a scan operation.
type ScanReport struct {
	ProjectPath    string
	ScanTimestamp  string // RFC 3339, scan start
	ScanDuration   string // human-readable, e.g., "1.23s"
	ScanDurationMs int64
	TotalFiles     int
	TotalFindings  int
	Findings       []Finding // sorted by severity, critical first
	Summary        ReportSummary
	Languages      []string
	ScannerVersion string
}

// ReportSummary holds finding counts grouped by category.
type ReportSummary struct {
	BySeverity map[Severity]int
	ByOWASP    map[OWASPCategory]int
	ByNIST     map[NISTFunction]int
	ByLanguage map[string]int
	ByFile     map[string]int
}

// NewReportSummary creates a ReportSummary with initialized maps.
func NewReportSummary() ReportSummary {
	return ReportSummary{
		BySeverity: make(map[Severity]int),
		ByOWASP:    make(map[OWASPCategory]int),
		ByNIST:     make(map[NISTFunction]int),
		ByLanguage: make(map[string]int),
		ByFile:     make(map[string]int),
	}
}
