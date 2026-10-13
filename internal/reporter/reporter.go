// Package reporter defines the interface for report generation and provides
// factory methods for the supported output formats.
package reporter

import (
	"fmt"
	"samuh/internal/rules"
)

// Format represents a supported report output format.
type Format string

const (
	FormatJSON     Format = "json"
	FormatHTML     Format = "html"
	FormatMarkdown Format = "markdown"
	FormatSARIF    Format = "sarif"
)

// Reporter generates a report from scan results.
type Reporter interface {
	// Format returns the output format of this reporter.
	Format() Format

	// Generate produces the report content as bytes.
	Generate(report *rules.ScanReport) ([]byte, error)

	// FileExtension returns the appropriate file extension for the output
	// (e.g., ".json", ".html", ".md").
	FileExtension() string
}

// New creates a reporter for the specified format.
func New(format Format) (Reporter, error) {
	switch format {
	case FormatJSON:
		return &JSONReporter{}, nil
	case FormatHTML:
		return &HTMLReporter{}, nil
	case FormatMarkdown:
		return &MarkdownReporter{}, nil
	case FormatSARIF:
		return &SARIFReporter{}, nil
	default:
		return nil, fmt.Errorf("unsupported report format: %s", format)
	}
}
