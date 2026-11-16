package reporter

import (
	"encoding/json"

	"samuh/internal/rules"
)

// JSONReporter outputs the scan report as pretty-printed JSON.
type JSONReporter struct{}

// Format returns the format of this reporter.
func (r *JSONReporter) Format() Format {
	return FormatJSON
}

// jsonScanReport is the JSON view of a scan report.
// Error values are written as strings; the error interface marshals as {}.
type jsonScanReport struct {
	*rules.ScanReport
	ErrorCount int      `json:"ErrorCount"`
	Errors     []string `json:"Errors"`
}

// Generate produces the JSON report content as bytes.
func (r *JSONReporter) Generate(report *rules.ScanReport) ([]byte, error) {
	msgs := errorMessages(report.Errors)

	return json.MarshalIndent(jsonScanReport{
		ScanReport: report,
		ErrorCount: len(msgs),
		Errors:     msgs,
	}, "", "  ")
}

// FileExtension returns the file extension for JSON reports.
func (r *JSONReporter) FileExtension() string {
	return ".json"
}
