package reporter

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"samuh/internal/rules"
)

func reportWithErrors(errs ...error) *rules.ScanReport {
	return &rules.ScanReport{
		ProjectPath: "proj",
		Summary:     rules.NewReportSummary(),
		Errors:      errs,
	}
}

func TestJSONReporterErrors(t *testing.T) {
	out, err := (&JSONReporter{}).Generate(reportWithErrors(errors.New("a.js: boom"), nil))
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		ErrorCount int
		Errors     []string
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if got.ErrorCount != 1 || len(got.Errors) != 1 || got.Errors[0] != "a.js: boom" {
		t.Fatalf("unexpected: %+v", got)
	}
}

func TestJSONReporterNoErrorsIsEmptyArray(t *testing.T) {
	out, err := (&JSONReporter{}).Generate(reportWithErrors())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"Errors": []`) || !strings.Contains(string(out), `"ErrorCount": 0`) {
		t.Fatalf("expected empty Errors array and zero count:\n%s", out)
	}
}

func TestMarkdownReporterErrors(t *testing.T) {
	out, err := (&MarkdownReporter{}).Generate(reportWithErrors(errors.New("a.js: boom")))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{"**Errors:** 1", "## Operational Errors / Skipped Files", "`a.js: boom`"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q", want)
		}
	}
	out, _ = (&MarkdownReporter{}).Generate(reportWithErrors())
	if strings.Contains(string(out), "Operational Errors") || !strings.Contains(string(out), "**Errors:** 0") {
		t.Error("clean report should have count 0 and no error section")
	}
}

func TestHTMLReporterErrors(t *testing.T) {
	out, err := (&HTMLReporter{}).Generate(reportWithErrors(errors.New("a.js: <b>boom</b>")))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, "Operational Errors / Skipped Files") {
		t.Error("missing error section")
	}
	if strings.Contains(s, "<b>boom</b>") || !strings.Contains(s, "&lt;b&gt;boom") {
		t.Error("error text must be HTML-escaped")
	}
	out, _ = (&HTMLReporter{}).Generate(reportWithErrors())
	if strings.Contains(string(out), "Operational Errors / Skipped Files") {
		t.Error("clean report should not have error section")
	}
}

func TestSARIFReporterErrors(t *testing.T) {
	out, err := (&SARIFReporter{}).Generate(reportWithErrors(errors.New("a.js: boom")))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Runs []struct {
			Invocations []struct {
				ExecutionSuccessful        bool
				ToolExecutionNotifications []struct {
					Level   string
					Message struct{ Text string }
				}
				Properties struct{ ErrorCount int }
			}
		}
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	inv := doc.Runs[0].Invocations[0]
	if inv.ExecutionSuccessful || inv.Properties.ErrorCount != 1 ||
		len(inv.ToolExecutionNotifications) != 1 ||
		inv.ToolExecutionNotifications[0].Level != "error" ||
		inv.ToolExecutionNotifications[0].Message.Text != "a.js: boom" {
		t.Fatalf("unexpected invocation: %+v", inv)
	}

	out, _ = (&SARIFReporter{}).Generate(reportWithErrors())
	_ = json.Unmarshal(out, &doc)
	if !doc.Runs[0].Invocations[0].ExecutionSuccessful {
		t.Error("clean scan should be executionSuccessful")
	}
}
