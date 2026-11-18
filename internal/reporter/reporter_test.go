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

func TestJSONReporterKeepsReportFields(t *testing.T) {
	rep := reportWithErrors(errors.New("e"))
	rep.TotalFiles = 7
	rep.ProjectPath = "my-proj"
	out, err := (&JSONReporter{}).Generate(rep)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if got["ProjectPath"] != "my-proj" || got["TotalFiles"] != float64(7) {
		t.Fatalf("embedded report fields lost: %v", got)
	}
}

func TestErrorMessagesSkipsNil(t *testing.T) {
	got := errorMessages([]error{nil, errors.New("a"), nil, errors.New("b")})
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("unexpected: %v", got)
	}
	if got := errorMessages(nil); got == nil || len(got) != 0 {
		t.Fatalf("nil input should give empty non-nil slice, got %#v", got)
	}
}

func TestHTMLReporterShowsErrorCount(t *testing.T) {
	out, err := (&HTMLReporter{}).Generate(reportWithErrors(errors.New("a"), errors.New("b")))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	i := strings.Index(s, `summary-label">Errors<`)
	if i < 0 || !strings.Contains(s[max(0, i-80):i], ">2<") {
		t.Fatal("error count of 2 not shown in summary")
	}
}

func TestSARIFReporterErrorsCoexistWithFindings(t *testing.T) {
	rep := reportWithErrors(errors.New("a"))
	rep.Findings = []rules.Finding{{RuleID: "R-1", Severity: rules.SeverityHigh, FilePath: "x.js", Line: 1}}
	rep.TotalFindings = 1
	out, err := (&SARIFReporter{}).Generate(rep)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Runs []struct {
			Results     []any
			Invocations []any
		}
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Runs[0].Results) != 1 || len(doc.Runs[0].Invocations) != 1 {
		t.Fatalf("results/invocations wrong: %s", out)
	}
}
