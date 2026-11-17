package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"samuh/internal/analyzer"
	"samuh/internal/rules"
)

type fakeAnalyzer struct {
	analyzeFn func(fc analyzer.FileContext) ([]rules.Finding, error)
	projectFn func() ([]rules.Finding, error)
}

func (f *fakeAnalyzer) Name() string         { return "fake" }
func (f *fakeAnalyzer) Extensions() []string { return []string{".js"} }
func (f *fakeAnalyzer) Analyze(_ context.Context, fc analyzer.FileContext) ([]rules.Finding, error) {
	return f.analyzeFn(fc)
}
func (f *fakeAnalyzer) AnalyzeProject(_ context.Context, _ string) ([]rules.Finding, error) {
	if f.projectFn == nil {
		return nil, nil
	}
	return f.projectFn()
}

func runEngine(t *testing.T, a analyzer.Analyzer, scope rules.ScanScope, files map[string]string) *rules.ScanReport {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	reg := analyzer.NewRegistry()
	if err := reg.Register(a); err != nil {
		t.Fatal(err)
	}
	rep, err := New(reg, Options{Scope: scope, Path: dir, MaxFileSize: 1 << 20}).Run(context.Background())
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	return rep
}

func TestRunCollectsErrorsAndContinues(t *testing.T) {
	a := &fakeAnalyzer{analyzeFn: func(fc analyzer.FileContext) ([]rules.Finding, error) {
		if strings.HasPrefix(filepath.Base(fc.Path), "bad") {
			return nil, errors.New("boom")
		}
		return []rules.Finding{{RuleID: "X-1", Severity: rules.SeverityHigh, FilePath: fc.Path}}, nil
	}}
	rep := runEngine(t, a, rules.ScanScopeFolder, map[string]string{
		"bad1.js": "x = 1", "bad2.js": "x = 2", "good.js": "x = 3",
	})
	if len(rep.Errors) != 2 {
		t.Fatalf("want 2 errors, got %d: %v", len(rep.Errors), rep.Errors)
	}
	if rep.TotalFindings != 1 {
		t.Fatalf("good file should still yield a finding, got %d", rep.TotalFindings)
	}
	for _, e := range rep.Errors {
		if !strings.Contains(e.Error(), "analyzer fake") || !strings.Contains(e.Error(), "boom") {
			t.Errorf("error lacks context: %v", e)
		}
	}
	if rep.Errors[0].Error() > rep.Errors[1].Error() {
		t.Errorf("errors not sorted: %v", rep.Errors)
	}
}

func TestRunRecoversFromPanic(t *testing.T) {
	a := &fakeAnalyzer{analyzeFn: func(fc analyzer.FileContext) ([]rules.Finding, error) {
		panic("kaboom")
	}}
	rep := runEngine(t, a, rules.ScanScopeFolder, map[string]string{"a.js": "x = 1"})
	if len(rep.Errors) != 1 || !strings.Contains(rep.Errors[0].Error(), "panic: kaboom") {
		t.Fatalf("unexpected errors: %v", rep.Errors)
	}
}

func TestRunProjectErrorAndPanic(t *testing.T) {
	a := &fakeAnalyzer{
		analyzeFn: func(analyzer.FileContext) ([]rules.Finding, error) { return nil, nil },
		projectFn: func() ([]rules.Finding, error) { return nil, errors.New("proj fail") },
	}
	rep := runEngine(t, a, rules.ScanScopeProject, map[string]string{"a.js": "x = 1"})
	if len(rep.Errors) != 1 || !strings.Contains(rep.Errors[0].Error(), "project analysis") {
		t.Fatalf("unexpected errors: %v", rep.Errors)
	}

	a.projectFn = func() ([]rules.Finding, error) { panic("pp") }
	rep = runEngine(t, a, rules.ScanScopeProject, map[string]string{"a.js": "x = 1"})
	if len(rep.Errors) != 1 || !strings.Contains(rep.Errors[0].Error(), "panic: pp") {
		t.Fatalf("unexpected errors: %v", rep.Errors)
	}
}

func TestRunNoErrors(t *testing.T) {
	a := &fakeAnalyzer{analyzeFn: func(analyzer.FileContext) ([]rules.Finding, error) { return nil, nil }}
	rep := runEngine(t, a, rules.ScanScopeFolder, map[string]string{"a.js": "x = 1"})
	if len(rep.Errors) != 0 {
		t.Fatalf("expected no errors, got %v", rep.Errors)
	}
}

