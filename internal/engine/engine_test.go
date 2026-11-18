package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
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


func TestRunProjectAnalysisSkippedForFolderScope(t *testing.T) {
	called := false
	a := &fakeAnalyzer{
		analyzeFn: func(analyzer.FileContext) ([]rules.Finding, error) { return nil, nil },
		projectFn: func() ([]rules.Finding, error) { called = true; return nil, errors.New("x") },
	}
	rep := runEngine(t, a, rules.ScanScopeFolder, map[string]string{"a.js": "x = 1"})
	if called || len(rep.Errors) != 0 {
		t.Fatalf("project analysis must not run for folder scope (called=%v, errors=%v)", called, rep.Errors)
	}
}

func TestRunProjectFindingsKeptAlongsideErrors(t *testing.T) {
	a := &fakeAnalyzer{
		analyzeFn: func(analyzer.FileContext) ([]rules.Finding, error) { return nil, errors.New("file fail") },
		projectFn: func() ([]rules.Finding, error) {
			return []rules.Finding{{RuleID: "P-1", Severity: rules.SeverityHigh}}, nil
		},
	}
	rep := runEngine(t, a, rules.ScanScopeProject, map[string]string{"a.js": "x = 1"})
	if rep.TotalFindings != 1 || len(rep.Errors) != 1 {
		t.Fatalf("want 1 finding and 1 error, got %d and %d", rep.TotalFindings, len(rep.Errors))
	}
}

func TestRunIgnoresUnsupportedExtensions(t *testing.T) {
	calls := 0
	var mu sync.Mutex
	a := &fakeAnalyzer{analyzeFn: func(analyzer.FileContext) ([]rules.Finding, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		return nil, errors.New("should not be called for .js only")
	}}
	rep := runEngine(t, a, rules.ScanScopeFolder, map[string]string{"notes.txt": "hello"})
	if calls != 0 || len(rep.Errors) != 0 {
		t.Fatalf("analyzer called %d times, errors=%v", calls, rep.Errors)
	}
}

func TestRunCancelledContextReturnsError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.js"), []byte("x = 1"), 0o644); err != nil {
		t.Fatal(err)
	}
	reg := analyzer.NewRegistry()
	_ = reg.Register(&fakeAnalyzer{analyzeFn: func(analyzer.FileContext) ([]rules.Finding, error) { return nil, nil }})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := New(reg, Options{Scope: rules.ScanScopeFolder, Path: dir, MaxFileSize: 1 << 20}).Run(ctx); err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

