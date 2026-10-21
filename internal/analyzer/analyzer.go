/*
Package analyzer defines the interface for language-specific security analyzers
and provides a registry for discovering and managing them.
*/
package analyzer

import (
	"context"

	"samuh/internal/rules"
)

// FileContext provides all necessary information about a file to be analyzed.
type FileContext struct {
	Path         string // absolute
	RelativePath string // relative to the project root
	Content      []byte
	Lines        []string
	Language     string
	Size         int64 // bytes
}

// Analyzer detects vulnerabilities in files of its supported language(s).
type Analyzer interface {
	Name() string
	Extensions() []string
	Analyze(ctx context.Context, file FileContext) ([]rules.Finding, error)
	AnalyzeProject(ctx context.Context, projectRoot string) ([]rules.Finding, error)
}
