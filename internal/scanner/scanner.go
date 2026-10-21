package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"samuh/internal/analyzer"
	"samuh/internal/util"
)

// Scanner handles file discovery and content extraction.
type Scanner struct {
	basePath    string
	excludes    []string
	maxFileSize int64
}

// New creates a new Scanner.
func New(basePath string, excludes []string, maxFileSize int64) *Scanner {
	return &Scanner{
		basePath:    basePath,
		excludes:    excludes,
		maxFileSize: maxFileSize,
	}
}

// DiscoverFiles walks the directory tree and returns files to be analyzed.
func (s *Scanner) DiscoverFiles(ctx context.Context) ([]*analyzer.FileContext, error) {
	var files []*analyzer.FileContext

	absBasePath, err := filepath.Abs(s.basePath)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path: %w", err)
	}

	err = filepath.Walk(absBasePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip paths with errors
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Skip hidden directories and dependency folders.
		if info.IsDir() {
			name := info.Name()
			if strings.HasPrefix(name, ".") && name != "." && name != ".." {
				return filepath.SkipDir
			}
			if name == "node_modules" || name == "vendor" || name == "bower_components" {
				return filepath.SkipDir
			}
			return nil
		}

		if info.Size() > s.maxFileSize {
			return nil
		}

		relPath, _ := filepath.Rel(absBasePath, path)
		for _, pattern := range s.excludes {
			if matched, _ := filepath.Match(pattern, relPath); matched {
				return nil
			}
			if matched, _ := filepath.Match(pattern, info.Name()); matched {
				return nil
			}
		}

		// Resolve symlinks so a malicious project cannot make us read files outside its root.
		realPath, evalErr := filepath.EvalSymlinks(path)
		if evalErr != nil {
			return nil
		}
		realBase, _ := filepath.EvalSymlinks(absBasePath)
		if realBase == "" {
			realBase = absBasePath
		}
		if !strings.HasPrefix(filepath.Clean(realPath), filepath.Clean(realBase)+string(filepath.Separator)) &&
			filepath.Clean(realPath) != filepath.Clean(realBase) {
			return nil
		}

		fullContent, readErr2 := os.ReadFile(path)
		if readErr2 != nil {
			return nil
		}

		checkLen := len(fullContent)
		if checkLen > 512 {
			checkLen = 512
		}
		if util.IsBinaryFile(fullContent[:checkLen]) {
			return nil
		}

		lines, err := util.ReadFileLines(path, s.maxFileSize)
		if err != nil {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		language := detectLanguage(ext)

		files = append(files, &analyzer.FileContext{
			Path:         path,
			RelativePath: relPath,
			Content:      fullContent,
			Lines:        lines,
			Language:     language,
			Size:         info.Size(),
		})

		return nil
	})

	if err != nil {
		return nil, err
	}

	return files, nil
}

// detectLanguage maps a file extension to a language name.
func detectLanguage(ext string) string {
	switch ext {
	case ".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".phps":
		return "PHP"
	case ".js", ".mjs", ".cjs":
		return "JavaScript"
	case ".ts", ".tsx":
		return "TypeScript"
	case ".jsx":
		return "JavaScript/React"
	case ".vue":
		return "Vue"
	case ".svelte":
		return "Svelte"
	default:
		return ""
	}
}
