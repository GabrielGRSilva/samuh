package util

import (
	"path/filepath"
	"strings"
)

// SanitizeSnippet strips non-printable control characters and truncates to maxLen.
func SanitizeSnippet(code string, maxLen int) string {
	cleaned := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return r
		}
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, code)

	return TruncateString(cleaned, maxLen)
}

// SanitizeFilePath cleans a file path for display.
func SanitizeFilePath(path string) string {
	return filepath.Clean(path)
}

// TruncateString truncates s to maxLen bytes, adding "..." when there is room.
func TruncateString(s string, maxLen int) string {
	if maxLen <= 0 {
		return ""
	}
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}
