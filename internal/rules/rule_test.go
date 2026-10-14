package rules_test

import (
	"samuh/internal/rules"
	"testing"
)

func TestSeverity_IsAtLeast(t *testing.T) {
	tests := []struct {
		name     string
		severity rules.Severity
		other    rules.Severity
		expected bool
	}{
		{"Critical is at least critical", rules.SeverityCritical, rules.SeverityCritical, true},
		{"Critical is at least high", rules.SeverityCritical, rules.SeverityHigh, true},
		{"Critical is at least medium", rules.SeverityCritical, rules.SeverityMedium, true},
		{"Critical is at least low", rules.SeverityCritical, rules.SeverityLow, true},
		{"Critical is at least info", rules.SeverityCritical, rules.SeverityInfo, true},
		{"High is at least critical", rules.SeverityHigh, rules.SeverityCritical, false},
		{"High is at least high", rules.SeverityHigh, rules.SeverityHigh, true},
		{"High is at least medium", rules.SeverityHigh, rules.SeverityMedium, true},
		{"High is at least low", rules.SeverityHigh, rules.SeverityLow, true},
		{"High is at least info", rules.SeverityHigh, rules.SeverityInfo, true},
		{"Medium is at least critical", rules.SeverityMedium, rules.SeverityCritical, false},
		{"Medium is at least high", rules.SeverityMedium, rules.SeverityHigh, false},
		{"Medium is at least medium", rules.SeverityMedium, rules.SeverityMedium, true},
		{"Medium is at least low", rules.SeverityMedium, rules.SeverityLow, true},
		{"Medium is at least info", rules.SeverityMedium, rules.SeverityInfo, true},
		{"Low is at least critical", rules.SeverityLow, rules.SeverityCritical, false},
		{"Low is at least high", rules.SeverityLow, rules.SeverityHigh, false},
		{"Low is at least medium", rules.SeverityLow, rules.SeverityMedium, false},
		{"Low is at least low", rules.SeverityLow, rules.SeverityLow, true},
		{"Low is at least info", rules.SeverityLow, rules.SeverityInfo, true},
		{"Critical is at least info", rules.SeverityCritical, rules.SeverityInfo, true},
		{"Info is at least critical", rules.SeverityInfo, rules.SeverityCritical, false},
		{"Info is at least high", rules.SeverityInfo, rules.SeverityHigh, false},
		{"Info is at least medium", rules.SeverityInfo, rules.SeverityMedium, false},
		{"Bad input", rules.Severity("TESTBADINPUT"), rules.SeverityLow, false},
		{"Info with casting", rules.Severity("INFO"), rules.Severity("INFO"), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.severity.IsAtLeast(tt.other)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestSeverity_Rank(t *testing.T) {
	tests := []struct {
		name     string
		severity rules.Severity
		expected int
	}{
		{"Critical", rules.SeverityCritical, 5},
		{"High", rules.SeverityHigh, 4},
		{"Medium", rules.SeverityMedium, 3},
		{"Low", rules.SeverityLow, 2},
		{"Info", rules.SeverityInfo, 1},
		{"Bad input", rules.Severity("TESTBADINPUT"), 0},
		{"Info with casting", rules.Severity("INFO"), 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.severity.Rank()
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}
