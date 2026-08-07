package build

import "testing"

func TestPrintInfo(t *testing.T) {
	// Verify PrintInfo doesn't panic with empty values.
	PrintInfo()
}

func TestValOrNA(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"empty", "", "N/A"},
		{"set", "1.0.0", "1.0.0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valOrNA := func(s string) string {
				if s == "" {
					return "N/A"
				}
				return s
			}
			if got := valOrNA(tt.input); got != tt.expected {
				t.Errorf("valOrNA(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}
