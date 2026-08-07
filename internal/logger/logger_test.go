package logger

import (
	"testing"

	"go.uber.org/zap"
)

func TestInitialize(t *testing.T) {
	tests := []struct {
		name    string
		level   string
		wantErr bool
	}{
		{"info", "info", false},
		{"debug", "debug", false},
		{"error", "error", false},
		{"invalid", "invalid", true},
		{"empty", "", false}, // empty defaults to "info"
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Initialize(tt.level)
			if (err != nil) != tt.wantErr {
				t.Errorf("Initialize(%q) error = %v, wantErr = %v", tt.level, err, tt.wantErr)
			}
			if err == nil {
				if Log == nil {
					t.Error("Log is nil after successful Initialize")
				}
				// Verify logger works.
				Log.Info("test message")
			}
		})
	}
}

func TestLogNop(t *testing.T) {
	// Fresh default should not panic.
	old := Log
	Log = zap.NewNop()
	defer func() { Log = old }()

	Log.Info("should not panic")
	Log.Error("should not panic either")
}
