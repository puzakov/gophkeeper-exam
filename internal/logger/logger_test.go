package logger

import (
	"testing"

	"go.uber.org/zap"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		level   string
		wantErr bool
	}{
		{"info", "info", false},
		{"debug", "debug", false},
		{"error", "error", false},
		{"empty defaults to info", "", false},
		{"invalid", "invalid", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log, err := New(tt.level)
			if (err != nil) != tt.wantErr {
				t.Fatalf("New(%q) error = %v, wantErr = %v", tt.level, err, tt.wantErr)
			}
			if err == nil {
				defer func() { _ = log.Sync() }()
				if log == nil {
					t.Fatal("log is nil after successful New")
				}
				// Verify the logger works.
				log.Info("test message")
			}
		})
	}
}

func TestNew_ChildLoggerWith(t *testing.T) {
	root, err := New("info")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Sync() }()

	child := root.With(zap.String("component", "test-component"))
	if child == nil {
		t.Fatal("child logger is nil")
	}
	child.Info("component-scoped message")
}
