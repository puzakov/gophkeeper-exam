// Package logger provides a global zap.Logger instance with lazy initialization.
// It defaults to a no-op logger until Initialize is called.
package logger

import (
	"go.uber.org/zap"
)

// Log is the global application logger. It defaults to a no-op logger
// until Initialize is called.
var Log *zap.Logger = zap.NewNop()

// Initialize configures the global Log with the given level (e.g. "info", "debug").
func Initialize(level string) error {
	lvl, err := zap.ParseAtomicLevel(level)
	if err != nil {
		return err
	}

	cfg := zap.NewProductionConfig()
	cfg.Level = lvl
	zl, err := cfg.Build()
	if err != nil {
		return err
	}

	Log = zl
	return nil
}
