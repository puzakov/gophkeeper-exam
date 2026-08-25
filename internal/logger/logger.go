// Package logger provides zap.Logger construction helpers.
//
// The logger is created in main and passed to components explicitly;
// child loggers with component-scoped fields are derived via zap.Logger.With.
package logger

import (
	"go.uber.org/zap"
)

// New builds a production zap.Logger with the given level
// (e.g. "info", "debug"). The returned logger must be closed by the caller
// via Sync to flush buffered output.
func New(level string) (*zap.Logger, error) {
	lvl, err := zap.ParseAtomicLevel(level)
	if err != nil {
		return nil, err
	}

	cfg := zap.NewProductionConfig()
	cfg.Level = lvl
	return cfg.Build()
}
