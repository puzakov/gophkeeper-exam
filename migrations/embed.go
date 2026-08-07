// Package migrations handles database schema migrations using goose
// with embedded SQL migration files.
package migrations

import (
	"database/sql"
	"embed"

	"github.com/pressly/goose/v3"
)

// FS contains all SQL migration files.
//
//go:embed *.sql
var FS embed.FS

// Up applies all pending SQL migrations using goose.
func Up(db *sql.DB) error {
	goose.SetBaseFS(FS)
	if err := goose.SetDialect("postgres"); err != nil {
		return err
	}
	return goose.Up(db, ".")
}
