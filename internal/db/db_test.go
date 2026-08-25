package db

import (
	"testing"
)

func TestNewDatabaseConnection_EmptyDSN(t *testing.T) {
	_, err := NewDatabaseConnection(t.Context(), "")
	if err == nil {
		t.Error("expected error for empty connection string")
	}
}

func TestDatabaseConnection_Ping_NilPool(t *testing.T) {
	conn := &DatabaseConnection{}
	err := conn.Ping(t.Context())
	if err == nil {
		t.Error("expected error for nil pool")
	}
}

func TestDatabaseConnection_Close_NilSafe(t *testing.T) {
	// Must not panic.
	var conn *DatabaseConnection
	conn.Close()

	conn = &DatabaseConnection{}
	conn.Close()
}

func TestNewDatabaseConnection_InvalidDSN(t *testing.T) {
	_, err := NewDatabaseConnection(t.Context(), "not-a-valid-dsn")
	if err == nil {
		t.Error("expected error for invalid DSN")
	}
}

func TestNewDatabaseConnection_Unreachable(t *testing.T) {
	// Valid format, but nothing listens on the port — ping must fail.
	_, err := NewDatabaseConnection(t.Context(), "postgres://u:p@127.0.0.1:1/db?connect_timeout=1")
	if err == nil {
		t.Error("expected error for unreachable database")
	}
}
