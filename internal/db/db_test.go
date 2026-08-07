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
