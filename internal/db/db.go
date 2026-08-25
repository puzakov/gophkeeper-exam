// Package db provides PostgreSQL connection management using pgx/v5.
package db

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DatabaseConnection wraps a pgx connection pool.
type DatabaseConnection struct {
	// Pool is the underlying pgx connection pool.
	Pool *pgxpool.Pool
}

// NewDatabaseConnection creates a new PostgreSQL connection pool and pings it.
func NewDatabaseConnection(ctx context.Context, connString string) (*DatabaseConnection, error) {
	if connString == "" {
		return nil, errors.New("empty connection string")
	}

	pool, err := pgxpool.New(ctx, connString)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}

	return &DatabaseConnection{Pool: pool}, nil
}

// Ping checks that the database connection pool is usable.
// Returns an error if the pool is nil or the ping fails.
func (c *DatabaseConnection) Ping(ctx context.Context) error {
	if c == nil || c.Pool == nil {
		return errors.New("database pool is nil")
	}
	return c.Pool.Ping(ctx)
}

// Close shuts down the connection pool. Safe to call on a nil receiver.
func (c *DatabaseConnection) Close() {
	if c == nil || c.Pool == nil {
		return
	}
	c.Pool.Close()
}
