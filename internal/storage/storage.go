// Package storage defines repository interfaces and provides PostgreSQL implementations
// for persisting users, secrets and refresh tokens.
package storage

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/puzakov/gophkeeper-exam/internal/model"
)

// DBPool is the minimal pgx pool interface used by repositories.
// It is satisfied by *pgxpool.Pool in production and by pgxmock pools in tests.
type DBPool interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// UserRepository persists user accounts.
type UserRepository interface {
	Create(ctx context.Context, u *model.User) error
	GetByLogin(ctx context.Context, login string) (*model.User, error)
	GetByID(ctx context.Context, id uuid.UUID) (*model.User, error)
	UpdateKeyMaterial(ctx context.Context, id uuid.UUID, salt, wrappedDEK []byte, params string) error
}

// RefreshTokenRepository persists opaque refresh tokens.
type RefreshTokenRepository interface {
	Create(ctx context.Context, t *model.RefreshToken) error
	GetByHash(ctx context.Context, hash []byte) (*model.RefreshToken, error)
	Revoke(ctx context.Context, hash []byte) error
	RevokeAllForUser(ctx context.Context, userID uuid.UUID) error
}

// SecretRepository persists encrypted secrets.
type SecretRepository interface {
	Create(ctx context.Context, s *model.Secret) error
	Get(ctx context.Context, userID, secretID uuid.UUID) (*model.Secret, error)
	ListSummaries(ctx context.Context, userID uuid.UUID) ([]model.SecretSummary, error)
	UpdateIfVersion(ctx context.Context, userID, secretID uuid.UUID,
		expectedVersion int64, data, meta []byte, comment string) (int64, error)
	Delete(ctx context.Context, userID, secretID uuid.UUID) error
	ListForSync(ctx context.Context, userID uuid.UUID) ([]model.Secret, error)
}

// PostgresStorage aggregates all PostgreSQL-backed repositories.
type PostgresStorage struct {
	Users         UserRepository
	RefreshTokens RefreshTokenRepository
	Secrets       SecretRepository
}

// NewPostgresStorage creates repository implementations backed by the given pgx pool.
func NewPostgresStorage(pool *pgxpool.Pool) *PostgresStorage {
	return &PostgresStorage{
		Users:         &pgUserRepo{pool: pool},
		RefreshTokens: &pgTokenRepo{pool: pool},
		Secrets:       &pgSecretRepo{pool: pool},
	}
}
