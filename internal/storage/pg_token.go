package storage

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/puzakov/gophkeeper-exam/internal/model"
)

type pgTokenRepo struct {
	pool *pgxpool.Pool
}

func (r *pgTokenRepo) Create(ctx context.Context, t *model.RefreshToken) error {
	const query = `
		INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
		VALUES ($1, $2, $3)
		RETURNING id, created_at`

	return r.pool.QueryRow(ctx, query,
		t.UserID, t.TokenHash, t.ExpiresAt,
	).Scan(&t.ID, &t.CreatedAt)
}

func (r *pgTokenRepo) GetByHash(ctx context.Context, hash []byte) (*model.RefreshToken, error) {
	const query = `
		SELECT id, user_id, token_hash, expires_at, revoked_at, created_at
		FROM refresh_tokens WHERE token_hash = $1`

	t := &model.RefreshToken{}
	err := r.pool.QueryRow(ctx, query, hash).Scan(
		&t.ID, &t.UserID, &t.TokenHash, &t.ExpiresAt, &t.RevokedAt, &t.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, model.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return t, nil
}

func (r *pgTokenRepo) Revoke(ctx context.Context, hash []byte) error {
	const query = `UPDATE refresh_tokens SET revoked_at = $2 WHERE token_hash = $1`

	now := time.Now()
	tag, err := r.pool.Exec(ctx, query, hash, now)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return model.ErrNotFound
	}
	return nil
}

func (r *pgTokenRepo) RevokeAllForUser(ctx context.Context, userID uuid.UUID) error {
	const query = `UPDATE refresh_tokens SET revoked_at = $2 WHERE user_id = $1 AND revoked_at IS NULL`

	_, err := r.pool.Exec(ctx, query, userID, time.Now())
	return err
}
