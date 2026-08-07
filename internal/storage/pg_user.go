package storage

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/puzakov/gophkeeper-exam/internal/model"
)

type pgUserRepo struct {
	pool *pgxpool.Pool
}

func (r *pgUserRepo) Create(ctx context.Context, u *model.User) error {
	const query = `
		INSERT INTO users (login, password_hash, kek_salt, wrapped_dek, kek_params)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, created_at`

	err := r.pool.QueryRow(ctx, query,
		u.Login,
		u.PasswordHash,
		u.KEKSalt,
		u.WrappedDEK,
		u.KEKParams,
	).Scan(&u.ID, &u.CreatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return model.ErrConflict
		}
		return err
	}
	return nil
}

func (r *pgUserRepo) GetByLogin(ctx context.Context, login string) (*model.User, error) {
	const query = `
		SELECT id, login, password_hash, kek_salt, wrapped_dek, kek_params, created_at
		FROM users WHERE login = $1`

	u := &model.User{}
	err := r.pool.QueryRow(ctx, query, login).Scan(
		&u.ID, &u.Login, &u.PasswordHash,
		&u.KEKSalt, &u.WrappedDEK, &u.KEKParams, &u.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, model.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (r *pgUserRepo) GetByID(ctx context.Context, id uuid.UUID) (*model.User, error) {
	const query = `
		SELECT id, login, password_hash, kek_salt, wrapped_dek, kek_params, created_at
		FROM users WHERE id = $1`

	u := &model.User{}
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&u.ID, &u.Login, &u.PasswordHash,
		&u.KEKSalt, &u.WrappedDEK, &u.KEKParams, &u.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, model.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (r *pgUserRepo) UpdateKeyMaterial(ctx context.Context, id uuid.UUID, salt, wrappedDEK []byte, params string) error {
	const query = `
		UPDATE users SET kek_salt = $2, wrapped_dek = $3, kek_params = $4
		WHERE id = $1`

	tag, err := r.pool.Exec(ctx, query, id, salt, wrappedDEK, params)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return model.ErrNotFound
	}
	return nil
}

// isUniqueViolation checks if the error is a PostgreSQL unique constraint violation.
func isUniqueViolation(err error) bool {
	var pgErr interface{ SQLState() string }
	if errors.As(err, &pgErr) {
		return pgErr.SQLState() == "23505"
	}
	return false
}
