package storage

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/puzakov/gophkeeper-exam/internal/model"
)

type pgSecretRepo struct {
	pool DBPool
}

func (r *pgSecretRepo) Create(ctx context.Context, s *model.Secret) error {
	const query = `
		INSERT INTO secrets (user_id, type, encrypted_data, encrypted_metadata, comment)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, version, created_at, updated_at`

	return r.pool.QueryRow(ctx, query,
		s.UserID, s.Type, s.EncryptedData, s.EncryptedMetadata, s.Comment,
	).Scan(&s.ID, &s.Version, &s.CreatedAt, &s.UpdatedAt)
}

func (r *pgSecretRepo) Get(ctx context.Context, userID, secretID uuid.UUID) (*model.Secret, error) {
	const query = `
		SELECT id, user_id, type, encrypted_data, encrypted_metadata, comment,
		       version, created_at, updated_at, deleted_at
		FROM secrets
		WHERE id = $1 AND user_id = $2 AND deleted_at IS NULL`

	s := &model.Secret{}
	err := r.pool.QueryRow(ctx, query, secretID, userID).Scan(
		&s.ID, &s.UserID, &s.Type,
		&s.EncryptedData, &s.EncryptedMetadata, &s.Comment,
		&s.Version, &s.CreatedAt, &s.UpdatedAt, &s.DeletedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, model.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (r *pgSecretRepo) ListSummaries(ctx context.Context, userID uuid.UUID) ([]model.SecretSummary, error) {
	const query = `
		SELECT id, type, comment, version, updated_at
		FROM secrets
		WHERE user_id = $1 AND deleted_at IS NULL
		ORDER BY updated_at DESC`

	rows, err := r.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []model.SecretSummary
	for rows.Next() {
		var s model.SecretSummary
		if err := rows.Scan(&s.ID, &s.Type, &s.Comment, &s.Version, &s.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (r *pgSecretRepo) UpdateIfVersion(ctx context.Context, userID, secretID uuid.UUID,
	expectedVersion int64, data, meta []byte, comment string) (int64, error) {

	const query = `
		UPDATE secrets
		SET encrypted_data = $3, encrypted_metadata = $4, comment = $5,
		    version = version + 1, updated_at = NOW()
		WHERE id = $2 AND user_id = $1 AND version = $6 AND deleted_at IS NULL
		RETURNING version`

	var newVersion int64
	err := r.pool.QueryRow(ctx, query,
		userID, secretID, data, meta, comment, expectedVersion,
	).Scan(&newVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		// Distinguish: row doesn't exist at all vs version mismatch.
		existing, checkErr := r.exists(ctx, userID, secretID)
		if checkErr != nil {
			return 0, checkErr
		}
		if !existing {
			return 0, model.ErrNotFound
		}
		return 0, model.ErrConflict
	}
	if err != nil {
		return 0, err
	}
	return newVersion, nil
}

func (r *pgSecretRepo) Delete(ctx context.Context, userID, secretID uuid.UUID) error {
	const query = `
		UPDATE secrets
		SET deleted_at = NOW(), version = version + 1, updated_at = NOW()
		WHERE id = $2 AND user_id = $1 AND deleted_at IS NULL`

	tag, err := r.pool.Exec(ctx, query, userID, secretID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return model.ErrNotFound
	}
	return nil
}

func (r *pgSecretRepo) ListForSync(ctx context.Context, userID uuid.UUID) ([]model.Secret, error) {
	const query = `
		SELECT id, user_id, type, encrypted_data, encrypted_metadata, comment,
		       version, created_at, updated_at, deleted_at
		FROM secrets WHERE user_id = $1
		ORDER BY updated_at DESC`

	rows, err := r.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []model.Secret
	for rows.Next() {
		var s model.Secret
		if err := rows.Scan(
			&s.ID, &s.UserID, &s.Type,
			&s.EncryptedData, &s.EncryptedMetadata, &s.Comment,
			&s.Version, &s.CreatedAt, &s.UpdatedAt, &s.DeletedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// exists checks whether a secret row exists (regardless of tombstone).
func (r *pgSecretRepo) exists(ctx context.Context, userID, secretID uuid.UUID) (bool, error) {
	const query = `SELECT EXISTS(SELECT 1 FROM secrets WHERE id = $1 AND user_id = $2)`
	var ok bool
	err := r.pool.QueryRow(ctx, query, secretID, userID).Scan(&ok)
	return ok, err
}

// Compile-time interface check.
var _ SecretRepository = (*pgSecretRepo)(nil)

// Helper for tests: now returns current time; overridden via pgxmock expectations.
func now() time.Time { return time.Now() }
