package storage

import (
	"context"
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pashagolub/pgxmock/v4"

	"github.com/puzakov/gophkeeper-exam/internal/model"
)

// newTestPool creates a pgxmock pool bound to the DBPool interface.
func newTestPool(t *testing.T) pgxmock.PgxPoolIface {
	t.Helper()
	pool, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("pgxmock.NewPool() error = %v", err)
	}
	return pool
}

func expectQuery(mock pgxmock.PgxPoolIface, sql string) *pgxmock.ExpectedQuery {
	return mock.ExpectQuery(regexp.QuoteMeta(sql))
}

func expectExec(mock pgxmock.PgxPoolIface, sql string) *pgxmock.ExpectedExec {
	return mock.ExpectExec(regexp.QuoteMeta(sql))
}

// --- User repository ---

func TestPgUserRepo_Create(t *testing.T) {
	mock := newTestPool(t)
	repo := &pgUserRepo{pool: mock}

	user := &model.User{
		Login:        "alice",
		PasswordHash: "hash",
		KEKSalt:      []byte("salt"),
		WrappedDEK:   []byte("wrapped"),
		KEKParams:    `{"m":65536,"t":3,"p":4}`,
	}

	expectQuery(mock, `INSERT INTO users (login, password_hash, kek_salt, wrapped_dek, kek_params) VALUES ($1, $2, $3, $4, $5) RETURNING id, created_at`).
		WithArgs("alice", "hash", []byte("salt"), []byte("wrapped"), `{"m":65536,"t":3,"p":4}`).
		WillReturnRows(mock.NewRows([]string{"id", "created_at"}).
			AddRow(uuid.New(), time.Now()))

	if err := repo.Create(context.Background(), user); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if user.ID == uuid.Nil {
		t.Error("Create() did not set ID")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestPgUserRepo_Create_UniqueViolation(t *testing.T) {
	mock := newTestPool(t)
	repo := &pgUserRepo{pool: mock}

	expectQuery(mock, `INSERT INTO users (login, password_hash, kek_salt, wrapped_dek, kek_params) VALUES ($1, $2, $3, $4, $5) RETURNING id, created_at`).
		WithArgs("alice", "hash", pgxmock.AnyArg(), pgxmock.AnyArg(), "").
		WillReturnError(&pgconn.PgError{Code: "23505"})

	err := repo.Create(context.Background(), &model.User{Login: "alice", PasswordHash: "hash"})
	if !errors.Is(err, model.ErrConflict) {
		t.Errorf("Create() error = %v, want ErrConflict", err)
	}
}

func TestPgUserRepo_GetByLogin(t *testing.T) {
	mock := newTestPool(t)
	repo := &pgUserRepo{pool: mock}

	id := uuid.New()
	expectQuery(mock, `SELECT id, login, password_hash, kek_salt, wrapped_dek, kek_params, created_at FROM users WHERE login = $1`).
		WithArgs("alice").
		WillReturnRows(mock.NewRows([]string{"id", "login", "password_hash", "kek_salt", "wrapped_dek", "kek_params", "created_at"}).
			AddRow(id, "alice", "hash", []byte("salt"), []byte("wrapped"), "params", time.Now()))

	got, err := repo.GetByLogin(context.Background(), "alice")
	if err != nil {
		t.Fatalf("GetByLogin() error = %v", err)
	}
	if got.Login != "alice" || got.ID != id {
		t.Errorf("GetByLogin() = %+v", got)
	}
}

func TestPgUserRepo_GetByLogin_NotFound(t *testing.T) {
	mock := newTestPool(t)
	repo := &pgUserRepo{pool: mock}

	expectQuery(mock, `SELECT id, login, password_hash, kek_salt, wrapped_dek, kek_params, created_at FROM users WHERE login = $1`).
		WithArgs("ghost").
		WillReturnRows(mock.NewRows([]string{"id", "login", "password_hash", "kek_salt", "wrapped_dek", "kek_params", "created_at"}))

	_, err := repo.GetByLogin(context.Background(), "ghost")
	if !errors.Is(err, model.ErrNotFound) {
		t.Errorf("GetByLogin() error = %v, want ErrNotFound", err)
	}
}

func TestPgUserRepo_GetByID(t *testing.T) {
	mock := newTestPool(t)
	repo := &pgUserRepo{pool: mock}

	id := uuid.New()
	expectQuery(mock, `SELECT id, login, password_hash, kek_salt, wrapped_dek, kek_params, created_at FROM users WHERE id = $1`).
		WithArgs(id).
		WillReturnRows(mock.NewRows([]string{"id", "login", "password_hash", "kek_salt", "wrapped_dek", "kek_params", "created_at"}).
			AddRow(id, "alice", "hash", []byte("salt"), []byte("wrapped"), "params", time.Now()))

	got, err := repo.GetByID(context.Background(), id)
	if err != nil {
		t.Fatalf("GetByID() error = %v", err)
	}
	if got.ID != id {
		t.Errorf("GetByID() = %+v", got)
	}
}

func TestPgUserRepo_UpdateKeyMaterial(t *testing.T) {
	mock := newTestPool(t)
	repo := &pgUserRepo{pool: mock}

	id := uuid.New()
	expectExec(mock, `UPDATE users SET kek_salt = $2, wrapped_dek = $3, kek_params = $4 WHERE id = $1`).
		WithArgs(id, []byte("salt2"), []byte("dek2"), "params2").
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	if err := repo.UpdateKeyMaterial(context.Background(), id, []byte("salt2"), []byte("dek2"), "params2"); err != nil {
		t.Fatalf("UpdateKeyMaterial() error = %v", err)
	}
}

func TestPgUserRepo_UpdateKeyMaterial_NotFound(t *testing.T) {
	mock := newTestPool(t)
	repo := &pgUserRepo{pool: mock}

	expectExec(mock, `UPDATE users SET kek_salt = $2, wrapped_dek = $3, kek_params = $4 WHERE id = $1`).
		WithArgs(uuid.Nil, []byte("s"), []byte("d"), "p").
		WillReturnResult(pgxmock.NewResult("UPDATE", 0))

	err := repo.UpdateKeyMaterial(context.Background(), uuid.Nil, []byte("s"), []byte("d"), "p")
	if !errors.Is(err, model.ErrNotFound) {
		t.Errorf("UpdateKeyMaterial() error = %v, want ErrNotFound", err)
	}
}

// --- Refresh token repository ---

func TestPgTokenRepo_Create(t *testing.T) {
	mock := newTestPool(t)
	repo := &pgTokenRepo{pool: mock}

	token := &model.RefreshToken{
		UserID:    uuid.New(),
		TokenHash: []byte("hash"),
		ExpiresAt: time.Now().Add(time.Hour),
	}

	expectQuery(mock, `INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3) RETURNING id, created_at`).
		WithArgs(token.UserID, token.TokenHash, token.ExpiresAt).
		WillReturnRows(mock.NewRows([]string{"id", "created_at"}).
			AddRow(uuid.New(), time.Now()))

	if err := repo.Create(context.Background(), token); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
}

func TestPgTokenRepo_GetByHash(t *testing.T) {
	mock := newTestPool(t)
	repo := &pgTokenRepo{pool: mock}

	id, userID := uuid.New(), uuid.New()
	expectQuery(mock, `SELECT id, user_id, token_hash, expires_at, revoked_at, created_at FROM refresh_tokens WHERE token_hash = $1`).
		WithArgs([]byte("hash")).
		WillReturnRows(mock.NewRows([]string{"id", "user_id", "token_hash", "expires_at", "revoked_at", "created_at"}).
			AddRow(id, userID, []byte("hash"), time.Now().Add(time.Hour), nil, time.Now()))

	got, err := repo.GetByHash(context.Background(), []byte("hash"))
	if err != nil {
		t.Fatalf("GetByHash() error = %v", err)
	}
	if got.ID != id || got.UserID != userID {
		t.Errorf("GetByHash() = %+v", got)
	}
}

func TestPgTokenRepo_GetByHash_NotFound(t *testing.T) {
	mock := newTestPool(t)
	repo := &pgTokenRepo{pool: mock}

	expectQuery(mock, `SELECT id, user_id, token_hash, expires_at, revoked_at, created_at FROM refresh_tokens WHERE token_hash = $1`).
		WithArgs([]byte("ghost")).
		WillReturnRows(mock.NewRows([]string{"id", "user_id", "token_hash", "expires_at", "revoked_at", "created_at"}))

	_, err := repo.GetByHash(context.Background(), []byte("ghost"))
	if !errors.Is(err, model.ErrNotFound) {
		t.Errorf("GetByHash() error = %v, want ErrNotFound", err)
	}
}

func TestPgTokenRepo_Revoke(t *testing.T) {
	mock := newTestPool(t)
	repo := &pgTokenRepo{pool: mock}

	expectExec(mock, `UPDATE refresh_tokens SET revoked_at = $2 WHERE token_hash = $1`).
		WithArgs([]byte("hash"), pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	if err := repo.Revoke(context.Background(), []byte("hash")); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
}

func TestPgTokenRepo_Revoke_NotFound(t *testing.T) {
	mock := newTestPool(t)
	repo := &pgTokenRepo{pool: mock}

	expectExec(mock, `UPDATE refresh_tokens SET revoked_at = $2 WHERE token_hash = $1`).
		WithArgs([]byte("ghost"), pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("UPDATE", 0))

	err := repo.Revoke(context.Background(), []byte("ghost"))
	if !errors.Is(err, model.ErrNotFound) {
		t.Errorf("Revoke() error = %v, want ErrNotFound", err)
	}
}

func TestPgTokenRepo_RevokeAllForUser(t *testing.T) {
	mock := newTestPool(t)
	repo := &pgTokenRepo{pool: mock}

	expectExec(mock, `UPDATE refresh_tokens SET revoked_at = $2 WHERE user_id = $1 AND revoked_at IS NULL`).
		WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("UPDATE", 3))

	if err := repo.RevokeAllForUser(context.Background(), uuid.New()); err != nil {
		t.Fatalf("RevokeAllForUser() error = %v", err)
	}
}

// --- Secret repository ---

func TestPgSecretRepo_Create(t *testing.T) {
	mock := newTestPool(t)
	repo := &pgSecretRepo{pool: mock}

	secret := &model.Secret{
		UserID:            uuid.New(),
		Type:              model.SecretTypeLoginPassword,
		EncryptedData:     []byte("data"),
		EncryptedMetadata: []byte("meta"),
		Comment:           "label",
	}

	expectQuery(mock, `INSERT INTO secrets (user_id, type, encrypted_data, encrypted_metadata, comment) VALUES ($1, $2, $3, $4, $5) RETURNING id, version, created_at, updated_at`).
		WithArgs(secret.UserID, model.SecretTypeLoginPassword, []byte("data"), []byte("meta"), "label").
		WillReturnRows(mock.NewRows([]string{"id", "version", "created_at", "updated_at"}).
			AddRow(uuid.New(), int64(1), time.Now(), time.Now()))

	if err := repo.Create(context.Background(), secret); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if secret.Version != 1 {
		t.Errorf("Create() version = %d, want 1", secret.Version)
	}
}

func TestPgSecretRepo_Get(t *testing.T) {
	mock := newTestPool(t)
	repo := &pgSecretRepo{pool: mock}

	userID, secretID := uuid.New(), uuid.New()
	expectQuery(mock, `SELECT id, user_id, type, encrypted_data, encrypted_metadata, comment, version, created_at, updated_at, deleted_at FROM secrets WHERE id = $1 AND user_id = $2 AND deleted_at IS NULL`).
		WithArgs(secretID, userID).
		WillReturnRows(mock.NewRows([]string{"id", "user_id", "type", "encrypted_data", "encrypted_metadata", "comment", "version", "created_at", "updated_at", "deleted_at"}).
			AddRow(secretID, userID, int16(2), []byte("data"), []byte("meta"), "text", int64(3), time.Now(), time.Now(), nil))

	got, err := repo.Get(context.Background(), userID, secretID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got.Type != model.SecretTypeText || got.Version != 3 {
		t.Errorf("Get() = %+v", got)
	}
}

func TestPgSecretRepo_Get_NotFound(t *testing.T) {
	mock := newTestPool(t)
	repo := &pgSecretRepo{pool: mock}

	userID, secretID := uuid.New(), uuid.New()
	expectQuery(mock, `SELECT id, user_id, type, encrypted_data, encrypted_metadata, comment, version, created_at, updated_at, deleted_at FROM secrets WHERE id = $1 AND user_id = $2 AND deleted_at IS NULL`).
		WithArgs(secretID, userID).
		WillReturnRows(mock.NewRows([]string{"id", "user_id", "type", "encrypted_data", "encrypted_metadata", "comment", "version", "created_at", "updated_at", "deleted_at"}))

	_, err := repo.Get(context.Background(), userID, secretID)
	if !errors.Is(err, model.ErrNotFound) {
		t.Errorf("Get() error = %v, want ErrNotFound", err)
	}
}

func TestPgSecretRepo_ListSummaries(t *testing.T) {
	mock := newTestPool(t)
	repo := &pgSecretRepo{pool: mock}

	userID := uuid.New()
	expectQuery(mock, `SELECT id, type, comment, version, updated_at FROM secrets WHERE user_id = $1 AND deleted_at IS NULL ORDER BY updated_at DESC`).
		WithArgs(userID).
		WillReturnRows(mock.NewRows([]string{"id", "type", "comment", "version", "updated_at"}).
			AddRow(uuid.New(), int16(1), "first", int64(1), time.Now()).
			AddRow(uuid.New(), int16(4), "card", int64(2), time.Now()))

	got, err := repo.ListSummaries(context.Background(), userID)
	if err != nil {
		t.Fatalf("ListSummaries() error = %v", err)
	}
	if len(got) != 2 {
		t.Errorf("ListSummaries() len = %d, want 2", len(got))
	}
	if got[0].Type != model.SecretTypeLoginPassword || got[1].Type != model.SecretTypeBankCard {
		t.Errorf("ListSummaries() order/types wrong: %+v", got)
	}
}

func TestPgSecretRepo_UpdateIfVersion_Success(t *testing.T) {
	mock := newTestPool(t)
	repo := &pgSecretRepo{pool: mock}

	userID, secretID := uuid.New(), uuid.New()
	expectQuery(mock, `UPDATE secrets SET encrypted_data = $3, encrypted_metadata = $4, comment = $5, version = version + 1, updated_at = NOW() WHERE id = $2 AND user_id = $1 AND version = $6 AND deleted_at IS NULL RETURNING version`).
		WithArgs(userID, secretID, []byte("newdata"), []byte("newmeta"), "newcomment", int64(2)).
		WillReturnRows(mock.NewRows([]string{"version"}).AddRow(int64(3)))

	got, err := repo.UpdateIfVersion(context.Background(), userID, secretID, 2, []byte("newdata"), []byte("newmeta"), "newcomment")
	if err != nil {
		t.Fatalf("UpdateIfVersion() error = %v", err)
	}
	if got != 3 {
		t.Errorf("UpdateIfVersion() = %d, want 3", got)
	}
}

func TestPgSecretRepo_UpdateIfVersion_Conflict(t *testing.T) {
	mock := newTestPool(t)
	repo := &pgSecretRepo{pool: mock}

	userID, secretID := uuid.New(), uuid.New()

	// Update matches no rows (version mismatch)…
	expectQuery(mock, `UPDATE secrets SET encrypted_data = $3, encrypted_metadata = $4, comment = $5, version = version + 1, updated_at = NOW() WHERE id = $2 AND user_id = $1 AND version = $6 AND deleted_at IS NULL RETURNING version`).
		WithArgs(userID, secretID, []byte("d"), []byte("m"), "c", int64(5)).
		WillReturnRows(mock.NewRows([]string{"version"}))

	// …but the row exists (exists check returns true).
	expectQuery(mock, `SELECT EXISTS(SELECT 1 FROM secrets WHERE id = $1 AND user_id = $2)`).
		WithArgs(secretID, userID).
		WillReturnRows(mock.NewRows([]string{"exists"}).AddRow(true))

	_, err := repo.UpdateIfVersion(context.Background(), userID, secretID, 5, []byte("d"), []byte("m"), "c")
	if !errors.Is(err, model.ErrConflict) {
		t.Errorf("UpdateIfVersion() error = %v, want ErrConflict", err)
	}
}

func TestPgSecretRepo_UpdateIfVersion_NotFound(t *testing.T) {
	mock := newTestPool(t)
	repo := &pgSecretRepo{pool: mock}

	userID, secretID := uuid.New(), uuid.New()

	expectQuery(mock, `UPDATE secrets SET encrypted_data = $3, encrypted_metadata = $4, comment = $5, version = version + 1, updated_at = NOW() WHERE id = $2 AND user_id = $1 AND version = $6 AND deleted_at IS NULL RETURNING version`).
		WithArgs(userID, secretID, []byte("d"), []byte("m"), "c", int64(1)).
		WillReturnRows(mock.NewRows([]string{"version"}))

	expectQuery(mock, `SELECT EXISTS(SELECT 1 FROM secrets WHERE id = $1 AND user_id = $2)`).
		WithArgs(secretID, userID).
		WillReturnRows(mock.NewRows([]string{"exists"}).AddRow(false))

	_, err := repo.UpdateIfVersion(context.Background(), userID, secretID, 1, []byte("d"), []byte("m"), "c")
	if !errors.Is(err, model.ErrNotFound) {
		t.Errorf("UpdateIfVersion() error = %v, want ErrNotFound", err)
	}
}

func TestPgSecretRepo_Delete(t *testing.T) {
	mock := newTestPool(t)
	repo := &pgSecretRepo{pool: mock}

	userID, secretID := uuid.New(), uuid.New()
	expectExec(mock, `UPDATE secrets SET deleted_at = NOW(), version = version + 1, updated_at = NOW() WHERE id = $2 AND user_id = $1 AND deleted_at IS NULL`).
		WithArgs(userID, secretID).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	if err := repo.Delete(context.Background(), userID, secretID); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
}

func TestPgSecretRepo_Delete_NotFound(t *testing.T) {
	mock := newTestPool(t)
	repo := &pgSecretRepo{pool: mock}

	userID, secretID := uuid.New(), uuid.New()
	expectExec(mock, `UPDATE secrets SET deleted_at = NOW(), version = version + 1, updated_at = NOW() WHERE id = $2 AND user_id = $1 AND deleted_at IS NULL`).
		WithArgs(userID, secretID).
		WillReturnResult(pgxmock.NewResult("UPDATE", 0))

	err := repo.Delete(context.Background(), userID, secretID)
	if !errors.Is(err, model.ErrNotFound) {
		t.Errorf("Delete() error = %v, want ErrNotFound", err)
	}
}

func TestPgSecretRepo_ListForSync(t *testing.T) {
	mock := newTestPool(t)
	repo := &pgSecretRepo{pool: mock}

	userID := uuid.New()
	deletedAt := time.Now()
	expectQuery(mock, `SELECT id, user_id, type, encrypted_data, encrypted_metadata, comment, version, created_at, updated_at, deleted_at FROM secrets WHERE user_id = $1 ORDER BY updated_at DESC`).
		WithArgs(userID).
		WillReturnRows(mock.NewRows([]string{"id", "user_id", "type", "encrypted_data", "encrypted_metadata", "comment", "version", "created_at", "updated_at", "deleted_at"}).
			AddRow(uuid.New(), userID, int16(1), []byte("d"), []byte("m"), "live", int64(2), time.Now(), time.Now(), nil).
			AddRow(uuid.New(), userID, int16(2), []byte("d"), []byte("m"), "deleted", int64(3), time.Now(), time.Now(), &deletedAt))

	got, err := repo.ListForSync(context.Background(), userID)
	if err != nil {
		t.Fatalf("ListForSync() error = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("ListForSync() len = %d, want 2", len(got))
	}
	// Tombstone row must be included with DeletedAt set.
	if got[0].DeletedAt != nil {
		t.Error("ListForSync() first row should be live")
	}
	if got[1].DeletedAt == nil || got[1].Comment != "deleted" {
		t.Error("ListForSync() second row should be a tombstone")
	}
}
