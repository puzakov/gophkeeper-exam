package client

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"

	"github.com/puzakov/gophkeeper-exam/internal/model"
)

// LocalStore is the client-side SQLite cache. It holds server-encrypted
// secrets (the client decrypts them with the in-memory DEK) and the wrapped
// key material needed for offline unlock.
type LocalStore struct {
	db *sql.DB
}

// KeyMaterial is the locally persisted material needed to re-derive the DEK
// from the master password without contacting the server.
type KeyMaterial struct {
	Login      string
	KEKSalt    []byte
	WrappedDEK []byte
	KEKParams  string
}

// OpenLocalStore opens (or creates) the local SQLite cache at the given path.
func OpenLocalStore(path string) (*LocalStore, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS secrets (
		id                 TEXT PRIMARY KEY,
		user_id            TEXT NOT NULL DEFAULT '',
		type               INTEGER NOT NULL,
		encrypted_data     BLOB NOT NULL,
		encrypted_metadata BLOB NOT NULL DEFAULT x'',
		comment            TEXT NOT NULL DEFAULT '',
		version            INTEGER NOT NULL,
		created_at         INTEGER NOT NULL DEFAULT 0,
		updated_at         INTEGER NOT NULL DEFAULT 0,
		deleted_at         INTEGER
	)`); err != nil {
		db.Close()
		return nil, fmt.Errorf("create secrets table: %w", err)
	}

	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS key_material (
		id          INTEGER PRIMARY KEY CHECK (id = 1),
		login       TEXT NOT NULL,
		kek_salt    BLOB NOT NULL,
		wrapped_dek BLOB NOT NULL,
		kek_params  TEXT NOT NULL
	)`); err != nil {
		db.Close()
		return nil, fmt.Errorf("create key_material table: %w", err)
	}

	return &LocalStore{db: db}, nil
}

// Close closes the underlying database.
func (s *LocalStore) Close() error {
	return s.db.Close()
}

// SaveKeyMaterial upserts the key material row.
func (s *LocalStore) SaveKeyMaterial(km KeyMaterial) error {
	_, err := s.db.Exec(`INSERT INTO key_material (id, login, kek_salt, wrapped_dek, kek_params)
		VALUES (1, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET login=excluded.login, kek_salt=excluded.kek_salt,
			wrapped_dek=excluded.wrapped_dek, kek_params=excluded.kek_params`,
		km.Login, km.KEKSalt, km.WrappedDEK, km.KEKParams)
	if err != nil {
		return fmt.Errorf("save key material: %w", err)
	}
	return nil
}

// LoadKeyMaterial reads the key material row. Returns model.ErrNotFound if absent.
func (s *LocalStore) LoadKeyMaterial() (KeyMaterial, error) {
	var km KeyMaterial
	err := s.db.QueryRow(`SELECT login, kek_salt, wrapped_dek, kek_params FROM key_material WHERE id = 1`).
		Scan(&km.Login, &km.KEKSalt, &km.WrappedDEK, &km.KEKParams)
	if err == sql.ErrNoRows {
		return KeyMaterial{}, model.ErrNotFound
	}
	if err != nil {
		return KeyMaterial{}, fmt.Errorf("load key material: %w", err)
	}
	return km, nil
}

// ClearKeyMaterial removes the key material row (logout).
func (s *LocalStore) ClearKeyMaterial() error {
	if _, err := s.db.Exec(`DELETE FROM key_material`); err != nil {
		return fmt.Errorf("clear key material: %w", err)
	}
	return nil
}

// SaveSecret upserts an encrypted secret into the cache.
func (s *LocalStore) SaveSecret(sec *model.Secret) error {
	var deletedAt any
	if sec.DeletedAt != nil {
		deletedAt = sec.DeletedAt.Unix()
	}
	meta := sec.EncryptedMetadata
	if meta == nil {
		meta = []byte{}
	}
	_, err := s.db.Exec(`INSERT INTO secrets
		(id, user_id, type, encrypted_data, encrypted_metadata, comment, version, created_at, updated_at, deleted_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			type=excluded.type, encrypted_data=excluded.encrypted_data,
			encrypted_metadata=excluded.encrypted_metadata, comment=excluded.comment,
			version=excluded.version, updated_at=excluded.updated_at, deleted_at=excluded.deleted_at`,
		sec.ID.String(), sec.UserID.String(), int16(sec.Type), sec.EncryptedData, meta,
		sec.Comment, sec.Version, sec.CreatedAt.Unix(), sec.UpdatedAt.Unix(), deletedAt)
	if err != nil {
		return fmt.Errorf("save secret: %w", err)
	}
	return nil
}

// SaveSecrets upserts a batch of encrypted secrets.
func (s *LocalStore) SaveSecrets(secrets []*model.Secret) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, sec := range secrets {
		var deletedAt any
		if sec.DeletedAt != nil {
			deletedAt = sec.DeletedAt.Unix()
		}
		meta := sec.EncryptedMetadata
		if meta == nil {
			meta = []byte{}
		}
		if _, err := tx.Exec(`INSERT INTO secrets
			(id, user_id, type, encrypted_data, encrypted_metadata, comment, version, created_at, updated_at, deleted_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(id) DO UPDATE SET
				type=excluded.type, encrypted_data=excluded.encrypted_data,
				encrypted_metadata=excluded.encrypted_metadata, comment=excluded.comment,
				version=excluded.version, updated_at=excluded.updated_at, deleted_at=excluded.deleted_at`,
			sec.ID.String(), sec.UserID.String(), int16(sec.Type), sec.EncryptedData, meta,
			sec.Comment, sec.Version, sec.CreatedAt.Unix(), sec.UpdatedAt.Unix(), deletedAt); err != nil {
			return fmt.Errorf("save secret %s: %w", sec.ID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// LoadSecret reads a single encrypted secret from the cache.
func (s *LocalStore) LoadSecret(id string) (*model.Secret, error) {
	var (
		sec       model.Secret
		typeInt   int16
		userID    string
		createdAt int64
		updatedAt int64
		deletedAt sql.NullInt64
	)
	err := s.db.QueryRow(`SELECT id, user_id, type, encrypted_data, encrypted_metadata, comment, version, created_at, updated_at, deleted_at
		FROM secrets WHERE id = ?`, id).
		Scan(&sec.ID, &userID, &typeInt, &sec.EncryptedData, &sec.EncryptedMetadata,
			&sec.Comment, &sec.Version, &createdAt, &updatedAt, &deletedAt)
	if err == sql.ErrNoRows {
		return nil, model.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("load secret: %w", err)
	}

	sec.Type = model.SecretType(typeInt)
	sec.UserID, _ = uuid.Parse(userID)
	sec.CreatedAt = time.Unix(createdAt, 0)
	sec.UpdatedAt = time.Unix(updatedAt, 0)
	if deletedAt.Valid {
		t := time.Unix(deletedAt.Int64, 0)
		sec.DeletedAt = &t
	}
	return &sec, nil
}

// LoadSecrets reads all cached secrets (including tombstones).
func (s *LocalStore) LoadSecrets() ([]*model.Secret, error) {
	rows, err := s.db.Query(`SELECT id, user_id, type, encrypted_data, encrypted_metadata, comment, version, created_at, updated_at, deleted_at
		FROM secrets`)
	if err != nil {
		return nil, fmt.Errorf("query secrets: %w", err)
	}
	defer rows.Close()

	var out []*model.Secret
	for rows.Next() {
		var (
			sec       model.Secret
			typeInt   int16
			userID    string
			createdAt int64
			updatedAt int64
			deletedAt sql.NullInt64
		)
		if err := rows.Scan(&sec.ID, &userID, &typeInt, &sec.EncryptedData, &sec.EncryptedMetadata,
			&sec.Comment, &sec.Version, &createdAt, &updatedAt, &deletedAt); err != nil {
			return nil, fmt.Errorf("scan secret: %w", err)
		}
		sec.Type = model.SecretType(typeInt)
		sec.UserID, _ = uuid.Parse(userID)
		sec.CreatedAt = time.Unix(createdAt, 0)
		sec.UpdatedAt = time.Unix(updatedAt, 0)
		if deletedAt.Valid {
			t := time.Unix(deletedAt.Int64, 0)
			sec.DeletedAt = &t
		}
		out = append(out, &sec)
	}
	return out, rows.Err()
}

// DeleteSecret removes a secret from the cache.
func (s *LocalStore) DeleteSecret(id string) error {
	if _, err := s.db.Exec(`DELETE FROM secrets WHERE id = ?`, id); err != nil {
		return fmt.Errorf("delete secret: %w", err)
	}
	return nil
}

// Clear removes all cached data (logout).
func (s *LocalStore) Clear() error {
	if _, err := s.db.Exec(`DELETE FROM secrets`); err != nil {
		return fmt.Errorf("clear secrets: %w", err)
	}
	return s.ClearKeyMaterial()
}
