package client

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/puzakov/gophkeeper-exam/internal/model"
)

func newTestLocalStore(t *testing.T) *LocalStore {
	t.Helper()
	store, err := OpenLocalStore(filepath.Join(t.TempDir(), "cache.db"))
	if err != nil {
		t.Fatalf("OpenLocalStore() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestLocalStore_KeyMaterialRoundtrip(t *testing.T) {
	store := newTestLocalStore(t)

	// Empty store → ErrNotFound.
	if _, err := store.LoadKeyMaterial(); !errors.Is(err, model.ErrNotFound) {
		t.Errorf("LoadKeyMaterial() on empty store = %v, want ErrNotFound", err)
	}

	km := KeyMaterial{
		Login:      "alice",
		KEKSalt:    []byte("salt-16-bytes!!!"),
		WrappedDEK: []byte("wrapped-dek"),
		KEKParams:  `{"m":65536,"t":3,"p":4}`,
	}
	if err := store.SaveKeyMaterial(km); err != nil {
		t.Fatalf("SaveKeyMaterial() error = %v", err)
	}

	got, err := store.LoadKeyMaterial()
	if err != nil {
		t.Fatalf("LoadKeyMaterial() error = %v", err)
	}
	if got.Login != km.Login || string(got.KEKSalt) != string(km.KEKSalt) ||
		string(got.WrappedDEK) != string(km.WrappedDEK) || got.KEKParams != km.KEKParams {
		t.Errorf("LoadKeyMaterial() = %+v", got)
	}

	// Upsert replaces the row.
	km2 := KeyMaterial{Login: "bob", KEKSalt: []byte("other"), WrappedDEK: []byte("x"), KEKParams: "p"}
	if err := store.SaveKeyMaterial(km2); err != nil {
		t.Fatal(err)
	}
	got, _ = store.LoadKeyMaterial()
	if got.Login != "bob" {
		t.Errorf("after upsert login = %q, want bob", got.Login)
	}

	// Clear.
	if err := store.ClearKeyMaterial(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadKeyMaterial(); !errors.Is(err, model.ErrNotFound) {
		t.Errorf("LoadKeyMaterial() after clear = %v, want ErrNotFound", err)
	}
}

func TestLocalStore_SecretRoundtrip(t *testing.T) {
	store := newTestLocalStore(t)

	userID := uuid.New()
	sec := &model.Secret{
		ID:                uuid.New(),
		UserID:            userID,
		Type:              model.SecretTypeBankCard,
		EncryptedData:     []byte("encrypted-data"),
		EncryptedMetadata: []byte("encrypted-meta"),
		Comment:           "my card",
		Version:           3,
		CreatedAt:         time.Now().Truncate(time.Second),
		UpdatedAt:         time.Now().Truncate(time.Second),
	}

	if err := store.SaveSecret(sec); err != nil {
		t.Fatalf("SaveSecret() error = %v", err)
	}

	got, err := store.LoadSecret(sec.ID.String())
	if err != nil {
		t.Fatalf("LoadSecret() error = %v", err)
	}
	if got.ID != sec.ID || got.Type != sec.Type || got.Version != sec.Version ||
		string(got.EncryptedData) != string(sec.EncryptedData) || got.Comment != sec.Comment {
		t.Errorf("LoadSecret() = %+v", got)
	}

	// Upsert updates.
	sec.Version = 4
	sec.Comment = "updated"
	if err := store.SaveSecret(sec); err != nil {
		t.Fatal(err)
	}
	got, _ = store.LoadSecret(sec.ID.String())
	if got.Version != 4 || got.Comment != "updated" {
		t.Errorf("after upsert = %+v", got)
	}

	// LoadSecrets lists it.
	all, err := store.LoadSecrets()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 || all[0].ID != sec.ID {
		t.Errorf("LoadSecrets() = %+v", all)
	}

	// Tombstone roundtrip.
	deletedAt := time.Now().Truncate(time.Second)
	sec.DeletedAt = &deletedAt
	if err := store.SaveSecret(sec); err != nil {
		t.Fatal(err)
	}
	got, _ = store.LoadSecret(sec.ID.String())
	if got.DeletedAt == nil || !got.DeletedAt.Equal(deletedAt) {
		t.Errorf("tombstone not preserved: %+v", got.DeletedAt)
	}

	// Delete.
	if err := store.DeleteSecret(sec.ID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadSecret(sec.ID.String()); !errors.Is(err, model.ErrNotFound) {
		t.Errorf("LoadSecret() after delete = %v, want ErrNotFound", err)
	}
}

func TestLocalStore_SaveSecretsBatch(t *testing.T) {
	store := newTestLocalStore(t)

	secrets := []*model.Secret{
		{ID: uuid.New(), UserID: uuid.New(), Type: model.SecretTypeText, EncryptedData: []byte("a"), Version: 1},
		{ID: uuid.New(), UserID: uuid.New(), Type: model.SecretTypeBinary, EncryptedData: []byte("b"), Version: 2},
	}
	if err := store.SaveSecrets(secrets); err != nil {
		t.Fatalf("SaveSecrets() error = %v", err)
	}

	all, err := store.LoadSecrets()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Errorf("LoadSecrets() len = %d, want 2", len(all))
	}
}

func TestLocalStore_Clear(t *testing.T) {
	store := newTestLocalStore(t)

	_ = store.SaveKeyMaterial(KeyMaterial{Login: "a", KEKSalt: []byte("s"), WrappedDEK: []byte("d"), KEKParams: "p"})
	_ = store.SaveSecret(&model.Secret{ID: uuid.New(), Type: model.SecretTypeText, EncryptedData: []byte("d"), Version: 1})

	if err := store.Clear(); err != nil {
		t.Fatalf("Clear() error = %v", err)
	}
	if all, _ := store.LoadSecrets(); len(all) != 0 {
		t.Errorf("secrets after Clear = %d, want 0", len(all))
	}
	if _, err := store.LoadKeyMaterial(); !errors.Is(err, model.ErrNotFound) {
		t.Errorf("key material after Clear = %v, want ErrNotFound", err)
	}
}
