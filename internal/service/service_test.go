package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/puzakov/gophkeeper-exam/internal/model"
)

// --- Fakes ---

type fakeUserRepo struct {
	users     map[string]*model.User // by login
	createErr error
	updateErr error
}

func newFakeUserRepo() *fakeUserRepo {
	return &fakeUserRepo{users: make(map[string]*model.User)}
}

func (f *fakeUserRepo) Create(_ context.Context, u *model.User) error {
	if f.createErr != nil {
		return f.createErr
	}
	if _, exists := f.users[u.Login]; exists {
		return model.ErrConflict
	}
	u.ID = uuid.New()
	u.CreatedAt = time.Now()
	f.users[u.Login] = u
	return nil
}

func (f *fakeUserRepo) GetByLogin(_ context.Context, login string) (*model.User, error) {
	u, ok := f.users[login]
	if !ok {
		return nil, model.ErrNotFound
	}
	return u, nil
}

func (f *fakeUserRepo) GetByID(_ context.Context, id uuid.UUID) (*model.User, error) {
	for _, u := range f.users {
		if u.ID == id {
			return u, nil
		}
	}
	return nil, model.ErrNotFound
}

func (f *fakeUserRepo) UpdateKeyMaterial(_ context.Context, id uuid.UUID, salt, wrappedDEK []byte, params string) error {
	if f.updateErr != nil {
		return f.updateErr
	}
	for _, u := range f.users {
		if u.ID == id {
			u.KEKSalt = salt
			u.WrappedDEK = wrappedDEK
			u.KEKParams = params
			return nil
		}
	}
	return model.ErrNotFound
}

type fakeTokenRepo struct {
	tokens map[string]*model.RefreshToken // by hash (hex string key)
}

func newFakeTokenRepo() *fakeTokenRepo {
	return &fakeTokenRepo{tokens: make(map[string]*model.RefreshToken)}
}

func (f *fakeTokenRepo) Create(_ context.Context, t *model.RefreshToken) error {
	t.ID = uuid.New()
	t.CreatedAt = time.Now()
	f.tokens[string(t.TokenHash)] = t
	return nil
}

func (f *fakeTokenRepo) GetByHash(_ context.Context, hash []byte) (*model.RefreshToken, error) {
	t, ok := f.tokens[string(hash)]
	if !ok {
		return nil, model.ErrNotFound
	}
	return t, nil
}

func (f *fakeTokenRepo) Revoke(_ context.Context, hash []byte) error {
	t, ok := f.tokens[string(hash)]
	if !ok {
		return model.ErrNotFound
	}
	now := time.Now()
	t.RevokedAt = &now
	return nil
}

func (f *fakeTokenRepo) RevokeAllForUser(_ context.Context, userID uuid.UUID) error {
	now := time.Now()
	for _, t := range f.tokens {
		if t.UserID == userID {
			t.RevokedAt = &now
		}
	}
	return nil
}

type fakeSecretRepo struct {
	secrets   map[string]*model.Secret // by id
	createErr error
	updateErr error
	listErr   error
}

func newFakeSecretRepo() *fakeSecretRepo {
	return &fakeSecretRepo{secrets: make(map[string]*model.Secret)}
}

func (f *fakeSecretRepo) Create(_ context.Context, s *model.Secret) error {
	if f.createErr != nil {
		return f.createErr
	}
	s.ID = uuid.New()
	s.Version = 1
	s.CreatedAt = time.Now()
	s.UpdatedAt = s.CreatedAt
	f.secrets[s.ID.String()] = s
	return nil
}

func (f *fakeSecretRepo) Get(_ context.Context, userID, secretID uuid.UUID) (*model.Secret, error) {
	s, ok := f.secrets[secretID.String()]
	if !ok || s.UserID != userID || s.DeletedAt != nil {
		return nil, model.ErrNotFound
	}
	return s, nil
}

func (f *fakeSecretRepo) ListSummaries(_ context.Context, userID uuid.UUID) ([]model.SecretSummary, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	var out []model.SecretSummary
	for _, s := range f.secrets {
		if s.UserID == userID && s.DeletedAt == nil {
			out = append(out, model.SecretSummary{
				ID:        s.ID,
				Type:      s.Type,
				Comment:   s.Comment,
				Version:   s.Version,
				UpdatedAt: s.UpdatedAt,
			})
		}
	}
	return out, nil
}

func (f *fakeSecretRepo) UpdateIfVersion(_ context.Context, userID, secretID uuid.UUID,
	expectedVersion int64, data, meta []byte, comment string) (int64, error) {
	if f.updateErr != nil {
		return 0, f.updateErr
	}
	s, ok := f.secrets[secretID.String()]
	if !ok || s.UserID != userID || s.DeletedAt != nil {
		return 0, model.ErrNotFound
	}
	if s.Version != expectedVersion {
		return 0, model.ErrConflict
	}
	s.Version++
	s.UpdatedAt = time.Now()
	s.EncryptedData = data
	s.EncryptedMetadata = meta
	s.Comment = comment
	return s.Version, nil
}

func (f *fakeSecretRepo) Delete(_ context.Context, userID, secretID uuid.UUID) error {
	s, ok := f.secrets[secretID.String()]
	if !ok || s.UserID != userID || s.DeletedAt != nil {
		return model.ErrNotFound
	}
	now := time.Now()
	s.DeletedAt = &now
	s.Version++
	return nil
}

func (f *fakeSecretRepo) ListForSync(_ context.Context, userID uuid.UUID) ([]model.Secret, error) {
	var out []model.Secret
	for _, s := range f.secrets {
		if s.UserID == userID {
			out = append(out, *s)
		}
	}
	return out, nil
}

// --- AuthService tests ---

func newTestAuthService() (*AuthService, *fakeUserRepo, *fakeTokenRepo) {
	users := newFakeUserRepo()
	tokens := newFakeTokenRepo()
	svc := NewAuthService(users, tokens, "test-jwt-secret")
	return svc, users, tokens
}

func TestAuthService_Register_Success(t *testing.T) {
	svc, users, _ := newTestAuthService()

	user, access, refresh, err := svc.Register(context.Background(), "alice", "password123", []byte("salt"), []byte("dek"), "params")
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if user.ID == uuid.Nil {
		t.Error("Register() did not set user ID")
	}
	if access == "" || refresh == "" {
		t.Error("Register() returned empty tokens")
	}
	if len(users.users) != 1 {
		t.Errorf("Register() stored %d users, want 1", len(users.users))
	}
}

func TestAuthService_Register_InvalidLogin(t *testing.T) {
	svc, _, _ := newTestAuthService()

	_, _, _, err := svc.Register(context.Background(), "ab", "password123", nil, nil, "")
	if !errors.Is(err, model.ErrInvalid) {
		t.Errorf("Register() error = %v, want ErrInvalid", err)
	}
}

func TestAuthService_Register_ShortPassword(t *testing.T) {
	svc, _, _ := newTestAuthService()

	_, _, _, err := svc.Register(context.Background(), "alice", "short", nil, nil, "")
	if !errors.Is(err, model.ErrInvalid) {
		t.Errorf("Register() error = %v, want ErrInvalid", err)
	}
}

func TestAuthService_Register_DuplicateLogin(t *testing.T) {
	svc, _, _ := newTestAuthService()

	_, _, _, err := svc.Register(context.Background(), "alice", "password123", nil, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, err = svc.Register(context.Background(), "alice", "password456", nil, nil, "")
	if !errors.Is(err, model.ErrConflict) {
		t.Errorf("Register() error = %v, want ErrConflict", err)
	}
}

func TestAuthService_Login_Success(t *testing.T) {
	svc, _, _ := newTestAuthService()
	if _, _, _, err := svc.Register(context.Background(), "alice", "password123", nil, nil, ""); err != nil {
		t.Fatal(err)
	}

	user, access, refresh, err := svc.Login(context.Background(), "alice", "password123")
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	if user.Login != "alice" || access == "" || refresh == "" {
		t.Errorf("Login() = %+v", user)
	}
}

func TestAuthService_Login_WrongPassword(t *testing.T) {
	svc, _, _ := newTestAuthService()
	if _, _, _, err := svc.Register(context.Background(), "alice", "password123", nil, nil, ""); err != nil {
		t.Fatal(err)
	}

	_, _, _, err := svc.Login(context.Background(), "alice", "wrongpass")
	if !errors.Is(err, model.ErrUnauthorized) {
		t.Errorf("Login() error = %v, want ErrUnauthorized", err)
	}
}

func TestAuthService_Login_NotFound(t *testing.T) {
	svc, _, _ := newTestAuthService()

	_, _, _, err := svc.Login(context.Background(), "ghost", "password123")
	if !errors.Is(err, model.ErrNotFound) {
		t.Errorf("Login() error = %v, want ErrNotFound", err)
	}
}

func TestAuthService_RefreshToken_SuccessAndRotation(t *testing.T) {
	svc, _, tokens := newTestAuthService()
	_, _, refresh, err := svc.Register(context.Background(), "alice", "password123", nil, nil, "")
	if err != nil {
		t.Fatal(err)
	}

	userID, access, newRefresh, err := svc.RefreshToken(context.Background(), refresh)
	if err != nil {
		t.Fatalf("RefreshToken() error = %v", err)
	}
	if userID == uuid.Nil || access == "" || newRefresh == "" {
		t.Error("RefreshToken() returned empty values")
	}
	if newRefresh == refresh {
		t.Error("RefreshToken() did not rotate")
	}

	// Old token must be revoked.
	stored, err := tokens.GetByHash(context.Background(), hashToken(refresh))
	if err != nil {
		t.Fatal(err)
	}
	if stored.RevokedAt == nil {
		t.Error("old refresh token was not revoked")
	}
}

func TestAuthService_RefreshToken_UnknownToken(t *testing.T) {
	svc, _, _ := newTestAuthService()

	_, _, _, err := svc.RefreshToken(context.Background(), "unknown-token")
	if !errors.Is(err, model.ErrUnauthorized) {
		t.Errorf("RefreshToken() error = %v, want ErrUnauthorized", err)
	}
}

func TestAuthService_RefreshToken_Revoked(t *testing.T) {
	svc, _, _ := newTestAuthService()
	_, _, refresh, _ := svc.Register(context.Background(), "alice", "password123", nil, nil, "")

	// Revoke then refresh.
	if err := svc.Logout(context.Background(), refresh); err != nil {
		t.Fatal(err)
	}
	_, _, _, err := svc.RefreshToken(context.Background(), refresh)
	if !errors.Is(err, model.ErrRevoked) {
		t.Errorf("RefreshToken() error = %v, want ErrRevoked", err)
	}
}

func TestAuthService_RefreshToken_Expired(t *testing.T) {
	svc, _, tokens := newTestAuthService()
	_, _, refresh, _ := svc.Register(context.Background(), "alice", "password123", nil, nil, "")

	// Force expiry.
	stored, _ := tokens.GetByHash(context.Background(), hashToken(refresh))
	stored.ExpiresAt = time.Now().Add(-time.Hour)

	_, _, _, err := svc.RefreshToken(context.Background(), refresh)
	if !errors.Is(err, model.ErrExpired) {
		t.Errorf("RefreshToken() error = %v, want ErrExpired", err)
	}
}

func TestAuthService_Logout_Revokes(t *testing.T) {
	svc, _, tokens := newTestAuthService()
	_, _, refresh, _ := svc.Register(context.Background(), "alice", "password123", nil, nil, "")

	if err := svc.Logout(context.Background(), refresh); err != nil {
		t.Fatalf("Logout() error = %v", err)
	}
	stored, _ := tokens.GetByHash(context.Background(), hashToken(refresh))
	if stored.RevokedAt == nil {
		t.Error("Logout() did not revoke token")
	}
}

func TestAuthService_ValidateAccessToken(t *testing.T) {
	svc, _, _ := newTestAuthService()
	_, access, _, err := svc.Register(context.Background(), "alice", "password123", nil, nil, "")
	if err != nil {
		t.Fatal(err)
	}

	userID, err := svc.ValidateAccessToken(access)
	if err != nil {
		t.Fatalf("ValidateAccessToken() error = %v", err)
	}
	if userID == uuid.Nil {
		t.Error("ValidateAccessToken() returned nil user ID")
	}
}

func TestAuthService_ValidateAccessToken_Invalid(t *testing.T) {
	svc, _, _ := newTestAuthService()

	tests := []struct {
		name  string
		token string
	}{
		{"garbage", "not-a-jwt"},
		{"empty", ""},
		{"wrong signature", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.bad"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.ValidateAccessToken(tt.token)
			if !errors.Is(err, model.ErrUnauthorized) {
				t.Errorf("ValidateAccessToken() error = %v, want ErrUnauthorized", err)
			}
		})
	}
}

// --- SecretService tests ---

func TestSecretService_Create_Valid(t *testing.T) {
	repo := newFakeSecretRepo()
	svc := NewSecretService(repo)

	userID := uuid.New()
	secret, err := svc.Create(context.Background(), userID, model.SecretTypeText, []byte("data"), []byte("meta"), "note")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if secret.Version != 1 || secret.ID == uuid.Nil {
		t.Errorf("Create() = %+v", secret)
	}
}

func TestSecretService_Create_InvalidType(t *testing.T) {
	svc := NewSecretService(newFakeSecretRepo())

	_, err := svc.Create(context.Background(), uuid.New(), model.SecretType(99), nil, nil, "")
	if !errors.Is(err, model.ErrInvalid) {
		t.Errorf("Create() error = %v, want ErrInvalid", err)
	}
}

func TestSecretService_Update_VersionConflict(t *testing.T) {
	repo := newFakeSecretRepo()
	svc := NewSecretService(repo)

	userID := uuid.New()
	secret, _ := svc.Create(context.Background(), userID, model.SecretTypeText, []byte("d"), nil, "c")

	_, err := svc.Update(context.Background(), userID, secret.ID, 99, []byte("new"), nil, "new")
	if !errors.Is(err, model.ErrConflict) {
		t.Errorf("Update() error = %v, want ErrConflict", err)
	}
}

func TestSecretService_Update_Success(t *testing.T) {
	repo := newFakeSecretRepo()
	svc := NewSecretService(repo)

	userID := uuid.New()
	secret, _ := svc.Create(context.Background(), userID, model.SecretTypeText, []byte("d"), nil, "c")

	newVersion, err := svc.Update(context.Background(), userID, secret.ID, 1, []byte("new"), nil, "new")
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}
	if newVersion != 2 {
		t.Errorf("Update() version = %d, want 2", newVersion)
	}
}

func TestSecretService_Delete(t *testing.T) {
	repo := newFakeSecretRepo()
	svc := NewSecretService(repo)

	userID := uuid.New()
	secret, _ := svc.Create(context.Background(), userID, model.SecretTypeText, []byte("d"), nil, "c")

	if err := svc.Delete(context.Background(), userID, secret.ID); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	// Get must now return not found.
	_, err := svc.Get(context.Background(), userID, secret.ID)
	if !errors.Is(err, model.ErrNotFound) {
		t.Errorf("Get() after Delete error = %v, want ErrNotFound", err)
	}

	// List must exclude it.
	summaries, _ := svc.List(context.Background(), userID)
	if len(summaries) != 0 {
		t.Errorf("List() after Delete len = %d, want 0", len(summaries))
	}
}

func TestSecretService_Get_NotOwner(t *testing.T) {
	repo := newFakeSecretRepo()
	svc := NewSecretService(repo)

	owner := uuid.New()
	secret, _ := svc.Create(context.Background(), owner, model.SecretTypeText, []byte("d"), nil, "c")

	_, err := svc.Get(context.Background(), uuid.New(), secret.ID)
	if !errors.Is(err, model.ErrNotFound) {
		t.Errorf("Get() by non-owner error = %v, want ErrNotFound", err)
	}
}

// --- SyncService tests ---

func TestSyncService_Diff(t *testing.T) {
	repo := newFakeSecretRepo()
	secretSvc := NewSecretService(repo)
	svc := NewSyncService(repo)

	userID := uuid.New()

	// Seed: three secrets; update one, delete another.
	s1, _ := secretSvc.Create(context.Background(), userID, model.SecretTypeText, []byte("d"), nil, "one")
	s2, _ := secretSvc.Create(context.Background(), userID, model.SecretTypeText, []byte("d"), nil, "two")
	s3, _ := secretSvc.Create(context.Background(), userID, model.SecretTypeText, []byte("d"), nil, "three")
	_, _ = secretSvc.Update(context.Background(), userID, s2.ID, 1, []byte("updated"), nil, "two")
	_ = secretSvc.Delete(context.Background(), userID, s3.ID)

	t.Run("client has nothing", func(t *testing.T) {
		diff, err := svc.Diff(context.Background(), userID, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		// s1 (live), s2 (live, v2) should be in Updated; s3 tombstone in DeletedIDs.
		if len(diff.Updated) != 2 {
			t.Errorf("Updated len = %d, want 2", len(diff.Updated))
		}
		if len(diff.DeletedIDs) != 1 || diff.DeletedIDs[0] != s3.ID.String() {
			t.Errorf("DeletedIDs = %v", diff.DeletedIDs)
		}
	})

	t.Run("client up to date", func(t *testing.T) {
		clientVersions := map[string]int64{
			s1.ID.String(): 1,
			s2.ID.String(): 2,
		}
		diff, err := svc.Diff(context.Background(), userID, clientVersions, []string{s3.ID.String()})
		if err != nil {
			t.Fatal(err)
		}
		if len(diff.Updated) != 0 {
			t.Errorf("Updated len = %d, want 0", len(diff.Updated))
		}
		if len(diff.DeletedIDs) != 0 {
			t.Errorf("DeletedIDs = %v, want empty", diff.DeletedIDs)
		}
		if len(diff.Conflicts) != 0 {
			t.Errorf("Conflicts = %v, want empty", diff.Conflicts)
		}
	})

	t.Run("client stale", func(t *testing.T) {
		clientVersions := map[string]int64{
			s2.ID.String(): 1, // server has v2
		}
		diff, err := svc.Diff(context.Background(), userID, clientVersions, nil)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, s := range diff.Updated {
			if s.ID == s2.ID {
				found = true
				break
			}
		}
		if !found {
			t.Error("stale secret s2 not in Updated")
		}
	})

	t.Run("client ahead — conflict", func(t *testing.T) {
		clientVersions := map[string]int64{
			s1.ID.String(): 5, // client claims v5, server has v1
		}
		diff, err := svc.Diff(context.Background(), userID, clientVersions, nil)
		if err != nil {
			t.Fatal(err)
		}
		if ver, ok := diff.Conflicts[s1.ID.String()]; !ok || ver != 1 {
			t.Errorf("Conflicts = %v, want %s:1", diff.Conflicts, s1.ID)
		}
	})

	t.Run("server versions map complete", func(t *testing.T) {
		diff, err := svc.Diff(context.Background(), userID, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		// s1, s2 live + s3 tombstone — all three in ServerVersions.
		if len(diff.ServerVersions) != 3 {
			t.Errorf("ServerVersions len = %d, want 3", len(diff.ServerVersions))
		}
	})
}
