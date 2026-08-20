package server

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/puzakov/gophkeeper-exam/internal/config"
	"github.com/puzakov/gophkeeper-exam/internal/crypto"
	"github.com/puzakov/gophkeeper-exam/internal/model"
	protov1 "github.com/puzakov/gophkeeper-exam/internal/proto/v1"
	"github.com/puzakov/gophkeeper-exam/internal/service"
)

// --- In-memory repo fakes (compact versions for transport tests) ---

type memUsers struct {
	mu      sync.Mutex
	byLogin map[string]*model.User
	byID    map[uuid.UUID]*model.User
}

func newMemUsers() *memUsers {
	return &memUsers{byLogin: map[string]*model.User{}, byID: map[uuid.UUID]*model.User{}}
}

func (m *memUsers) Create(_ context.Context, u *model.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.byLogin[u.Login]; ok {
		return model.ErrConflict
	}
	u.ID = uuid.New()
	u.CreatedAt = time.Now()
	m.byLogin[u.Login] = u
	m.byID[u.ID] = u
	return nil
}

func (m *memUsers) GetByLogin(_ context.Context, login string) (*model.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.byLogin[login]
	if !ok {
		return nil, model.ErrNotFound
	}
	return u, nil
}

func (m *memUsers) GetByID(_ context.Context, id uuid.UUID) (*model.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.byID[id]
	if !ok {
		return nil, model.ErrNotFound
	}
	return u, nil
}

func (m *memUsers) UpdateKeyMaterial(_ context.Context, id uuid.UUID, salt, dek []byte, params string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.byID[id]
	if !ok {
		return model.ErrNotFound
	}
	u.KEKSalt, u.WrappedDEK, u.KEKParams = salt, dek, params
	return nil
}

type memTokens struct {
	mu     sync.Mutex
	byHash map[string]*model.RefreshToken
}

func newMemTokens() *memTokens {
	return &memTokens{byHash: map[string]*model.RefreshToken{}}
}

func (m *memTokens) Create(_ context.Context, t *model.RefreshToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t.ID = uuid.New()
	t.CreatedAt = time.Now()
	m.byHash[string(t.TokenHash)] = t
	return nil
}

func (m *memTokens) GetByHash(_ context.Context, hash []byte) (*model.RefreshToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.byHash[string(hash)]
	if !ok {
		return nil, model.ErrNotFound
	}
	return t, nil
}

func (m *memTokens) Revoke(_ context.Context, hash []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.byHash[string(hash)]
	if !ok {
		return model.ErrNotFound
	}
	now := time.Now()
	t.RevokedAt = &now
	return nil
}

func (m *memTokens) RevokeAllForUser(_ context.Context, userID uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for _, t := range m.byHash {
		if t.UserID == userID {
			t.RevokedAt = &now
		}
	}
	return nil
}

type memSecrets struct {
	mu   sync.Mutex
	byID map[uuid.UUID]*model.Secret
}

func newMemSecrets() *memSecrets {
	return &memSecrets{byID: map[uuid.UUID]*model.Secret{}}
}

func (m *memSecrets) Create(_ context.Context, s *model.Secret) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s.ID = uuid.New()
	s.Version = 1
	s.CreatedAt = time.Now()
	s.UpdatedAt = s.CreatedAt
	m.byID[s.ID] = s
	return nil
}

func (m *memSecrets) Get(_ context.Context, userID, secretID uuid.UUID) (*model.Secret, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.byID[secretID]
	if !ok || s.UserID != userID || s.DeletedAt != nil {
		return nil, model.ErrNotFound
	}
	return s, nil
}

func (m *memSecrets) ListSummaries(_ context.Context, userID uuid.UUID) ([]model.SecretSummary, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []model.SecretSummary
	for _, s := range m.byID {
		if s.UserID == userID && s.DeletedAt == nil {
			out = append(out, model.SecretSummary{ID: s.ID, Type: s.Type, Comment: s.Comment, Version: s.Version, UpdatedAt: s.UpdatedAt})
		}
	}
	return out, nil
}

func (m *memSecrets) UpdateIfVersion(_ context.Context, userID, secretID uuid.UUID, expected int64, data, meta []byte, comment string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.byID[secretID]
	if !ok || s.UserID != userID || s.DeletedAt != nil {
		return 0, model.ErrNotFound
	}
	if s.Version != expected {
		return 0, model.ErrConflict
	}
	s.Version++
	s.UpdatedAt = time.Now()
	s.EncryptedData, s.EncryptedMetadata, s.Comment = data, meta, comment
	return s.Version, nil
}

func (m *memSecrets) Delete(_ context.Context, userID, secretID uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.byID[secretID]
	if !ok || s.UserID != userID || s.DeletedAt != nil {
		return model.ErrNotFound
	}
	now := time.Now()
	s.DeletedAt = &now
	s.Version++
	return nil
}

func (m *memSecrets) ListForSync(_ context.Context, userID uuid.UUID) ([]model.Secret, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []model.Secret
	for _, s := range m.byID {
		if s.UserID == userID {
			out = append(out, *s)
		}
	}
	return out, nil
}

// --- Test harness: bufconn + real TLS with the shared dev CA ---

type testEnv struct {
	authClient   protov1.AuthServiceClient
	secretClient protov1.SecretServiceClient
	syncClient   protov1.SyncServiceClient
	close        func()
	accessToken  string
	refreshToken string
	userID       string
}

func setupTestEnv(t *testing.T) *testEnv {
	t.Helper()

	// Shared dev CA in an isolated home.
	t.Setenv("HOME", t.TempDir())

	serverCreds, err := crypto.LoadOrGenerateServerCreds("", "")
	if err != nil {
		t.Fatal(err)
	}
	clientCreds, err := crypto.LoadOrGenerateClientCreds("")
	if err != nil {
		t.Fatal(err)
	}

	users := newMemUsers()
	tokens := newMemTokens()
	secrets := newMemSecrets()

	authSvc := service.NewAuthService(users, tokens, "test-secret")
	secretSvc := service.NewSecretService(secrets)
	syncSvc := service.NewSyncService(secrets)

	validateToken := func(tokenStr string) (string, error) {
		uid, err := authSvc.ValidateAccessToken(tokenStr)
		if err != nil {
			return "", err
		}
		return uid.String(), nil
	}

	srv := grpc.NewServer(
		grpc.Creds(serverCreds),
		grpc.ChainUnaryInterceptor(
			LoggingInterceptor(zap.NewNop()),
			AuthInterceptor(validateToken),
		),
	)
	protov1.RegisterAuthServiceServer(srv, NewAuthServer(authSvc))
	protov1.RegisterSecretServiceServer(srv, NewSecretServer(secretSvc))
	protov1.RegisterSyncServiceServer(srv, NewSyncServer(syncSvc))

	lis := bufconn.Listen(1 << 20)
	go func() { _ = srv.Serve(lis) }()

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(clientCreds),
	)
	if err != nil {
		t.Fatal(err)
	}

	return &testEnv{
		authClient:   protov1.NewAuthServiceClient(conn),
		secretClient: protov1.NewSecretServiceClient(conn),
		syncClient:   protov1.NewSyncServiceClient(conn),
		close: func() {
			_ = conn.Close()
			srv.Stop()
			_ = lis.Close()
		},
	}
}

func (e *testEnv) authCtx() context.Context {
	md := metadata.New(map[string]string{"authorization": "Bearer " + e.accessToken})
	return metadata.NewOutgoingContext(context.Background(), md)
}

func (e *testEnv) register(t *testing.T, login, password string) {
	t.Helper()
	resp, err := e.authClient.Register(context.Background(), (&protov1.RegisterRequest_builder{
		Login:    login,
		Password: password,
	}).Build())
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	e.accessToken = resp.GetAccessToken()
	e.refreshToken = resp.GetRefreshToken()
	e.userID = resp.GetUserId()
}

// --- Tests ---

func TestServer_AuthFlow(t *testing.T) {
	env := setupTestEnv(t)
	defer env.close()

	// Register.
	env.register(t, "alice", "password123")

	// Duplicate registration → AlreadyExists.
	_, err := env.authClient.Register(context.Background(), (&protov1.RegisterRequest_builder{
		Login:    "alice",
		Password: "password456",
	}).Build())
	if status.Code(err) != codes.AlreadyExists {
		t.Errorf("duplicate Register() code = %v, want AlreadyExists", status.Code(err))
	}

	// Login with wrong password → Unauthenticated.
	_, err = env.authClient.Login(context.Background(), (&protov1.LoginRequest_builder{
		Login:    "alice",
		Password: "wrongpass",
	}).Build())
	if status.Code(err) != codes.Unauthenticated {
		t.Errorf("bad Login() code = %v, want Unauthenticated", status.Code(err))
	}

	// Login correct.
	resp, err := env.authClient.Login(context.Background(), (&protov1.LoginRequest_builder{
		Login:    "alice",
		Password: "password123",
	}).Build())
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	if resp.GetUserId() != env.userID {
		t.Error("Login() returned different user ID")
	}

	// Refresh token flow.
	refreshResp, err := env.authClient.RefreshToken(context.Background(), (&protov1.RefreshTokenRequest_builder{
		RefreshToken: resp.GetRefreshToken(),
	}).Build())
	if err != nil {
		t.Fatalf("RefreshToken() error = %v", err)
	}
	if refreshResp.GetAccessToken() == "" {
		t.Error("RefreshToken() returned empty access token")
	}

	// Logout.
	if _, err := env.authClient.Logout(context.Background(), (&protov1.LogoutRequest_builder{
		RefreshToken: refreshResp.GetRefreshToken(),
	}).Build()); err != nil {
		t.Fatalf("Logout() error = %v", err)
	}
}

func TestServer_SecretCRUD_RequiresAuth(t *testing.T) {
	env := setupTestEnv(t)
	defer env.close()

	// No token → Unauthenticated.
	_, err := env.secretClient.CreateSecret(context.Background(), (&protov1.CreateSecretRequest_builder{
		Type:          protov1.SecretType_SECRET_TYPE_TEXT,
		EncryptedData: []byte("data"),
	}).Build())
	if status.Code(err) != codes.Unauthenticated {
		t.Errorf("CreateSecret without token code = %v, want Unauthenticated", status.Code(err))
	}

	// Garbage token → Unauthenticated.
	badCtx := metadata.NewOutgoingContext(context.Background(),
		metadata.Pairs("authorization", "Bearer not-a-jwt"))
	_, err = env.secretClient.ListSecrets(badCtx, (&protov1.ListSecretsRequest_builder{}).Build())
	if status.Code(err) != codes.Unauthenticated {
		t.Errorf("ListSecrets with bad token code = %v, want Unauthenticated", status.Code(err))
	}

	env.register(t, "bob", "password123")

	// Create.
	createResp, err := env.secretClient.CreateSecret(env.authCtx(), (&protov1.CreateSecretRequest_builder{
		Type:              protov1.SecretType_SECRET_TYPE_LOGIN_PASSWORD,
		EncryptedData:     []byte("encrypted-data"),
		EncryptedMetadata: []byte("encrypted-meta"),
		Comment:           "my login",
	}).Build())
	if err != nil {
		t.Fatalf("CreateSecret() error = %v", err)
	}
	secretID := createResp.GetId()

	// List.
	listResp, err := env.secretClient.ListSecrets(env.authCtx(), (&protov1.ListSecretsRequest_builder{}).Build())
	if err != nil {
		t.Fatalf("ListSecrets() error = %v", err)
	}
	if len(listResp.GetSecrets()) != 1 {
		t.Fatalf("ListSecrets() len = %d, want 1", len(listResp.GetSecrets()))
	}
	if listResp.GetSecrets()[0].GetId() != secretID {
		t.Error("ListSecrets() returned wrong secret ID")
	}

	// Get.
	getResp, err := env.secretClient.GetSecret(env.authCtx(), (&protov1.GetSecretRequest_builder{
		Id: secretID,
	}).Build())
	if err != nil {
		t.Fatalf("GetSecret() error = %v", err)
	}
	if string(getResp.GetSecret().GetEncryptedData()) != "encrypted-data" {
		t.Error("GetSecret() returned wrong data")
	}

	// Update with wrong version → Aborted.
	_, err = env.secretClient.UpdateSecret(env.authCtx(), (&protov1.UpdateSecretRequest_builder{
		Id:              secretID,
		ExpectedVersion: 99,
		EncryptedData:   []byte("new"),
		Comment:         "x",
	}).Build())
	if status.Code(err) != codes.Aborted {
		t.Errorf("UpdateSecret wrong version code = %v, want Aborted", status.Code(err))
	}

	// Update correct.
	updateResp, err := env.secretClient.UpdateSecret(env.authCtx(), (&protov1.UpdateSecretRequest_builder{
		Id:              secretID,
		ExpectedVersion: 1,
		EncryptedData:   []byte("new-data"),
		Comment:         "x",
	}).Build())
	if err != nil {
		t.Fatalf("UpdateSecret() error = %v", err)
	}
	if updateResp.GetVersion() != 2 {
		t.Errorf("UpdateSecret() version = %d, want 2", updateResp.GetVersion())
	}

	// Get unknown → NotFound.
	_, err = env.secretClient.GetSecret(env.authCtx(), (&protov1.GetSecretRequest_builder{
		Id: uuid.NewString(),
	}).Build())
	if status.Code(err) != codes.NotFound {
		t.Errorf("GetSecret unknown code = %v, want NotFound", status.Code(err))
	}

	// Delete.
	if _, err := env.secretClient.DeleteSecret(env.authCtx(), (&protov1.DeleteSecretRequest_builder{
		Id: secretID,
	}).Build()); err != nil {
		t.Fatalf("DeleteSecret() error = %v", err)
	}

	// List after delete → empty.
	listResp, _ = env.secretClient.ListSecrets(env.authCtx(), (&protov1.ListSecretsRequest_builder{}).Build())
	if len(listResp.GetSecrets()) != 0 {
		t.Errorf("ListSecrets() after delete len = %d, want 0", len(listResp.GetSecrets()))
	}
}

func TestServer_Sync(t *testing.T) {
	env := setupTestEnv(t)
	defer env.close()

	env.register(t, "carol", "password123")

	// Create two secrets.
	createResp, err := env.secretClient.CreateSecret(env.authCtx(), (&protov1.CreateSecretRequest_builder{
		Type:          protov1.SecretType_SECRET_TYPE_TEXT,
		EncryptedData: []byte("one"),
		Comment:       "s1",
	}).Build())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.secretClient.CreateSecret(env.authCtx(), (&protov1.CreateSecretRequest_builder{
		Type:          protov1.SecretType_SECRET_TYPE_TEXT,
		EncryptedData: []byte("two"),
		Comment:       "s2",
	}).Build()); err != nil {
		t.Fatal(err)
	}

	// Sync with empty client state → both secrets returned.
	syncResp, err := env.syncClient.SyncSecrets(env.authCtx(), (&protov1.SyncSecretsRequest_builder{}).Build())
	if err != nil {
		t.Fatalf("SyncSecrets() error = %v", err)
	}
	if len(syncResp.GetUpdatedSecrets()) != 2 {
		t.Errorf("SyncSecrets() updated len = %d, want 2", len(syncResp.GetUpdatedSecrets()))
	}

	// Sync with current versions → nothing updated.
	syncResp, err = env.syncClient.SyncSecrets(env.authCtx(), (&protov1.SyncSecretsRequest_builder{
		ClientVersions: []*protov1.SyncVersion{
			(&protov1.SyncVersion_builder{SecretId: createResp.GetId(), Version: 1}).Build(),
		},
	}).Build())
	if err != nil {
		t.Fatalf("SyncSecrets() error = %v", err)
	}
	// Only the unlisted secret is new to the client.
	if len(syncResp.GetUpdatedSecrets()) != 1 {
		t.Errorf("SyncSecrets() updated len = %d, want 1", len(syncResp.GetUpdatedSecrets()))
	}

	// Client claims higher version → conflict entry.
	syncResp, err = env.syncClient.SyncSecrets(env.authCtx(), (&protov1.SyncSecretsRequest_builder{
		ClientVersions: []*protov1.SyncVersion{
			(&protov1.SyncVersion_builder{SecretId: createResp.GetId(), Version: 42}).Build(),
		},
	}).Build())
	if err != nil {
		t.Fatal(err)
	}
	foundConflict := false
	for _, c := range syncResp.GetConflicts() {
		if c.GetSecretId() == createResp.GetId() {
			foundConflict = true
			break
		}
	}
	if !foundConflict {
		t.Error("SyncSecrets() did not report conflict for higher client version")
	}

	// Sync without token → Unauthenticated.
	_, err = env.syncClient.SyncSecrets(context.Background(), (&protov1.SyncSecretsRequest_builder{}).Build())
	if status.Code(err) != codes.Unauthenticated {
		t.Errorf("SyncSecrets without token code = %v, want Unauthenticated", status.Code(err))
	}
}

func TestServer_DeleteThenSync_PropagatesTombstone(t *testing.T) {
	env := setupTestEnv(t)
	defer env.close()

	env.register(t, "dave", "password123")

	createResp, _ := env.secretClient.CreateSecret(env.authCtx(), (&protov1.CreateSecretRequest_builder{
		Type:          protov1.SecretType_SECRET_TYPE_TEXT,
		EncryptedData: []byte("d"),
	}).Build())

	// Client has the secret at v1.
	if _, err := env.secretClient.DeleteSecret(env.authCtx(), (&protov1.DeleteSecretRequest_builder{
		Id: createResp.GetId(),
	}).Build()); err != nil {
		t.Fatal(err)
	}

	syncResp, err := env.syncClient.SyncSecrets(env.authCtx(), (&protov1.SyncSecretsRequest_builder{
		ClientVersions: []*protov1.SyncVersion{
			(&protov1.SyncVersion_builder{SecretId: createResp.GetId(), Version: 1}).Build(),
		},
	}).Build())
	if err != nil {
		t.Fatal(err)
	}
	if len(syncResp.GetDeletedIds()) != 1 || syncResp.GetDeletedIds()[0] != createResp.GetId() {
		t.Errorf("SyncSecrets() deleted ids = %v, want [%s]", syncResp.GetDeletedIds(), createResp.GetId())
	}
}

// Unit tests for interceptors.

func TestAuthInterceptor_PublicMethodsSkipAuth(t *testing.T) {
	called := false
	interceptor := AuthInterceptor(func(string) (string, error) {
		t.Fatal("validate should not be called for public methods")
		return "", nil
	})

	handler := func(ctx context.Context, req any) (any, error) {
		called = true
		return "ok", nil
	}

	info := &grpc.UnaryServerInfo{FullMethod: "/gophkeeper.v1.AuthService/Register"}
	_, err := interceptor(context.Background(), nil, info, handler)
	if err != nil {
		t.Fatalf("interceptor error = %v", err)
	}
	if !called {
		t.Error("handler was not called")
	}
}

func TestAuthInterceptor_MissingMetadata(t *testing.T) {
	interceptor := AuthInterceptor(func(string) (string, error) { return "u", nil })

	info := &grpc.UnaryServerInfo{FullMethod: "/gophkeeper.v1.SecretService/ListSecrets"}
	_, err := interceptor(context.Background(), nil, info, func(ctx context.Context, req any) (any, error) {
		return nil, nil
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Errorf("code = %v, want Unauthenticated", status.Code(err))
	}
}

func TestAuthInterceptor_ValidTokenInjectsUserID(t *testing.T) {
	interceptor := AuthInterceptor(func(string) (string, error) { return "user-123", nil })

	md := metadata.New(map[string]string{"authorization": "Bearer valid-token"})
	ctx := metadata.NewIncomingContext(context.Background(), md)

	info := &grpc.UnaryServerInfo{FullMethod: "/gophkeeper.v1.SecretService/ListSecrets"}
	_, err := interceptor(ctx, nil, info, func(ctx context.Context, req any) (any, error) {
		id, ok := UserIDFromContext(ctx)
		if !ok || id != "user-123" {
			t.Errorf("user ID in context = %q, ok=%v", id, ok)
		}
		return nil, nil
	})
	if err != nil {
		t.Fatalf("interceptor error = %v", err)
	}
}

func TestAuthInterceptor_InvalidToken(t *testing.T) {
	interceptor := AuthInterceptor(func(string) (string, error) { return "", errors.New("bad") })

	md := metadata.New(map[string]string{"authorization": "Bearer bad-token"})
	ctx := metadata.NewIncomingContext(context.Background(), md)

	info := &grpc.UnaryServerInfo{FullMethod: "/gophkeeper.v1.SecretService/ListSecrets"}
	_, err := interceptor(ctx, nil, info, func(ctx context.Context, req any) (any, error) {
		return nil, nil
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Errorf("code = %v, want Unauthenticated", status.Code(err))
	}
}

func TestLoggingInterceptor_PassesThrough(t *testing.T) {
	interceptor := LoggingInterceptor(zap.NewNop())

	info := &grpc.UnaryServerInfo{FullMethod: "/gophkeeper.v1.AuthService/Login"}
	resp, err := interceptor(context.Background(), nil, info, func(ctx context.Context, req any) (any, error) {
		return "ok", nil
	})
	if err != nil || resp != "ok" {
		t.Errorf("LoggingInterceptor() = (%v, %v), want (ok, nil)", resp, err)
	}
}

// The test env above dials with real TLS creds from the shared dev CA —
// insecure transport is intentionally not used anywhere in this package.

// --- GRPCServer wiring tests ---

func TestNewGRPCServer_ServeAndGracefulStop(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	cfg := &config.ServerConfig{GRPCAddress: "127.0.0.1:0"}

	authSvc := service.NewAuthService(newMemUsers(), newMemTokens(), "test-secret")
	secretSvc := service.NewSecretService(newMemSecrets())
	syncSvc := service.NewSyncService(newMemSecrets())

	srv, err := NewGRPCServer(cfg, nil, authSvc, secretSvc, syncSvc, zap.NewNop())
	if err != nil {
		t.Fatalf("NewGRPCServer() error = %v", err)
	}
	if srv.Addr() != cfg.GRPCAddress {
		t.Errorf("Addr() = %q, want %q", srv.Addr(), cfg.GRPCAddress)
	}

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve() }()

	// Give the server a moment to start, then stop gracefully.
	time.Sleep(50 * time.Millisecond)
	srv.GracefulStop()

	select {
	case err := <-serveErr:
		if err != nil {
			t.Fatalf("Serve() error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve() did not return after GracefulStop")
	}
}

func TestNewGRPCServer_ForceStop(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	cfg := &config.ServerConfig{GRPCAddress: "127.0.0.1:0"}

	authSvc := service.NewAuthService(newMemUsers(), newMemTokens(), "test-secret")
	secretSvc := service.NewSecretService(newMemSecrets())
	syncSvc := service.NewSyncService(newMemSecrets())

	srv, err := NewGRPCServer(cfg, nil, authSvc, secretSvc, syncSvc, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve() }()

	time.Sleep(50 * time.Millisecond)
	srv.Stop()

	select {
	case <-serveErr:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve() did not return after Stop")
	}
}

func TestLoadTLSCreds_ExplicitFiles(t *testing.T) {
	certPEM, keyPEM, err := crypto.GenerateCertificate()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile := dir + "/cert.pem"
	keyFile := dir + "/key.pem"
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	creds, err := loadTLSCreds(&config.ServerConfig{TLSCert: certFile, TLSKey: keyFile})
	if err != nil {
		t.Fatalf("loadTLSCreds() error = %v", err)
	}
	if creds == nil {
		t.Error("loadTLSCreds() returned nil")
	}
}

func TestLoadTLSCreds_Generated(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	creds, err := loadTLSCreds(&config.ServerConfig{})
	if err != nil {
		t.Fatalf("loadTLSCreds() error = %v", err)
	}
	if creds == nil {
		t.Error("loadTLSCreds() returned nil")
	}
}

func TestServer_CreateSecret_TooLarge(t *testing.T) {
	env := setupTestEnv(t)
	defer env.close()

	env.register(t, "oversized", "password123")

	// Tighten the limit so the test payload is small.
	old := model.MaxEncryptedSecretSize
	model.MaxEncryptedSecretSize = 100
	t.Cleanup(func() { model.MaxEncryptedSecretSize = old })

	_, err := env.secretClient.CreateSecret(env.authCtx(), (&protov1.CreateSecretRequest_builder{
		Type:          protov1.SecretType_SECRET_TYPE_BINARY,
		EncryptedData: make([]byte, 200),
	}).Build())
	if status.Code(err) != codes.ResourceExhausted {
		t.Errorf("CreateSecret() oversized code = %v, want ResourceExhausted", status.Code(err))
	}
}

func TestServer_UpdateSecret_TooLarge(t *testing.T) {
	env := setupTestEnv(t)
	defer env.close()

	env.register(t, "oversized-upd", "password123")

	createResp, err := env.secretClient.CreateSecret(env.authCtx(), (&protov1.CreateSecretRequest_builder{
		Type:          protov1.SecretType_SECRET_TYPE_TEXT,
		EncryptedData: []byte("small"),
	}).Build())
	if err != nil {
		t.Fatal(err)
	}

	old := model.MaxEncryptedSecretSize
	model.MaxEncryptedSecretSize = 100
	t.Cleanup(func() { model.MaxEncryptedSecretSize = old })

	_, err = env.secretClient.UpdateSecret(env.authCtx(), (&protov1.UpdateSecretRequest_builder{
		Id:              createResp.GetId(),
		ExpectedVersion: 1,
		EncryptedData:   make([]byte, 200),
	}).Build())
	if status.Code(err) != codes.ResourceExhausted {
		t.Errorf("UpdateSecret() oversized code = %v, want ResourceExhausted", status.Code(err))
	}
}

func TestServer_CreateSecret_UnderLimit_Succeeds(t *testing.T) {
	env := setupTestEnv(t)
	defer env.close()

	env.register(t, "fits", "password123")

	old := model.MaxEncryptedSecretSize
	model.MaxEncryptedSecretSize = 100
	t.Cleanup(func() { model.MaxEncryptedSecretSize = old })

	_, err := env.secretClient.CreateSecret(env.authCtx(), (&protov1.CreateSecretRequest_builder{
		Type:          protov1.SecretType_SECRET_TYPE_BINARY,
		EncryptedData: make([]byte, 90),
	}).Build())
	if err != nil {
		t.Errorf("CreateSecret() under limit error = %v", err)
	}
}
