package client

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/puzakov/gophkeeper-exam/internal/config"
	"github.com/puzakov/gophkeeper-exam/internal/crypto"
	"github.com/puzakov/gophkeeper-exam/internal/model"
	protov1 "github.com/puzakov/gophkeeper-exam/internal/proto/v1"
)

// --- In-process fake gRPC server implementing the GophKeeper services ---

type fakeServer struct {
	protov1.UnimplementedAuthServiceServer
	protov1.UnimplementedSecretServiceServer
	protov1.UnimplementedSyncServiceServer

	mu      sync.Mutex
	users   map[string]*fakeUser   // by login
	secrets map[string]*fakeSecret // by id
}

type fakeUser struct {
	id         uuid.UUID
	login      string
	password   string
	kekSalt    []byte
	wrappedDEK []byte
	kekParams  string
}

type fakeSecret struct {
	id        uuid.UUID
	userID    uuid.UUID
	typ       protov1.SecretType
	data      []byte
	meta      []byte
	comment   string
	version   int64
	updatedAt time.Time
	deletedAt *time.Time
}

func newFakeServer() *fakeServer {
	return &fakeServer{
		users:   map[string]*fakeUser{},
		secrets: map[string]*fakeSecret{},
	}
}

func (s *fakeServer) Register(_ context.Context, req *protov1.RegisterRequest) (*protov1.AuthResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.users[req.GetLogin()]; ok {
		return nil, status.Error(codes.AlreadyExists, "user exists")
	}
	u := &fakeUser{
		id:         uuid.New(),
		login:      req.GetLogin(),
		password:   req.GetPassword(),
		kekSalt:    req.GetKekSalt(),
		wrappedDEK: req.GetWrappedDek(),
		kekParams:  req.GetKekParams(),
	}
	s.users[u.login] = u

	return (&protov1.AuthResponse_builder{
		UserId:       u.id.String(),
		AccessToken:  "access-" + u.id.String(),
		RefreshToken: "refresh-" + u.id.String(),
		ExpiresIn:    900,
	}).Build(), nil
}

func (s *fakeServer) Login(_ context.Context, req *protov1.LoginRequest) (*protov1.AuthResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	u, ok := s.users[req.GetLogin()]
	if !ok || u.password != req.GetPassword() {
		return nil, status.Error(codes.Unauthenticated, "bad credentials")
	}

	return (&protov1.AuthResponse_builder{
		UserId:       u.id.String(),
		AccessToken:  "access-" + u.id.String(),
		RefreshToken: "refresh-" + u.id.String(),
		ExpiresIn:    900,
		KekSalt:      u.kekSalt,
		WrappedDek:   u.wrappedDEK,
		KekParams:    u.kekParams,
	}).Build(), nil
}

func (s *fakeServer) RefreshToken(_ context.Context, req *protov1.RefreshTokenRequest) (*protov1.AuthResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.users {
		if "refresh-"+u.id.String() == req.GetRefreshToken() {
			return (&protov1.AuthResponse_builder{
				UserId:       u.id.String(),
				AccessToken:  "access-" + u.id.String(),
				RefreshToken: "refresh-2-" + u.id.String(),
				ExpiresIn:    900,
			}).Build(), nil
		}
	}
	return nil, status.Error(codes.Unauthenticated, "unknown token")
}

func (s *fakeServer) Logout(_ context.Context, _ *protov1.LogoutRequest) (*protov1.LogoutResponse, error) {
	return (&protov1.LogoutResponse_builder{}).Build(), nil
}

func (s *fakeServer) CreateSecret(_ context.Context, req *protov1.CreateSecretRequest) (*protov1.CreateSecretResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sec := &fakeSecret{
		id:        uuid.New(),
		userID:    uuid.Nil, // fake server doesn't track users per secret
		typ:       req.GetType(),
		data:      req.GetEncryptedData(),
		meta:      req.GetEncryptedMetadata(),
		comment:   req.GetComment(),
		version:   1,
		updatedAt: time.Now(),
	}
	s.secrets[sec.id.String()] = sec

	return (&protov1.CreateSecretResponse_builder{Id: sec.id.String(), Version: 1}).Build(), nil
}

func (s *fakeServer) GetSecret(_ context.Context, req *protov1.GetSecretRequest) (*protov1.GetSecretResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sec, ok := s.secrets[req.GetId()]
	if !ok || sec.deletedAt != nil {
		return nil, status.Error(codes.NotFound, "not found")
	}

	return (&protov1.GetSecretResponse_builder{
		Secret: (&protov1.Secret_builder{
			Id:                sec.id.String(),
			Type:              sec.typ,
			EncryptedData:     sec.data,
			EncryptedMetadata: sec.meta,
			Comment:           sec.comment,
			Version:           sec.version,
			UpdatedAt:         sec.updatedAt.Unix(),
		}).Build(),
	}).Build(), nil
}

func (s *fakeServer) ListSecrets(_ context.Context, _ *protov1.ListSecretsRequest) (*protov1.ListSecretsResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var out []*protov1.SecretSummary
	for _, sec := range s.secrets {
		if sec.deletedAt != nil {
			continue
		}
		out = append(out, (&protov1.SecretSummary_builder{
			Id:        sec.id.String(),
			Type:      sec.typ,
			Comment:   sec.comment,
			Version:   sec.version,
			UpdatedAt: sec.updatedAt.Unix(),
		}).Build())
	}
	return (&protov1.ListSecretsResponse_builder{Secrets: out}).Build(), nil
}

func (s *fakeServer) UpdateSecret(_ context.Context, req *protov1.UpdateSecretRequest) (*protov1.UpdateSecretResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sec, ok := s.secrets[req.GetId()]
	if !ok || sec.deletedAt != nil {
		return nil, status.Error(codes.NotFound, "not found")
	}
	if sec.version != req.GetExpectedVersion() {
		return nil, status.Error(codes.Aborted, "version conflict")
	}
	sec.version++
	sec.data = req.GetEncryptedData()
	sec.meta = req.GetEncryptedMetadata()
	sec.comment = req.GetComment()
	sec.updatedAt = time.Now()

	return (&protov1.UpdateSecretResponse_builder{Version: sec.version}).Build(), nil
}

func (s *fakeServer) DeleteSecret(_ context.Context, req *protov1.DeleteSecretRequest) (*protov1.DeleteSecretResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sec, ok := s.secrets[req.GetId()]
	if !ok || sec.deletedAt != nil {
		return nil, status.Error(codes.NotFound, "not found")
	}
	now := time.Now()
	sec.deletedAt = &now
	sec.version++
	return (&protov1.DeleteSecretResponse_builder{}).Build(), nil
}

func (s *fakeServer) SyncSecrets(_ context.Context, req *protov1.SyncSecretsRequest) (*protov1.SyncSecretsResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	clientVersions := map[string]int64{}
	for _, v := range req.GetClientVersions() {
		clientVersions[v.GetSecretId()] = v.GetVersion()
	}

	var updated []*protov1.Secret
	var deleted []string
	var versions []*protov1.SyncVersion

	for id, sec := range s.secrets {
		cv, has := clientVersions[id]
		if sec.deletedAt != nil {
			versions = append(versions, (&protov1.SyncVersion_builder{SecretId: id, Version: sec.version}).Build())
			if !has {
				deleted = append(deleted, id)
			}
			continue
		}
		versions = append(versions, (&protov1.SyncVersion_builder{SecretId: id, Version: sec.version}).Build())
		if !has || sec.version > cv {
			updated = append(updated, (&protov1.Secret_builder{
				Id:                sec.id.String(),
				Type:              sec.typ,
				EncryptedData:     sec.data,
				EncryptedMetadata: sec.meta,
				Comment:           sec.comment,
				Version:           sec.version,
				UpdatedAt:         sec.updatedAt.Unix(),
			}).Build())
		}
	}

	return (&protov1.SyncSecretsResponse_builder{
		UpdatedSecrets: updated,
		DeletedIds:     deleted,
		ServerVersions: versions,
	}).Build(), nil
}

// --- Harness ---

type clientTestEnv struct {
	client     *GophKeeperClient
	server     *fakeServer
	stop       func()
	stopServer func()
}

func setupClientEnv(t *testing.T) *clientTestEnv {
	t.Helper()

	t.Setenv("HOME", t.TempDir())

	serverCreds, err := crypto.LoadOrGenerateServerCreds("", "")
	if err != nil {
		t.Fatal(err)
	}

	fake := newFakeServer()
	srv := grpc.NewServer(grpc.Creds(serverCreds))
	protov1.RegisterAuthServiceServer(srv, fake)
	protov1.RegisterSecretServiceServer(srv, fake)
	protov1.RegisterSyncServiceServer(srv, fake)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(lis) }()

	cfg := &config.ClientConfig{
		ServerAddress: lis.Addr().String(),
		ConfigDir:     filepath.Join(t.TempDir(), "gophkeeper"),
	}
	if err := cfg.EnsureConfigDir(); err != nil {
		t.Fatal(err)
	}

	c, err := Connect(cfg)
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}

	return &clientTestEnv{
		client: c,
		server: fake,
		stop: func() {
			_ = c.Close()
			srv.Stop()
			_ = lis.Close()
		},
		stopServer: func() {
			srv.Stop()
			_ = lis.Close()
		},
	}
}

// --- Tests ---

func TestClient_RegisterAndLogin_Roundtrip(t *testing.T) {
	env := setupClientEnv(t)
	defer env.stop()

	if err := env.client.Register(context.Background(), "alice", "master-pass-1"); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if !env.client.IsLoggedIn() {
		t.Error("IsLoggedIn() = false after Register")
	}
	if !env.client.HasKeyMaterial() {
		t.Error("HasKeyMaterial() = false after Register")
	}

	// Server must have received key material.
	u := env.server.users["alice"]
	if len(u.kekSalt) != 16 {
		t.Errorf("server kekSalt len = %d, want 16", len(u.kekSalt))
	}
	if len(u.wrappedDEK) == 0 {
		t.Error("server did not receive wrapped DEK")
	}

	// A second client instance (simulating another device) logs in
	// and must derive the same DEK from server key material.
	cfg := &config.ClientConfig{
		ServerAddress: env.client.cfg.ServerAddress,
		ConfigDir:     filepath.Join(t.TempDir(), "gophkeeper"),
	}
	if err := cfg.EnsureConfigDir(); err != nil {
		t.Fatal(err)
	}
	second, err := Connect(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()

	if err := second.Login(context.Background(), "alice", "master-pass-1"); err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	if !second.HasKeyMaterial() {
		t.Error("second client did not restore key material after Login")
	}

	// Wrong password must fail.
	third, err := Connect(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer third.Close()
	if err := third.Login(context.Background(), "alice", "wrong-password"); err == nil {
		t.Error("Login() with wrong password succeeded")
	}
}

func TestClient_SecretCRUD_EncryptedInFlight(t *testing.T) {
	env := setupClientEnv(t)
	defer env.stop()

	if err := env.client.Register(context.Background(), "bob", "master-pass-1"); err != nil {
		t.Fatal(err)
	}

	plaintext := "super-secret-password"
	sec, err := env.client.CreateSecret(context.Background(),
		model.SecretTypeLoginPassword,
		&model.LoginPasswordPayload{Login: "bob@example.com", Password: plaintext},
		nil, "my login")
	if err != nil {
		t.Fatalf("CreateSecret() error = %v", err)
	}

	// The server must store ciphertext, never the plaintext.
	stored := env.server.secrets[sec.ID.String()]
	if stored == nil {
		t.Fatal("server did not store the secret")
	}
	if contains(stored.data, []byte(plaintext)) {
		t.Error("server received plaintext password")
	}
	if len(stored.data) == 0 {
		t.Error("server stored empty data")
	}

	// Get decrypts it back.
	_, payload, _, err := env.client.GetSecret(context.Background(), sec.ID)
	if err != nil {
		t.Fatalf("GetSecret() error = %v", err)
	}
	p, ok := payload.(*model.LoginPasswordPayload)
	if !ok {
		t.Fatalf("payload type = %T", payload)
	}
	if p.Password != plaintext {
		t.Errorf("decrypted password = %q, want %q", p.Password, plaintext)
	}

	// List returns the summary.
	summaries, err := env.client.ListSecrets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(summaries) != 1 || summaries[0].ID != sec.ID {
		t.Errorf("ListSecrets() = %+v", summaries)
	}

	// Update with stale version fails with conflict.
	if _, err := env.client.UpdateSecret(context.Background(), sec.ID, 99,
		&model.LoginPasswordPayload{Login: "bob@example.com", Password: "changed"},
		nil, "my login"); err == nil {
		t.Error("UpdateSecret() with stale version succeeded")
	}

	// Update with correct version.
	newVersion, err := env.client.UpdateSecret(context.Background(), sec.ID, 1,
		&model.LoginPasswordPayload{Login: "bob@example.com", Password: "changed"},
		nil, "my login")
	if err != nil {
		t.Fatalf("UpdateSecret() error = %v", err)
	}
	if newVersion != 2 {
		t.Errorf("UpdateSecret() version = %d, want 2", newVersion)
	}

	// Delete.
	if err := env.client.DeleteSecret(context.Background(), sec.ID); err != nil {
		t.Fatalf("DeleteSecret() error = %v", err)
	}
	summaries, _ = env.client.ListSecrets(context.Background())
	if len(summaries) != 0 {
		t.Errorf("ListSecrets() after delete len = %d, want 0", len(summaries))
	}
}

func TestClient_Sync(t *testing.T) {
	env := setupClientEnv(t)
	defer env.stop()

	if err := env.client.Register(context.Background(), "carol", "master-pass-1"); err != nil {
		t.Fatal(err)
	}

	sec1, _ := env.client.CreateSecret(context.Background(), model.SecretTypeText, &model.TextPayload{Text: "hello"}, nil, "s1")
	sec2, _ := env.client.CreateSecret(context.Background(), model.SecretTypeText, &model.TextPayload{Text: "world"}, nil, "s2")

	// Sync with empty client state → both secrets returned.
	result, err := env.client.Sync(context.Background(), nil, nil)
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if len(result.Updated) != 2 {
		t.Errorf("Sync() updated len = %d, want 2", len(result.Updated))
	}

	// SyncAndDecrypt decrypts them.
	synced, err := env.client.SyncAndDecrypt(context.Background(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(synced) != 2 {
		t.Fatalf("SyncAndDecrypt() len = %d, want 2", len(synced))
	}
	for _, s := range synced {
		if s.Secret.ID != sec1.ID && s.Secret.ID != sec2.ID {
			t.Errorf("unexpected synced secret %s", s.Secret.ID)
		}
	}

	// Sync with current versions → nothing updated.
	versions := map[string]int64{sec1.ID.String(): 1, sec2.ID.String(): 1}
	result, err = env.client.Sync(context.Background(), versions, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Updated) != 0 {
		t.Errorf("Sync() with current versions updated len = %d, want 0", len(result.Updated))
	}
}

func TestClient_ContextDeadline_Propagates(t *testing.T) {
	env := setupClientEnv(t)
	defer env.stop()

	if err := env.client.Register(context.Background(), "dave", "master-pass-1"); err != nil {
		t.Fatal(err)
	}

	// Already-expired context must fail fast with DeadlineExceeded.
	ctx, cancel := context.WithTimeout(context.Background(), -time.Second)
	defer cancel()

	_, err := env.client.ListSecrets(ctx)
	if err == nil {
		t.Error("ListSecrets() with expired context succeeded")
	}
	if status.Code(err) != codes.DeadlineExceeded && status.Code(err) != codes.Canceled {
		t.Errorf("ListSecrets() code = %v, want DeadlineExceeded/Canceled", status.Code(err))
	}
}

func TestClient_TokenPersistence(t *testing.T) {
	env := setupClientEnv(t)
	defer env.stop()

	if err := env.client.Register(context.Background(), "erin", "master-pass-1"); err != nil {
		t.Fatal(err)
	}

	// Token file exists.
	if _, err := os.Stat(env.client.cfg.TokenPath()); err != nil {
		t.Fatalf("token file: %v", err)
	}

	// A fresh client loads tokens from disk.
	cfg := &config.ClientConfig{
		ServerAddress: env.client.cfg.ServerAddress,
		ConfigDir:     env.client.cfg.ConfigDir,
	}
	restored, err := Connect(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()

	if err := restored.LoadTokens(); err != nil {
		t.Fatalf("LoadTokens() error = %v", err)
	}
	if !restored.IsLoggedIn() {
		t.Error("restored client is not logged in")
	}
	if restored.SavedLogin() != "erin" {
		t.Errorf("SavedLogin() = %q, want erin", restored.SavedLogin())
	}

	// ClearTokens removes the file and state.
	if err := restored.ClearTokens(); err != nil {
		t.Fatalf("ClearTokens() error = %v", err)
	}
	if restored.IsLoggedIn() {
		t.Error("client still logged in after ClearTokens")
	}
	if _, err := os.Stat(cfg.TokenPath()); !os.IsNotExist(err) {
		t.Error("token file still exists after ClearTokens")
	}
}

func TestClient_Logout(t *testing.T) {
	env := setupClientEnv(t)
	defer env.stop()

	if err := env.client.Register(context.Background(), "frank", "master-pass-1"); err != nil {
		t.Fatal(err)
	}
	if err := env.client.Logout(context.Background()); err != nil {
		t.Fatalf("Logout() error = %v", err)
	}
	if env.client.IsLoggedIn() {
		t.Error("client still logged in after Logout")
	}
}

// helpers

func contains(haystack, needle []byte) bool {
	if len(needle) == 0 {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// --- Offline mode tests ---

func TestClient_OfflineFallback_ListAndGet(t *testing.T) {
	env := setupClientEnv(t)
	defer env.stop()

	if err := env.client.Register(context.Background(), "grace", "master-pass-1"); err != nil {
		t.Fatal(err)
	}

	// Create a secret while online — it lands in the local cache.
	sec, err := env.client.CreateSecret(context.Background(), model.SecretTypeText,
		&model.TextPayload{Text: "offline-readable"}, nil, "cached")
	if err != nil {
		t.Fatal(err)
	}

	// Server goes down.
	env.stopServer()

	// ListSecrets falls back to the cache.
	summaries, err := env.client.ListSecrets(context.Background())
	if err != nil {
		t.Fatalf("ListSecrets() offline error = %v", err)
	}
	if len(summaries) != 1 || summaries[0].ID != sec.ID {
		t.Errorf("offline ListSecrets() = %+v", summaries)
	}
	if env.client.IsOnline() {
		t.Error("IsOnline() = true while server is down")
	}

	// GetSecret falls back to the cache and decrypts.
	_, payload, _, err := env.client.GetSecret(context.Background(), sec.ID)
	if err != nil {
		t.Fatalf("GetSecret() offline error = %v", err)
	}
	text, ok := payload.(*model.TextPayload)
	if !ok || text.Text != "offline-readable" {
		t.Errorf("offline GetSecret() payload = %+v", payload)
	}

	// Mutations must fail when offline.
	if _, err := env.client.CreateSecret(context.Background(), model.SecretTypeText,
		&model.TextPayload{Text: "x"}, nil, "x"); err == nil {
		t.Error("CreateSecret() succeeded while offline")
	}
}

func TestClient_OfflineUnlock_AfterRestart(t *testing.T) {
	env := setupClientEnv(t)

	if err := env.client.Register(context.Background(), "heidi", "master-pass-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := env.client.CreateSecret(context.Background(), model.SecretTypeText,
		&model.TextPayload{Text: "survives restart"}, nil, "cached"); err != nil {
		t.Fatal(err)
	}

	cacheDir := env.client.cfg.ConfigDir
	env.stop() // closes client AND stops the server

	// "Restart": new client, same config dir, server unreachable.
	cfg := &config.ClientConfig{
		ServerAddress: "127.0.0.1:1", // nothing listens here
		ConfigDir:     cacheDir,
	}
	restarted, err := Connect(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()

	// Unlock with the master password — no server involved.
	if err := restarted.Unlock("master-pass-1"); err != nil {
		t.Fatalf("Unlock() offline error = %v", err)
	}
	if !restarted.HasKeyMaterial() {
		t.Error("Unlock() did not restore key material")
	}

	// Wrong password must fail.
	bad, err := Connect(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer bad.Close()
	if err := bad.Unlock("wrong-password"); err == nil {
		t.Error("Unlock() with wrong password succeeded")
	}

	// Cached secret is readable after offline unlock.
	summaries, err := restarted.ListSecrets(context.Background())
	if err != nil {
		t.Fatalf("offline ListSecrets() error = %v", err)
	}
	if len(summaries) != 1 {
		t.Fatalf("offline ListSecrets() len = %d, want 1", len(summaries))
	}
	_, payload, _, err := restarted.GetSecret(context.Background(), summaries[0].ID)
	if err != nil {
		t.Fatalf("offline GetSecret() error = %v", err)
	}
	text, ok := payload.(*model.TextPayload)
	if !ok || text.Text != "survives restart" {
		t.Errorf("offline payload = %+v", payload)
	}
}

func TestClient_Unlock_NoKeyMaterial(t *testing.T) {
	env := setupClientEnv(t)
	defer env.stop()

	// Fresh client with empty cache cannot unlock offline.
	if err := env.client.Unlock("any-password"); err == nil {
		t.Error("Unlock() with empty local store succeeded")
	}
	if env.client.CanUnlockOffline() {
		t.Error("CanUnlockOffline() = true with empty local store")
	}
}

func TestClient_Monitor_UpdatesStatus(t *testing.T) {
	env := setupClientEnv(t)
	defer env.stop()

	if err := env.client.Register(context.Background(), "ivan", "master-pass-1"); err != nil {
		t.Fatal(err)
	}

	// Start monitor; the first probe runs immediately.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env.client.StartConnectivityMonitor(ctx)

	// Wait for the immediate probe to mark online.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if env.client.IsOnline() {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !env.client.IsOnline() {
		t.Error("IsOnline() = false after probe with running server")
	}

	// Stop the server and force a probe via a mutation attempt.
	env.stopServer()
	_, err := env.client.ListSecrets(context.Background())
	if err != nil {
		t.Fatalf("ListSecrets() error = %v", err)
	}
	if env.client.IsOnline() {
		t.Error("IsOnline() = true after server stopped")
	}
}

func TestClient_CreateSecret_RefusesOversizedPayload(t *testing.T) {
	env := setupClientEnv(t)
	defer env.stop()

	if err := env.client.Register(context.Background(), "karen", "master-pass-1"); err != nil {
		t.Fatal(err)
	}

	// Tighten the limit — any encrypted payload exceeds it.
	old := model.MaxEncryptedSecretSize
	model.MaxEncryptedSecretSize = 32
	t.Cleanup(func() { model.MaxEncryptedSecretSize = old })

	_, err := env.client.CreateSecret(context.Background(), model.SecretTypeText,
		&model.TextPayload{Text: "hello world"}, nil, "c")
	if err == nil {
		t.Error("CreateSecret() with oversized encrypted payload succeeded")
	}

	// The server must NOT have received anything.
	if len(env.server.secrets) != 0 {
		t.Errorf("server stored %d secrets, want 0", len(env.server.secrets))
	}
}
