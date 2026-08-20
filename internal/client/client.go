// Package client provides a GophKeeper gRPC client with TLS, authentication,
// and client-side encryption support.
package client

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/puzakov/gophkeeper-exam/internal/config"
	"github.com/puzakov/gophkeeper-exam/internal/crypto"
	"github.com/puzakov/gophkeeper-exam/internal/model"
	protov1 "github.com/puzakov/gophkeeper-exam/internal/proto/v1"
)

// GophKeeperClient wraps gRPC connections and manages authentication state.
type GophKeeperClient struct {
	cfg *config.ClientConfig
	cc  *grpc.ClientConn

	Auth    protov1.AuthServiceClient
	Secrets protov1.SecretServiceClient
	SyncSvc protov1.SyncServiceClient

	// Auth state.
	login        string
	accessToken  string
	refreshToken string
	userID       uuid.UUID

	// Crypto state.
	dek       []byte // unwrapped DEK (in memory only)
	kekSalt   []byte
	kekParams crypto.KDFParams

	// Offline support.
	local       *LocalStore   // local SQLite cache
	status      *OnlineStatus // connectivity tracker
	closed      chan struct{} // closed when the client shuts down
	monitorOnce sync.Once     // guards the connectivity monitor goroutine
}

// IsOnline reports whether the server was reachable at the last probe.
func (c *GophKeeperClient) IsOnline() bool {
	if c.status == nil {
		return false
	}
	return c.status.IsOnline()
}

// SavedToken is persisted to disk between sessions.
type SavedToken struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	UserID       string `json:"user_id"`
	Login        string `json:"login"`
	KEKSalt      []byte `json:"kek_salt"`
	KEKParams    string `json:"kek_params"`
}

// HasKeyMaterial reports whether the DEK is available for crypto operations.
func (c *GophKeeperClient) HasKeyMaterial() bool {
	return len(c.dek) == 32
}

// Connect establishes a TLS-secured gRPC connection to the server.
// The server certificate is always verified: against cfg.TLSCAFile when set,
// otherwise against the shared dev CA (~/.gophkeeper/ca.pem), which is
// generated on first use. Verification is never skipped.
func Connect(cfg *config.ClientConfig) (*GophKeeperClient, error) {
	creds, err := crypto.LoadOrGenerateClientCreds(cfg.TLSCAFile)
	if err != nil {
		return nil, fmt.Errorf("TLS creds: %w", err)
	}

	cc, err := grpc.NewClient(cfg.ServerAddress,
		grpc.WithTransportCredentials(creds),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(model.GRPCMaxMsgSize),
			grpc.MaxCallSendMsgSize(model.GRPCMaxMsgSize),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", cfg.ServerAddress, err)
	}

	// Open the local SQLite cache for offline reads.
	local, err := OpenLocalStore(cfg.CachePath())
	if err != nil {
		cc.Close()
		return nil, fmt.Errorf("open local store: %w", err)
	}

	return &GophKeeperClient{
		cfg:     cfg,
		cc:      cc,
		Auth:    protov1.NewAuthServiceClient(cc),
		Secrets: protov1.NewSecretServiceClient(cc),
		SyncSvc: protov1.NewSyncServiceClient(cc),
		local:   local,
		status:  &OnlineStatus{},
		closed:  make(chan struct{}),
	}, nil
}

// Close shuts down the gRPC connection and the local cache.
func (c *GophKeeperClient) Close() error {
	select {
	case <-c.closed:
		// Already closed.
	default:
		close(c.closed)
	}
	if c.local != nil {
		_ = c.local.Close()
	}
	return c.cc.Close()
}

// LocalStore exposes the client's local cache for offline reads.
func (c *GophKeeperClient) LocalStore() *LocalStore {
	return c.local
}

// IsLoggedIn reports whether the client has valid tokens.
func (c *GophKeeperClient) IsLoggedIn() bool {
	return c.accessToken != "" && c.refreshToken != ""
}

// UserID returns the authenticated user's UUID.
func (c *GophKeeperClient) UserID() uuid.UUID { return c.userID }

// AccessToken returns the current access token.
func (c *GophKeeperClient) AccessToken() string { return c.accessToken }

// AuthContext returns ctx with the Bearer token attached for authenticated RPCs.
func (c *GophKeeperClient) AuthContext(ctx context.Context) context.Context {
	md := metadata.New(map[string]string{
		"authorization": "Bearer " + c.accessToken,
	})
	return metadata.NewOutgoingContext(ctx, md)
}

// SaveTokens persists authentication tokens to disk.
func (c *GophKeeperClient) SaveTokens() error {
	paramsJSON, _ := crypto.MarshalKDFParams(c.kekParams)
	st := SavedToken{
		AccessToken:  c.accessToken,
		RefreshToken: c.refreshToken,
		UserID:       c.userID.String(),
		Login:        c.login,
		KEKSalt:      c.kekSalt,
		KEKParams:    string(paramsJSON),
	}
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return os.WriteFile(c.cfg.TokenPath(), data, 0o600)
}

// LoadTokens reads authentication tokens from disk.
func (c *GophKeeperClient) LoadTokens() error {
	data, err := os.ReadFile(c.cfg.TokenPath())
	if err != nil {
		return err
	}
	var st SavedToken
	if err := json.Unmarshal(data, &st); err != nil {
		return err
	}
	c.login = st.Login
	c.accessToken = st.AccessToken
	c.refreshToken = st.RefreshToken
	c.userID, _ = uuid.Parse(st.UserID)
	c.kekSalt = st.KEKSalt
	if st.KEKParams != "" {
		c.kekParams, _ = crypto.UnmarshalKDFParams([]byte(st.KEKParams))
	}
	return nil
}

// SavedLogin returns the login saved in the token file, if any.
func (c *GophKeeperClient) SavedLogin() string {
	data, err := os.ReadFile(c.cfg.TokenPath())
	if err != nil {
		return ""
	}
	var st SavedToken
	if err := json.Unmarshal(data, &st); err != nil {
		return ""
	}
	return st.Login
}

// ClearTokens removes the stored token file and resets state.
func (c *GophKeeperClient) ClearTokens() error {
	c.accessToken = ""
	c.refreshToken = ""
	c.userID = uuid.Nil
	c.dek = nil
	return os.Remove(c.cfg.TokenPath())
}
