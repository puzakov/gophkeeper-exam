package client

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/puzakov/gophkeeper-exam/internal/crypto"
	protov1 "github.com/puzakov/gophkeeper-exam/internal/proto/v1"
)

// Register creates a new account and derives encryption keys from the master password.
func (c *GophKeeperClient) Register(ctx context.Context, login, masterPassword string) error {
	// Generate crypto material.
	kekSalt, err := crypto.GenerateSalt()
	if err != nil {
		return fmt.Errorf("generate salt: %w", err)
	}
	kekParams := crypto.DefaultKDFParams()
	kek := crypto.DeriveKey(masterPassword, kekSalt, kekParams)

	dek, err := crypto.GenerateDEK()
	if err != nil {
		return fmt.Errorf("generate DEK: %w", err)
	}
	wrappedDEK, err := crypto.WrapDEK(dek, kek)
	if err != nil {
		return fmt.Errorf("wrap DEK: %w", err)
	}

	paramsJSON, err := crypto.MarshalKDFParams(kekParams)
	if err != nil {
		return fmt.Errorf("marshal KDF params: %w", err)
	}

	resp, err := c.Auth.Register(ctx, (&protov1.RegisterRequest_builder{
		Login:      login,
		Password:   masterPassword,
		KekSalt:    kekSalt,
		WrappedDek: wrappedDEK,
		KekParams:  string(paramsJSON),
	}).Build())
	if err != nil {
		return fmt.Errorf("register: %w", err)
	}

	c.login = login
	c.accessToken = resp.GetAccessToken()
	c.refreshToken = resp.GetRefreshToken()
	c.userID, _ = uuid.Parse(resp.GetUserId())

	// Store crypto state in memory.
	c.dek = dek
	c.kekSalt = kekSalt
	c.kekParams = kekParams

	// Persist key material locally so offline unlock works after restart.
	if c.local != nil {
		if err := c.local.SaveKeyMaterial(KeyMaterial{
			Login:      login,
			KEKSalt:    kekSalt,
			WrappedDEK: wrappedDEK,
			KEKParams:  string(paramsJSON),
		}); err != nil {
			return fmt.Errorf("save key material: %w", err)
		}
	}

	return c.SaveTokens()
}

// Login authenticates and derives the encryption keys from the master password.
func (c *GophKeeperClient) Login(ctx context.Context, login, masterPassword string) error {
	resp, err := c.Auth.Login(ctx, (&protov1.LoginRequest_builder{
		Login:    login,
		Password: masterPassword,
	}).Build())
	if err != nil {
		return fmt.Errorf("login: %w", err)
	}

	c.login = login
	c.accessToken = resp.GetAccessToken()
	c.refreshToken = resp.GetRefreshToken()
	c.userID, _ = uuid.Parse(resp.GetUserId())

	// Derive KEK from password and server-provided salt.
	if len(resp.GetKekSalt()) > 0 {
		c.kekSalt = resp.GetKekSalt()
		c.kekParams, _ = crypto.UnmarshalKDFParams([]byte(resp.GetKekParams()))
		kek := crypto.DeriveKey(masterPassword, c.kekSalt, c.kekParams)

		// Unwrap DEK.
		if len(resp.GetWrappedDek()) > 0 {
			dek, err := crypto.UnwrapDEK(resp.GetWrappedDek(), kek)
			if err != nil {
				return fmt.Errorf("unwrap DEK: wrong password? %w", err)
			}
			c.dek = dek
		}

		// Persist key material locally so offline unlock works after restart.
		if c.local != nil {
			if err := c.local.SaveKeyMaterial(KeyMaterial{
				Login:      login,
				KEKSalt:    c.kekSalt,
				WrappedDEK: resp.GetWrappedDek(),
				KEKParams:  resp.GetKekParams(),
			}); err != nil {
				return fmt.Errorf("save key material: %w", err)
			}
		}
	}

	return c.SaveTokens()
}

// Unlock restores the DEK from locally stored key material using only the
// master password — no server connection required. It is used for offline
// read-only sessions. Returns model.ErrNotFound if no key material is stored.
func (c *GophKeeperClient) Unlock(masterPassword string) error {
	if c.local == nil {
		return fmt.Errorf("local store is not available")
	}

	km, err := c.local.LoadKeyMaterial()
	if err != nil {
		return err // model.ErrNotFound when no material stored
	}

	kekParams, err := crypto.UnmarshalKDFParams([]byte(km.KEKParams))
	if err != nil {
		return fmt.Errorf("parse KDF params: %w", err)
	}
	kek := crypto.DeriveKey(masterPassword, km.KEKSalt, kekParams)

	dek, err := crypto.UnwrapDEK(km.WrappedDEK, kek)
	if err != nil {
		return fmt.Errorf("unwrap DEK: wrong password? %w", err)
	}

	c.login = km.Login
	c.dek = dek
	c.kekSalt = km.KEKSalt
	c.kekParams = kekParams
	return nil
}

// CanUnlockOffline reports whether local key material is available for offline unlock.
func (c *GophKeeperClient) CanUnlockOffline() bool {
	if c.local == nil {
		return false
	}
	_, err := c.local.LoadKeyMaterial()
	return err == nil
}

// Logout revokes the refresh token and clears local state.
func (c *GophKeeperClient) Logout(ctx context.Context) error {
	if c.refreshToken != "" {
		_, _ = c.Auth.Logout(ctx, (&protov1.LogoutRequest_builder{
			RefreshToken: c.refreshToken,
		}).Build())
	}
	if c.local != nil {
		_ = c.local.Clear()
	}
	return c.ClearTokens()
}
