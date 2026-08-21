package client

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/puzakov/gophkeeper-exam/internal/crypto"
	"github.com/puzakov/gophkeeper-exam/internal/model"
	protov1 "github.com/puzakov/gophkeeper-exam/internal/proto/v1"
)

// CreateSecret encrypts and stores a new secret. Requires an online server.
func (c *GophKeeperClient) CreateSecret(ctx context.Context, st model.SecretType, payload any, meta model.Metadata, comment string) (*model.Secret, error) {
	plainData, err := model.EncodePayload(payload)
	if err != nil {
		return nil, fmt.Errorf("encode payload: %w", err)
	}

	plainMeta, err := model.EncodeMetadata(meta)
	if err != nil {
		return nil, fmt.Errorf("encode metadata: %w", err)
	}

	encData, err := crypto.EncryptSecret(plainData, c.dek)
	if err != nil {
		return nil, fmt.Errorf("encrypt data: %w", err)
	}

	encMeta, err := crypto.EncryptMetadata(plainMeta, c.dek)
	if err != nil {
		return nil, fmt.Errorf("encrypt metadata: %w", err)
	}

	// Defense in depth: refuse to send oversized payloads.
	if int64(len(encData)) > model.MaxEncryptedSecretSize {
		return nil, fmt.Errorf("secret is %d bytes — exceeds the %d byte limit",
			len(encData), model.MaxEncryptedSecretSize)
	}

	resp, err := c.Secrets.CreateSecret(c.AuthContext(ctx), (&protov1.CreateSecretRequest_builder{
		Type:              protov1.SecretType(st),
		EncryptedData:     encData,
		EncryptedMetadata: encMeta,
		Comment:           comment,
	}).Build())
	if err != nil {
		c.applyStatusFromError(err)
		return nil, fmt.Errorf("create secret: %w", err)
	}

	c.applyStatusFromError(nil)
	id, _ := uuid.Parse(resp.GetId())
	sec := &model.Secret{
		ID:                id,
		UserID:            c.userID,
		Type:              st,
		EncryptedData:     encData,
		EncryptedMetadata: encMeta,
		Comment:           comment,
		Version:           resp.GetVersion(),
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
	}

	// Update the local cache for offline reads.
	if c.local != nil {
		_ = c.local.SaveSecret(sec)
	}

	return sec, nil
}

// GetSecret retrieves and decrypts a secret. Falls back to the local cache
// when the server is unreachable (read-only offline mode).
func (c *GophKeeperClient) GetSecret(ctx context.Context, secretID uuid.UUID) (*model.Secret, any, model.Metadata, error) {
	resp, err := c.Secrets.GetSecret(c.AuthContext(ctx), (&protov1.GetSecretRequest_builder{
		Id: secretID.String(),
	}).Build())
	if err == nil {
		c.status.setOnline(true)
		s := resp.GetSecret()
		// Keep the cache fresh.
		if c.local != nil {
			_ = c.local.SaveSecret(protoToModelSecret(s))
		}
		return c.decryptProtoSecret(s)
	}

	// Offline fallback only on network unavailability; caller-side
	// cancellation/deadlines are propagated as-is.
	if !isNetworkError(err) {
		return nil, nil, nil, fmt.Errorf("get secret: %w", err)
	}
	c.status.setOnline(false)
	sec, payload, meta, cacheErr := c.getFromCache(secretID)
	if cacheErr != nil {
		return nil, nil, nil, fmt.Errorf("get secret: %w (cache: %v)", err, cacheErr)
	}
	return sec, payload, meta, nil
}

// getFromCache loads and decrypts a secret from the local cache.
func (c *GophKeeperClient) getFromCache(secretID uuid.UUID) (*model.Secret, any, model.Metadata, error) {
	if c.local == nil {
		return nil, nil, nil, model.ErrNotFound
	}

	sec, err := c.local.LoadSecret(secretID.String())
	if err != nil {
		return nil, nil, nil, err
	}
	if sec.DeletedAt != nil {
		return nil, nil, nil, model.ErrNotFound
	}

	return c.decryptModelSecret(sec)
}

// decryptModelSecret decrypts a cached model.Secret using the in-memory DEK.
func (c *GophKeeperClient) decryptModelSecret(sec *model.Secret) (*model.Secret, any, model.Metadata, error) {
	plainData, err := crypto.DecryptSecret(sec.EncryptedData, c.dek)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decrypt data: %w", err)
	}

	plainMeta, err := crypto.DecryptMetadata(sec.EncryptedMetadata, c.dek)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decrypt metadata: %w", err)
	}

	payload, err := model.DecodePayload(plainData, sec.Type)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decode payload: %w", err)
	}

	meta, err := model.DecodeMetadata(plainMeta)
	if err != nil {
		meta = model.Metadata{}
	}

	return sec, payload, meta, nil
}

// ListSecrets returns metadata summaries for all secrets. Falls back to the
// local cache when the server is unreachable.
func (c *GophKeeperClient) ListSecrets(ctx context.Context) ([]model.SecretSummary, error) {
	resp, err := c.Secrets.ListSecrets(c.AuthContext(ctx), (&protov1.ListSecretsRequest_builder{}).Build())
	if err != nil {
		if !isNetworkError(err) {
			return nil, fmt.Errorf("list secrets: %w", err)
		}
		c.status.setOnline(false)
		return c.listFromCache()
	}

	c.status.setOnline(true)
	out := make([]model.SecretSummary, len(resp.GetSecrets()))
	for i, s := range resp.GetSecrets() {
		id, _ := uuid.Parse(s.GetId())
		out[i] = model.SecretSummary{
			ID:        id,
			Type:      model.SecretType(s.GetType()),
			Comment:   s.GetComment(),
			Version:   s.GetVersion(),
			UpdatedAt: timestampToTime(s.GetUpdatedAt()),
		}
	}
	return out, nil
}

// listFromCache builds summaries from cached secrets.
func (c *GophKeeperClient) listFromCache() ([]model.SecretSummary, error) {
	if c.local == nil {
		return nil, model.ErrNotFound
	}
	cached, err := c.local.LoadSecrets()
	if err != nil {
		return nil, err
	}
	var out []model.SecretSummary
	for _, s := range cached {
		if s.DeletedAt != nil {
			continue
		}
		out = append(out, model.SecretSummary{
			ID:        s.ID,
			Type:      s.Type,
			Comment:   s.Comment,
			Version:   s.Version,
			UpdatedAt: s.UpdatedAt,
		})
	}
	return out, nil
}

// UpdateSecret re-encrypts and updates a secret with optimistic concurrency.
// Requires an online server.
func (c *GophKeeperClient) UpdateSecret(ctx context.Context, secretID uuid.UUID, expectedVersion int64,
	payload any, meta model.Metadata, comment string) (int64, error) {

	plainData, err := model.EncodePayload(payload)
	if err != nil {
		return 0, fmt.Errorf("encode payload: %w", err)
	}
	plainMeta, err := model.EncodeMetadata(meta)
	if err != nil {
		return 0, fmt.Errorf("encode metadata: %w", err)
	}

	encData, err := crypto.EncryptSecret(plainData, c.dek)
	if err != nil {
		return 0, fmt.Errorf("encrypt data: %w", err)
	}
	encMeta, err := crypto.EncryptMetadata(plainMeta, c.dek)
	if err != nil {
		return 0, fmt.Errorf("encrypt metadata: %w", err)
	}

	resp, err := c.Secrets.UpdateSecret(c.AuthContext(ctx), (&protov1.UpdateSecretRequest_builder{
		Id:                secretID.String(),
		ExpectedVersion:   expectedVersion,
		EncryptedData:     encData,
		EncryptedMetadata: encMeta,
		Comment:           comment,
	}).Build())
	if err != nil {
		c.applyStatusFromError(err)
		return 0, fmt.Errorf("update secret: %w", err)
	}

	c.applyStatusFromError(nil)
	newVersion := resp.GetVersion()

	// Update the local cache.
	if c.local != nil {
		if sec, err := c.local.LoadSecret(secretID.String()); err == nil {
			sec.Version = newVersion
			sec.EncryptedData = encData
			sec.EncryptedMetadata = encMeta
			sec.Comment = comment
			sec.UpdatedAt = time.Now()
			_ = c.local.SaveSecret(sec)
		}
	}

	return newVersion, nil
}

// DeleteSecret soft-deletes a secret on the server. Requires an online server.
func (c *GophKeeperClient) DeleteSecret(ctx context.Context, secretID uuid.UUID) error {
	_, err := c.Secrets.DeleteSecret(c.AuthContext(ctx), (&protov1.DeleteSecretRequest_builder{
		Id: secretID.String(),
	}).Build())
	if err != nil {
		c.applyStatusFromError(err)
		return fmt.Errorf("delete secret: %w", err)
	}

	c.applyStatusFromError(nil)

	// Update the local cache (tombstone).
	if c.local != nil {
		if sec, err := c.local.LoadSecret(secretID.String()); err == nil {
			now := time.Now()
			sec.DeletedAt = &now
			sec.Version++
			_ = c.local.SaveSecret(sec)
		}
	}
	return nil
}

// decryptProtoSecret decrypts a proto Secret into a model Secret + typed payload + metadata.
func (c *GophKeeperClient) decryptProtoSecret(s *protov1.Secret) (*model.Secret, any, model.Metadata, error) {
	id, _ := uuid.Parse(s.GetId())
	st := model.SecretType(s.GetType())

	plainData, err := crypto.DecryptSecret(s.GetEncryptedData(), c.dek)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decrypt data: %w", err)
	}

	plainMeta, err := crypto.DecryptMetadata(s.GetEncryptedMetadata(), c.dek)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decrypt metadata: %w", err)
	}

	payload, err := model.DecodePayload(plainData, st)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decode payload: %w", err)
	}

	meta, err := model.DecodeMetadata(plainMeta)
	if err != nil {
		meta = model.Metadata{} // tolerate empty/broken metadata
	}

	sec := &model.Secret{
		ID:        id,
		UserID:    c.userID,
		Type:      st,
		Comment:   s.GetComment(),
		Version:   s.GetVersion(),
		CreatedAt: timestampToTime(s.GetCreatedAt()),
		UpdatedAt: timestampToTime(s.GetUpdatedAt()),
	}

	return sec, payload, meta, nil
}

// timestampToTime converts unix seconds to a time value.
func timestampToTime(ts int64) time.Time {
	if ts == 0 {
		return time.Time{}
	}
	return time.Unix(ts, 0)
}

// isNetworkError reports whether the error means the server is unreachable
// (as opposed to a caller-side cancellation, auth failure, etc.).
func isNetworkError(err error) bool {
	return status.Code(err) == codes.Unavailable
}
