package client

import (
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/puzakov/gophkeeper-exam/internal/crypto"
	"github.com/puzakov/gophkeeper-exam/internal/model"
	protov1 "github.com/puzakov/gophkeeper-exam/internal/proto/v1"
)

// CreateSecret encrypts and stores a new secret.
func (c *GophKeeperClient) CreateSecret(st model.SecretType, payload any, meta model.Metadata, comment string) (*model.Secret, error) {
	plainData, err := model.EncodePayload(payload)
	if err != nil {
		return nil, fmt.Errorf("encode payload: %w", err)
	}

	plainMeta, err := model.EncodeMetadata(meta)
	if err != nil {
		return nil, fmt.Errorf("encode metadata: %w", err)
	}

	encData, err := crypto.EncryptSecret(plainData, c.dek, "new", 0)
	if err != nil {
		return nil, fmt.Errorf("encrypt data: %w", err)
	}

	encMeta, err := crypto.EncryptMetadata(plainMeta, c.dek)
	if err != nil {
		return nil, fmt.Errorf("encrypt metadata: %w", err)
	}

	resp, err := c.Secrets.CreateSecret(c.AuthContext(), &protov1.CreateSecretRequest{
		Type:              protov1.SecretType(st),
		EncryptedData:     encData,
		EncryptedMetadata: encMeta,
		Comment:           comment,
	})
	if err != nil {
		return nil, fmt.Errorf("create secret: %w", err)
	}

	id, _ := uuid.Parse(resp.GetId())
	return &model.Secret{
		ID:      id,
		Type:    st,
		Comment: comment,
		Version: resp.GetVersion(),
	}, nil
}

// GetSecret retrieves and decrypts a secret.
func (c *GophKeeperClient) GetSecret(secretID uuid.UUID) (*model.Secret, any, model.Metadata, error) {
	resp, err := c.Secrets.GetSecret(c.AuthContext(), &protov1.GetSecretRequest{
		Id: secretID.String(),
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("get secret: %w", err)
	}

	s := resp.GetSecret()
	return c.decryptProtoSecret(s)
}

// ListSecrets returns metadata summaries for all secrets.
func (c *GophKeeperClient) ListSecrets() ([]model.SecretSummary, error) {
	resp, err := c.Secrets.ListSecrets(c.AuthContext(), &protov1.ListSecretsRequest{})
	if err != nil {
		return nil, fmt.Errorf("list secrets: %w", err)
	}

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

// UpdateSecret re-encrypts and updates a secret with optimistic concurrency.
func (c *GophKeeperClient) UpdateSecret(secretID uuid.UUID, expectedVersion int64,
	payload any, meta model.Metadata, comment string) (int64, error) {

	plainData, err := model.EncodePayload(payload)
	if err != nil {
		return 0, fmt.Errorf("encode payload: %w", err)
	}
	plainMeta, err := model.EncodeMetadata(meta)
	if err != nil {
		return 0, fmt.Errorf("encode metadata: %w", err)
	}

	encData, err := crypto.EncryptSecret(plainData, c.dek, secretID.String(), expectedVersion+1)
	if err != nil {
		return 0, fmt.Errorf("encrypt data: %w", err)
	}
	encMeta, err := crypto.EncryptMetadata(plainMeta, c.dek)
	if err != nil {
		return 0, fmt.Errorf("encrypt metadata: %w", err)
	}

	resp, err := c.Secrets.UpdateSecret(c.AuthContext(), &protov1.UpdateSecretRequest{
		Id:                secretID.String(),
		ExpectedVersion:   expectedVersion,
		EncryptedData:     encData,
		EncryptedMetadata: encMeta,
		Comment:           comment,
	})
	if err != nil {
		return 0, fmt.Errorf("update secret: %w", err)
	}

	return resp.GetVersion(), nil
}

// DeleteSecret soft-deletes a secret on the server.
func (c *GophKeeperClient) DeleteSecret(secretID uuid.UUID) error {
	_, err := c.Secrets.DeleteSecret(c.AuthContext(), &protov1.DeleteSecretRequest{
		Id: secretID.String(),
	})
	if err != nil {
		return fmt.Errorf("delete secret: %w", err)
	}
	return nil
}

// decryptProtoSecret decrypts a proto Secret into a model Secret + typed payload + metadata.
func (c *GophKeeperClient) decryptProtoSecret(s *protov1.Secret) (*model.Secret, any, model.Metadata, error) {
	id, _ := uuid.Parse(s.GetId())
	st := model.SecretType(s.GetType())

	plainData, err := crypto.DecryptSecret(s.GetEncryptedData(), c.dek, s.GetId(), s.GetVersion())
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
