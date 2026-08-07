package service

import (
	"context"

	"github.com/google/uuid"

	"github.com/puzakov/gophkeeper-exam/internal/model"
	"github.com/puzakov/gophkeeper-exam/internal/storage"
)

// SecretService handles business logic for encrypted secrets.
// It acts as a thin validation layer over the repository — the server
// treats encrypted data as opaque bytes.
type SecretService struct {
	secrets storage.SecretRepository
}

// NewSecretService creates a new SecretService.
func NewSecretService(secrets storage.SecretRepository) *SecretService {
	return &SecretService{secrets: secrets}
}

// Create stores a new encrypted secret.
func (s *SecretService) Create(ctx context.Context, userID uuid.UUID, st model.SecretType, encryptedData, encryptedMetadata []byte, comment string) (*model.Secret, error) {
	if !st.Valid() {
		return nil, model.ErrInvalid
	}

	secret := &model.Secret{
		UserID:            userID,
		Type:              st,
		EncryptedData:     encryptedData,
		EncryptedMetadata: encryptedMetadata,
		Comment:           comment,
	}

	if err := s.secrets.Create(ctx, secret); err != nil {
		return nil, err
	}
	return secret, nil
}

// Get returns a single secret owned by the user.
func (s *SecretService) Get(ctx context.Context, userID, secretID uuid.UUID) (*model.Secret, error) {
	return s.secrets.Get(ctx, userID, secretID)
}

// List returns metadata summaries for all active secrets owned by the user.
func (s *SecretService) List(ctx context.Context, userID uuid.UUID) ([]model.SecretSummary, error) {
	return s.secrets.ListSummaries(ctx, userID)
}

// Update replaces encrypted data for an existing secret using optimistic concurrency.
func (s *SecretService) Update(ctx context.Context, userID, secretID uuid.UUID,
	expectedVersion int64, encryptedData, encryptedMetadata []byte, comment string) (int64, error) {

	return s.secrets.UpdateIfVersion(ctx, userID, secretID, expectedVersion, encryptedData, encryptedMetadata, comment)
}

// Delete performs a soft delete (tombstone) on a secret.
func (s *SecretService) Delete(ctx context.Context, userID, secretID uuid.UUID) error {
	return s.secrets.Delete(ctx, userID, secretID)
}
