package model

import (
	"time"

	"github.com/google/uuid"
)

// Secret represents an encrypted secret stored on the server.
// The server never sees the plaintext — encryptedData and encryptedMetadata
// are client-encrypted envelopes (AES-256-GCM: nonce || ciphertext || tag).
type Secret struct {
	ID                uuid.UUID
	UserID            uuid.UUID
	Type              SecretType
	EncryptedData     []byte
	EncryptedMetadata []byte
	Comment           string // plaintext, non-sensitive label
	Version           int64
	CreatedAt         time.Time
	UpdatedAt         time.Time
	DeletedAt         *time.Time // non-nil means tombstone
}

// SecretSummary contains metadata only — used by ListSecrets to avoid
// downloading encrypted blobs for every item.
type SecretSummary struct {
	ID        uuid.UUID
	Type      SecretType
	Comment   string
	Version   int64
	UpdatedAt time.Time
}
