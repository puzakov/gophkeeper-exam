// Package model defines domain types for the GophKeeper system.
package model

import (
	"time"

	"github.com/google/uuid"
)

// User represents a registered user in the system.
type User struct {
	ID           uuid.UUID
	Login        string
	PasswordHash string
	KEKSalt      []byte // Argon2id salt (16 bytes)
	WrappedDEK   []byte // DEK wrapped with KEK
	KEKParams    string // JSON: {"m":65536,"t":3,"p":4}
	CreatedAt    time.Time
}

// RefreshToken represents an opaque refresh token stored server-side.
type RefreshToken struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	TokenHash []byte // SHA-256 of the opaque token
	ExpiresAt time.Time
	RevokedAt *time.Time
	CreatedAt time.Time
}
