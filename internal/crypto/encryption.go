package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

// KDFParams defines the Argon2id key derivation parameters.
// Serialised to JSON and stored server-side so parameters can be upgraded.
type KDFParams struct {
	Memory      uint32 `json:"m"` // KiB
	Iterations  uint32 `json:"t"`
	Parallelism uint8  `json:"p"`
	SaltLen     int    `json:"salt_len,omitempty"` // not serialised; informational
}

// DefaultKDFParams returns the recommended Argon2id parameters.
func DefaultKDFParams() KDFParams {
	return KDFParams{
		Memory:      65536, // 64 MiB
		Iterations:  3,
		Parallelism: 4,
	}
}

// MarshalKDFParams serialises KDF parameters to JSON bytes.
func MarshalKDFParams(p KDFParams) ([]byte, error) {
	return json.Marshal(p)
}

// UnmarshalKDFParams parses KDF parameters from JSON bytes.
func UnmarshalKDFParams(data []byte) (KDFParams, error) {
	var p KDFParams
	if err := json.Unmarshal(data, &p); err != nil {
		return KDFParams{}, fmt.Errorf("unmarshal KDF params: %w", err)
	}
	return p, nil
}

// DeriveKey derives a 32-byte encryption key from a password and salt using Argon2id.
func DeriveKey(password string, salt []byte, params KDFParams) []byte {
	return argon2.IDKey(
		[]byte(password),
		salt,
		params.Iterations,
		params.Memory,
		params.Parallelism,
		32, // AES-256 key
	)
}

// GenerateSalt creates a random 16-byte salt for Argon2id.
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}
	return salt, nil
}

// GenerateDEK creates a random 32-byte Data Encryption Key.
func GenerateDEK() ([]byte, error) {
	dek := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, fmt.Errorf("generate DEK: %w", err)
	}
	return dek, nil
}

// WrapDEK encrypts a DEK using a KEK via AES-256-GCM.
// Returns nonce || ciphertext || tag.
func WrapDEK(dek, kek []byte) ([]byte, error) {
	return encrypt(dek, kek, nil)
}

// UnwrapDEK decrypts a wrapped DEK using a KEK via AES-256-GCM.
func UnwrapDEK(wrapped, kek []byte) ([]byte, error) {
	return decrypt(wrapped, kek, nil)
}

// EncryptSecret encrypts plaintext using AES-256-GCM with the DEK.
// AAD is derived from secretID and version to bind the ciphertext.
// Returns nonce || ciphertext || tag.
func EncryptSecret(plaintext, dek []byte, secretID string, version int64) ([]byte, error) {
	aad := buildAAD(secretID, version)
	return encrypt(plaintext, dek, aad)
}

// DecryptSecret decrypts ciphertext using AES-256-GCM with the DEK.
// AAD must match the secretID and version used during encryption.
func DecryptSecret(ciphertext, dek []byte, secretID string, version int64) ([]byte, error) {
	aad := buildAAD(secretID, version)
	return decrypt(ciphertext, dek, aad)
}

// EncryptMetadata encrypts metadata using AES-256-GCM with the DEK.
func EncryptMetadata(plaintext, dek []byte) ([]byte, error) {
	return encrypt(plaintext, dek, nil)
}

// DecryptMetadata decrypts metadata using AES-256-GCM with the DEK.
func DecryptMetadata(ciphertext, dek []byte) ([]byte, error) {
	return decrypt(ciphertext, dek, nil)
}

// encrypt is the internal AES-256-GCM encryption helper.
func encrypt(plaintext, key, aad []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes, got %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	// nonce || ciphertext || tag
	ciphertext := gcm.Seal(nonce, nonce, plaintext, aad)
	return ciphertext, nil
}

// decrypt is the internal AES-256-GCM decryption helper.
func decrypt(ciphertext, key, aad []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes, got %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return plaintext, nil
}

// buildAAD creates Additional Authenticated Data from secret ID and version.
// This binds the ciphertext to a specific secret + version, preventing rollback.
func buildAAD(secretID string, version int64) []byte {
	data := fmt.Sprintf("%s:%d", secretID, version)
	h := sha256.Sum256([]byte(data))
	return h[:]
}
