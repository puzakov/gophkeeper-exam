// Package crypto provides RSA-OAEP encryption and decryption helpers
// for asymmetric encryption of data between client and server.
package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// LoadPublicKey reads a PEM-encoded RSA public key from the given file path.
// Supports both PKIX (SPKI) and PKCS1 formats.
func LoadPublicKey(path string) (*rsa.PublicKey, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public key file: %w", err)
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block found in public key file")
	}

	// Try PKIX/SPKI format first.
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err == nil {
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("key is not an RSA public key")
		}
		return pub, nil
	}

	// Fallback: try PKCS1 format.
	pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, errors.New("public key is not in PKIX or PKCS1 format")
	}
	return pub, nil
}

// LoadPrivateKey reads a PEM-encoded RSA private key from the given file path.
func LoadPrivateKey(path string) (*rsa.PrivateKey, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key file: %w", err)
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block found in private key file")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Fallback: try PKCS1 format.
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.New("private key is not in PKCS8 or PKCS1 format")
		}
	}

	priv, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("key is not an RSA private key")
	}

	return priv, nil
}

// EncryptOAEP encrypts plaintext using RSA-OAEP with SHA-256.
// The label is empty. Returns the ciphertext.
func EncryptOAEP(plaintext []byte, pub *rsa.PublicKey) ([]byte, error) {
	if pub == nil {
		return nil, errors.New("public key is nil")
	}
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, plaintext, nil)
	if err != nil {
		return nil, fmt.Errorf("rsa encrypt: %w", err)
	}
	return ciphertext, nil
}

// DecryptOAEP decrypts ciphertext using RSA-OAEP with SHA-256.
// The label is empty. Returns the plaintext.
func DecryptOAEP(ciphertext []byte, priv *rsa.PrivateKey) ([]byte, error) {
	if priv == nil {
		return nil, errors.New("private key is nil")
	}
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("rsa decrypt: %w", err)
	}
	return plaintext, nil
}
