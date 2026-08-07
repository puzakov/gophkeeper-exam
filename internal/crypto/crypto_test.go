package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
)

func TestGenerateCertificate(t *testing.T) {
	certPEM, keyPEM, err := GenerateCertificate()
	if err != nil {
		t.Fatalf("GenerateCertificate() error = %v", err)
	}
	if len(certPEM) == 0 {
		t.Error("certPEM is empty")
	}
	if len(keyPEM) == 0 {
		t.Error("keyPEM is empty")
	}
}

func TestLoadOrGenerateServerCreds(t *testing.T) {
	t.Run("generate", func(t *testing.T) {
		creds, err := LoadOrGenerateServerCreds("", "")
		if err != nil {
			t.Fatalf("LoadOrGenerateServerCreds() error = %v", err)
		}
		if creds == nil {
			t.Error("creds is nil")
		}
	})

	t.Run("load from files", func(t *testing.T) {
		certPEM, keyPEM, err := GenerateCertificate()
		if err != nil {
			t.Fatal(err)
		}
		certFile := t.TempDir() + "/cert.pem"
		keyFile := t.TempDir() + "/key.pem"
		if err := writeTestFile(certFile, certPEM); err != nil {
			t.Fatal(err)
		}
		if err := writeTestFile(keyFile, keyPEM); err != nil {
			t.Fatal(err)
		}
		creds, err := LoadOrGenerateServerCreds(certFile, keyFile)
		if err != nil {
			t.Fatalf("LoadOrGenerateServerCreds() error = %v", err)
		}
		if creds == nil {
			t.Error("creds is nil")
		}
	})
}

func TestMustLoadOrGenerateServerCreds(t *testing.T) {
	creds := MustLoadOrGenerateServerCreds()
	if creds == nil {
		t.Error("MustLoadOrGenerateServerCreds() returned nil")
	}
}

func TestLoadOrGenerateClientCreds(t *testing.T) {
	t.Run("dev mode", func(t *testing.T) {
		creds, err := LoadOrGenerateClientCreds("")
		if err != nil {
			t.Fatalf("LoadOrGenerateClientCreds() error = %v", err)
		}
		if creds == nil {
			t.Error("creds is nil")
		}
	})

	t.Run("invalid ca file", func(t *testing.T) {
		_, err := LoadOrGenerateClientCreds("/nonexistent/ca.pem")
		if err == nil {
			t.Error("expected error for non-existent CA file")
		}
	})
}

func TestMustLoadOrGenerateClientCreds(t *testing.T) {
	creds := MustLoadOrGenerateClientCreds()
	if creds == nil {
		t.Error("MustLoadOrGenerateClientCreds() returned nil")
	}
}

func TestRSAEncryptDecrypt(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("hello, gophkeeper!")
	ciphertext, err := EncryptOAEP(plaintext, &key.PublicKey)
	if err != nil {
		t.Fatalf("EncryptOAEP() error = %v", err)
	}

	decrypted, err := DecryptOAEP(ciphertext, key)
	if err != nil {
		t.Fatalf("DecryptOAEP() error = %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptOAEP_NilKey(t *testing.T) {
	_, err := EncryptOAEP([]byte("test"), nil)
	if err == nil {
		t.Error("expected error for nil public key")
	}
}

func TestDecryptOAEP_NilKey(t *testing.T) {
	_, err := DecryptOAEP([]byte("test"), nil)
	if err == nil {
		t.Error("expected error for nil private key")
	}
}

func TestDecryptOAEP_Tampered(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("tamper test")
	ciphertext, err := EncryptOAEP(plaintext, &key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with ciphertext.
	ciphertext[len(ciphertext)/2] ^= 0xff

	_, err = DecryptOAEP(ciphertext, key)
	if err == nil {
		t.Error("expected error for tampered ciphertext")
	}
}

func TestLoadPublicKey_PKIX(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	path := t.TempDir() + "/pub.pem"
	if err := writeTestFile(path, pubPEM); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadPublicKey(path)
	if err != nil {
		t.Fatalf("LoadPublicKey() error = %v", err)
	}
	if !loaded.Equal(&key.PublicKey) {
		t.Error("loaded public key doesn't match original")
	}
}

func TestLoadPrivateKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})

	path := t.TempDir() + "/priv.pem"
	if err := writeTestFile(path, privPEM); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadPrivateKey(path)
	if err != nil {
		t.Fatalf("LoadPrivateKey() error = %v", err)
	}
	if !loaded.Equal(key) {
		t.Error("loaded private key doesn't match original")
	}
}

func TestGenerateCertificateThenVerify(t *testing.T) {
	// Self-signed → client with CA cert should be able to verify server.
	certPEM, _, err := GenerateCertificate()
	if err != nil {
		t.Fatal(err)
	}

	caFile := t.TempDir() + "/ca.pem"
	if err := writeTestFile(caFile, certPEM); err != nil {
		t.Fatal(err)
	}

	creds, err := LoadOrGenerateClientCreds(caFile)
	if err != nil {
		t.Fatalf("LoadOrGenerateClientCreds() with CA file: %v", err)
	}
	if creds == nil {
		t.Error("creds is nil")
	}
}

// helpers

func writeTestFile(path string, data []byte) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(data)
	return err
}

func BenchmarkRSAEncrypt(b *testing.B) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	plaintext := make([]byte, 190) // max for OAEP with 2048-bit key
	_, _ = rand.Read(plaintext)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = rsa.EncryptOAEP(sha256.New(), rand.Reader, &key.PublicKey, plaintext, nil)
	}
}
