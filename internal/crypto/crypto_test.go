package crypto

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"strings"
	"testing"
	"time"
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

// isolatedHome redirects the shared dev CA location into a temp dir.
func isolatedHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	return home
}

func TestLoadOrGenerateServerCreds(t *testing.T) {
	t.Run("generate with shared CA", func(t *testing.T) {
		isolatedHome(t)
		creds, err := LoadOrGenerateServerCreds("", "")
		if err != nil {
			t.Fatalf("LoadOrGenerateServerCreds() error = %v", err)
		}
		if creds == nil {
			t.Error("creds is nil")
		}
		// The shared CA must have been created.
		certPath, keyPath := DefaultCAPath()
		if _, err := os.Stat(certPath); err != nil {
			t.Errorf("shared CA cert not created: %v", err)
		}
		if _, err := os.Stat(keyPath); err != nil {
			t.Errorf("shared CA key not created: %v", err)
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
	isolatedHome(t)
	creds := MustLoadOrGenerateServerCreds()
	if creds == nil {
		t.Error("MustLoadOrGenerateServerCreds() returned nil")
	}
}

func TestLoadOrGenerateClientCreds(t *testing.T) {
	t.Run("dev mode generates shared CA", func(t *testing.T) {
		home := isolatedHome(t)
		creds, err := LoadOrGenerateClientCreds("")
		if err != nil {
			t.Fatalf("LoadOrGenerateClientCreds() error = %v", err)
		}
		if creds == nil {
			t.Error("creds is nil")
		}
		// The shared CA files must now exist.
		certPath, keyPath := DefaultCAPath()
		if _, err := os.Stat(certPath); err != nil {
			t.Errorf("shared CA cert not created: %v", err)
		}
		if _, err := os.Stat(keyPath); err != nil {
			t.Errorf("shared CA key not created: %v", err)
		}
		if !strings.HasPrefix(certPath, home) {
			t.Errorf("CA path %q not under isolated home %q", certPath, home)
		}
	})

	t.Run("reuses existing shared CA", func(t *testing.T) {
		home := isolatedHome(t)
		first, err := LoadOrGenerateClientCreds("")
		if err != nil {
			t.Fatal(err)
		}
		certPath, _ := DefaultCAPath()
		firstData, err := os.ReadFile(certPath)
		if err != nil {
			t.Fatal(err)
		}

		second, err := LoadOrGenerateClientCreds("")
		if err != nil {
			t.Fatal(err)
		}
		secondData, err := os.ReadFile(certPath)
		if err != nil {
			t.Fatal(err)
		}

		if first == nil || second == nil {
			t.Error("creds is nil")
		}
		if !bytes.Equal(firstData, secondData) {
			t.Error("shared CA file changed between calls")
		}
		if !strings.HasPrefix(certPath, home) {
			t.Errorf("CA path %q not under isolated home %q", certPath, home)
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
	isolatedHome(t)
	creds := MustLoadOrGenerateClientCreds()
	if creds == nil {
		t.Error("MustLoadOrGenerateClientCreds() returned nil")
	}
}

func TestGenerateServerCert(t *testing.T) {
	caCertPEM, caKeyPEM, err := GenerateCertificate()
	if err != nil {
		t.Fatal(err)
	}

	certPEM, keyPEM, err := GenerateServerCert(caCertPEM, caKeyPEM)
	if err != nil {
		t.Fatalf("GenerateServerCert() error = %v", err)
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		t.Error("empty server cert/key")
	}

	// Parse and verify the server cert is signed by the CA.
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("no PEM block in server cert")
	}
	serverCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	caBlock, _ := pem.Decode(caCertPEM)
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	if _, err := serverCert.Verify(x509.VerifyOptions{
		Roots:     roots,
		DNSName:   "localhost",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Errorf("server cert not verified against CA: %v", err)
	}
}

func TestLoadOrGenerateSharedCA_FirstUseAndReuse(t *testing.T) {
	home := isolatedHome(t)

	cert1, key1, err := LoadOrGenerateSharedCA()
	if err != nil {
		t.Fatal(err)
	}

	// Second call must return the same CA (no regeneration).
	cert2, key2, err := LoadOrGenerateSharedCA()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(cert1, cert2) || !bytes.Equal(key1, key2) {
		t.Error("shared CA regenerated on second call")
	}

	certPath, keyPath := DefaultCAPath()
	fi, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("CA key permissions = %o, want 600", fi.Mode().Perm())
	}
	if !strings.HasPrefix(certPath, home) {
		t.Errorf("CA path %q not under isolated home %q", certPath, home)
	}
}

// TestTLSHandshake_ClientVerifiesServer runs a real TLS handshake over
// net.Pipe: server uses the generated shared CA, client verifies it.
func TestTLSHandshake_ClientVerifiesServer(t *testing.T) {
	isolatedHome(t)

	serverCreds, err := LoadOrGenerateServerCreds("", "")
	if err != nil {
		t.Fatal(err)
	}
	clientCreds, err := LoadOrGenerateClientCreds("")
	if err != nil {
		t.Fatal(err)
	}

	serverRaw, clientRaw := net.Pipe()
	defer serverRaw.Close()
	defer clientRaw.Close()

	serverErrCh := make(chan error, 1)
	go func() {
		_, _, err := serverCreds.ServerHandshake(serverRaw)
		serverErrCh <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	clientConn, _, err := clientCreds.ClientHandshake(ctx, "localhost:50051", clientRaw)
	if err != nil {
		t.Fatalf("client handshake failed (verification broken?): %v", err)
	}
	defer clientConn.Close()

	if err := <-serverErrCh; err != nil {
		t.Fatalf("server handshake failed: %v", err)
	}
}

// TestTLSHandshake_ClientRejectsUnknownServer ensures the client fails the
// handshake when the server presents a certificate from an unknown CA —
// i.e. verification is really on.
func TestTLSHandshake_ClientRejectsUnknownServer(t *testing.T) {
	// Server CA lives in home A.
	t.Setenv("HOME", t.TempDir())
	serverCreds, err := LoadOrGenerateServerCreds("", "")
	if err != nil {
		t.Fatal(err)
	}

	// Client CA lives in home B (different CA).
	t.Setenv("HOME", t.TempDir())
	clientCreds, err := LoadOrGenerateClientCreds("")
	if err != nil {
		t.Fatal(err)
	}

	serverRaw, clientRaw := net.Pipe()
	defer serverRaw.Close()
	defer clientRaw.Close()

	serverErrCh := make(chan error, 1)
	go func() {
		_, _, err := serverCreds.ServerHandshake(serverRaw)
		serverErrCh <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, _, err = clientCreds.ClientHandshake(ctx, "localhost:50051", clientRaw)
	if err == nil {
		t.Error("expected handshake to fail with unknown server CA — verification is off")
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
