// Package crypto provides TLS certificate generation and loading helpers
// for gRPC server and client transport security.
//
// Dev mode: when no certificate files are configured, both sides use a shared
// self-signed CA stored at ~/.gophkeeper/ca.{pem,key}. Whoever starts first
// generates the CA and saves it; the other side loads it. The client ALWAYS
// verifies the server certificate against this CA — there is no mode that
// skips certificate verification.
package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/grpc/credentials"
)

// GenerateCertificate creates a self-signed CA certificate and returns
// the PEM-encoded certificate and private key.
func GenerateCertificate() (certPEM, keyPEM []byte, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("generate serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "gophkeeper dev CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:              []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create certificate: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	return certPEM, keyPEM, nil
}

// GenerateServerCert creates a server certificate for localhost signed by
// the given CA. Returns the PEM-encoded certificate and private key.
func GenerateServerCert(caCertPEM, caKeyPEM []byte) (certPEM, keyPEM []byte, err error) {
	caBlock, _ := pem.Decode(caCertPEM)
	if caBlock == nil {
		return nil, nil, errors.New("no PEM block found in CA certificate")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA certificate: %w", err)
	}

	keyBlock, _ := pem.Decode(caKeyPEM)
	if keyBlock == nil {
		return nil, nil, errors.New("no PEM block found in CA private key")
	}
	caKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA private key: %w", err)
	}

	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("generate server key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("generate serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "gophkeeper gRPC server",
		},
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:    []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create server certificate: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverKey)})

	return certPEM, keyPEM, nil
}

// DefaultCAPath returns the shared dev CA file paths
// (~/.gophkeeper/ca.pem and ~/.gophkeeper/ca.key).
func DefaultCAPath() (certPath, keyPath string) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		home = "."
	}
	dir := filepath.Join(home, ".gophkeeper")
	return filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key")
}

// LoadOrGenerateSharedCA loads the shared dev CA from its default location,
// generating and saving it on first use.
func LoadOrGenerateSharedCA() (certPEM, keyPEM []byte, err error) {
	certPath, keyPath := DefaultCAPath()

	if _, statErr := os.Stat(certPath); statErr == nil {
		certPEM, err = os.ReadFile(certPath)
		if err != nil {
			return nil, nil, fmt.Errorf("read shared CA certificate: %w", err)
		}
		keyPEM, err = os.ReadFile(keyPath)
		if err != nil {
			return nil, nil, fmt.Errorf("read shared CA private key: %w", err)
		}
		return certPEM, keyPEM, nil
	}

	certPEM, keyPEM, err = GenerateCertificate()
	if err != nil {
		return nil, nil, fmt.Errorf("generate shared CA: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
		return nil, nil, fmt.Errorf("create CA directory: %w", err)
	}
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return nil, nil, fmt.Errorf("write shared CA certificate: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, nil, fmt.Errorf("write shared CA private key: %w", err)
	}

	return certPEM, keyPEM, nil
}

// LoadOrGenerateServerCreds returns gRPC transport credentials for the server.
// If certFile and keyFile are both non-empty, the certificate is loaded from those files.
// Otherwise, a server certificate is issued from the shared dev CA
// (~/.gophkeeper/ca.pem), which is generated on first use.
func LoadOrGenerateServerCreds(certFile, keyFile string) (credentials.TransportCredentials, error) {
	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("load server TLS cert: %w", err)
		}
		return credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}), nil
	}

	caCertPEM, caKeyPEM, err := LoadOrGenerateSharedCA()
	if err != nil {
		return nil, err
	}

	serverCertPEM, serverKeyPEM, err := GenerateServerCert(caCertPEM, caKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("generate server cert: %w", err)
	}

	cert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse generated server cert: %w", err)
	}

	// Append the CA to the served chain so clients can verify it even with
	// an incomplete trust pool.
	if caBlock, _ := pem.Decode(caCertPEM); caBlock != nil {
		cert.Certificate = append(cert.Certificate, caBlock.Bytes)
	}

	return credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}), nil
}

// MustLoadOrGenerateServerCreds is like LoadOrGenerateServerCreds but panics on error.
// Useful in tests and startup code where failure is unexpected.
func MustLoadOrGenerateServerCreds() credentials.TransportCredentials {
	creds, err := LoadOrGenerateServerCreds("", "")
	if err != nil {
		panic("crypto: " + err.Error())
	}
	return creds
}

// LoadOrGenerateClientCreds returns gRPC transport credentials for the client
// with full server certificate verification.
//
// If caCertFile is non-empty, the server certificate is verified against that CA file.
// If caCertFile is empty, the shared dev CA (~/.gophkeeper/ca.pem) is used,
// generated on first use. Certificate verification is NEVER skipped.
func LoadOrGenerateClientCreds(caCertFile string) (credentials.TransportCredentials, error) {
	if caCertFile == "" {
		caCertPEM, _, err := LoadOrGenerateSharedCA()
		if err != nil {
			return nil, err
		}

		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caCertPEM) {
			return nil, errors.New("parse shared CA: no valid PEM block found")
		}

		return credentials.NewTLS(&tls.Config{
			RootCAs:    caPool,
			ServerName: "localhost",
			MinVersion: tls.VersionTLS12,
		}), nil
	}

	caData, err := os.ReadFile(caCertFile)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caData) {
		return nil, fmt.Errorf("parse CA cert: no valid PEM block found in %s", caCertFile)
	}

	return credentials.NewTLS(&tls.Config{
		RootCAs:    caPool,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS12,
	}), nil
}

// MustLoadOrGenerateClientCreds is like LoadOrGenerateClientCreds but panics on error.
// Useful in tests and startup code where failure is unexpected.
func MustLoadOrGenerateClientCreds() credentials.TransportCredentials {
	creds, err := LoadOrGenerateClientCreds("")
	if err != nil {
		panic("crypto: " + err.Error())
	}
	return creds
}
