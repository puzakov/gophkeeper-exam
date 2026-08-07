// Package crypto provides TLS certificate generation and loading helpers
// for gRPC server and client transport security.
package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
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
			CommonName: "gophkeeper gRPC",
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

// LoadOrGenerateServerCreds returns gRPC transport credentials for the server.
// If certFile and keyFile are both non-empty, the certificate is loaded from those files.
// Otherwise, a self-signed certificate is generated in memory.
func LoadOrGenerateServerCreds(certFile, keyFile string) (credentials.TransportCredentials, error) {
	var cert tls.Certificate

	if certFile != "" && keyFile != "" {
		var err error
		cert, err = tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("load server TLS cert: %w", err)
		}
	} else {
		certPEM, keyPEM, err := GenerateCertificate()
		if err != nil {
			return nil, fmt.Errorf("generate server TLS cert: %w", err)
		}
		cert, err = tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return nil, fmt.Errorf("parse generated cert: %w", err)
		}
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

// LoadOrGenerateClientCreds returns gRPC transport credentials for the client.
// If caCertFile is non-empty, the server certificate is verified using the given CA file.
// Otherwise, server verification is skipped (InsecureSkipVerify) — suitable for development
// with self-signed certificates.
func LoadOrGenerateClientCreds(caCertFile string) (credentials.TransportCredentials, error) {
	if caCertFile != "" {
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

	// Dev mode: accept any server certificate (encrypted but not verified).
	return credentials.NewTLS(&tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
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
