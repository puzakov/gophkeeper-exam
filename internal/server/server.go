package server

import (
	"fmt"
	"net"

	"github.com/puzakov/gophkeeper-exam/internal/config"
	"github.com/puzakov/gophkeeper-exam/internal/crypto"
	"github.com/puzakov/gophkeeper-exam/internal/logger"
	"github.com/puzakov/gophkeeper-exam/internal/service"
	"github.com/puzakov/gophkeeper-exam/internal/storage"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"

	protov1 "github.com/puzakov/gophkeeper-exam/internal/proto/v1"
)

// GRPCServer wraps the gRPC server instance and its listener.
type GRPCServer struct {
	server   *grpc.Server
	listener net.Listener
	addr     string
}

// NewGRPCServer creates and configures the gRPC server with all services registered.
func NewGRPCServer(cfg *config.ServerConfig, store *storage.PostgresStorage, authSvc *service.AuthService, secretSvc *service.SecretService, syncSvc *service.SyncService) (*GRPCServer, error) {
	lis, err := net.Listen("tcp", cfg.GRPCAddress)
	if err != nil {
		return nil, fmt.Errorf("gRPC listen on %s: %w", cfg.GRPCAddress, err)
	}

	creds, err := loadTLSCreds(cfg)
	if err != nil {
		return nil, fmt.Errorf("TLS credentials: %w", err)
	}

	// Adapt auth service's ValidateAccessToken to return string.
	validateToken := func(tokenStr string) (string, error) {
		uid, err := authSvc.ValidateAccessToken(tokenStr)
		if err != nil {
			return "", err
		}
		return uid.String(), nil
	}

	srv := grpc.NewServer(
		grpc.Creds(creds),
		grpc.ChainUnaryInterceptor(
			LoggingInterceptor(),
			AuthInterceptor(validateToken),
		),
	)

	// Register services.
	protov1.RegisterAuthServiceServer(srv, NewAuthServer(authSvc))
	protov1.RegisterSecretServiceServer(srv, NewSecretServer(secretSvc))
	protov1.RegisterSyncServiceServer(srv, NewSyncServer(syncSvc))

	// Enable server reflection for debugging (e.g. grpcurl).
	reflection.Register(srv)

	return &GRPCServer{
		server:   srv,
		listener: lis,
		addr:     cfg.GRPCAddress,
	}, nil
}

// Serve starts the gRPC server and blocks until it stops.
func (s *GRPCServer) Serve() error {
	logger.Log.Info("gRPC server started", zap.String("addr", s.addr))
	return s.server.Serve(s.listener)
}

// GracefulStop stops the gRPC server gracefully.
func (s *GRPCServer) GracefulStop() {
	logger.Log.Info("gRPC server shutting down gracefully")
	s.server.GracefulStop()
}

// Addr returns the address the server is listening on.
func (s *GRPCServer) Addr() string {
	return s.addr
}

func loadTLSCreds(cfg *config.ServerConfig) (credentials.TransportCredentials, error) {
	if cfg.TLSCert != "" && cfg.TLSKey != "" {
		return crypto.LoadOrGenerateServerCreds(cfg.TLSCert, cfg.TLSKey)
	}
	return crypto.LoadOrGenerateServerCreds("", "")
}
