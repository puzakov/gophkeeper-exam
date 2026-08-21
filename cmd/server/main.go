// GophKeeper server — gRPC service for secure password management.
package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/stdlib"
	"go.uber.org/zap"

	"github.com/puzakov/gophkeeper-exam/internal/build"
	"github.com/puzakov/gophkeeper-exam/internal/config"
	"github.com/puzakov/gophkeeper-exam/internal/db"
	"github.com/puzakov/gophkeeper-exam/internal/logger"
	"github.com/puzakov/gophkeeper-exam/internal/server"
	"github.com/puzakov/gophkeeper-exam/internal/service"
	"github.com/puzakov/gophkeeper-exam/internal/storage"
	"github.com/puzakov/gophkeeper-exam/migrations"
)

func main() {
	build.PrintInfo()

	var (
		address     string
		grpcAddress string
		databaseDSN string
		jwtSecret   string
		tlsCert     string
		tlsKey      string
		logLevel    string
		configFile  string
	)

	flag.StringVar(&address, "a", "localhost:8080", "HTTP server address")
	flag.StringVar(&grpcAddress, "g", "localhost:50051", "gRPC server address")
	flag.StringVar(&grpcAddress, "grpc", "localhost:50051", "gRPC server address")
	flag.StringVar(&databaseDSN, "d", "", "PostgreSQL DSN (required)")
	flag.StringVar(&jwtSecret, "jwt-secret", "", "JWT signing secret (required)")
	flag.StringVar(&tlsCert, "tls-cert", "", "TLS certificate path")
	flag.StringVar(&tlsKey, "tls-key", "", "TLS key path")
	flag.StringVar(&logLevel, "l", "info", "log level")
	flag.StringVar(&configFile, "c", "", "config file path")
	flag.StringVar(&configFile, "config", "", "config file path")
	flag.Parse()

	// Load config file (lowest priority).
	var fileCfg *config.ServerConfigFile
	if configFile != "" {
		var err error
		fileCfg, err = config.LoadServerConfigFile(configFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error loading config file: %v\n", err)
		}
	}

	flags := &config.ServerConfig{
		Address:     address,
		GRPCAddress: grpcAddress,
		DatabaseDSN: databaseDSN,
		JWTSecret:   jwtSecret,
		TLSCert:     tlsCert,
		TLSKey:      tlsKey,
		LogLevel:    logLevel,
	}

	cfg := config.MergeServerConfig(flags, fileCfg)

	// Build the root logger here and pass named children down explicitly.
	log, err := logger.New(cfg.LogLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = log.Sync() }()

	if cfg.DatabaseDSN == "" {
		log.Fatal("Database DSN is required (set via -d flag or DATABASE_DSN env)")
	}
	if cfg.JWTSecret == "" {
		log.Fatal("JWT secret is required (set via -jwt-secret or JWT_SECRET env)")
	}

	if err := run(cfg, log); err != nil {
		log.Fatal("server error", zap.Error(err))
	}
}

func run(cfg *config.ServerConfig, log *zap.Logger) error {
	ctx := context.Background()
	dbLog := log.With(zap.String("component", "db"))
	grpcLog := log.With(zap.String("component", "grpc-server"))

	// Database.
	conn, err := db.NewDatabaseConnection(ctx, cfg.DatabaseDSN)
	if err != nil {
		return fmt.Errorf("database connection: %w", err)
	}
	defer conn.Close()

	// Run migrations (watchdog pattern).
	sqlDB := stdlib.OpenDB(*conn.Pool.Config().ConnConfig)
	defer func(db *sql.DB) { _ = db.Close() }(sqlDB)
	if err := migrations.Up(sqlDB); err != nil {
		return fmt.Errorf("migrations: %w", err)
	}
	dbLog.Info("database migrations applied")

	// Storage.
	store := storage.NewPostgresStorage(conn.Pool)

	// Services.
	authSvc := service.NewAuthService(store.Users, store.RefreshTokens, cfg.JWTSecret)
	secretSvc := service.NewSecretService(store.Secrets)
	syncSvc := service.NewSyncService(store.Secrets)

	// gRPC server.
	grpcSrv, err := server.NewGRPCServer(cfg, store, authSvc, secretSvc, syncSvc, grpcLog)
	if err != nil {
		return fmt.Errorf("gRPC server: %w", err)
	}

	// Graceful shutdown: the signal context is cancelled on SIGINT/SIGTERM/
	// SIGQUIT and can be passed straight to child components.
	sigCtx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		errCh <- grpcSrv.Serve()
	}()

	select {
	case err := <-errCh:
		return err
	case <-sigCtx.Done():
		log.Info("received signal, shutting down", zap.Error(sigCtx.Err()))

		// GracefulStop blocks until all RPCs finish, so run it in a goroutine
		// and race it against the shutdown deadline.
		stopped := make(chan struct{})
		go func() {
			grpcSrv.GracefulStop()
			close(stopped)
		}()

		shutdownCtx, cancel := context.WithTimeout(sigCtx, 30*time.Second)
		defer cancel()

		select {
		case <-stopped:
			log.Info("server stopped gracefully")
		case <-shutdownCtx.Done():
			log.Warn("graceful shutdown timed out, forcing stop")
			grpcSrv.Stop()
			<-stopped
		}

		// Serve() returns nil after GracefulStop/Stop; drain it to avoid
		// leaking the goroutine result.
		<-errCh
		return nil
	}
}
