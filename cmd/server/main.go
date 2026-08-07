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

	"github.com/puzakov/gophkeeper-exam/internal/build"
	"github.com/puzakov/gophkeeper-exam/internal/config"
	"github.com/puzakov/gophkeeper-exam/internal/db"
	"github.com/puzakov/gophkeeper-exam/internal/logger"
	"github.com/puzakov/gophkeeper-exam/internal/server"
	"github.com/puzakov/gophkeeper-exam/internal/service"
	"github.com/puzakov/gophkeeper-exam/internal/storage"
	"github.com/puzakov/gophkeeper-exam/migrations"
	"go.uber.org/zap"
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
	flag.StringVar(&databaseDSN, "d", "postgres://gophkeeper_db_user:secret@localhost:5434/gophkeeper_db_app?sslmode=disable", "PostgreSQL DSN")
	flag.StringVar(&jwtSecret, "jwt-secret", "", "JWT signing secret")
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

	if err := logger.Initialize(cfg.LogLevel); err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize logger: %v\n", err)
		os.Exit(1)
	}

	if cfg.JWTSecret == "" {
		logger.Log.Fatal("JWT secret is required (set via -jwt-secret or JWT_SECRET env)")
	}

	if err := run(cfg); err != nil {
		logger.Log.Fatal("server error", zap.Error(err))
	}
}

func run(cfg *config.ServerConfig) error {
	ctx := context.Background()

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
	logger.Log.Info("database migrations applied")

	// Storage.
	store := storage.NewPostgresStorage(conn.Pool)

	// Services.
	authSvc := service.NewAuthService(store.Users, store.RefreshTokens, cfg.JWTSecret)
	secretSvc := service.NewSecretService(store.Secrets)
	syncSvc := service.NewSyncService(store.Secrets)

	// gRPC server.
	grpcSrv, err := server.NewGRPCServer(cfg, store, authSvc, secretSvc, syncSvc)
	if err != nil {
		return fmt.Errorf("gRPC server: %w", err)
	}

	// Graceful shutdown.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	errCh := make(chan error, 1)
	go func() {
		errCh <- grpcSrv.Serve()
	}()

	select {
	case err := <-errCh:
		return err
	case sig := <-quit:
		logger.Log.Info("received signal, shutting down", zap.String("signal", sig.String()))

		grpcSrv.GracefulStop()

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		<-shutdownCtx.Done()
		logger.Log.Info("server stopped")
		return nil
	}
}
