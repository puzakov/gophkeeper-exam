// Package config provides configuration parsing from command-line flags,
// environment variables and YAML config files for the server and client.
package config

import (
	"fmt"
	"os"

	"github.com/caarlos0/env/v6"
	"gopkg.in/yaml.v3"
)

// ServerConfig holds server configuration populated from environment variables,
// command-line flags and an optional YAML config file.
// Environment variables take precedence over flags, which take precedence over the config file.
type ServerConfig struct {
	Address     string `env:"ADDRESS"      yaml:"address"`
	GRPCAddress string `env:"GRPC_ADDRESS" yaml:"grpc_address"`
	DatabaseDSN string `env:"DATABASE_DSN" yaml:"database_dsn"`
	JWTSecret   string `env:"JWT_SECRET"   yaml:"jwt_secret"`
	TLSCert     string `env:"TLS_CERT"     yaml:"tls_cert"`
	TLSKey      string `env:"TLS_KEY"      yaml:"tls_key"`
	LogLevel    string `env:"LOG_LEVEL"    yaml:"log_level"`
}

// ServerConfigFile is the structure of the server's YAML config file.
type ServerConfigFile struct {
	Address     string `yaml:"address"`
	GRPCAddress string `yaml:"grpc_address"`
	DatabaseDSN string `yaml:"database_dsn"`
	JWTSecret   string `yaml:"jwt_secret"`
	TLSCert     string `yaml:"tls_cert"`
	TLSKey      string `yaml:"tls_key"`
	LogLevel    string `yaml:"log_level"`
}

// DefaultServerConfig returns a ServerConfig with safe defaults.
// Credentials (JWTSecret, DatabaseDSN) have NO defaults
func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		Address:     "localhost:8080",
		GRPCAddress: "localhost:50051",
		DatabaseDSN: "",
		JWTSecret:   "",
		LogLevel:    "info",
	}
}

// LoadServerConfigFile reads and parses a YAML config file at the given path.
func LoadServerConfigFile(path string) (*ServerConfigFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	var cfg ServerConfigFile
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config file: %w", err)
	}

	return &cfg, nil
}

// MergeServerConfig merges flag values, env vars and an optional config file
// into a single ServerConfig. Precedence: env vars > flags > config file > defaults.
func MergeServerConfig(flags *ServerConfig, fileCfg *ServerConfigFile) *ServerConfig {
	cfg := DefaultServerConfig()

	// Apply config file (lowest priority above defaults).
	if fileCfg != nil {
		applyFileCfg(cfg, fileCfg)
	}

	// Apply flags (higher priority than file).
	if flags != nil {
		applyFlags(cfg, flags)
	}

	// Apply env vars (highest priority).
	var envCfg ServerConfig
	if err := env.Parse(&envCfg); err != nil {
		fmt.Fprintf(os.Stderr, "error parsing env: %v\n", err)
	}
	applyEnv(cfg, &envCfg)

	return cfg
}

func applyFileCfg(cfg *ServerConfig, file *ServerConfigFile) {
	if file.Address != "" {
		cfg.Address = file.Address
	}
	if file.GRPCAddress != "" {
		cfg.GRPCAddress = file.GRPCAddress
	}
	if file.DatabaseDSN != "" {
		cfg.DatabaseDSN = file.DatabaseDSN
	}
	if file.JWTSecret != "" {
		cfg.JWTSecret = file.JWTSecret
	}
	if file.TLSCert != "" {
		cfg.TLSCert = file.TLSCert
	}
	if file.TLSKey != "" {
		cfg.TLSKey = file.TLSKey
	}
	if file.LogLevel != "" {
		cfg.LogLevel = file.LogLevel
	}
}

func applyFlags(cfg, flags *ServerConfig) {
	if flags.Address != "" {
		cfg.Address = flags.Address
	}
	if flags.GRPCAddress != "" {
		cfg.GRPCAddress = flags.GRPCAddress
	}
	if flags.DatabaseDSN != "" {
		cfg.DatabaseDSN = flags.DatabaseDSN
	}
	if flags.JWTSecret != "" {
		cfg.JWTSecret = flags.JWTSecret
	}
	if flags.TLSCert != "" {
		cfg.TLSCert = flags.TLSCert
	}
	if flags.TLSKey != "" {
		cfg.TLSKey = flags.TLSKey
	}
	if flags.LogLevel != "" {
		cfg.LogLevel = flags.LogLevel
	}
}

func applyEnv(cfg, env *ServerConfig) {
	if env.Address != "" {
		cfg.Address = env.Address
	}
	if env.GRPCAddress != "" {
		cfg.GRPCAddress = env.GRPCAddress
	}
	if env.DatabaseDSN != "" {
		cfg.DatabaseDSN = env.DatabaseDSN
	}
	if env.JWTSecret != "" {
		cfg.JWTSecret = env.JWTSecret
	}
	if env.TLSCert != "" {
		cfg.TLSCert = env.TLSCert
	}
	if env.TLSKey != "" {
		cfg.TLSKey = env.TLSKey
	}
	if env.LogLevel != "" {
		cfg.LogLevel = env.LogLevel
	}
}
