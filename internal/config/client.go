package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/caarlos0/env/v6"
	"gopkg.in/yaml.v3"
)

// ClientConfig holds client configuration from flags, env vars and config file.
type ClientConfig struct {
	ServerAddress string `env:"GOPHKEEPER_SERVER_ADDRESS" yaml:"server_address"`
	TLSCAFile     string `env:"GOPHKEEPER_TLS_CA_FILE"   yaml:"tls_ca_file"`
	ConfigDir     string `env:"GOPHKEEPER_CONFIG_DIR"    yaml:"config_dir"`
}

// DefaultClientConfig returns a ClientConfig with safe defaults.
func DefaultClientConfig() *ClientConfig {
	home, _ := os.UserHomeDir()
	return &ClientConfig{
		ServerAddress: "localhost:50051",
		ConfigDir:     filepath.Join(home, ".gophkeeper"),
	}
}

// LoadClientConfigFile reads and parses the client's YAML config file.
func LoadClientConfigFile(path string) (*ClientConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	var cfg ClientConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config file: %w", err)
	}

	return &cfg, nil
}

// MergeClientConfig merges flag values, env vars and an optional config file
// into a single ClientConfig. Precedence: env vars > flags > config file > defaults.
func MergeClientConfig(flags *ClientConfig, fileCfg *ClientConfig) *ClientConfig {
	cfg := DefaultClientConfig()

	if fileCfg != nil {
		if fileCfg.ServerAddress != "" {
			cfg.ServerAddress = fileCfg.ServerAddress
		}
		if fileCfg.TLSCAFile != "" {
			cfg.TLSCAFile = fileCfg.TLSCAFile
		}
		if fileCfg.ConfigDir != "" {
			cfg.ConfigDir = fileCfg.ConfigDir
		}
	}

	if flags != nil {
		if flags.ServerAddress != "" {
			cfg.ServerAddress = flags.ServerAddress
		}
		if flags.TLSCAFile != "" {
			cfg.TLSCAFile = flags.TLSCAFile
		}
		if flags.ConfigDir != "" {
			cfg.ConfigDir = flags.ConfigDir
		}
	}

	var envCfg ClientConfig
	if err := env.Parse(&envCfg); err != nil {
		fmt.Fprintf(os.Stderr, "error parsing env: %v\n", err)
	}
	if envCfg.ServerAddress != "" {
		cfg.ServerAddress = envCfg.ServerAddress
	}
	if envCfg.TLSCAFile != "" {
		cfg.TLSCAFile = envCfg.TLSCAFile
	}
	if envCfg.ConfigDir != "" {
		cfg.ConfigDir = envCfg.ConfigDir
	}

	return cfg
}

// EnsureConfigDir creates the client config directory if it doesn't exist.
func (c *ClientConfig) EnsureConfigDir() error {
	return os.MkdirAll(c.ConfigDir, 0o700)
}

// TokenPath returns the path to the token file inside the config directory.
func (c *ClientConfig) TokenPath() string {
	return filepath.Join(c.ConfigDir, "token.json")
}

// CachePath returns the path to the local SQLite cache inside the config directory.
func (c *ClientConfig) CachePath() string {
	return filepath.Join(c.ConfigDir, "cache.db")
}

// ConfigPath returns the path to the YAML config file inside the config directory.
func (c *ClientConfig) ConfigPath() string {
	return filepath.Join(c.ConfigDir, "config.yaml")
}
