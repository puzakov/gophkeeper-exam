package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultServerConfig(t *testing.T) {
	cfg := DefaultServerConfig()
	if cfg.Address == "" {
		t.Error("Address should have a default")
	}
	if cfg.GRPCAddress == "" {
		t.Error("GRPCAddress should have a default")
	}
	if cfg.LogLevel != "info" {
		t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, "info")
	}
	if cfg.JWTSecret != "" {
		t.Errorf("JWTSecret must have NO default, got %q", cfg.JWTSecret)
	}
	if cfg.DatabaseDSN != "" {
		t.Errorf("DatabaseDSN must have NO default, got %q", cfg.DatabaseDSN)
	}
}

func TestDefaultClientConfig(t *testing.T) {
	cfg := DefaultClientConfig()
	if cfg.ServerAddress == "" {
		t.Error("ServerAddress should have a default")
	}
	if cfg.ConfigDir == "" {
		t.Error("ConfigDir should have a default")
	}
}

func TestLoadServerConfigFile(t *testing.T) {
	yamlContent := `
address: "0.0.0.0:9090"
grpc_address: "0.0.0.0:50052"
database_dsn: "postgres://test:test@localhost:5432/testdb"
jwt_secret: "test-secret"
log_level: "debug"
`
	path := filepath.Join(t.TempDir(), "server.yaml")
	if err := os.WriteFile(path, []byte(yamlContent), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadServerConfigFile(path)
	if err != nil {
		t.Fatalf("LoadServerConfigFile() error = %v", err)
	}
	if cfg.Address != "0.0.0.0:9090" {
		t.Errorf("Address = %q", cfg.Address)
	}
	if cfg.GRPCAddress != "0.0.0.0:50052" {
		t.Errorf("GRPCAddress = %q", cfg.GRPCAddress)
	}
	if cfg.JWTSecret != "test-secret" {
		t.Errorf("JWTSecret = %q", cfg.JWTSecret)
	}
}

func TestLoadServerConfigFile_NotFound(t *testing.T) {
	_, err := LoadServerConfigFile("/nonexistent/path.yaml")
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestLoadServerConfigFile_InvalidYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invalid.yaml")
	if err := os.WriteFile(path, []byte("{{{invalid"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadServerConfigFile(path)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestMergeServerConfig_DefaultsOnly(t *testing.T) {
	cfg := MergeServerConfig(nil, nil)
	if cfg == nil {
		t.Fatal("cfg is nil")
	}
	if cfg.Address != "localhost:8080" {
		t.Errorf("default Address = %q", cfg.Address)
	}
}

func TestMergeServerConfig_FileOverridesDefaults(t *testing.T) {
	fileCfg := &ServerConfigFile{
		Address: "0.0.0.0:9090",
	}
	cfg := MergeServerConfig(nil, fileCfg)
	if cfg.Address != "0.0.0.0:9090" {
		t.Errorf("Address = %q, want 0.0.0.0:9090", cfg.Address)
	}
}

func TestMergeServerConfig_FlagsOverrideFile(t *testing.T) {
	fileCfg := &ServerConfigFile{Address: "from-file:9090"}
	flags := &ServerConfig{Address: "from-flags:9090"}
	cfg := MergeServerConfig(flags, fileCfg)
	if cfg.Address != "from-flags:9090" {
		t.Errorf("Address = %q, want from-flags:9090", cfg.Address)
	}
}

func TestMergeClientConfig(t *testing.T) {
	cfg := MergeClientConfig(nil, nil)
	if cfg == nil {
		t.Fatal("cfg is nil")
	}
	if cfg.ServerAddress != "localhost:50051" {
		t.Errorf("ServerAddress = %q", cfg.ServerAddress)
	}
}

func TestClientConfig_TokenPath(t *testing.T) {
	cfg := &ClientConfig{ConfigDir: "/home/user/.gophkeeper"}
	if cfg.TokenPath() != "/home/user/.gophkeeper/token.json" {
		t.Errorf("TokenPath() = %q", cfg.TokenPath())
	}
}

func TestClientConfig_ConfigPath(t *testing.T) {
	cfg := &ClientConfig{ConfigDir: "/home/user/.gophkeeper"}
	if cfg.ConfigPath() != "/home/user/.gophkeeper/config.yaml" {
		t.Errorf("ConfigPath() = %q", cfg.ConfigPath())
	}
}

func TestClientConfig_EnsureConfigDir(t *testing.T) {
	cfg := &ClientConfig{ConfigDir: filepath.Join(t.TempDir(), "newdir")}
	if err := cfg.EnsureConfigDir(); err != nil {
		t.Fatalf("EnsureConfigDir() error = %v", err)
	}

	fi, err := os.Stat(cfg.ConfigDir)
	if err != nil {
		t.Fatalf("stat config dir: %v", err)
	}
	if !fi.IsDir() {
		t.Error("config dir is not a directory")
	}
}
