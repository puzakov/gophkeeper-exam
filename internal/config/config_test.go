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

func TestMergeServerConfig_EnvOverridesFlags(t *testing.T) {
	t.Setenv("ADDRESS", "env-addr:9090")
	t.Setenv("GRPC_ADDRESS", "env-grpc:50052")
	t.Setenv("DATABASE_DSN", "postgres://env")
	t.Setenv("JWT_SECRET", "env-secret")
	t.Setenv("TLS_CERT", "/env/cert.pem")
	t.Setenv("TLS_KEY", "/env/key.pem")
	t.Setenv("LOG_LEVEL", "debug")

	flags := &ServerConfig{
		Address:     "flag-addr:8080",
		GRPCAddress: "flag-grpc:50051",
		DatabaseDSN: "postgres://flag",
		JWTSecret:   "flag-secret",
		TLSCert:     "/flag/cert.pem",
		TLSKey:      "/flag/key.pem",
		LogLevel:    "info",
	}

	cfg := MergeServerConfig(flags, nil)

	checks := map[string]struct{ got, want string }{
		"Address":     {cfg.Address, "env-addr:9090"},
		"GRPCAddress": {cfg.GRPCAddress, "env-grpc:50052"},
		"DatabaseDSN": {cfg.DatabaseDSN, "postgres://env"},
		"JWTSecret":   {cfg.JWTSecret, "env-secret"},
		"TLSCert":     {cfg.TLSCert, "/env/cert.pem"},
		"TLSKey":      {cfg.TLSKey, "/env/key.pem"},
		"LogLevel":    {cfg.LogLevel, "debug"},
	}
	for name, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q (env must override flags)", name, c.got, c.want)
		}
	}
}

func TestMergeServerConfig_FileThenFlagsThenEnv(t *testing.T) {
	t.Setenv("ADDRESS", "env-addr:9090")

	fileCfg := &ServerConfigFile{Address: "file-addr:7070", GRPCAddress: "file-grpc:7000"}
	flags := &ServerConfig{Address: "flag-addr:8080"}

	cfg := MergeServerConfig(flags, fileCfg)

	// Env > flags > file.
	if cfg.Address != "env-addr:9090" {
		t.Errorf("Address = %q, want env-addr:9090", cfg.Address)
	}
	// GRPCAddress: no env, no flag → from file.
	if cfg.GRPCAddress != "file-grpc:7000" {
		t.Errorf("GRPCAddress = %q, want file-grpc:7000", cfg.GRPCAddress)
	}
	// JWTSecret: nothing anywhere → no default.
	if cfg.JWTSecret != "" {
		t.Errorf("JWTSecret = %q, want empty", cfg.JWTSecret)
	}
}

func TestMergeClientConfig_EnvOverridesFlags(t *testing.T) {
	t.Setenv("GOPHKEEPER_SERVER_ADDRESS", "env:50051")
	t.Setenv("GOPHKEEPER_TLS_CA_FILE", "/env/ca.pem")
	t.Setenv("GOPHKEEPER_CONFIG_DIR", "/env/config")

	flags := &ClientConfig{
		ServerAddress: "flag:50051",
		TLSCAFile:     "/flag/ca.pem",
		ConfigDir:     "/flag/config",
	}

	cfg := MergeClientConfig(flags, nil)

	if cfg.ServerAddress != "env:50051" {
		t.Errorf("ServerAddress = %q, want env:50051", cfg.ServerAddress)
	}
	if cfg.TLSCAFile != "/env/ca.pem" {
		t.Errorf("TLSCAFile = %q, want /env/ca.pem", cfg.TLSCAFile)
	}
	if cfg.ConfigDir != "/env/config" {
		t.Errorf("ConfigDir = %q, want /env/config", cfg.ConfigDir)
	}
}

func TestMergeClientConfig_FileThenFlags(t *testing.T) {
	fileCfg := &ClientConfig{ServerAddress: "file:50051"}
	flags := &ClientConfig{ServerAddress: "flag:50051", TLSCAFile: "/flag/ca.pem"}

	cfg := MergeClientConfig(flags, fileCfg)

	if cfg.ServerAddress != "flag:50051" {
		t.Errorf("ServerAddress = %q, want flag:50051", cfg.ServerAddress)
	}
	if cfg.TLSCAFile != "/flag/ca.pem" {
		t.Errorf("TLSCAFile = %q, want /flag/ca.pem", cfg.TLSCAFile)
	}
}

func TestLoadClientConfigFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.yaml")
	yamlContent := "server_address: \"remote:50051\"\ntls_ca_file: \"/ca.pem\"\n"
	if err := os.WriteFile(path, []byte(yamlContent), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadClientConfigFile(path)
	if err != nil {
		t.Fatalf("LoadClientConfigFile() error = %v", err)
	}
	if cfg.ServerAddress != "remote:50051" || cfg.TLSCAFile != "/ca.pem" {
		t.Errorf("LoadClientConfigFile() = %+v", cfg)
	}
}

func TestLoadClientConfigFile_NotFound(t *testing.T) {
	_, err := LoadClientConfigFile("/nonexistent.yaml")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoadClientConfigFile_InvalidYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(path, []byte("not: [valid: yaml"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadClientConfigFile(path)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}
