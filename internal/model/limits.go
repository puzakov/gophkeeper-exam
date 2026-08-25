package model

// Size limits for binary secrets.
//
// The gRPC protocol uses unary calls with a 4 MiB default message limit,
// which we raise explicitly (see internal/server and internal/client).
// Limits are variables so tests can tighten them.
var (
	// MaxBinaryFileSize is the maximum plaintext file size a client accepts
	// for a binary secret. Clients check the file size BEFORE reading it
	// into memory (fail fast).
	MaxBinaryFileSize int64 = 10 << 20 // 10 MiB

	// MaxEncryptedSecretSize is the maximum size of the encrypted blob the
	// server accepts. It exceeds MaxBinaryFileSize to account for base64
	// inflation (4/3), JSON envelope, and GCM nonce/tag overhead.
	MaxEncryptedSecretSize int64 = 16 << 20 // 16 MiB

	// GRPCMaxMsgSize is the gRPC message limit configured on both sides.
	// It is comfortably above MaxEncryptedSecretSize so application-level
	// checks trigger before the transport-level limit.
	GRPCMaxMsgSize int = 32 << 20 // 32 MiB
)
