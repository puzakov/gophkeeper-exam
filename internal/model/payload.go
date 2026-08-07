package model

import (
	"encoding/json"
	"fmt"
)

// Payload types are the decrypted (client-side) representations of secrets.
// They are JSON-encoded before encryption and JSON-decoded after decryption.

// LoginPasswordPayload stores a login/password pair.
type LoginPasswordPayload struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

// TextPayload stores arbitrary text.
type TextPayload struct {
	Text string `json:"text"`
}

// BinaryPayload stores arbitrary binary data (base64-encoded in JSON).
type BinaryPayload struct {
	Data     []byte `json:"data"`
	FileName string `json:"file_name,omitempty"`
}

// BankCardPayload stores bank card information.
type BankCardPayload struct {
	Number     string `json:"number"`
	Expiry     string `json:"expiry"` // MM/YY
	CVV        string `json:"cvv"`
	HolderName string `json:"holder_name,omitempty"`
}

// Metadata is a flat key/value map for arbitrary text metadata.
type Metadata map[string]string

// EncodePayload marshals a payload to JSON bytes ready for encryption.
func EncodePayload(payload any) ([]byte, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode payload: %w", err)
	}
	return data, nil
}

// DecodePayload unmarshals JSON bytes into the appropriate payload type
// based on the secret type.
func DecodePayload(data []byte, st SecretType) (any, error) {
	switch st {
	case SecretTypeLoginPassword:
		var p LoginPasswordPayload
		if err := json.Unmarshal(data, &p); err != nil {
			return nil, fmt.Errorf("decode login_password payload: %w", err)
		}
		return &p, nil
	case SecretTypeText:
		var p TextPayload
		if err := json.Unmarshal(data, &p); err != nil {
			return nil, fmt.Errorf("decode text payload: %w", err)
		}
		return &p, nil
	case SecretTypeBinary:
		var p BinaryPayload
		if err := json.Unmarshal(data, &p); err != nil {
			return nil, fmt.Errorf("decode binary payload: %w", err)
		}
		return &p, nil
	case SecretTypeBankCard:
		var p BankCardPayload
		if err := json.Unmarshal(data, &p); err != nil {
			return nil, fmt.Errorf("decode bank_card payload: %w", err)
		}
		return &p, nil
	default:
		return nil, fmt.Errorf("unknown secret type: %d", st)
	}
}

// EncodeMetadata marshals metadata to JSON bytes ready for encryption.
func EncodeMetadata(m Metadata) ([]byte, error) {
	data, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("encode metadata: %w", err)
	}
	return data, nil
}

// DecodeMetadata unmarshals JSON bytes into a Metadata map.
func DecodeMetadata(data []byte) (Metadata, error) {
	var m Metadata
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("decode metadata: %w", err)
	}
	return m, nil
}
