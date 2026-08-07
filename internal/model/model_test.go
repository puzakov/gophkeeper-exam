package model

import (
	"testing"
)

func TestSecretType_String(t *testing.T) {
	tests := []struct {
		name string
		st   SecretType
		want string
	}{
		{"login_password", SecretTypeLoginPassword, "login_password"},
		{"text", SecretTypeText, "text"},
		{"binary", SecretTypeBinary, "binary"},
		{"bank_card", SecretTypeBankCard, "bank_card"},
		{"unspecified", SecretTypeUnspecified, "unknown"},
		{"invalid", SecretType(99), "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.st.String(); got != tt.want {
				t.Errorf("SecretType(%d).String() = %q, want %q", tt.st, got, tt.want)
			}
		})
	}
}

func TestSecretType_Valid(t *testing.T) {
	tests := []struct {
		st    SecretType
		valid bool
	}{
		{SecretTypeUnspecified, false},
		{SecretTypeLoginPassword, true},
		{SecretTypeText, true},
		{SecretTypeBinary, true},
		{SecretTypeBankCard, true},
		{SecretType(99), false},
		{SecretType(0), false},
	}
	for _, tt := range tests {
		if got := tt.st.Valid(); got != tt.valid {
			t.Errorf("SecretType(%d).Valid() = %v, want %v", tt.st, got, tt.valid)
		}
	}
}

func TestEncodeDecodePayload(t *testing.T) {
	t.Run("login_password", func(t *testing.T) {
		orig := &LoginPasswordPayload{Login: "user@example.com", Password: "s3cret!"}
		data, err := EncodePayload(orig)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodePayload(data, SecretTypeLoginPassword)
		if err != nil {
			t.Fatal(err)
		}
		p, ok := decoded.(*LoginPasswordPayload)
		if !ok {
			t.Fatalf("unexpected type: %T", decoded)
		}
		if p.Login != orig.Login || p.Password != orig.Password {
			t.Errorf("roundtrip mismatch: %+v vs %+v", orig, p)
		}
	})

	t.Run("text", func(t *testing.T) {
		orig := &TextPayload{Text: "hello world"}
		data, _ := EncodePayload(orig)
		decoded, err := DecodePayload(data, SecretTypeText)
		if err != nil {
			t.Fatal(err)
		}
		p := decoded.(*TextPayload)
		if p.Text != orig.Text {
			t.Errorf("roundtrip mismatch: %q vs %q", orig.Text, p.Text)
		}
	})

	t.Run("binary", func(t *testing.T) {
		orig := &BinaryPayload{Data: []byte{0x00, 0xff, 0x42}, FileName: "secret.bin"}
		data, _ := EncodePayload(orig)
		decoded, err := DecodePayload(data, SecretTypeBinary)
		if err != nil {
			t.Fatal(err)
		}
		p := decoded.(*BinaryPayload)
		if len(p.Data) != len(orig.Data) || p.FileName != orig.FileName {
			t.Errorf("roundtrip mismatch")
		}
	})

	t.Run("bank_card", func(t *testing.T) {
		orig := &BankCardPayload{
			Number:     "4111111111111111",
			Expiry:     "12/28",
			CVV:        "123",
			HolderName: "IVAN PETROV",
		}
		data, _ := EncodePayload(orig)
		decoded, err := DecodePayload(data, SecretTypeBankCard)
		if err != nil {
			t.Fatal(err)
		}
		p := decoded.(*BankCardPayload)
		if p.Number != orig.Number || p.CVV != orig.CVV {
			t.Errorf("roundtrip mismatch")
		}
	})

	t.Run("unknown_type", func(t *testing.T) {
		_, err := DecodePayload([]byte(`{}`), SecretType(99))
		if err == nil {
			t.Error("expected error for unknown type")
		}
	})
}

func TestEncodeDecodeMetadata(t *testing.T) {
	orig := Metadata{"url": "https://example.com", "notes": "personal account"}
	data, err := EncodeMetadata(orig)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeMetadata(data)
	if err != nil {
		t.Fatal(err)
	}
	if decoded["url"] != orig["url"] || decoded["notes"] != orig["notes"] {
		t.Errorf("roundtrip mismatch: %+v vs %+v", orig, decoded)
	}
}

func TestDecodeMetadata_Empty(t *testing.T) {
	m, err := DecodeMetadata([]byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 0 {
		t.Errorf("expected empty map, got %d entries", len(m))
	}
}
