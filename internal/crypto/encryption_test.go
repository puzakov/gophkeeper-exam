package crypto

import (
	"bytes"
	"testing"
)

func TestDeriveKey_Deterministic(t *testing.T) {
	salt := []byte("0123456789abcdef")
	params := DefaultKDFParams()

	k1 := DeriveKey("password", salt, params)
	k2 := DeriveKey("password", salt, params)

	if len(k1) != 32 {
		t.Errorf("key length = %d, want 32", len(k1))
	}
	if !bytes.Equal(k1, k2) {
		t.Error("DeriveKey is not deterministic")
	}
}

func TestDeriveKey_DifferentPassword(t *testing.T) {
	salt := []byte("0123456789abcdef")
	params := DefaultKDFParams()

	k1 := DeriveKey("password1", salt, params)
	k2 := DeriveKey("password2", salt, params)

	if bytes.Equal(k1, k2) {
		t.Error("different passwords produced same key")
	}
}

func TestDeriveKey_DifferentSalt(t *testing.T) {
	params := DefaultKDFParams()

	k1 := DeriveKey("password", []byte("salt111111111111"), params)
	k2 := DeriveKey("password", []byte("salt222222222222"), params)

	if bytes.Equal(k1, k2) {
		t.Error("different salts produced same key")
	}
}

func TestGenerateSalt(t *testing.T) {
	salt1, err := GenerateSalt()
	if err != nil {
		t.Fatal(err)
	}
	if len(salt1) != 16 {
		t.Errorf("salt length = %d, want 16", len(salt1))
	}

	salt2, err := GenerateSalt()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(salt1, salt2) {
		t.Error("two salts should not be equal")
	}
}

func TestGenerateDEK(t *testing.T) {
	dek, err := GenerateDEK()
	if err != nil {
		t.Fatal(err)
	}
	if len(dek) != 32 {
		t.Errorf("DEK length = %d, want 32", len(dek))
	}
}

func TestWrapUnwrapDEK(t *testing.T) {
	dek, _ := GenerateDEK()
	kek := DeriveKey("master", []byte("saltsaltsaltsalt"), DefaultKDFParams())

	wrapped, err := WrapDEK(dek, kek)
	if err != nil {
		t.Fatal(err)
	}

	unwrapped, err := UnwrapDEK(wrapped, kek)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(dek, unwrapped) {
		t.Error("DEK roundtrip failed")
	}
}

func TestUnwrapDEK_WrongKey(t *testing.T) {
	dek, _ := GenerateDEK()
	kek1 := DeriveKey("correct", []byte("salt"), DefaultKDFParams())
	kek2 := DeriveKey("wrong", []byte("salt"), DefaultKDFParams())

	wrapped, _ := WrapDEK(dek, kek1)
	_, err := UnwrapDEK(wrapped, kek2)
	if err == nil {
		t.Error("expected error with wrong key")
	}
}

func TestEncryptDecryptSecret(t *testing.T) {
	dek, _ := GenerateDEK()
	plaintext := []byte("my secret login data")

	ciphertext, err := EncryptSecret(plaintext, dek, "secret-1", 1)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := DecryptSecret(ciphertext, dek, "secret-1", 1)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Error("secret roundtrip failed")
	}
}

func TestDecryptSecret_WrongAAD(t *testing.T) {
	dek, _ := GenerateDEK()

	ciphertext, _ := EncryptSecret([]byte("data"), dek, "secret-1", 1)

	// Wrong ID.
	_, err := DecryptSecret(ciphertext, dek, "secret-2", 1)
	if err == nil {
		t.Error("expected error with wrong secret ID")
	}

	// Wrong version.
	_, err = DecryptSecret(ciphertext, dek, "secret-1", 2)
	if err == nil {
		t.Error("expected error with wrong version")
	}
}

func TestDecryptSecret_WrongKey(t *testing.T) {
	dek1, _ := GenerateDEK()
	dek2, _ := GenerateDEK()

	ciphertext, _ := EncryptSecret([]byte("data"), dek1, "s1", 1)
	_, err := DecryptSecret(ciphertext, dek2, "s1", 1)
	if err == nil {
		t.Error("expected error with wrong DEK")
	}
}

func TestDecryptSecret_Tampered(t *testing.T) {
	dek, _ := GenerateDEK()

	ciphertext, _ := EncryptSecret([]byte("data"), dek, "s1", 1)
	ciphertext[len(ciphertext)/2] ^= 0xff

	_, err := DecryptSecret(ciphertext, dek, "s1", 1)
	if err == nil {
		t.Error("expected error for tampered ciphertext")
	}
}

func TestEncryptDecryptMetadata(t *testing.T) {
	dek, _ := GenerateDEK()
	plaintext := []byte(`{"url":"example.com"}`)

	ciphertext, err := EncryptMetadata(plaintext, dek)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := DecryptMetadata(ciphertext, dek)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext, decrypted) {
		t.Error("metadata roundtrip failed")
	}
}

func TestKDFParams_MarshalRoundtrip(t *testing.T) {
	orig := DefaultKDFParams()
	data, err := MarshalKDFParams(orig)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := UnmarshalKDFParams(data)
	if err != nil {
		t.Fatal(err)
	}
	if orig.Memory != parsed.Memory || orig.Iterations != parsed.Iterations || orig.Parallelism != parsed.Parallelism {
		t.Errorf("KDF params mismatch: %+v vs %+v", orig, parsed)
	}
}

func TestEncrypt_InvalidKeySize(t *testing.T) {
	_, err := encrypt([]byte("data"), make([]byte, 16), nil)
	if err == nil {
		t.Error("expected error for 16-byte key")
	}
}
