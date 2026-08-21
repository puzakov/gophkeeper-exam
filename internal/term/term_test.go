package term

import (
	"bufio"
	"os"
	"testing"
)

// setStdin replaces os.Stdin with the pipe's read end and resets the
// shared buffered reader so successive reads consume the piped data.
func setStdin(t *testing.T) *os.File {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdin
	os.Stdin = r
	stdinReader = bufio.NewReader(r)
	t.Cleanup(func() {
		os.Stdin = old
		_ = r.Close()
		_ = w.Close()
	})
	return w
}

func TestReadPassword_NonTTY(t *testing.T) {
	w := setStdin(t)

	go func() {
		_, _ = w.WriteString("secret123\n")
		_ = w.Close()
	}()

	got, err := ReadPassword("Prompt: ")
	if err != nil {
		t.Fatalf("ReadPassword() error = %v", err)
	}
	if got != "secret123" {
		t.Errorf("ReadPassword() = %q, want %q", got, "secret123")
	}
}

func TestReadPassword_NonTTY_CRLF(t *testing.T) {
	w := setStdin(t)

	go func() {
		_, _ = w.WriteString("secret456\r\n")
		_ = w.Close()
	}()

	got, err := ReadPassword("Prompt: ")
	if err != nil {
		t.Fatalf("ReadPassword() error = %v", err)
	}
	if got != "secret456" {
		t.Errorf("ReadPassword() = %q, want %q", got, "secret456")
	}
}

func TestReadPasswordWithConfirm_Match(t *testing.T) {
	w := setStdin(t)

	go func() {
		_, _ = w.WriteString("secret123\n")
		_, _ = w.WriteString("secret123\n")
		_ = w.Close()
	}()

	got, err := ReadPasswordWithConfirm("Prompt: ")
	if err != nil {
		t.Fatalf("ReadPasswordWithConfirm() error = %v", err)
	}
	if got != "secret123" {
		t.Errorf("ReadPasswordWithConfirm() = %q, want %q", got, "secret123")
	}
}

func TestReadPasswordWithConfirm_Mismatch(t *testing.T) {
	w := setStdin(t)

	go func() {
		_, _ = w.WriteString("secret123\n")
		_, _ = w.WriteString("different\n")
		_ = w.Close()
	}()

	_, err := ReadPasswordWithConfirm("Prompt: ")
	if err == nil {
		t.Error("expected error for mismatched passwords")
	}
}
