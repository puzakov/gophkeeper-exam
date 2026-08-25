// Package term provides secure terminal input helpers for secrets.
package term

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"

	"golang.org/x/term"
)

// stdinReader is a shared buffered reader for non-TTY fallback input.
// A single instance avoids losing buffered data between successive reads.
var stdinReader = bufio.NewReader(os.Stdin)

// readLock serialises terminal reads (TTY mode doesn't share state,
// but non-TTY reads from the same reader must not interleave).
var readLock sync.Mutex

// ReadPassword prompts the user and reads a password from the terminal
// without echoing it. Falls back to plain stdin if the terminal is not a TTY.
func ReadPassword(prompt string) (string, error) {
	readLock.Lock()
	defer readLock.Unlock()

	fmt.Fprint(os.Stderr, prompt)

	if term.IsTerminal(int(os.Stdin.Fd())) {
		bytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr) // newline after password input
		if err != nil {
			return "", fmt.Errorf("read password: %w", err)
		}
		return string(bytes), nil
	}

	// Fallback for non-TTY input (pipes, scripts).
	line, err := stdinReader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// ReadPasswordWithConfirm prompts twice and checks that both entries match.
func ReadPasswordWithConfirm(prompt string) (string, error) {
	first, err := ReadPassword(prompt)
	if err != nil {
		return "", err
	}
	second, err := ReadPassword("Confirm password: ")
	if err != nil {
		return "", err
	}
	if first != second {
		return "", fmt.Errorf("passwords do not match")
	}
	return first, nil
}
