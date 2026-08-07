// Package build holds build-time injected variables (version, date, commit)
// and provides PrintInfo to display them at application startup.
//
// Values are set via -ldflags at build time:
//
//	go build -ldflags "-X github.com/puzakov/gophkeeper-exam/internal/build.Version=1.0.0 -X github.com/puzakov/gophkeeper-exam/internal/build.Date=$(date +%Y-%m-%d) -X github.com/puzakov/gophkeeper-exam/internal/build.Commit=$(git rev-parse --short HEAD)"
package build

import "fmt"

// Build info variables — set via -ldflags.
var (
	Version string
	Date    string
	Commit  string
)

// PrintInfo prints the build version, date, and commit to stdout.
// Missing values are displayed as "N/A".
func PrintInfo() {
	valOrNA := func(s string) string {
		if s == "" {
			return "N/A"
		}
		return s
	}

	fmt.Printf("Build version: %s\n", valOrNA(Version))
	fmt.Printf("Build date: %s\n", valOrNA(Date))
	fmt.Printf("Build commit: %s\n", valOrNA(Commit))
}
