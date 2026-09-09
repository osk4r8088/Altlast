// Package paths resolves where Altlast stores cache and state, following the
// XDG Base Directory specification.
package paths

import (
	"fmt"
	"os"
	"path/filepath"
)

const appName = "altlast"

// Cache returns the directory for disposable data such as registry tag
// lists. Deleting it is always safe.
func Cache() (string, error) {
	return ensure(os.Getenv("XDG_CACHE_HOME"), ".cache")
}

// Data returns the directory for durable state, currently the database.
// Deleting it loses history.
func Data() (string, error) {
	return ensure(os.Getenv("XDG_DATA_HOME"), filepath.Join(".local", "share"))
}

// ensure resolves a base directory and creates the app subdirectory in it.
func ensure(envValue, fallback string) (string, error) {
	base := envValue
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("locating home directory: %w", err)
		}
		base = filepath.Join(home, fallback)
	}

	dir := filepath.Join(base, appName)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("creating %s: %w", dir, err)
	}
	return dir, nil
}
