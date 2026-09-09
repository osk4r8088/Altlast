package resolve

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/osk4r8088/altlast/internal/paths"
)

// DefaultTTL is how long a cached tag list stays usable. Tag lists change
// rarely and registries rate limit aggressively, so this is generous.
const DefaultTTL = 6 * time.Hour

// cacheEntry is what we persist per repository.
type cacheEntry struct {
	FetchedAt time.Time `json:"fetched_at"`
	Tags      []string  `json:"tags"`
}

// tagCache stores tag lists on disk under the XDG cache directory.
type tagCache struct {
	dir string
	ttl time.Duration
}

func newTagCache(ttl time.Duration) (*tagCache, error) {
	base, err := paths.Cache()
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(base, "tags")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("creating tag cache: %w", err)
	}
	return &tagCache{dir: dir, ttl: ttl}, nil
}

// path derives a filename from the repository reference. Repositories
// contain slashes and registries contain dots and colons, none of which
// belong in a filename, so we hash instead of sanitising.
func (c *tagCache) path(registry, repository string) string {
	sum := sha256.Sum256([]byte(registry + "/" + repository))
	return filepath.Join(c.dir, hex.EncodeToString(sum[:])+".json")
}

// get returns cached tags when a fresh entry exists.
func (c *tagCache) get(registry, repository string) ([]string, bool) {
	data, err := os.ReadFile(c.path(registry, repository))
	if err != nil {
		return nil, false // missing or unreadable: treat as a miss
	}

	var entry cacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, false // corrupt: treat as a miss
	}

	if time.Since(entry.FetchedAt) > c.ttl {
		return nil, false
	}
	return entry.Tags, true
}

// put writes tags to the cache. Failures are returned but callers may
// reasonably ignore them: a cache miss is not a fatal condition.
func (c *tagCache) put(registry, repository string, tags []string) error {
	entry := cacheEntry{FetchedAt: time.Now(), Tags: tags}

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("encoding cache entry: %w", err)
	}

	// Write to a temporary file and rename, so an interrupted write never
	// leaves a half-written cache file behind. Rename is atomic on POSIX.
	final := c.path(registry, repository)
	tmp := final + ".tmp"

	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("writing cache: %w", err)
	}
	if err := os.Rename(tmp, final); err != nil {
		return fmt.Errorf("finalising cache: %w", err)
	}
	return nil
}
