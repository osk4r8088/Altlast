package enrich

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

// jsonCache stores API responses on disk under the XDG cache directory.
type jsonCache struct {
	dir string
	ttl time.Duration
}

type jsonCacheEntry struct {
	FetchedAt time.Time       `json:"fetched_at"`
	Payload   json.RawMessage `json:"payload"`
}

func newJSONCache(name string, ttl time.Duration) (*jsonCache, error) {
	base, err := paths.Cache()
	if err != nil {
		return nil, err
	}

	dir := filepath.Join(base, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("creating %s cache: %w", name, err)
	}
	return &jsonCache{dir: dir, ttl: ttl}, nil
}

func (c *jsonCache) path(key string) string {
	sum := sha256.Sum256([]byte(key))
	return filepath.Join(c.dir, hex.EncodeToString(sum[:])+".json")
}

// get decodes a fresh cache entry into dst. It reports false on a miss,
// stale entry, or any read error: a cache problem is never fatal.
func (c *jsonCache) get(key string, dst any) bool {
	data, err := os.ReadFile(c.path(key))
	if err != nil {
		return false
	}

	var entry jsonCacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return false
	}
	if time.Since(entry.FetchedAt) > c.ttl {
		return false
	}
	return json.Unmarshal(entry.Payload, dst) == nil
}

func (c *jsonCache) put(key string, payload any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encoding payload: %w", err)
	}

	data, err := json.Marshal(jsonCacheEntry{FetchedAt: time.Now(), Payload: raw})
	if err != nil {
		return fmt.Errorf("encoding cache entry: %w", err)
	}

	// Write to a temporary file and rename, so an interrupted write never
	// leaves a half-written cache file behind.
	//
	// The temporary name must be unique per write, not per key: assets that
	// map to the same product are looked up concurrently, and a shared name
	// would let one writer rename the other's partial file.
	final := c.path(key)
	tmp, err := os.CreateTemp(c.dir, filepath.Base(final)+".*.tmp")
	if err != nil {
		return fmt.Errorf("creating cache file: %w", err)
	}
	// After a successful rename the temporary name no longer exists and this
	// fails harmlessly. On any earlier failure it removes the partial file.
	defer func() { _ = os.Remove(tmp.Name()) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("writing cache: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("writing cache: %w", err)
	}
	if err := os.Rename(tmp.Name(), final); err != nil {
		return fmt.Errorf("finalising cache: %w", err)
	}
	return nil
}
