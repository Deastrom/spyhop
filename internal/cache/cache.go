// Package cache stores the MCP tool list on disk so listing and completion
// need no network round trip.
package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Deastrom/spyhop/internal/mcp"
)

// TTL is how long a cached tool list counts as fresh.
const TTL = 24 * time.Hour

// Store reads and writes tool lists under Dir.
type Store struct {
	Dir string
	Now func() time.Time // nil means time.Now
}

type entry struct {
	FetchedAt time.Time  `json:"fetched_at"`
	Tools     []mcp.Tool `json:"tools"`
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Path is the file for one auth mode and endpoint; the hash keeps OAuth and
// token caches (and different endpoints) apart.
func (s *Store) Path(mode, endpoint string) string {
	sum := sha256.Sum256([]byte(mode + "\n" + endpoint))
	return filepath.Join(s.Dir, "tools-"+hex.EncodeToString(sum[:8])+".json")
}

// Load returns the cached tools. found is false when there is no readable
// entry; fresh is false once the entry is older than TTL. Stale entries are
// still returned so completion can fall back to them.
func (s *Store) Load(mode, endpoint string) (tools []mcp.Tool, fresh, found bool) {
	data, err := os.ReadFile(s.Path(mode, endpoint))
	if err != nil {
		return nil, false, false
	}
	var e entry
	if json.Unmarshal(data, &e) != nil {
		return nil, false, false // corrupt cache is a miss, not an error
	}
	return e.Tools, s.now().Sub(e.FetchedAt) < TTL, true
}

// Save writes the tool list atomically (dir 0700, file 0600).
func (s *Store) Save(mode, endpoint string, tools []mcp.Tool) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return fmt.Errorf("create cache dir: %w", err)
	}
	data, err := json.Marshal(entry{FetchedAt: s.now(), Tools: tools})
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.Dir, ".spyhop-tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	name := tmp.Name()
	fail := func(err error) error {
		_ = tmp.Close()
		_ = os.Remove(name)
		return fmt.Errorf("write cache: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		return fail(err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		return fail(err)
	}
	if err := os.Rename(name, s.Path(mode, endpoint)); err != nil {
		return fail(err)
	}
	return nil
}

// Clear removes the whole cache dir; absent is not an error.
func (s *Store) Clear() error {
	return os.RemoveAll(s.Dir)
}
