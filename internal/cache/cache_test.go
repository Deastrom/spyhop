package cache_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Deastrom/spyhop/internal/cache"
	"github.com/Deastrom/spyhop/internal/mcp"
)

var tools = []mcp.Tool{{Name: "get_alert", Description: "Get one alert."}}

func TestSaveThenLoad(t *testing.T) {
	s := &cache.Store{Dir: filepath.Join(t.TempDir(), "spyhop")}
	err := s.Save("oauth", "https://x/", tools)
	got, fresh, found := s.Load("oauth", "https://x/")
	st, statErr := os.Stat(s.Path("oauth", "https://x/"))
	dir, _ := os.Stat(s.Dir)
	type res struct {
		Err        error
		Name       string
		Fresh, Hit bool
		File, Dir  os.FileMode
	}
	var g res
	if len(got) == 1 && statErr == nil {
		g = res{err, got[0].Name, fresh, found, st.Mode().Perm(), dir.Mode().Perm()}
	}
	if want := (res{nil, "get_alert", true, true, 0o600, 0o700}); g != want {
		t.Fatalf("got %+v (err=%v statErr=%v), want %+v", g, err, statErr, want)
	}
}

func TestStaleAfterTTL(t *testing.T) {
	dir := t.TempDir()
	old := &cache.Store{Dir: dir, Now: func() time.Time { return time.Now().Add(-cache.TTL - time.Minute) }}
	_ = old.Save("oauth", "https://x/", tools)
	got, fresh, found := (&cache.Store{Dir: dir}).Load("oauth", "https://x/")
	if len(got) != 1 || fresh || !found {
		t.Fatalf("got (%d tools, fresh=%v, found=%v), want 1 stale found tool", len(got), fresh, found)
	}
}

func TestModeAndEndpointIsolated(t *testing.T) {
	s := &cache.Store{Dir: t.TempDir()}
	_ = s.Save("oauth", "https://x/", tools)
	_, _, otherMode := s.Load("token", "https://x/")
	_, _, otherEndpoint := s.Load("oauth", "https://y/")
	if otherMode || otherEndpoint || s.Path("oauth", "https://x/") == s.Path("token", "https://x/") {
		t.Fatalf("cache entries leak across mode/endpoint (mode=%v endpoint=%v)", otherMode, otherEndpoint)
	}
}

func TestMissingIsNotFound(t *testing.T) {
	_, _, found := (&cache.Store{Dir: t.TempDir()}).Load("oauth", "https://x/")
	if found {
		t.Fatal("found a cache entry in an empty dir")
	}
}

func TestClearRemovesDir(t *testing.T) {
	s := &cache.Store{Dir: filepath.Join(t.TempDir(), "spyhop")}
	_ = s.Save("oauth", "https://x/", tools)
	err := s.Clear()
	_, statErr := os.Stat(s.Dir)
	if err != nil || !os.IsNotExist(statErr) {
		t.Fatalf("got (err=%v, stat=%v), want removed dir", err, statErr)
	}
}

func TestClearMissingDirIsNotAnError(t *testing.T) {
	if err := (&cache.Store{Dir: filepath.Join(t.TempDir(), "none")}).Clear(); err != nil {
		t.Fatalf("got %v, want nil", err)
	}
}

func TestSaveFailsWhenDirUnwritable(t *testing.T) {
	file := filepath.Join(t.TempDir(), "afile")
	_ = os.WriteFile(file, nil, 0o600)
	if err := (&cache.Store{Dir: filepath.Join(file, "sub")}).Save("oauth", "https://x/", tools); err == nil {
		t.Fatal("expected an error saving under a regular file")
	}
}
