package cmd_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Deastrom/spyhop/internal/auth"
	"github.com/Deastrom/spyhop/internal/cache"
	"github.com/Deastrom/spyhop/internal/mcp"
)

var alertTools = []mcp.Tool{
	{Name: "get_alert", Description: "Get one alert. Returns the full record."},
	{Name: "get_alert_timeline", Description: "Timeline events of an alert."},
	{Name: "get_alerts_with_similar_alert_type", Description: "Find alerts of a similar type."},
	{Name: "discovery_search", Description: "Search assets by phrase.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"search_phrase":{"type":"string"},"limit":{"type":"integer"}}}`)},
}

// tokenRun runs the CLI in token mode with an explicit cache dir.
func tokenRun(t *testing.T, f *fakeMCP, cacheDir string, args ...string) run {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	return spyhopEnv(t, map[string]string{"ORCA_TOKEN": "tok-synth", "SPYHOP_MCP_URL": f.URL, "SPYHOP_CACHE_DIR": cacheDir}, args...)
}

func seed(t *testing.T, dir, mode, endpoint string, age time.Duration, tools []mcp.Tool) {
	t.Helper()
	s := &cache.Store{Dir: dir, Now: func() time.Time { return time.Now().Add(-age) }}
	if err := s.Save(mode, endpoint, tools); err != nil {
		t.Fatal(err)
	}
}

func cacheFiles(t *testing.T, dir string) []string {
	t.Helper()
	m, _ := filepath.Glob(filepath.Join(dir, "tools-*.json"))
	return m
}

func TestCacheHitMakesNoRequest(t *testing.T) {
	f := newFakeMCP(t)
	dir := t.TempDir()
	seed(t, dir, "token", f.URL, time.Hour, []mcp.Tool{{Name: "cached_tool", Description: "From cache. More."}})
	r := tokenRun(t, f, dir, "tools")
	got := struct {
		Run      run
		Requests int
	}{r, f.Requests}
	if want := (struct {
		Run      run
		Requests int
	}{run{0, "cached_tool\tFrom cache.\n", ""}, 0}); got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestCacheMissFetchesOnceAndWrites0600(t *testing.T) {
	f := newFakeMCP(t)
	f.Tools = alertTools
	dir := filepath.Join(t.TempDir(), "spyhop")
	r := tokenRun(t, f, dir, "tools")
	files := cacheFiles(t, dir)
	var mode os.FileMode
	if len(files) == 1 {
		st, _ := os.Stat(files[0])
		mode = st.Mode().Perm()
	}
	got := struct {
		Code, Lists, Files int
		Mode               os.FileMode
	}{r.Code, f.ListCalls, len(files), mode}
	if want := (struct {
		Code, Lists, Files int
		Mode               os.FileMode
	}{0, 1, 1, 0o600}); got != want {
		t.Fatalf("got %+v (stderr %q), want %+v", got, r.Err, want)
	}
}

func TestStaleCacheRefetches(t *testing.T) {
	f := newFakeMCP(t)
	f.Tools = alertTools
	dir := t.TempDir()
	seed(t, dir, "token", f.URL, 25*time.Hour, []mcp.Tool{{Name: "old_tool"}})
	r := tokenRun(t, f, dir, "tools")
	tools, fresh, _ := (&cache.Store{Dir: dir}).Load("token", f.URL)
	got := struct {
		Code, Lists, Cached int
		Fresh               bool
	}{r.Code, f.ListCalls, len(tools), fresh}
	if want := (struct {
		Code, Lists, Cached int
		Fresh               bool
	}{0, 1, len(alertTools), true}); got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestRefreshBypassesFreshCache(t *testing.T) {
	f := newFakeMCP(t)
	f.Tools = alertTools
	dir := t.TempDir()
	seed(t, dir, "token", f.URL, time.Minute, []mcp.Tool{{Name: "old_tool"}})
	r := tokenRun(t, f, dir, "tools", "--refresh")
	tools, _, _ := (&cache.Store{Dir: dir}).Load("token", f.URL)
	got := struct {
		Code, Lists, Cached int
	}{r.Code, f.ListCalls, len(tools)}
	if want := (struct{ Code, Lists, Cached int }{0, 1, len(alertTools)}); got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestEndpointIsolationAcrossModes(t *testing.T) {
	f := newFakeMCP(t)
	f.Tools = alertTools
	dir := t.TempDir()
	home := t.TempDir()
	t.Setenv("HOME", home)
	auth.SaveTokens(&auth.Tokens{ClientID: "c", AccessToken: "a", RefreshToken: "r", ExpiresAt: time.Now().Add(time.Hour)})
	spyhopEnv(t, map[string]string{"SPYHOP_MCP_URL": f.URL, "SPYHOP_CACHE_DIR": dir}, "tools")
	oauthFiles := cacheFiles(t, dir)
	before, _ := os.ReadFile(oauthFiles[0])
	spyhopEnv(t, map[string]string{"ORCA_TOKEN": "t", "SPYHOP_MCP_URL": f.URL, "SPYHOP_CACHE_DIR": dir}, "tools", "--refresh")
	after, _ := os.ReadFile(oauthFiles[0])
	got := struct {
		OAuthFiles, Files int
		Untouched         bool
	}{len(oauthFiles), len(cacheFiles(t, dir)), string(before) == string(after)}
	if want := (struct {
		OAuthFiles, Files int
		Untouched         bool
	}{1, 2, true}); got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestGrepAllMustMatch(t *testing.T) {
	f := newFakeMCP(t)
	f.Tools = alertTools
	r := tokenRun(t, f, t.TempDir(), "tools", "--grep", "alert", "--grep", "similar")
	if want := (run{0, "get_alerts_with_similar_alert_type\tFind alerts of a similar type.\n", ""}); r != want {
		t.Fatalf("got %+v, want %+v", r, want)
	}
}

func TestGrepMatchesDescriptionCaseInsensitively(t *testing.T) {
	f := newFakeMCP(t)
	f.Tools = alertTools
	r := tokenRun(t, f, t.TempDir(), "tools", "--grep", "BY PHRASE")
	if want := (run{0, "discovery_search\tSearch assets by phrase.\n", ""}); r != want {
		t.Fatalf("got %+v, want %+v", r, want)
	}
}

func TestGrepNoMatch(t *testing.T) {
	f := newFakeMCP(t)
	f.Tools = alertTools
	r := tokenRun(t, f, t.TempDir(), "tools", "--grep", "zzz")
	if want := (run{1, "", "no tools match\n"}); r != want {
		t.Fatalf("got %+v, want %+v", r, want)
	}
}

func TestCompleteToolNames(t *testing.T) {
	f := newFakeMCP(t)
	f.Tools = alertTools
	r := tokenRun(t, f, t.TempDir(), "__complete", "call", "get_al")
	want := run{0, "get_alert\tGet one alert.\nget_alert_timeline\tTimeline events of an alert.\n" +
		"get_alerts_with_similar_alert_type\tFind alerts of a similar type.\n:4\n", ""}
	if r != want {
		t.Fatalf("got %+v, want %+v", r, want)
	}
}

func TestCompleteArgKeys(t *testing.T) {
	f := newFakeMCP(t)
	f.Tools = alertTools
	r := tokenRun(t, f, t.TempDir(), "__complete", "call", "discovery_search", "--arg", "")
	if want := (run{0, "search_phrase=\nlimit=\n:6\n", ""}); r != want {
		t.Fatalf("got %+v, want %+v", r, want)
	}
}

func TestCompleteFixedValues(t *testing.T) {
	f := newFakeMCP(t)
	cases := map[string][]string{
		"open\nin_progress\nclosed\nsnoozed\ndismissed\n:4\n": {"__complete", "alert", "status", "orca-1", "--to", ""},
		"us\neu\nau\nin\nsa\n:4\n":                            {"__complete", "tools", "--region", ""},
		"text\njson\ntsv\n:4\n":                               {"__complete", "tools", "--format", ""},
	}
	for want, args := range cases {
		t.Run(strings.Join(args[1:], " "), func(t *testing.T) {
			r := tokenRun(t, f, t.TempDir(), args...)
			if r != (run{0, want, ""}) {
				t.Fatalf("got %+v, want out %q", r, want)
			}
			if f.Requests != 0 {
				t.Fatalf("fixed-value completion made %d requests", f.Requests)
			}
		})
	}
}

func TestCompleteOfflineUsesStaleCache(t *testing.T) {
	f := newFakeMCP(t)
	dir := t.TempDir()
	seed(t, dir, "token", f.URL, 48*time.Hour, []mcp.Tool{{Name: "stale_tool", Description: "Was cached."}})
	f.Close()
	r := tokenRun(t, f, dir, "__complete", "call", "")
	if want := (run{0, "stale_tool\tWas cached.\n:4\n", ""}); r != want {
		t.Fatalf("got %+v, want %+v", r, want)
	}
}

func TestCompleteWithoutCredentialsIsSilent(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	r := spyhopEnv(t, map[string]string{"SPYHOP_CACHE_DIR": t.TempDir()}, "__complete", "call", "")
	if want := (run{0, ":4\n", ""}); r != want {
		t.Fatalf("got %+v, want %+v", r, want)
	}
}

func TestStaleCacheAndUnauthorizedExit4(t *testing.T) {
	f := newFakeMCP(t)
	dir := t.TempDir()
	seed(t, dir, "token", f.URL, 48*time.Hour, []mcp.Tool{{Name: "stale_tool"}})
	f.Deny = true
	r := tokenRun(t, f, dir, "tools")
	if r.Code != 4 || !strings.Contains(r.Err, "unauthorized") || r.Out != "" {
		t.Fatalf("got %+v", r)
	}
}

func TestLogoutClearsDefaultCacheDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".cache", "spyhop")
	seed(t, dir, "oauth", "https://x/", time.Hour, alertTools)
	auth.SaveTokens(&auth.Tokens{ClientID: "c", AccessToken: "a", RefreshToken: "r"})
	r := spyhopEnv(t, map[string]string{}, "auth", "logout")
	_, statErr := os.Stat(dir)
	if got := (struct {
		Code int
		Gone bool
	}{r.Code, os.IsNotExist(statErr)}); got != (struct {
		Code int
		Gone bool
	}{0, true}) {
		t.Fatalf("got %+v, stderr %q", got, r.Err)
	}
}

func TestUnwritableCacheIsNotFatal(t *testing.T) {
	f := newFakeMCP(t)
	f.Tools = alertTools
	blocker := filepath.Join(t.TempDir(), "afile")
	_ = os.WriteFile(blocker, nil, 0o600)
	r := tokenRun(t, f, filepath.Join(blocker, "sub"), "tools", "--grep", "discovery")
	if want := (run{0, "discovery_search\tSearch assets by phrase.\n", ""}); r != want {
		t.Fatalf("got %+v, want %+v", r, want)
	}
}
