package cmd_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Deastrom/spyhop/internal/auth"
)

func TestBadRegion(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	r := spyhopEnv(t, map[string]string{}, "--region", "xx", "tools")
	got := run{r.Code, "", ""}
	got.Err = map[bool]string{true: "lists", false: r.Err}[strings.Contains(r.Err, "us, eu, au, in, sa")]
	if want := (run{2, "", "lists"}); got != want {
		t.Fatalf("got %+v (stderr %q), want %+v", got, r.Err, want)
	}
}

func TestAuthStatus(t *testing.T) {
	t.Run("given token mode", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir())
		r := spyhopEnv(t, map[string]string{"ORCA_TOKEN": "tok-secret", "ORCA_REGION": "eu"}, "auth", "status")
		t.Run("then it prints mode and endpoint, never the token", func(t *testing.T) {
			got := struct {
				Code           int
				Mode, Endpoint bool
				Leaked         bool
			}{r.Code, strings.Contains(r.Out, "token"), strings.Contains(r.Out, "https://api.eu.orcasecurity.io/mcp"), strings.Contains(r.Out+r.Err, "tok-secret")}
			if want := (struct {
				Code           int
				Mode, Endpoint bool
				Leaked         bool
			}{0, true, true, false}); got != want {
				t.Fatalf("got %+v, out %q", got, r.Out)
			}
		})
	})
	t.Run("given oauth mode", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir())
		exp := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
		auth.SaveTokens(&auth.Tokens{ClientID: "c", AccessToken: "acc-secret", RefreshToken: "ref-secret", ExpiresAt: exp})
		r := spyhopEnv(t, map[string]string{}, "auth", "status")
		t.Run("then it prints mode, endpoint and expiry, never tokens", func(t *testing.T) {
			got := struct {
				Code                   int
				Mode, Endpoint, Expiry bool
				Leaked                 bool
			}{r.Code, strings.Contains(r.Out, "oauth"), strings.Contains(r.Out, "https://mcp.orcasecurity.io/"),
				strings.Contains(r.Out, "2030-01-02T03:04:05Z"), strings.Contains(r.Out+r.Err, "secret")}
			if want := (struct {
				Code                   int
				Mode, Endpoint, Expiry bool
				Leaked                 bool
			}{0, true, true, true, false}); got != want {
				t.Fatalf("got %+v, out %q", got, r.Out)
			}
		})
	})
}

func TestAuthLogout(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	auth.SaveTokens(&auth.Tokens{ClientID: "c", AccessToken: "a", RefreshToken: "r"})
	r := spyhopEnv(t, map[string]string{}, "auth", "logout")
	_, statErr := os.Stat(filepath.Join(home, ".config", "spyhop", "tokens.json"))
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
