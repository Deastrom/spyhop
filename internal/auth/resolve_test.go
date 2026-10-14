package auth_test

import (
	"strings"
	"testing"

	"github.com/Deastrom/spyhop/internal/auth"
)

func envOf(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestMakePlan(t *testing.T) {
	type result struct {
		Mode, Endpoint, Token string
		ErrHasList            bool
	}
	cases := []struct {
		name   string
		env    map[string]string
		region string
		want   result
	}{
		{"given ORCA_TOKEN and ORCA_REGION=eu", map[string]string{"ORCA_TOKEN": "t0k", "ORCA_REGION": "eu"}, "",
			result{"token", "https://api.eu.orcasecurity.io/mcp", "t0k", false}},
		{"given ORCA_TOKEN and no region", map[string]string{"ORCA_TOKEN": "t0k"}, "",
			result{"token", "https://api.orcasecurity.io/mcp", "t0k", false}},
		{"given --region overriding ORCA_REGION", map[string]string{"ORCA_TOKEN": "t0k", "ORCA_REGION": "eu"}, "au",
			result{"token", "https://api.au.orcasecurity.io/mcp", "t0k", false}},
		{"given no ORCA_TOKEN", map[string]string{}, "",
			result{"oauth", "https://mcp.orcasecurity.io/", "", false}},
		{"given --region xx", map[string]string{}, "xx",
			result{"", "", "", true}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Run("when planned", func(t *testing.T) {
				p, err := auth.MakePlan(envOf(c.env), c.region)
				got := result{}
				if p != nil {
					got = result{p.Mode, p.Endpoint, p.Token, false}
				}
				if err != nil {
					got.ErrHasList = strings.Contains(err.Error(), "us, eu, au, in, sa")
				}
				t.Run("then it picks the mode, endpoint and token", func(t *testing.T) {
					if got != c.want {
						t.Fatalf("got %+v (err=%v), want %+v", got, err, c.want)
					}
				})
			})
		})
	}
}

func TestResolveTokenModeIgnoresStoredOAuth(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	s, err := auth.Resolve(envOf(map[string]string{"ORCA_TOKEN": "t0k"}), "")
	if err != nil || s.AuthHeader != "Token t0k" {
		t.Fatalf("got (%+v, %v), want AuthHeader %q", s, err, "Token t0k")
	}
}
