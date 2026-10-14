package auth_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Deastrom/spyhop/internal/auth"
)

// fakeOrca serves protected-resource metadata, AS metadata, DCR, token and
// revocation endpoints, recording what the client sent.
type fakeOrca struct {
	*httptest.Server
	mu          sync.Mutex
	registered  map[string]any
	tokenForms  []url.Values
	revoked     []url.Values
	authQuery   url.Values
	refreshFail bool
	challenge   string
}

func newFakeOrca(t *testing.T) *fakeOrca {
	t.Helper()
	f := &fakeOrca{}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"resource":              f.URL,
			"authorization_servers": []string{f.URL + "/as"},
		})
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server/as", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 f.URL + "/as",
			"authorization_endpoint": f.URL + "/as/authorize",
			"token_endpoint":         f.URL + "/as/token",
			"registration_endpoint":  f.URL + "/as/register",
			"revocation_endpoint":    f.URL + "/as/revoke",
		})
	})
	mux.HandleFunc("/as/register", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		json.NewDecoder(r.Body).Decode(&f.registered)
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{"client_id": "client-synth-1"})
	})
	mux.HandleFunc("/as/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		f.mu.Lock()
		f.tokenForms = append(f.tokenForms, r.PostForm)
		fail := f.refreshFail && r.PostForm.Get("grant_type") == "refresh_token"
		f.mu.Unlock()
		if fail {
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, `{"error":"invalid_grant"}`)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "access-synth-" + r.PostForm.Get("grant_type"), "refresh_token": "refresh-synth-2", "expires_in": 3600,
		})
	})
	mux.HandleFunc("/as/revoke", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		f.mu.Lock()
		f.revoked = append(f.revoked, r.PostForm)
		f.mu.Unlock()
	})
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	return f
}

// browser simulates the user approving the request: it follows the authorize
// URL's redirect_uri with a code.
func (f *fakeOrca) browser(t *testing.T) func(string) error {
	return func(authURL string) error {
		u, err := url.Parse(authURL)
		if err != nil {
			return err
		}
		f.mu.Lock()
		f.authQuery = u.Query()
		f.mu.Unlock()
		cb := u.Query().Get("redirect_uri") + "?code=code-synth&state=" + url.QueryEscape(u.Query().Get("state"))
		go func() {
			resp, err := http.Get(cb)
			if err == nil {
				resp.Body.Close()
			}
		}()
		return nil
	}
}

func TestLogin(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	f := newFakeOrca(t)

	var out strings.Builder
	tok, err := auth.Login(auth.LoginOptions{Resource: f.URL + "/", Open: f.browser(t), Out: &out}, "")
	if err == nil {
		err = auth.SaveTokens(tok)
	}
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	t.Run("given no stored credentials", func(t *testing.T) {
		t.Run("when login runs", func(t *testing.T) {
			t.Run("then DCR registers a public client with the fixed callback", func(t *testing.T) {
				got := map[string]any{
					"auth":     f.registered["token_endpoint_auth_method"],
					"redirect": f.registered["redirect_uris"],
				}
				want := map[string]any{"auth": "none", "redirect": []any{"http://127.0.0.1:19877/callback"}}
				if !jsonEqual(got, want) {
					t.Fatalf("got %v, want %v", got, want)
				}
			})
			t.Run("then the authorize URL carries PKCE S256 and the resource", func(t *testing.T) {
				q := f.authQuery
				got := []string{q.Get("response_type"), q.Get("client_id"), q.Get("code_challenge_method"), q.Get("resource")}
				want := []string{"code", "client-synth-1", "S256", f.URL + "/"}
				if !jsonEqual(got, want) {
					t.Fatalf("got %v, want %v", got, want)
				}
			})
			t.Run("then the authorize URL is printed", func(t *testing.T) {
				if !strings.Contains(out.String(), "/as/authorize?") {
					t.Fatalf("output %q lacks the authorize URL", out.String())
				}
			})
			t.Run("then the code exchange proves the PKCE verifier and sends resource", func(t *testing.T) {
				form := f.tokenForms[0]
				sum := sha256.Sum256([]byte(form.Get("code_verifier")))
				ok := base64.RawURLEncoding.EncodeToString(sum[:]) == f.authQuery.Get("code_challenge") &&
					form.Get("resource") == f.URL+"/" && form.Get("code") == "code-synth"
				if !ok {
					t.Fatalf("token form %v does not match challenge %q", form, f.authQuery.Get("code_challenge"))
				}
			})
			t.Run("then tokens.json is stored with mode 0600", func(t *testing.T) {
				p := filepath.Join(home, ".config", "spyhop", "tokens.json")
				st, err := os.Stat(p)
				stored, _ := auth.LoadTokens()
				got := struct {
					Mode           os.FileMode
					Client, Access string
					Refresh        string
				}{}
				if err == nil && stored != nil {
					got.Mode, got.Client, got.Access, got.Refresh = st.Mode().Perm(), stored.ClientID, stored.AccessToken, stored.RefreshToken
				}
				want := got
				want.Mode, want.Client, want.Access, want.Refresh = 0o600, "client-synth-1", "access-synth-authorization_code", "refresh-synth-2"
				if got != want {
					t.Fatalf("got %+v (err=%v), want %+v", got, err, want)
				}
			})
		})
	})
}

func TestSilentRefresh(t *testing.T) {
	f := newFakeOrca(t)
	expired := &auth.Tokens{ClientID: "client-synth-1", AccessToken: "old", RefreshToken: "refresh-synth-1",
		ExpiresAt: time.Now().Add(-time.Hour), Resource: f.URL + "/", TokenEndpoint: f.URL + "/as/token"}

	t.Run("given an expired access token and a valid refresh token", func(t *testing.T) {
		t.Run("when ensured valid", func(t *testing.T) {
			got, refreshed, err := auth.EnsureValid(expired)
			t.Run("then it refreshes with the refresh grant and resource", func(t *testing.T) {
				form := f.tokenForms[0]
				type res struct {
					Access            string
					Refreshed         bool
					Grant, RT, Resrce string
				}
				var g res
				if err == nil {
					g = res{got.AccessToken, refreshed, form.Get("grant_type"), form.Get("refresh_token"), form.Get("resource")}
				}
				want := res{"access-synth-refresh_token", true, "refresh_token", "refresh-synth-1", f.URL + "/"}
				if g != want {
					t.Fatalf("got %+v (err=%v), want %+v", g, err, want)
				}
			})
		})
	})
}

func TestRefreshFails(t *testing.T) {
	f := newFakeOrca(t)
	f.refreshFail = true
	expired := &auth.Tokens{AccessToken: "old", RefreshToken: "bad", ExpiresAt: time.Now().Add(-time.Hour),
		TokenEndpoint: f.URL + "/as/token"}

	_, _, err := auth.EnsureValid(expired)
	if err == nil || !strings.Contains(err.Error(), "run: spyhop auth login") {
		t.Fatalf("got %v, want error containing %q", err, "run: spyhop auth login")
	}
}

func TestResolveRefreshesAndSaves(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	f := newFakeOrca(t)
	auth.SaveTokens(&auth.Tokens{ClientID: "c", AccessToken: "old", RefreshToken: "r", ExpiresAt: time.Now().Add(-time.Hour),
		Resource: f.URL + "/", TokenEndpoint: f.URL + "/as/token"})

	s, err := auth.Resolve(envOf(map[string]string{"SPYHOP_MCP_URL": f.URL + "/"}), "")
	stored, _ := auth.LoadTokens()
	got := struct{ Header, Stored string }{}
	if err == nil {
		got.Header, got.Stored = s.AuthHeader, stored.AccessToken
	}
	want := struct{ Header, Stored string }{"Bearer access-synth-refresh_token", "access-synth-refresh_token"}
	if got != want {
		t.Fatalf("got %+v (err=%v), want %+v", got, err, want)
	}
}

func TestResolveNotLoggedIn(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	_, err := auth.Resolve(envOf(nil), "")
	if err == nil || !strings.Contains(err.Error(), "run: spyhop auth login") {
		t.Fatalf("got %v, want hint %q", err, "run: spyhop auth login")
	}
}

func TestLogout(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	f := newFakeOrca(t)
	tok := &auth.Tokens{ClientID: "c", AccessToken: "a", RefreshToken: "r-synth", ExpiresAt: time.Now().Add(time.Hour),
		RevocationEndpoint: f.URL + "/as/revoke"}
	auth.SaveTokens(tok)

	t.Run("given stored tokens", func(t *testing.T) {
		t.Run("when logout runs", func(t *testing.T) {
			revokeErr := auth.Revoke(tok)
			clearErr := auth.ClearTokens()
			after, _ := auth.LoadTokens()
			t.Run("then the refresh token is revoked and the file deleted", func(t *testing.T) {
				got := struct {
					Errs    [2]error
					Revoked string
					Gone    bool
				}{[2]error{revokeErr, clearErr}, f.revoked[0].Get("token"), after == nil}
				want := got
				want.Errs, want.Revoked, want.Gone = [2]error{}, "r-synth", true
				if got != want {
					t.Fatalf("got %+v, want %+v", got, want)
				}
			})
		})
	})
}

func jsonEqual(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}
