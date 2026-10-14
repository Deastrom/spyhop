//go:build contract

// Package contract verifies spyhop's MCP client and OAuth flow against local
// servers that enforce the specs (MCP Streamable HTTP, RFC 9728/8414
// discovery, RFC 7591 DCR, PKCE S256, RFC 8707 resource). No live
// credentials needed.
//
// Run with: mise run test:contract
package contract

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Deastrom/spyhop/internal/auth"
	"github.com/Deastrom/spyhop/internal/mcp"
)

const testSessionID = "test-session-abc123"

// mcpServer enforces: initialize first without a session, session id on every
// later request, notifications/initialized before other methods, dual Accept,
// JSON content type, and the exact Authorization header wantAuth.
func mcpServer(t *testing.T, wantAuth string, tools func(w http.ResponseWriter, req mcp.Request)) *httptest.Server {
	t.Helper()
	initialized, notified := false, false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != wantAuth {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		accept := r.Header.Get("Accept")
		if !strings.Contains(accept, "application/json") || !strings.Contains(accept, "text/event-stream") {
			t.Errorf("Accept must list application/json and text/event-stream, got %q", accept)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}
		var req mcp.Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("invalid JSON-RPC request: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		sid := r.Header.Get("Mcp-Session-Id")
		if req.Method != "initialize" && sid != testSessionID {
			t.Errorf("%s sent with Mcp-Session-Id %q, want %q", req.Method, sid, testSessionID)
		}
		switch req.Method {
		case "initialize":
			if sid != "" {
				t.Errorf("initialize must not carry Mcp-Session-Id")
			}
			w.Header().Set("Mcp-Session-Id", testSessionID)
			b, _ := json.Marshal(mcp.InitializeResult{ProtocolVersion: "2025-03-26", ServerInfo: mcp.ClientInfo{Name: "contract"}})
			json.NewEncoder(w).Encode(mcp.Response{JSONRPC: "2.0", ID: req.ID, Result: b})
			initialized = true
		case "notifications/initialized":
			if !initialized {
				t.Error("notifications/initialized before initialize")
			}
			notified = true
			w.WriteHeader(http.StatusAccepted)
		default:
			if !notified {
				t.Errorf("%s before notifications/initialized", req.Method)
			}
			if tools != nil {
				tools(w, req)
			}
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func reply(w http.ResponseWriter, req mcp.Request, result any) {
	b, _ := json.Marshal(result)
	json.NewEncoder(w).Encode(mcp.Response{JSONRPC: "2.0", ID: req.ID, Result: b})
}

func TestContractInitializeThenCallCarriesSession(t *testing.T) {
	srv := mcpServer(t, "Token t", func(w http.ResponseWriter, req mcp.Request) {
		reply(w, req, mcp.ToolCallResult{Content: []mcp.Content{{Type: "text", Text: "ok"}}})
	})
	res, err := mcp.New("Token t", srv.URL).CallTool("get_alert", map[string]any{"alert_id": "orca-1"})
	if err != nil || mcp.TextContent(res) != "ok" {
		t.Fatalf("got (%v, %v), want ok", res, err)
	}
}

func TestContractAuthHeaderVerbatim(t *testing.T) {
	srv := mcpServer(t, "Bearer abc", nil)
	if _, err := mcp.New("Bearer abc", srv.URL).Initialize(); err != nil {
		t.Fatalf("Initialize with matching header: %v", err)
	}
}

func TestContractUnauthorized(t *testing.T) {
	srv := mcpServer(t, "Token right", nil)
	_, err := mcp.New("Token wrong", srv.URL).Initialize()
	if err == nil || !strings.Contains(err.Error(), mcp.ErrUnauthorized.Error()) {
		t.Fatalf("got %v, want unauthorized", err)
	}
}

func TestContractToolErrorIsTyped(t *testing.T) {
	srv := mcpServer(t, "Token t", func(w http.ResponseWriter, req mcp.Request) {
		reply(w, req, mcp.ToolCallResult{IsError: true, Content: []mcp.Content{{Type: "text", Text: "no such alert"}}})
	})
	_, err := mcp.New("Token t", srv.URL).CallTool("get_alert", map[string]any{})
	te, ok := err.(*mcp.ToolError)
	if !ok || te.Text != "no such alert" {
		t.Fatalf("got %#v, want *mcp.ToolError{no such alert}", err)
	}
}

func TestContractSSEResponse(t *testing.T) {
	srv := mcpServer(t, "Token t", func(w http.ResponseWriter, req mcp.Request) {
		b, _ := json.Marshal(mcp.ToolCallResult{Content: []mcp.Content{{Type: "text", Text: "sse"}}})
		resp, _ := json.Marshal(mcp.Response{JSONRPC: "2.0", ID: req.ID, Result: b})
		w.Header().Set("Content-Type", "text/event-stream")
		w.Write([]byte("event: message\ndata: " + string(resp) + "\n\n"))
	})
	res, err := mcp.New("Token t", srv.URL).CallTool("x", map[string]any{})
	if err != nil || mcp.TextContent(res) != "sse" {
		t.Fatalf("got (%v, %v), want sse", res, err)
	}
}

// oauthServer is a strict authorization server: public clients only, PKCE
// S256 only, resource indicator required, single-use codes.
type oauthServer struct {
	*httptest.Server
	challenge string
	used      bool
}

func newOAuthServer(t *testing.T) *oauthServer {
	t.Helper()
	s := &oauthServer{}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"resource": s.URL, "authorization_servers": []string{s.URL}})
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer": s.URL, "authorization_endpoint": s.URL + "/authorize", "token_endpoint": s.URL + "/token",
			"registration_endpoint": s.URL + "/register", "revocation_endpoint": s.URL + "/revoke",
			"code_challenge_methods_supported": []string{"S256"}, "token_endpoint_auth_methods_supported": []string{"none"},
		})
	})
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		_ = json.NewDecoder(r.Body).Decode(&m)
		if m["token_endpoint_auth_method"] != "none" || m["redirect_uris"] == nil {
			t.Errorf("DCR must be a public client with redirect_uris, got %v", m)
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{"client_id": "contract-client"})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f := r.PostForm
		if f.Get("resource") == "" {
			t.Errorf("token request lacks resource")
		}
		if f.Get("grant_type") == "authorization_code" {
			sum := sha256.Sum256([]byte(f.Get("code_verifier")))
			if base64.RawURLEncoding.EncodeToString(sum[:]) != s.challenge || s.used || f.Get("code") != "the-code" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			s.used = true
		}
		json.NewEncoder(w).Encode(map[string]any{"access_token": "acc", "refresh_token": "ref", "expires_in": 3600})
	})
	s.Server = httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

func TestContractOAuthLoginAgainstStrictServer(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	s := newOAuthServer(t)
	open := func(authURL string) error {
		u, _ := url.Parse(authURL)
		q := u.Query()
		if q.Get("code_challenge_method") != "S256" || q.Get("resource") == "" || q.Get("response_type") != "code" {
			t.Errorf("authorize request not PKCE S256 + resource: %v", q)
		}
		s.challenge = q.Get("code_challenge")
		go func() {
			time.Sleep(50 * time.Millisecond)
			if resp, err := http.Get(q.Get("redirect_uri") + "?code=the-code&state=" + url.QueryEscape(q.Get("state"))); err == nil {
				resp.Body.Close()
			}
		}()
		return nil
	}
	tok, err := auth.Login(auth.LoginOptions{Resource: s.URL + "/", Open: open}, "")
	if err != nil || tok.AccessToken != "acc" || tok.ClientID != "contract-client" {
		t.Fatalf("got (%+v, %v), want a logged-in token set", tok, err)
	}
}
