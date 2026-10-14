package cmd_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Deastrom/spyhop/cmd"
	"github.com/Deastrom/spyhop/internal/mcp"
)

type run struct {
	Code     int
	Out, Err string
}

// fakeMCP serves a minimal MCP server. calls records tools/call params;
// onCall returns the tool result text (isError when errText is non-empty).
type fakeMCP struct {
	*httptest.Server
	Tools     []mcp.Tool
	Calls     []mcp.ToolCallParams
	AuthSeen  string
	Reply     string // text returned by every tools/call
	ErrText   string
	Handler   func(p mcp.ToolCallParams) string // overrides Reply when set
	Requests  int                               // every HTTP request, any method
	ListCalls int                               // tools/list requests
	Deny      bool                              // answer 401 to everything
}

func newFakeMCP(t *testing.T) *fakeMCP {
	t.Helper()
	f := &fakeMCP{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.Requests++
		f.AuthSeen = r.Header.Get("Authorization")
		if f.Deny {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var req mcp.Request
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Mcp-Session-Id", "s1")
		write := func(v any) {
			b, _ := json.Marshal(v)
			json.NewEncoder(w).Encode(mcp.Response{JSONRPC: "2.0", ID: req.ID, Result: b})
		}
		switch req.Method {
		case "initialize":
			write(mcp.InitializeResult{ProtocolVersion: "2025-03-26", ServerInfo: mcp.ClientInfo{Name: "fake"}})
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			f.ListCalls++
			write(mcp.ToolsListResult{Tools: f.Tools})
		case "tools/call":
			b, _ := json.Marshal(req.Params)
			var p mcp.ToolCallParams
			_ = json.Unmarshal(b, &p)
			f.Calls = append(f.Calls, p)
			if f.ErrText != "" {
				write(mcp.ToolCallResult{IsError: true, Content: []mcp.Content{{Type: "text", Text: f.ErrText}}})
				return
			}
			text := f.Reply
			if f.Handler != nil {
				text = f.Handler(p)
			}
			write(mcp.ToolCallResult{Content: []mcp.Content{{Type: "text", Text: text}}})
		}
	}))
	t.Cleanup(f.Close)
	return f
}

// spyhop runs the CLI in token mode against the fake server.
func spyhop(t *testing.T, f *fakeMCP, args ...string) run {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	return spyhopEnv(t, map[string]string{"ORCA_TOKEN": "tok-synth", "SPYHOP_MCP_URL": f.URL}, args...)
}

// spyhopIn is spyhop with stdin.
func spyhopIn(t *testing.T, f *fakeMCP, stdin string, args ...string) run {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	return runApp(t, map[string]string{"ORCA_TOKEN": "tok-synth", "SPYHOP_MCP_URL": f.URL}, stdin, args...)
}

func spyhopEnv(t *testing.T, env map[string]string, args ...string) run {
	t.Helper()
	return runApp(t, env, "", args...)
}

func runApp(t *testing.T, env map[string]string, stdin string, args ...string) run {
	t.Helper()
	var out, errb strings.Builder
	app := &cmd.App{Out: &out, Err: &errb, In: strings.NewReader(stdin), Getenv: func(k string) string { return env[k] }}
	code := cmd.ExitCode(app, args)
	return run{code, out.String(), errb.String()}
}
