package cmd_test

import (
	"encoding/json"
	"testing"

	"github.com/Deastrom/spyhop/internal/mcp"
)

func TestTools(t *testing.T) {
	f := newFakeMCP(t)
	f.Tools = []mcp.Tool{
		{Name: "get_alert", Description: "Get one alert. Returns the full record.", InputSchema: json.RawMessage(`{"type":"object","properties":{"alert_id":{"type":"string"}}}`)},
		{Name: "discovery_search", Description: "Search assets"},
	}

	t.Run("given a connected server", func(t *testing.T) {
		t.Run("when tools runs", func(t *testing.T) {
			r := spyhop(t, f, "tools")
			t.Run("then it prints name and first sentence per tool", func(t *testing.T) {
				want := run{0, "get_alert\tGet one alert.\ndiscovery_search\tSearch assets\n", ""}
				if r != want {
					t.Fatalf("got %+v, want %+v", r, want)
				}
			})
		})
		t.Run("when tools <name> runs", func(t *testing.T) {
			r := spyhop(t, f, "tools", "get_alert")
			t.Run("then it prints the input schema as JSON", func(t *testing.T) {
				want := run{0, `{"type":"object","properties":{"alert_id":{"type":"string"}}}` + "\n", ""}
				if r != want {
					t.Fatalf("got %+v, want %+v", r, want)
				}
			})
		})
	})
}

func TestCall(t *testing.T) {
	const reply = `{"status":"success","data":[{"id":"a1","data":{"Title":{"value":"x"},"N":{"value":3}}}],"total_items":1}`

	t.Run("given --arg values", func(t *testing.T) {
		f := newFakeMCP(t)
		f.Reply = reply
		t.Run("when call runs", func(t *testing.T) {
			r := spyhop(t, f, "call", "discovery_search", "--arg", "search_phrase=internet facing assets", "--arg", "limit=5")
			t.Run("then JSON-parsable values are typed and the result is unwrapped", func(t *testing.T) {
				got := struct {
					Run  run
					Call mcp.ToolCallParams
				}{r, f.Calls[0]}
				want := got
				want.Run = run{0, `{"data":[{"data":{"N":3,"Title":"x"},"id":"a1"}],"status":"success","total_items":1}` + "\n", ""}
				want.Call = mcp.ToolCallParams{Name: "discovery_search", Arguments: map[string]any{"search_phrase": "internet facing assets", "limit": float64(5)}}
				if !equalJSON(got, want) {
					t.Fatalf("got %+v, want %+v", got, want)
				}
			})
		})
		t.Run("when call runs with --raw", func(t *testing.T) {
			r := spyhop(t, f, "call", "discovery_search", "--raw")
			t.Run("then the result text prints unchanged", func(t *testing.T) {
				want := run{0, reply + "\n", ""}
				if r != want {
					t.Fatalf("got %+v, want %+v", r, want)
				}
			})
		})
	})
}

func TestToolErrorGoesToStderr(t *testing.T) {
	f := newFakeMCP(t)
	f.ErrText = "alert not found"
	t.Run("given a tool result with isError", func(t *testing.T) {
		t.Run("when a command prints it", func(t *testing.T) {
			r := spyhop(t, f, "call", "get_alert")
			t.Run("then the text goes to stderr and the exit code is 1", func(t *testing.T) {
				want := run{1, "", "alert not found\n"}
				if r != want {
					t.Fatalf("got %+v, want %+v", r, want)
				}
			})
		})
	})
}

func TestTokenModeSendsTokenHeader(t *testing.T) {
	f := newFakeMCP(t)
	f.Reply = "{}"
	spyhop(t, f, "call", "x")
	if f.AuthSeen != "Token tok-synth" {
		t.Fatalf("Authorization = %q, want %q", f.AuthSeen, "Token tok-synth")
	}
}

func equalJSON(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}
