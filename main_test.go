package main_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestBuiltBinaryReadsStdinBatch builds the real binary and pipes IDs into it.
// Unit tests inject stdin, so only this catches main.go failing to wire os.Stdin.
func TestBuiltBinaryReadsStdinBatch(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "spyhop")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     any            `json:"id"`
			Method string         `json:"method"`
			Params map[string]any `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Mcp-Session-Id", "s1")
		reply := func(result any) {
			b, _ := json.Marshal(result)
			json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": json.RawMessage(b)})
		}
		switch req.Method {
		case "initialize":
			reply(map[string]any{"protocolVersion": "2025-03-26", "serverInfo": map[string]any{"name": "fake"}})
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/call":
			id, _ := req.Params["arguments"].(map[string]any)["alert_id"].(string)
			text := `{"status":"success","data":[{"id":"u","type":"Alert","ui_url":"https://app.example.invalid/` + id +
				`","data":{"AlertId":{"value":"` + id + `"},"Title":{"value":"synthetic"}}}],"total_items":1}`
			reply(map[string]any{"content": []map[string]any{{"type": "text", "text": text}}})
		}
	}))
	defer srv.Close()

	cmd := exec.Command(bin, "alert", "get", "-")
	cmd.Stdin = strings.NewReader("orca-1\norca-2\n")
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir(), "ORCA_TOKEN=tok-synth", "SPYHOP_MCP_URL="+srv.URL, "SPYHOP_CACHE_DIR="+t.TempDir())
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()

	got := struct {
		ExitOK  bool
		Records int
		IDs     [2]bool
	}{err == nil, strings.Count(stdout.String(), "AlertId: "),
		[2]bool{strings.Contains(stdout.String(), "AlertId: orca-1\n"), strings.Contains(stdout.String(), "AlertId: orca-2\n")}}
	if want := (struct {
		ExitOK  bool
		Records int
		IDs     [2]bool
	}{true, 2, [2]bool{true, true}}); got != want {
		t.Fatalf("got %+v (err=%v), stdout %q stderr %q", got, err, stdout.String(), stderr.String())
	}
}
