package cmd_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Deastrom/spyhop/internal/auth"
	"github.com/Deastrom/spyhop/internal/mcp"
)

const emptyEnvelope = `{"status":"success","data":[],"total_items":0}`

// alertServer answers get_alert from the synthetic fixture, rewriting the id;
// "orca-missing" gets an empty envelope.
func alertServer(t *testing.T) *fakeMCP {
	t.Helper()
	b, err := os.ReadFile("../internal/format/testdata/alert.json")
	if err != nil {
		t.Fatal(err)
	}
	f := newFakeMCP(t)
	f.Handler = func(p mcp.ToolCallParams) string {
		id, _ := p.Arguments["alert_id"].(string)
		if id == "orca-missing" {
			return emptyEnvelope
		}
		return strings.ReplaceAll(string(b), "orca-1234", id)
	}
	return f
}

func single(t *testing.T, f *fakeMCP, id string, extra ...string) string {
	t.Helper()
	r := spyhop(t, f, append([]string{"alert", "get", id}, extra...)...)
	if r.Code != 0 {
		t.Fatalf("single get %s failed: %+v", id, r)
	}
	return r.Out
}

func TestBatchGetText(t *testing.T) {
	f := alertServer(t)
	one, two := single(t, f, "orca-1"), single(t, f, "orca-2")
	r := spyhopIn(t, f, "orca-1\n\norca-2\n", "alert", "get", "-")
	if want := (run{0, one + "\n" + two, ""}); r != want {
		t.Fatalf("got %+v, want %+v", r, want)
	}
}

func TestBatchGetNDJSON(t *testing.T) {
	f := alertServer(t)
	r := spyhopIn(t, f, "orca-1\n\norca-2\n", "alert", "get", "-", "--json")
	lines := strings.Split(strings.TrimSuffix(r.Out, "\n"), "\n")
	got := struct {
		Code  int
		Lines int
		Valid bool
		IDs   [2]bool
	}{r.Code, len(lines), json.Valid([]byte(lines[0])) && json.Valid([]byte(lines[len(lines)-1])),
		[2]bool{strings.Contains(lines[0], `"AlertId":"orca-1"`), strings.Contains(lines[len(lines)-1], `"AlertId":"orca-2"`)}}
	if want := (struct {
		Code  int
		Lines int
		Valid bool
		IDs   [2]bool
	}{0, 2, true, [2]bool{true, true}}); got != want {
		t.Fatalf("got %+v, out %q", got, r.Out)
	}
}

func TestBatchPartialFailure(t *testing.T) {
	f := alertServer(t)
	one, two := single(t, f, "orca-1"), single(t, f, "orca-2")
	r := spyhopIn(t, f, "orca-1\norca-missing\norca-2", "alert", "get", "-")
	if want := (run{1, one + "\n" + two, "orca-missing: alert not found\n"}); r != want {
		t.Fatalf("got %+v, want %+v", r, want)
	}
}

func TestSearchIDs(t *testing.T) {
	f := fixtureServer(t, "search.json")
	r := spyhop(t, f, "search", "x", "--ids")
	if want := (run{0, "orca-1234\nvm_synthetic_1\n", ""}); r != want {
		t.Fatalf("got %+v, want %+v", r, want)
	}
}

func TestFieldSelection(t *testing.T) {
	f := fixtureServer(t, "alert.json")
	r := spyhop(t, f, "alert", "get", "orca-1234", "--fields", "Title,Description,AlertId")
	want := run{0, "Title: Remote code execution in synthetic-lib (CVE-2099-0001)\n" +
		"Description: A long description that curated output must not print.\n" +
		"AlertId: orca-1234\n", ""}
	if r != want {
		t.Fatalf("got %+v, want %+v", r, want)
	}
}

func TestMissingFieldAcrossFormats(t *testing.T) {
	f := fixtureServer(t, "alert.json")
	title := "Remote code execution in synthetic-lib (CVE-2099-0001)"
	got := []run{
		spyhop(t, f, "alert", "get", "orca-1234", "--fields", "Title,Nope"),
		spyhop(t, f, "alert", "get", "orca-1234", "--fields", "Title,Nope", "--format", "json"),
		spyhop(t, f, "alert", "get", "orca-1234", "--fields", "Title,Nope", "--format", "tsv"),
	}
	want := []run{
		{0, "Title: " + title + "\n", ""},
		{0, `{"Title":"` + title + `"}` + "\n", ""},
		{0, "Title\tNope\n" + title + "\t\n", ""},
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("format %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestSearchTSV(t *testing.T) {
	f := newFakeMCP(t)
	f.Reply = `{"status":"success","data":[
{"id":"u1","type":"Alert","name":"orca-1","data":{"AlertId":{"value":"orca-1"},"Labels":{"value":["a","b"]},"Title":{"value":"has\ttab"}}},
{"id":"u2","type":"Alert","name":"orca-2","data":{"AlertId":{"value":"orca-2"},"Title":{"value":"plain"}}}],
"total_items":2,"app_url":"https://app.example.invalid/x"}`
	r := spyhop(t, f, "search", "x", "--format", "tsv", "--fields", "AlertId,Labels,Title")
	want := run{0, "AlertId\tLabels\tTitle\norca-1\ta,b\thas tab\norca-2\t\tplain\n", ""}
	if r != want {
		t.Fatalf("got %+v, want %+v", r, want)
	}
}

func TestJSONAliasIdentical(t *testing.T) {
	f := fixtureServer(t, "alert.json")
	a := spyhop(t, f, "alert", "get", "orca-1234", "--json")
	b := spyhop(t, f, "alert", "get", "orca-1234", "--format", "json")
	if a.Code != 0 || a != b {
		t.Fatalf("--json %+v != --format json %+v", a, b)
	}
}

func TestUsageErrorsExit2WithoutCalling(t *testing.T) {
	cases := [][]string{
		{"search", "x", "--limit", "0"},
		{"alert", "status", "orca-1", "--to", "bogus"},
		{"alert", "get", "orca-1", "--raw", "--fields", "Title"},
		{"search", "x", "--ids", "--format", "tsv"},
		{"search", "x", "--ids", "--fields", "Title"},
		{"alert", "get", "orca-1", "--format", "yaml"},
		{"--region", "xx", "tools"},
		{"nonsense"},
	}
	for _, args := range cases {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			f := fixtureServer(t, "alert.json")
			r := spyhop(t, f, args...)
			got := struct {
				Code    int
				Out     string
				HasErr  bool
				Request int
			}{r.Code, r.Out, r.Err != "", f.Requests}
			if want := (struct {
				Code    int
				Out     string
				HasErr  bool
				Request int
			}{2, "", true, 0}); got != want {
				t.Fatalf("got %+v (stderr %q), want %+v", got, r.Err, want)
			}
		})
	}
}

func TestUnauthorizedExit4(t *testing.T) {
	t.Run("given token mode and a 401", func(t *testing.T) {
		f := newFakeMCP(t)
		f.Deny = true
		r := spyhop(t, f, "tools")
		if r.Code != 4 || !strings.Contains(r.Err, "ORCA_TOKEN") {
			t.Fatalf("got %+v", r)
		}
	})
	t.Run("given oauth mode and a 401", func(t *testing.T) {
		f := newFakeMCP(t)
		f.Deny = true
		t.Setenv("HOME", t.TempDir())
		auth.SaveTokens(&auth.Tokens{ClientID: "c", AccessToken: "a", RefreshToken: "r", ExpiresAt: time.Now().Add(time.Hour)})
		r := spyhopEnv(t, map[string]string{"SPYHOP_MCP_URL": f.URL}, "tools")
		if r.Code != 4 || !strings.Contains(r.Err, "run: spyhop auth login") {
			t.Fatalf("got %+v", r)
		}
	})
	t.Run("given an expired token whose refresh fails", func(t *testing.T) {
		f := newFakeMCP(t)
		t.Setenv("HOME", t.TempDir())
		auth.SaveTokens(&auth.Tokens{ClientID: "c", AccessToken: "a", RefreshToken: "r", ExpiresAt: time.Now().Add(-time.Hour), TokenEndpoint: f.URL + "/token"})
		f.Deny = true
		r := spyhopEnv(t, map[string]string{"SPYHOP_MCP_URL": f.URL}, "tools")
		if r.Code != 4 || !strings.Contains(r.Err, "run: spyhop auth login") {
			t.Fatalf("got %+v", r)
		}
	})
	t.Run("given no stored login", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir())
		r := spyhopEnv(t, map[string]string{}, "tools")
		if r.Code != 4 || !strings.Contains(r.Err, "run: spyhop auth login") {
			t.Fatalf("got %+v", r)
		}
	})
}

func TestNotFoundExit1(t *testing.T) {
	f := newFakeMCP(t)
	f.Reply = emptyEnvelope
	r := spyhop(t, f, "asset", "get", "nope")
	if want := (run{1, "", "asset not found\n"}); r != want {
		t.Fatalf("got %+v, want %+v", r, want)
	}
}

func TestWritesStaySingle(t *testing.T) {
	f := newFakeMCP(t)
	r := spyhopIn(t, f, "orca-1\n", "alert", "status", "-", "--to", "closed")
	got := struct {
		Code     int
		Err      string
		Requests int
	}{r.Code, r.Err, f.Requests}
	if want := (struct {
		Code     int
		Err      string
		Requests int
	}{2, "alert status takes one alert ID\n", 0}); got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}
