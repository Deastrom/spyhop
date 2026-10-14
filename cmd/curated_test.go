package cmd_test

import (
	"os"
	"strings"
	"testing"

	"github.com/Deastrom/spyhop/internal/mcp"
)

func fixtureServer(t *testing.T, name string) *fakeMCP {
	t.Helper()
	b, err := os.ReadFile("../internal/format/testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	f := newFakeMCP(t)
	f.Reply = string(b)
	return f
}

func TestSearch(t *testing.T) {
	f := fixtureServer(t, "search.json")
	t.Run("given a phrase and --limit 10", func(t *testing.T) {
		t.Run("when search runs", func(t *testing.T) {
			r := spyhop(t, f, "search", "critical alerts in progress", "--limit", "10")
			t.Run("then it calls discovery_search and prints rows, total_items and app_url", func(t *testing.T) {
				got := struct {
					Run  run
					Call mcp.ToolCallParams
				}{r, f.Calls[0]}
				want := got
				want.Run = run{0, `Alert | orca-1234 | critical | 9.7 | in_progress | Remote code execution in synthetic-lib | synthetic-vm-01
AwsEc2Instance | 00000000-0000-0000-0000-0000000000a1 | synthetic-vm-01 | critical
total_items: 716
app_url: https://app.example.invalid/discovery?data=synthetic
`, ""}
				want.Call = mcp.ToolCallParams{Name: "discovery_search", Arguments: map[string]any{"search_phrase": "critical alerts in progress", "limit": float64(10)}}
				if !equalJSON(got, want) {
					t.Fatalf("got %+v, want %+v", got, want)
				}
			})
		})
		t.Run("when search runs with --json", func(t *testing.T) {
			r := spyhop(t, f, "search", "x", "--json")
			t.Run("then it prints an array of curated objects", func(t *testing.T) {
				ok := r.Code == 0 && strings.HasPrefix(r.Out, `[{`) && strings.Contains(r.Out, `"AlertId":"orca-1234"`) && f.Calls[len(f.Calls)-1].Arguments["limit"] == float64(5)
				if !ok {
					t.Fatalf("got %+v", r)
				}
			})
		})
	})
}

func TestSearchLimitBounds(t *testing.T) {
	for _, lim := range []string{"0", "51"} {
		t.Run("given --limit "+lim, func(t *testing.T) {
			f := fixtureServer(t, "search.json")
			t.Run("when search runs", func(t *testing.T) {
				r := spyhop(t, f, "search", "x", "--limit", lim)
				t.Run("then it exits 1 before calling the server", func(t *testing.T) {
					got := struct {
						Code  int
						Calls int
					}{r.Code, len(f.Calls)}
					if got != (struct {
						Code  int
						Calls int
					}{1, 0}) {
						t.Fatalf("got %+v, stderr %q", got, r.Err)
					}
				})
			})
		})
	}
}

func TestAlertGet(t *testing.T) {
	f := fixtureServer(t, "alert.json")
	r := spyhop(t, f, "alert", "get", "orca-1234")
	got := struct {
		Code  int
		Call  mcp.ToolCallParams
		First string
		Size  bool
	}{r.Code, f.Calls[0], strings.SplitN(r.Out, "\n", 2)[0], len(r.Out) < 1024}
	want := got
	want.Code, want.First, want.Size = 0, "AlertId: orca-1234", true
	want.Call = mcp.ToolCallParams{Name: "get_alert", Arguments: map[string]any{"alert_id": "orca-1234"}}
	if !equalJSON(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestAlertGetJSON(t *testing.T) {
	f := fixtureServer(t, "alert.json")
	r := spyhop(t, f, "alert", "get", "orca-1234", "--json")
	if r.Code != 0 || !strings.HasPrefix(r.Out, `{"`) || strings.Contains(r.Out, "ScoreVector") || !strings.Contains(r.Out, `"RiskLevel":"critical"`) {
		t.Fatalf("got %+v", r)
	}
}

func TestAlertStatus(t *testing.T) {
	t.Run("given --to in_progress", func(t *testing.T) {
		f := newFakeMCP(t)
		f.Reply = `{"status":"success","data":[],"total_items":0}`
		r := spyhop(t, f, "alert", "status", "orca-1234", "--to", "in_progress")
		t.Run("then it calls update_alert_status and prints the new status", func(t *testing.T) {
			got := struct {
				Run  run
				Call mcp.ToolCallParams
			}{r, f.Calls[0]}
			want := got
			want.Run = run{0, "orca-1234: in_progress\n", ""}
			want.Call = mcp.ToolCallParams{Name: "update_alert_status", Arguments: map[string]any{"alert_id": "orca-1234", "status": "in_progress"}}
			if !equalJSON(got, want) {
				t.Fatalf("got %+v, want %+v", got, want)
			}
		})
	})
	t.Run("given --to outside D12", func(t *testing.T) {
		f := newFakeMCP(t)
		r := spyhop(t, f, "alert", "status", "orca-1234", "--to", "resolved")
		t.Run("then it exits 1 before calling", func(t *testing.T) {
			if r.Code != 1 || len(f.Calls) != 0 || !strings.Contains(r.Err, "open, in_progress, closed, snoozed, dismissed") {
				t.Fatalf("got %+v calls=%d", r, len(f.Calls))
			}
		})
	})
}

func TestAssetGet(t *testing.T) {
	f := fixtureServer(t, "asset.json")
	r := spyhop(t, f, "asset", "get", "a1", "--model-type", "AwsEc2Instance")
	got := struct {
		Code  int
		Call  mcp.ToolCallParams
		First string
	}{r.Code, f.Calls[0], strings.SplitN(r.Out, "\n", 2)[0]}
	want := got
	want.Code, want.First = 0, "Name: synthetic-vm-01"
	want.Call = mcp.ToolCallParams{Name: "get_asset_by_id", Arguments: map[string]any{"asset_id": "a1", "model_type": "AwsEc2Instance"}}
	if !equalJSON(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestAssetGetWithoutModelType(t *testing.T) {
	f := fixtureServer(t, "asset.json")
	spyhop(t, f, "asset", "get", "a1")
	if _, has := f.Calls[0].Arguments["model_type"]; has {
		t.Fatalf("model_type sent without --model-type: %v", f.Calls[0].Arguments)
	}
}
