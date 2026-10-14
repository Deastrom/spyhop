package cmd_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Deastrom/spyhop/internal/mcp"
)

// toolServer answers each tool with the fixture mapped to its name.
func toolServer(t *testing.T, replies map[string]string) *fakeMCP {
	t.Helper()
	f := newFakeMCP(t)
	f.Handler = func(p mcp.ToolCallParams) string {
		if r, ok := replies[p.Name]; ok {
			return r
		}
		t.Errorf("unexpected tool call %q", p.Name)
		return "{}"
	}
	return f
}

func names(calls []mcp.ToolCallParams) []string {
	out := make([]string, len(calls))
	for i, c := range calls {
		out[i] = c.Name
	}
	return out
}

const assetUUID = "00000000-0000-0000-0000-0000000000a1"

func TestCrownJewelResolvesIDThenReadsGroupID(t *testing.T) {
	f := toolServer(t, map[string]string{
		"get_asset_by_id":            readFixture(t, "asset.json"),
		"get_asset_crown_jewel_info": readFixture(t, "crownjewel.json"),
	})
	r := spyhop(t, f, "asset", "crown-jewel", "vm_synthetic_1")
	got := struct {
		Run   run
		Calls []mcp.ToolCallParams
	}{r, f.Calls}
	want := got
	want.Run = run{0, "is_crown_jewel: true\nsource: auto_detected\nreason: Sensitive Data\nscore: 75\n", ""}
	want.Calls = []mcp.ToolCallParams{
		{Name: "get_asset_by_id", Arguments: map[string]any{"asset_id": "vm_synthetic_1"}},
		{Name: "get_asset_crown_jewel_info", Arguments: map[string]any{"group_unique_id": "vm_synthetic_group_1"}},
	}
	if !equalJSON(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestCrownJewelManualOmitsDetectedFields(t *testing.T) {
	f := toolServer(t, map[string]string{
		"get_asset_by_id":            readFixture(t, "asset.json"),
		"get_asset_crown_jewel_info": `{"is_crown_jewel":true,"details":{"source":"manual","auto_detected_details":null,"manual_crown_jewel_details":{"set_by":"x"}}}`,
	})
	r := spyhop(t, f, "asset", "crown-jewel", "vm_synthetic_1")
	if want := (run{0, "is_crown_jewel: true\nsource: manual\n", ""}); r != want {
		t.Fatalf("got %+v, want %+v", r, want)
	}
}

func TestAssetAlertsUUIDSkipsLookup(t *testing.T) {
	f := toolServer(t, map[string]string{
		"get_asset_alerts_count_grouped_by_risk_level": readFixture(t, "counts.json"),
		"get_asset_related_alerts_summary":             readFixture(t, "alertsummary.json"),
	})
	r := spyhop(t, f, "asset", "alerts", assetUUID)
	got := struct {
		Code   int
		Tools  []string
		AssetS []any
	}{r.Code, names(f.Calls), []any{f.Calls[0].Arguments["asset_id"], f.Calls[1].Arguments["asset_id"]}}
	want := got
	want.Code, want.Tools = 0, []string{"get_asset_alerts_count_grouped_by_risk_level", "get_asset_related_alerts_summary"}
	want.AssetS = []any{assetUUID, assetUUID}
	if !equalJSON(got, want) {
		t.Fatalf("got %+v (stderr %q), want %+v", got, r.Err, want)
	}
}

func TestAssetAlertsResolvesNonUUIDToRecordID(t *testing.T) {
	f := toolServer(t, map[string]string{
		"get_asset_by_id": readFixture(t, "asset.json"),
		"get_asset_alerts_count_grouped_by_risk_level": readFixture(t, "counts.json"),
		"get_asset_related_alerts_summary":             readFixture(t, "alertsummary.json"),
	})
	spyhop(t, f, "asset", "alerts", "vm_synthetic_1")
	if len(f.Calls) != 3 || f.Calls[0].Name != "get_asset_by_id" || f.Calls[1].Arguments["asset_id"] != assetUUID {
		t.Fatalf("got calls %+v, want lookup then UUID %s", f.Calls, assetUUID)
	}
}

func alertsServer(t *testing.T) *fakeMCP {
	return toolServer(t, map[string]string{
		"get_asset_alerts_count_grouped_by_risk_level": readFixture(t, "counts.json"),
		"get_asset_related_alerts_summary":             readFixture(t, "alertsummary.json"),
	})
}

func TestAssetAlertsCountsThenRows(t *testing.T) {
	r := spyhop(t, alertsServer(t), "asset", "alerts", assetUUID)
	want := run{0, "critical 3 high 5 medium 151 low 229 informational 2\n" +
		"orca-1 | critical | 10 | open | Title one\n" +
		"orca-2 | high | 7.5 | in_progress | Title two\n", ""}
	if r != want {
		t.Fatalf("got %+v, want %+v", r, want)
	}
}

func TestAssetAlertsIDs(t *testing.T) {
	r := spyhop(t, alertsServer(t), "asset", "alerts", assetUUID, "--ids")
	if want := (run{0, "orca-1\norca-2\n", ""}); r != want {
		t.Fatalf("got %+v, want %+v", r, want)
	}
}

func TestAssetAlertsJSON(t *testing.T) {
	r := spyhop(t, alertsServer(t), "asset", "alerts", assetUUID, "--json")
	want := run{0, `{"counts":{"critical":3,"high":5,"medium":151,"low":229,"informational":2},"alerts":[` +
		`{"name":"orca-1","risk_level":"critical","orca_score":10,"status":"open","alert_title":"Title one","ui_url":"https://app.example.invalid/alerts/orca-1"},` +
		`{"name":"orca-2","risk_level":"high","orca_score":7.5,"status":"in_progress","alert_title":"Title two","ui_url":"https://app.example.invalid/alerts/orca-2"}]}` + "\n", ""}
	if r != want {
		t.Fatalf("got %+v, want %+v", r, want)
	}
}

func TestAssetFind(t *testing.T) {
	byName := readFixture(t, "byname.json")
	t.Run("rows", func(t *testing.T) {
		f := toolServer(t, map[string]string{"get_asset_by_name": byName})
		r := spyhop(t, f, "asset", "find", "web", "--limit", "2")
		got := struct {
			Run  run
			Call mcp.ToolCallParams
		}{r, f.Calls[0]}
		want := got
		want.Run = run{0, "AwsEc2Instance | 00000000-0000-0000-0000-000000000001 | web-1 | critical\n" +
			"AwsEc2Instance | 00000000-0000-0000-0000-000000000002 | web-2 | high\ntotal_items: 2\n", ""}
		want.Call = mcp.ToolCallParams{Name: "get_asset_by_name", Arguments: map[string]any{"asset_name": "web", "name_match_limit": float64(2)}}
		if !equalJSON(got, want) {
			t.Fatalf("got %+v, want %+v", got, want)
		}
	})
	t.Run("ids", func(t *testing.T) {
		f := toolServer(t, map[string]string{"get_asset_by_name": byName})
		r := spyhop(t, f, "asset", "find", "web", "--ids", "--model-type", "AwsEc2Instance")
		got := struct {
			Run   run
			Model any
		}{r, f.Calls[0].Arguments["model_type"]}
		if want := (struct {
			Run   run
			Model any
		}{run{0, "vm_synth_1\nvm_synth_2\n", ""}, "AwsEc2Instance"}); got != want {
			t.Fatalf("got %+v, want %+v", got, want)
		}
	})
	t.Run("limit out of range", func(t *testing.T) {
		f := toolServer(t, map[string]string{"get_asset_by_name": byName})
		r := spyhop(t, f, "asset", "find", "web", "--limit", "51")
		if r.Code != 2 || f.Requests != 0 {
			t.Fatalf("got %+v requests=%d, want exit 2 with no request", r, f.Requests)
		}
	})
}

func TestAssetAttackPaths(t *testing.T) {
	f := toolServer(t, map[string]string{"get_asset_related_attack_paths_summary": readFixture(t, "attackpaths.json")})
	r := spyhop(t, f, "asset", "attack-paths", assetUUID)
	want := run{0, "ap-1 | db-1 | An adversary can compromise web-1 due to Unpatched OS\ntotal_items: 2\n", ""}
	if r != want || strings.Contains(r.Out, "||") {
		t.Fatalf("got %+v, want %+v", r, want)
	}
}

func TestDocs(t *testing.T) {
	t.Run("no answer exits 0", func(t *testing.T) {
		f := newFakeMCP(t)
		f.Reply = `{"answer":"No answer","question":"q","sources":[]}`
		r := spyhop(t, f, "docs", "q")
		if want := (run{0, "No answer\n", ""}); r != want || f.Calls[0].Arguments["question"] != "q" || f.Calls[0].Name != "documentation_search" {
			t.Fatalf("got %+v call %+v", r, f.Calls)
		}
	})
	t.Run("sources", func(t *testing.T) {
		f := newFakeMCP(t)
		f.Reply = readFixture(t, "docs.json")
		r := spyhop(t, f, "docs", "How do I triage an alert?")
		want := run{0, "Open the Alerts page and review each alert.\n" +
			"source: Alerts Page https://docs.example.invalid/alerts\nsource: Triage Agent https://docs.example.invalid/triage\n", ""}
		if r != want {
			t.Fatalf("got %+v, want %+v", r, want)
		}
	})
}

func TestCVEValidation(t *testing.T) {
	for _, bad := range []string{"log4j", "CVE-21-1", "CVE-2021-123", "2021-44228"} {
		t.Run(bad, func(t *testing.T) {
			f := newFakeMCP(t)
			r := spyhop(t, f, "cve", bad)
			if r.Code != 2 || r.Err == "" || f.Requests != 0 {
				t.Fatalf("got %+v requests=%d, want exit 2 with a message and no request", r, f.Requests)
			}
		})
	}
}

func TestCVECaseInsensitiveSentUppercase(t *testing.T) {
	f := newFakeMCP(t)
	f.Reply = readFixture(t, "cve.json")
	spyhop(t, f, "cve", "cve-2099-0001")
	if f.Calls[0].Name != "get_cve_from_catalog" || f.Calls[0].Arguments["cve_id"] != "CVE-2099-0001" {
		t.Fatalf("got %+v", f.Calls)
	}
}

func TestCVECuration(t *testing.T) {
	f := newFakeMCP(t)
	f.Reply = readFixture(t, "cve.json")
	r := spyhop(t, f, "cve", "CVE-2099-0001")
	want := run{0, "cve_id: CVE-2099-0001\ndetected: true\nhits: 15\nproducts: p0,p1,p2,p3,p4,p5,p6,p7,p8,p9 …2 more\nvendor_ids: V1,V2,V3\n", ""}
	if r != want {
		t.Fatalf("got %+v, want %+v", r, want)
	}
}

func TestCVEJSONAndRaw(t *testing.T) {
	f := newFakeMCP(t)
	f.Reply = readFixture(t, "cve.json")
	j := spyhop(t, f, "cve", "CVE-2099-0001", "--json")
	raw := spyhop(t, f, "cve", "CVE-2099-0001", "--raw")
	wantJSON := run{0, `{"cve_id":"CVE-2099-0001","detected":true,"hits":15,"products":["p0","p1","p2","p3","p4","p5","p6","p7","p8","p9"],"products_more":2,"vendor_ids":["V1","V2","V3"]}` + "\n", ""}
	if j != wantJSON || raw.Out != f.Reply+"\n" {
		t.Fatalf("json %+v, want %+v; raw unchanged=%v", j, wantJSON, raw.Out == f.Reply+"\n")
	}
}

func TestQueryFromStdin(t *testing.T) {
	f := newFakeMCP(t)
	f.Reply = `{"count":1}`
	r := spyhopIn(t, f, `{"models":["Alert"],"type":"object_set"}`, "query", "-", "--limit", "10", "--order-by", "-OrcaScore")
	want := mcp.ToolCallParams{Name: "run_svl_query", Arguments: map[string]any{
		"query": map[string]any{"models": []any{"Alert"}, "type": "object_set"}, "limit": float64(10), "offset": float64(0), "order_by": []any{"-OrcaScore"}}}
	if r.Code != 0 || !equalJSON(f.Calls[0], want) {
		t.Fatalf("got %+v call %+v, want %+v", r, f.Calls, want)
	}
}

func TestQueryBadInputExit2(t *testing.T) {
	cases := []struct {
		stdin string
		args  []string
	}{
		{"{not json", []string{"query", "-"}},
		{`["array"]`, []string{"query", "-"}},
		{`{}`, []string{"query", "-", "--limit", "201"}},
		{`{}`, []string{"query", "-", "--limit", "0"}},
		{`{}`, []string{"query", "-", "--offset", "-1"}},
	}
	for _, c := range cases {
		t.Run(c.stdin+strings.Join(c.args, " "), func(t *testing.T) {
			f := newFakeMCP(t)
			r := spyhopIn(t, f, c.stdin, c.args...)
			if r.Code != 2 || r.Err == "" || f.Requests != 0 {
				t.Fatalf("got %+v requests=%d, want exit 2 with a message and no request", r, f.Requests)
			}
		})
	}
}

func TestQueryOutputs(t *testing.T) {
	t.Run("non-envelope prints compact unwrapped JSON", func(t *testing.T) {
		f := newFakeMCP(t)
		f.Reply = `{"count":1,"rows":[{"a":{"value":1}}]}`
		r := spyhopIn(t, f, `{}`, "query", "-")
		if want := (run{0, `{"count":1,"rows":[{"a":1}]}` + "\n", ""}); r != want {
			t.Fatalf("got %+v, want %+v", r, want)
		}
	})
	t.Run("envelope prints search rows and total_items", func(t *testing.T) {
		f := newFakeMCP(t)
		f.Reply = readFixture(t, "search.json")
		r := spyhopIn(t, f, `{}`, "query", "-")
		if want := (run{0, similarRows, ""}); r != want {
			t.Fatalf("got %+v, want %+v", r, want)
		}
	})
	t.Run("envelope honors --fields and --format", func(t *testing.T) {
		f := newFakeMCP(t)
		f.Reply = readFixture(t, "search.json")
		r := spyhopIn(t, f, `{}`, "query", "-", "--fields", "AlertId", "--format", "tsv")
		if want := (run{0, "AlertId\norca-1234\n\n", ""}); r != want {
			t.Fatalf("got %+v, want %+v", r, want)
		}
	})
}

// Marking crown jewels is a leadership/central-team decision: no write command.
func TestNoCrownJewelMarkCommand(t *testing.T) {
	f := newFakeMCP(t)
	help := spyhop(t, f, "asset", "--help")
	mark := spyhop(t, f, "asset", "crown-jewel", "--mark", "x")
	got := struct {
		HelpMentionsMark bool
		MarkFlagExit     int
		Requests         int
	}{strings.Contains(strings.ToLower(help.Out), "mark"), mark.Code, f.Requests}
	if want := (struct {
		HelpMentionsMark bool
		MarkFlagExit     int
		Requests         int
	}{false, 2, 0}); got != want {
		t.Fatalf("got %+v", got)
	}
}

func TestDocsStripsHTMLFromAnswer(t *testing.T) {
	const html = `<p>Use <b>labels</b> &amp; tags</p>`
	reply := `{"answer":` + jsonString(html) + `,"question":"x","sources":[{"name":"Alerts Page","link":"https://docs.example.invalid/alerts"}]}`
	f := newFakeMCP(t)
	f.Reply = reply
	text := spyhop(t, f, "docs", "x")
	asJSON := spyhop(t, f, "docs", "x", "--json")
	raw := spyhop(t, f, "docs", "x", "--raw")
	// --json is compared decoded: encoding/json escapes & as \u0026.
	var decoded struct {
		Answer  string   `json:"answer"`
		Sources []string `json:"sources"`
	}
	jsonErr := json.Unmarshal([]byte(asJSON.Out), &decoded)
	asJSON.Out = ""
	got := []run{text, asJSON, raw}
	want := []run{
		{0, "Use labels & tags\nsource: Alerts Page https://docs.example.invalid/alerts\n", ""},
		{0, "", ""},
		{0, reply + "\n", ""},
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("variant %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
	if jsonErr != nil || decoded.Answer != "Use labels & tags" || len(decoded.Sources) != 1 || decoded.Sources[0] != "Alerts Page https://docs.example.invalid/alerts" {
		t.Fatalf("--json: got %+v (err=%v)", decoded, jsonErr)
	}
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
