package cmd_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/Deastrom/spyhop/internal/mcp"
)

const writeReply = `{"status":"success","data":[{"id":"x","data":{"Status":{"value":"dismissed"}}}],"total_items":1}`
const writeReplyUnwrapped = `{"data":[{"data":{"Status":"dismissed"},"id":"x"}],"status":"success","total_items":1}` + "\n"

func writeServer(t *testing.T) *fakeMCP {
	t.Helper()
	f := newFakeMCP(t)
	f.Reply = writeReply
	return f
}

func TestWriteWithoutYesPrintsPlanAndExits2(t *testing.T) {
	cases := map[string][]string{
		`{"tool":"dismiss_alert","args":{"alert_id":"orca-1","reason":"False Positive"}}`:                             {"alert", "dismiss", "orca-1", "--reason", "false positive"},
		`{"tool":"update_alert_status","args":{"alert_id":"orca-1","status":"closed"}}`:                               {"alert", "status", "orca-1", "--to", "closed"},
		`{"tool":"add_alert_comment","args":{"alert_id":"orca-1","comment":"triaged"}}`:                               {"alert", "comment", "orca-1", "--body", "triaged"},
		`{"tool":"verify_alert","args":{"alert_id":"orca-1"}}`:                                                        {"alert", "verify", "orca-1"},
		`{"tool":"change_alert_score","args":{"alert_id":"orca-1","orca_score":8.8}}`:                                 {"alert", "score", "orca-1", "--score", "8.8"},
		`{"tool":"snooze_alert","args":{"alert_id":"orca-1","days":7,"justification":"j","reason":"Non-Production"}}`: {"alert", "snooze", "orca-1", "--days", "7", "--reason", "non-production", "--justification", "j"},
	}
	for plan, args := range cases {
		t.Run(strings.Join(args[:3], " "), func(t *testing.T) {
			f := writeServer(t)
			r := spyhop(t, f, args...)
			got := struct {
				Run      run
				Requests int
			}{r, f.Requests}
			want := got
			want.Run, want.Requests = run{2, plan + "\n", "pass --yes to execute\n"}, 0
			if got != want {
				t.Fatalf("got %+v, want %+v", got, want)
			}
		})
	}
}

func TestWriteWithYesCallsOnceAndPrintsUnwrappedResult(t *testing.T) {
	f := writeServer(t)
	r := spyhop(t, f, "alert", "dismiss", "orca-1", "--reason", "false positive", "--yes")
	got := struct {
		Run   run
		Calls []mcp.ToolCallParams
	}{r, f.Calls}
	want := got
	want.Run = run{0, writeReplyUnwrapped, ""}
	want.Calls = []mcp.ToolCallParams{{Name: "dismiss_alert", Arguments: map[string]any{"alert_id": "orca-1", "reason": "False Positive"}}}
	if !equalJSON(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestWriteToolMappings(t *testing.T) {
	cases := []struct {
		args []string
		want mcp.ToolCallParams
	}{
		{[]string{"alert", "status", "orca-1", "--to", "in_progress"}, mcp.ToolCallParams{Name: "update_alert_status", Arguments: map[string]any{"alert_id": "orca-1", "status": "in_progress"}}},
		{[]string{"alert", "comment", "orca-1", "--body", "triaged"}, mcp.ToolCallParams{Name: "add_alert_comment", Arguments: map[string]any{"alert_id": "orca-1", "comment": "triaged"}}},
		{[]string{"alert", "verify", "orca-1"}, mcp.ToolCallParams{Name: "verify_alert", Arguments: map[string]any{"alert_id": "orca-1"}}},
		{[]string{"alert", "score", "orca-1", "--score", "8.8", "--reason", "acceptable risk", "--justification", "j"}, mcp.ToolCallParams{Name: "change_alert_score", Arguments: map[string]any{"alert_id": "orca-1", "orca_score": 8.8, "reason": "Acceptable Risk", "justification": "j"}}},
		{[]string{"alert", "snooze", "orca-1", "--days", "7", "--reason", "awaiting further context or confirmation"}, mcp.ToolCallParams{Name: "snooze_alert", Arguments: map[string]any{"alert_id": "orca-1", "days": float64(7), "reason": "Awaiting further context or confirmation"}}},
		{[]string{"alert", "score", "orca-1", "--score", "0"}, mcp.ToolCallParams{Name: "change_alert_score", Arguments: map[string]any{"alert_id": "orca-1", "orca_score": float64(0)}}},
	}
	for _, c := range cases {
		t.Run(strings.Join(c.args[:3], " "), func(t *testing.T) {
			f := writeServer(t)
			r := spyhop(t, f, append(c.args, "--yes")...)
			got := struct {
				Code  int
				Calls []mcp.ToolCallParams
			}{r.Code, f.Calls}
			want := got
			want.Code, want.Calls = 0, []mcp.ToolCallParams{c.want}
			if !equalJSON(got, want) {
				t.Fatalf("got %+v (stderr %q), want %+v", got, r.Err, want)
			}
		})
	}
}

func TestWriteUsageErrorsExit2WithoutCalling(t *testing.T) {
	cases := []struct {
		args []string
		msg  string
	}{
		{[]string{"alert", "snooze", "orca-1", "--days", "7", "--reason", "bogus"},
			"Temporarily deprioritized, Awaiting further context or confirmation, Non-Actionable, Non-Production, Other"},
		{[]string{"alert", "snooze", "orca-1", "--yes"}, "--days"},
		{[]string{"alert", "score", "orca-1", "--score", "11", "--yes"}, "--score"},
		{[]string{"alert", "score", "orca-1", "--score", "-1", "--yes"}, "--score"},
		{[]string{"alert", "score", "orca-1", "--yes"}, "--score"},
		{[]string{"alert", "comment", "orca-1", "--yes"}, "--body"},
		{[]string{"alert", "dismiss", "orca-1", "--reason", "bogus", "--yes"}, "False Positive, Non-Actionable, Non-Production, Acceptable Risk, Other"},
		{[]string{"alert", "verify", "-", "--yes"}, "takes one alert ID"},
	}
	for _, c := range cases {
		t.Run(strings.Join(c.args, " "), func(t *testing.T) {
			f := writeServer(t)
			r := spyhop(t, f, c.args...)
			got := struct {
				Code     int
				HasMsg   bool
				Requests int
			}{r.Code, strings.Contains(r.Err, c.msg), f.Requests}
			if want := (struct {
				Code     int
				HasMsg   bool
				Requests int
			}{2, true, 0}); got != want {
				t.Fatalf("got %+v (stderr %q), want stderr containing %q", got, r.Err, c.msg)
			}
		})
	}
}

func readFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("../internal/format/testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestTimelineLines(t *testing.T) {
	f := newFakeMCP(t)
	f.Reply = readFixture(t, "timeline.json")
	r := spyhop(t, f, "alert", "timeline", "orca-1")
	want := run{0, "2026-01-02T03:04:05Z alert_created Alert created\n" +
		"2026-01-03T10:00:00Z score_change Score changed 8.5→9.7 analyst@example.invalid\n", ""}
	if r != want || f.Calls[0].Name != "get_alert_timeline" {
		t.Fatalf("got %+v call %+v, want %+v", r, f.Calls, want)
	}
}

func TestTimelineJSON(t *testing.T) {
	f := newFakeMCP(t)
	f.Reply = readFixture(t, "timeline.json")
	r := spyhop(t, f, "alert", "timeline", "orca-1", "--json")
	want := run{0, `[{"create_time":"2026-01-02T03:04:05Z","details":{"description":"Alert created"},"type":"alert_created","user_email":null},` +
		`{"create_time":"2026-01-03T10:00:00Z","details":{"description":"Score changed","from":8.5,"to":9.7},"type":"score_change","user_email":"analyst@example.invalid"}]` + "\n", ""}
	if r != want {
		t.Fatalf("got %+v, want %+v", r, want)
	}
}

func TestAttackPathPrintsTotal(t *testing.T) {
	f := newFakeMCP(t)
	f.Reply = readFixture(t, "attackpath.json")
	r := spyhop(t, f, "alert", "attack-path", "orca-1")
	if want := (run{0, "[]\ntotal_items: 5\n", ""}); r != want || f.Calls[0].Name != "get_alert_attack_path_data" {
		t.Fatalf("got %+v, want %+v", r, want)
	}
}

// similarServer answers get_alert from the alert fixture and every similar-*
// tool from the search fixture.
func similarServer(t *testing.T) *fakeMCP {
	t.Helper()
	alert, search := readFixture(t, "alert.json"), readFixture(t, "search.json")
	f := newFakeMCP(t)
	f.Handler = func(p mcp.ToolCallParams) string {
		if p.Name == "get_alert" {
			return alert
		}
		return search
	}
	return f
}

const similarRows = `Alert | orca-1234 | critical | 9.7 | in_progress | Remote code execution in synthetic-lib | synthetic-vm-01
AwsEc2Instance | 00000000-0000-0000-0000-0000000000a1 | synthetic-vm-01 | critical
total_items: 716
app_url: https://app.example.invalid/discovery?data=synthetic
`

func TestSimilarBy(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want []mcp.ToolCallParams
	}{
		{"type", []string{"alert", "similar", "orca-1234", "--by", "type"}, []mcp.ToolCallParams{
			{Name: "get_alert", Arguments: map[string]any{"alert_id": "orca-1234"}},
			{Name: "get_alerts_with_similar_alert_type", Arguments: map[string]any{"alert_id": "orca-1234", "alert_type": "trending_cve"}}}},
		{"malware", []string{"alert", "similar", "orca-1234", "--by", "malware"}, []mcp.ToolCallParams{
			{Name: "get_alert", Arguments: map[string]any{"alert_id": "orca-1234"}},
			{Name: "get_alerts_with_similar_malware", Arguments: map[string]any{"alert_id": "orca-1234", "asset_id": "u-1"}}}},
		{"secret", []string{"alert", "similar", "orca-1234", "--by", "secret", "--secret-hash", "h"}, []mcp.ToolCallParams{
			{Name: "get_other_secret_occurrences", Arguments: map[string]any{"alert_id": "orca-1234", "secret_hash": "h"}}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := similarServer(t)
			r := spyhop(t, f, c.args...)
			got := struct {
				Run   run
				Calls []mcp.ToolCallParams
			}{r, f.Calls}
			want := got
			want.Run, want.Calls = run{0, similarRows, ""}, c.want
			if !equalJSON(got, want) {
				t.Fatalf("got %+v, want %+v", got, want)
			}
		})
	}
}

func TestSimilarUsageErrors(t *testing.T) {
	cases := []struct {
		args []string
		msg  string
	}{
		{[]string{"alert", "similar", "orca-1", "--by", "secret"}, "--secret-hash"},
		{[]string{"alert", "similar", "orca-1"}, "--by"},
		{[]string{"alert", "similar", "orca-1", "--by", "color"}, "type, malware, secret"},
	}
	for _, c := range cases {
		t.Run(strings.Join(c.args[3:], " "), func(t *testing.T) {
			f := similarServer(t)
			r := spyhop(t, f, c.args...)
			if r.Code != 2 || !strings.Contains(r.Err, c.msg) || f.Requests != 0 {
				t.Fatalf("got %+v requests=%d, want exit 2 mentioning %q", r, f.Requests, c.msg)
			}
		})
	}
}

func TestReasonCompletion(t *testing.T) {
	f := newFakeMCP(t)
	r := spyhop(t, f, "__complete", "alert", "dismiss", "x", "--reason", "")
	want := run{0, "False Positive\nNon-Actionable\nNon-Production\nAcceptable Risk\nOther\n:4\n", ""}
	if r != want || f.Requests != 0 {
		t.Fatalf("got %+v requests=%d, want %+v", r, f.Requests, want)
	}
}

func TestJSONFlagStillAllowedOnWrites(t *testing.T) {
	f := writeServer(t)
	r := spyhop(t, f, "alert", "verify", "orca-1", "--yes", "--json")
	var v any
	if r.Code != 0 || json.Unmarshal([]byte(r.Out), &v) != nil {
		t.Fatalf("got %+v", r)
	}
}
