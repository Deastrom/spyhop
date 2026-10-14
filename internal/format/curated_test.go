package format_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/Deastrom/spyhop/internal/format"
)

func load(t *testing.T, name string) *format.Envelope {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	env, err := format.ParseEnvelope(string(b))
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func TestAlertCurated(t *testing.T) {
	r := load(t, "alert.json").Records[0]
	t.Run("given a synthetic alert record", func(t *testing.T) {
		t.Run("when curated", func(t *testing.T) {
			got := format.Alert(r).Text()
			t.Run("then it prints the fixed fields in under 1KB", func(t *testing.T) {
				want := `AlertId: orca-1234
Title: Remote code execution in synthetic-lib (CVE-2099-0001)
RiskLevel: critical
OrcaScore: 9.7
Status: in_progress
Category: Vulnerabilities
CveIds: CVE-2099-0001
Labels: fix_available,remote_code_execution
Asset: synthetic-vm-01 (AwsEc2Instance) synthetic-account
Recommendation: Upgrade synthetic-lib to 2.0.0.
ui_url: https://app.example.invalid/alerts/orca-1234
`
				if got != want || len(got) >= 1024 {
					t.Fatalf("got (%d bytes):\n%s\nwant:\n%s", len(got), got, want)
				}
			})
		})
	})
}

func TestMissingFieldOmitted(t *testing.T) {
	r := format.Record{ID: "x", Fields: map[string]any{"AlertId": "orca-1", "Status": "open"}}
	got := format.Alert(r).Text()
	if want := "AlertId: orca-1\nStatus: open\n"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestAssetCurated(t *testing.T) {
	r := load(t, "asset.json").Records[0]
	got := format.Asset(r).Text()
	want := `Name: synthetic-vm-01
Type: AwsEc2Instance
RiskLevel: critical
OrcaScore: 10
State: running
Region: us-east-2
Exposure: internet_facing
IsCrownJewel: true
Account: synthetic-account
TotalVulnerabilitiesFound: 42
ui_url: https://app.example.invalid/inventory/a1
`
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestSearchRows(t *testing.T) {
	env := load(t, "search.json")
	got := []string{format.SearchRow(env.Records[0]).Line(), format.SearchRow(env.Records[1]).Line()}
	want := []string{
		"Alert | orca-1234 | critical | 9.7 | in_progress | Remote code execution in synthetic-lib | synthetic-vm-01",
		"AwsEc2Instance | synthetic-vm-01 | critical | synthetic-account",
	}
	if got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestCuratedMapJSON(t *testing.T) {
	r := load(t, "alert.json").Records[0]
	b, _ := json.Marshal(format.Alert(r).Map())
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	if m["AlertId"] != "orca-1234" || m["OrcaScore"] != 9.7 || m["ui_url"] == nil {
		t.Fatalf("unexpected map %s", b)
	}
}
