package format_test

import (
	"testing"

	"github.com/Deastrom/spyhop/internal/format"
)

func rec(fields map[string]any) format.Record { return format.Record{ID: "x", Fields: fields} }

func TestSelectOrderAndMissing(t *testing.T) {
	r := rec(map[string]any{"AlertId": "orca-1", "Title": "t"})
	t.Run("given fields Title,Description,AlertId and no Description", func(t *testing.T) {
		t.Run("when selected", func(t *testing.T) {
			got := format.Select(r, []string{"Title", "Description", "AlertId"})
			t.Run("then the present fields keep the given order and the missing one is omitted", func(t *testing.T) {
				if want := "Title: t\nAlertId: orca-1\n"; got.Text() != want {
					t.Fatalf("got %q, want %q", got.Text(), want)
				}
			})
		})
	})
}

func TestCuratedJSONKeepsOrder(t *testing.T) {
	r := rec(map[string]any{"AlertId": "orca-1", "Title": "t", "Score": 9.5})
	got := format.Select(r, []string{"Title", "Score", "AlertId"}).JSON()
	if want := `{"Title":"t","Score":9.5,"AlertId":"orca-1"}`; got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestTSV(t *testing.T) {
	rows := []format.Curated{
		format.Select(rec(map[string]any{"AlertId": "orca-1", "Labels": []any{"a", "b"}, "Title": "has\ttab"}), []string{"AlertId", "Labels", "Title", "Description"}),
		format.Select(rec(map[string]any{"AlertId": "orca-2", "Title": "multi\nline", "Description": map[string]any{"k": "v"}}), []string{"AlertId", "Labels", "Title", "Description"}),
	}
	t.Run("given two rows, a list, a tab, a newline, an object and a missing cell", func(t *testing.T) {
		t.Run("when rendered as TSV", func(t *testing.T) {
			got := format.TSV([]string{"AlertId", "Labels", "Title", "Description"}, rows)
			t.Run("then there is a header, sanitized cells, empty cells for missing values and no footer", func(t *testing.T) {
				want := "AlertId\tLabels\tTitle\tDescription\n" +
					"orca-1\ta,b\thas tab\t\n" +
					"orca-2\t\tmulti line\t{\"k\":\"v\"}\n"
				if got != want {
					t.Fatalf("got %q, want %q", got, want)
				}
			})
		})
	})
}

func TestID(t *testing.T) {
	env := load(t, "search.json")
	got := []string{format.ID(env.Records[0]), format.ID(env.Records[1])}
	if want := []string{"orca-1234", "vm_synthetic_1"}; got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestTSVColumnsDefaultToUnionInFirstSeenOrder(t *testing.T) {
	rows := []format.Curated{
		{{Key: "a", Value: "1"}},
		{{Key: "b", Value: "2"}, {Key: "a", Value: "3"}},
	}
	got := format.TSV(nil, rows)
	if want := "a\tb\n1\t\n3\t2\n"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
