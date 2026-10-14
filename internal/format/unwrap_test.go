package format_test

import (
	"encoding/json"
	"testing"

	"github.com/Deastrom/spyhop/internal/format"
)

func TestUnwrap(t *testing.T) {
	t.Run("given an envelope with {value:X} fields", func(t *testing.T) {
		t.Run("when unwrapped", func(t *testing.T) {
			var in any
			_ = json.Unmarshal([]byte(`{"a":{"value":[{"value":1},{"b":2}]},"c":{"value":null},"d":{"value":1,"x":2}}`), &in)
			got, _ := json.Marshal(format.Unwrap(in))
			t.Run("then single-key value objects collapse recursively", func(t *testing.T) {
				want := `{"a":[1,{"b":2}],"c":null,"d":{"value":1,"x":2}}`
				if string(got) != want {
					t.Fatalf("got %s, want %s", got, want)
				}
			})
		})
	})
}

func TestFirstSentence(t *testing.T) {
	got := []string{format.FirstSentence("Get one alert. Returns more."), format.FirstSentence("No period here"), format.FirstSentence("Line one\nLine two")}
	want := []string{"Get one alert.", "No period here", "Line one"}
	if got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("got %q, want %q", got, want)
	}
}
