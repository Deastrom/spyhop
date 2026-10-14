package format_test

import (
	"testing"

	"github.com/Deastrom/spyhop/internal/format"
)

func TestStripHTML(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"tags and entities", `<p>Use <b>labels</b> &amp; tags</p>`, "Use labels & tags"},
		{"paragraphs become single newlines", "<p>One.</p>\n\n<p>Two.</p>", "One.\nTwo."},
		{"br and list items break lines", "Steps:<br/><ul><li>First</li><li>Second</li></ul>", "Steps:\nFirst\nSecond"},
		{"whitespace collapses", "  a \t  b \n\n\n  c  ", "a b\nc"},
		{"escaped tags stay literal text", "Write &lt;b&gt; for bold", "Write <b> for bold"},
		{"attributes are dropped", `<a href="https://x.example.invalid/?a=1&amp;b=2" class="k">link</a> text`, "link text"},
		{"nbsp becomes a space", "a&nbsp;b", "a b"},
		{"plain text is untouched", "No markup here.", "No markup here."},
		{"No answer", "No answer", "No answer"},
	}
	for _, c := range cases {
		t.Run("given "+c.name, func(t *testing.T) {
			t.Run("when stripped", func(t *testing.T) {
				got := format.StripHTML(c.in)
				t.Run("then it is plain text", func(t *testing.T) {
					if got != c.want {
						t.Fatalf("got %q, want %q", got, c.want)
					}
				})
			})
		})
	}
}
