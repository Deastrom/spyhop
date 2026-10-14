// Package format turns Orca MCP envelopes into short output.
package format

import "strings"

// Unwrap collapses every {"value": X} object to X, recursively. Orca wraps
// each record field this way; objects with other keys are left intact.
func Unwrap(v any) any {
	switch t := v.(type) {
	case map[string]any:
		if inner, ok := t["value"]; ok && len(t) == 1 {
			return Unwrap(inner)
		}
		out := make(map[string]any, len(t))
		for k, e := range t {
			out[k] = Unwrap(e)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = Unwrap(e)
		}
		return out
	}
	return v
}

// FirstSentence returns s up to and including the first period that ends a
// sentence, or its first line when there is none.
func FirstSentence(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "\n"); i >= 0 {
		s = s[:i]
	}
	if i := strings.Index(s, ". "); i >= 0 {
		return s[:i+1]
	}
	return s
}
