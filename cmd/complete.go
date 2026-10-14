package cmd

import (
	"encoding/json"
	"strings"

	"github.com/Deastrom/spyhop/internal/format"
	"github.com/spf13/cobra"
)

// completeToolNames completes the first positional argument with tool names.
func (a *App) completeToolNames(o *opts) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return func(_ *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if len(args) > 0 {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		var out []string
		for _, t := range a.completionTools(o) {
			if strings.HasPrefix(t.Name, toComplete) {
				out = append(out, t.Name+"\t"+format.FirstSentence(t.Description))
			}
		}
		return out, cobra.ShellCompDirectiveNoFileComp
	}
}

// completeArgKeys completes `--arg` with `key=` from the tool's input schema.
func (a *App) completeArgKeys(o *opts) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return func(_ *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		const directive = cobra.ShellCompDirectiveNoSpace | cobra.ShellCompDirectiveNoFileComp
		if len(args) == 0 || strings.Contains(toComplete, "=") {
			return nil, directive
		}
		for _, t := range a.completionTools(o) {
			if t.Name != args[0] {
				continue
			}
			var out []string
			for _, k := range schemaKeys(t.InputSchema) {
				if strings.HasPrefix(k, toComplete) {
					out = append(out, k+"=")
				}
			}
			return out, directive
		}
		return nil, directive
	}
}

// fixedValues completes a flag from a fixed list, without any network call.
func fixedValues(values ...string) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return func(_ *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		var out []string
		for _, v := range values {
			if strings.HasPrefix(v, toComplete) {
				out = append(out, v)
			}
		}
		return out, cobra.ShellCompDirectiveNoFileComp
	}
}

// schemaKeys returns the property names of a JSON Schema in declaration order.
func schemaKeys(schema json.RawMessage) []string {
	var s struct {
		Properties orderedKeys `json:"properties"`
	}
	if json.Unmarshal(schema, &s) != nil {
		return nil
	}
	return s.Properties
}

type orderedKeys []string

func (k *orderedKeys) UnmarshalJSON(b []byte) error {
	dec := json.NewDecoder(strings.NewReader(string(b)))
	if _, err := dec.Token(); err != nil { // opening brace
		return err
	}
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return err
		}
		*k = append(*k, key.(string))
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return err
		}
	}
	return nil
}
