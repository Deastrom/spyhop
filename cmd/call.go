package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Deastrom/spyhop/internal/format"
	"github.com/Deastrom/spyhop/internal/mcp"
	"github.com/spf13/cobra"
)

func (a *App) callCmd(o *opts) *cobra.Command {
	var kv []string
	c := &cobra.Command{
		Use:   "call <tool> [--arg key=value ...]",
		Short: "Call any Orca MCP tool by name",
		Args:  positional(cobra.ExactArgs(1)),
		RunE: func(_ *cobra.Command, args []string) error {
			toolArgs := map[string]any{}
			for _, p := range kv {
				k, v, ok := strings.Cut(p, "=")
				if !ok || k == "" {
					return fmt.Errorf("--arg %q: want key=value", p)
				}
				toolArgs[k] = parseArg(v)
			}
			res, err := a.callTool(o, args[0], toolArgs)
			if err != nil {
				return err
			}
			return a.printResult(o, res)
		},
	}
	c.Flags().StringArrayVar(&kv, "arg", nil, "Tool argument key=value (value sent as JSON when it parses, else string)")
	return c
}

// parseArg types a value: JSON-parsable text is sent as that JSON value.
func parseArg(v string) any {
	var out any
	if json.Unmarshal([]byte(v), &out) == nil {
		return out
	}
	return v
}

// printResult prints the unwrapped result as compact JSON, or the text
// unchanged with --raw or when it is not JSON.
func (a *App) printResult(o *opts, res *mcp.ToolCallResult) error {
	text := mcp.TextContent(res)
	if o.raw {
		fmt.Fprintln(a.Out, text)
		return nil
	}
	var v any
	if err := json.Unmarshal([]byte(text), &v); err != nil {
		fmt.Fprintln(a.Out, text)
		return nil
	}
	b, err := json.Marshal(format.Unwrap(v))
	if err != nil {
		return err
	}
	fmt.Fprintln(a.Out, string(b))
	return nil
}
