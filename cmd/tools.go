package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/Deastrom/spyhop/internal/format"
	"github.com/spf13/cobra"
)

func (a *App) toolsCmd(o *opts) *cobra.Command {
	return &cobra.Command{
		Use:   "tools [name]",
		Short: "List tools, or print one tool's input schema",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			c, mode, err := a.client(o)
			if err != nil {
				return err
			}
			tools, err := c.ListTools()
			if err != nil {
				return unauthorized(mode, err)
			}
			if len(args) == 1 {
				for _, t := range tools {
					if t.Name == args[0] {
						schema := t.InputSchema
						if len(schema) == 0 {
							schema = json.RawMessage("{}")
						}
						fmt.Fprintln(a.Out, string(schema))
						return nil
					}
				}
				return fmt.Errorf("unknown tool %q", args[0])
			}
			for _, t := range tools {
				fmt.Fprintf(a.Out, "%s\t%s\n", t.Name, format.FirstSentence(t.Description))
			}
			return nil
		},
	}
}
