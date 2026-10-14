package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Deastrom/spyhop/internal/auth"
	"github.com/Deastrom/spyhop/internal/cache"
	"github.com/Deastrom/spyhop/internal/format"
	"github.com/Deastrom/spyhop/internal/mcp"
	"github.com/spf13/cobra"
)

const completionTimeout = 3 * time.Second

// store is the tool-list cache: $SPYHOP_CACHE_DIR, else ~/.cache/spyhop.
func (a *App) store() *cache.Store {
	if d := a.Getenv("SPYHOP_CACHE_DIR"); d != "" {
		return &cache.Store{Dir: d}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return &cache.Store{Dir: filepath.Join(home, ".cache", "spyhop")}
}

// toolList returns the tool list from a fresh cache, else from the server
// (and refreshes the cache; a failed cache write is not fatal, D5).
func (a *App) toolList(o *opts, refresh bool) ([]mcp.Tool, error) {
	p, err := auth.MakePlan(a.Getenv, o.region)
	if err != nil {
		return nil, err
	}
	store := a.store()
	if cached, fresh, found := store.Load(p.Mode, p.Endpoint); found && fresh && !refresh {
		return cached, nil
	}
	c, mode, err := a.client(o)
	if err != nil {
		return nil, err
	}
	tools, err := c.ListTools()
	if err != nil {
		return nil, unauthorized(mode, err)
	}
	_ = store.Save(p.Mode, p.Endpoint, tools)
	return tools, nil
}

// completionTools is toolList for tab completion: never fatal, bounded by a
// short timeout, falling back to a stale cache (D5) and to nothing.
func (a *App) completionTools(o *opts) []mcp.Tool {
	p, err := auth.MakePlan(a.Getenv, o.region)
	if err != nil {
		return nil
	}
	store := a.store()
	cached, fresh, found := store.Load(p.Mode, p.Endpoint)
	if found && fresh {
		return cached
	}
	c, _, err := a.client(o)
	if err != nil {
		return cached
	}
	c.SetTimeout(completionTimeout)
	tools, err := c.ListTools()
	if err != nil {
		return cached
	}
	_ = store.Save(p.Mode, p.Endpoint, tools)
	return tools
}

func matchesAll(t mcp.Tool, greps []string) bool {
	hay := strings.ToLower(t.Name + " " + t.Description)
	for _, g := range greps {
		if !strings.Contains(hay, strings.ToLower(g)) {
			return false
		}
	}
	return true
}

func (a *App) toolsCmd(o *opts) *cobra.Command {
	var refresh bool
	var greps []string
	c := &cobra.Command{
		Use:   "tools [name]",
		Short: "List tools (cached 24h), or print one tool's input schema",
		Args:  positional(cobra.MaximumNArgs(1)),
		RunE: func(_ *cobra.Command, args []string) error {
			if len(args) == 1 && len(greps) > 0 {
				return usagef("--grep applies to the tool list, not to `tools <name>`")
			}
			tools, err := a.toolList(o, refresh)
			if err != nil {
				return err
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
			matched := 0
			for _, t := range tools {
				if matchesAll(t, greps) {
					matched++
					fmt.Fprintf(a.Out, "%s\t%s\n", t.Name, format.FirstSentence(t.Description))
				}
			}
			if matched == 0 {
				return fmt.Errorf("no tools match")
			}
			return nil
		},
		ValidArgsFunction: a.completeToolNames(o),
	}
	c.Flags().BoolVar(&refresh, "refresh", false, "Refetch the tool list instead of using the 24h cache")
	c.Flags().StringArrayVar(&greps, "grep", nil, "Keep tools whose name or description contains this text (repeat to require all)")
	return c
}
