package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"strings"

	"github.com/Deastrom/spyhop/internal/format"
	"github.com/Deastrom/spyhop/internal/mcp"
	"github.com/spf13/cobra"
)

var alertStatuses = []string{"open", "in_progress", "closed", "snoozed", "dismissed"}

// view is the validated output selection for a curated command.
type view struct {
	format string // text, json, tsv
	fields []string
	ids    bool
}

// resolveView validates flag combinations before any network call (D4, D6).
func (o *opts) resolveView(ids bool) (view, error) {
	v := view{format: "text", ids: ids}
	if o.fields != "" {
		for _, f := range strings.Split(o.fields, ",") {
			if f = strings.TrimSpace(f); f != "" {
				v.fields = append(v.fields, f)
			}
		}
	}
	if o.format != "" {
		v.format = o.format
	}
	if o.json {
		if o.format != "" && o.format != "json" {
			return v, usagef("--json conflicts with --format %s", o.format)
		}
		v.format = "json"
	}
	switch v.format {
	case "text", "json", "tsv":
	default:
		return v, usagef("--format %q invalid; allowed: text, json, tsv", v.format)
	}
	shaped := o.json || o.format != "" || o.fields != "" || ids
	if o.raw && shaped {
		return v, usagef("--raw cannot be combined with --fields, --format, --json or --ids")
	}
	if ids && (o.fields != "" || o.format != "" || o.json) {
		return v, usagef("--ids cannot be combined with --fields, --format or --json")
	}
	return v, nil
}

// fetch calls a tool and parses its envelope. With --raw it prints the result
// text unchanged and returns done=true.
func (a *App) fetch(o *opts, tool string, args map[string]any) (env *format.Envelope, done bool, err error) {
	res, err := a.callTool(o, tool, args)
	if err != nil {
		return nil, false, err
	}
	if o.raw {
		fmt.Fprintln(a.Out, mcp.TextContent(res))
		return nil, true, nil
	}
	env, err = format.ParseEnvelope(mcp.TextContent(res))
	return env, false, err
}

// readIDs reads one ID per line from stdin, skipping blanks.
func (a *App) readIDs() ([]string, error) {
	if a.In == nil {
		return nil, usagef("no IDs on stdin")
	}
	var ids []string
	sc := bufio.NewScanner(a.In)
	for sc.Scan() {
		if id := strings.TrimSpace(sc.Text()); id != "" {
			ids = append(ids, id)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read stdin: %w", err)
	}
	if len(ids) == 0 {
		return nil, usagef("no IDs on stdin")
	}
	return ids, nil
}

// getCmd builds `alert get` / `asset get`: one ID, or `-` for IDs on stdin.
func (a *App) getCmd(o *opts, use, short, what, tool string, argKey string, extra func(map[string]any), curate func(format.Record) format.Curated) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: short,
		Args:  positional(cobra.ExactArgs(1)),
		RunE: func(_ *cobra.Command, args []string) error {
			v, err := o.resolveView(false)
			if err != nil {
				return err
			}
			ids := args
			if args[0] == "-" {
				if ids, err = a.readIDs(); err != nil {
					return err
				}
			}
			var rows []format.Curated
			firstFail := 0
			for _, id := range ids {
				toolArgs := map[string]any{argKey: id}
				if extra != nil {
					extra(toolArgs)
				}
				env, done, err := a.fetch(o, tool, toolArgs)
				if err == nil && !done && len(env.Records) == 0 {
					err = errors.New(what + " not found")
				}
				if err != nil {
					if len(ids) == 1 {
						return err
					}
					fmt.Fprintf(a.Err, "%s: %s\n", id, errMessage(err))
					if firstFail == 0 {
						firstFail = codeOf(err)
					}
					continue
				}
				if done {
					continue
				}
				r := env.Records[0]
				if len(v.fields) > 0 {
					rows = append(rows, format.Select(r, v.fields))
				} else {
					rows = append(rows, curate(r))
				}
			}
			a.printRows(v, rows)
			if firstFail != 0 {
				return &exitError{code: firstFail, err: errors.New("one or more lookups failed"), silent: true}
			}
			return nil
		},
	}
}

// printRows renders records: text separated by blank lines, NDJSON, or TSV.
func (a *App) printRows(v view, rows []format.Curated) {
	switch v.format {
	case "json":
		for _, r := range rows {
			fmt.Fprintln(a.Out, r.JSON())
		}
	case "tsv":
		if len(rows) > 0 {
			fmt.Fprint(a.Out, format.TSV(v.fields, rows))
		}
	default:
		texts := make([]string, len(rows))
		for i, r := range rows {
			texts[i] = r.Text()
		}
		fmt.Fprint(a.Out, strings.Join(texts, "\n"))
	}
}

func (a *App) searchCmd(o *opts) *cobra.Command {
	var limit int
	var ids bool
	c := &cobra.Command{
		Use:   "search <phrase>",
		Short: "Natural-language search over alerts and assets (discovery_search)",
		Args:  positional(cobra.ExactArgs(1)),
		RunE: func(_ *cobra.Command, args []string) error {
			v, err := o.resolveView(ids)
			if err != nil {
				return err
			}
			if limit < 1 || limit > 50 {
				return usagef("--limit %d out of range; allowed 1-50", limit)
			}
			env, done, err := a.fetch(o, "discovery_search", map[string]any{"search_phrase": args[0], "limit": limit})
			if err != nil || done {
				return err
			}
			if v.ids {
				for _, r := range env.Records {
					if id := format.ID(r); id != "" {
						fmt.Fprintln(a.Out, id)
					}
				}
				return nil
			}
			a.printSearch(v, env)
			return nil
		},
	}
	c.Flags().IntVar(&limit, "limit", 5, "Number of results (1-50)")
	c.Flags().BoolVar(&ids, "ids", false, "Print only AlertId / asset_unique_id, one per line")
	return c
}

// printSearch renders search-style rows: text lines plus footer, JSON array,
// or TSV.
func (a *App) printSearch(v view, env *format.Envelope) {
	rows := make([]format.Curated, len(env.Records))
	for i, r := range env.Records {
		if len(v.fields) > 0 {
			rows[i] = format.Select(r, v.fields)
		} else {
			rows[i] = format.SearchRow(r)
		}
	}
	switch v.format {
	case "json":
		parts := make([]string, len(rows))
		for i, r := range rows {
			parts[i] = r.JSON()
		}
		fmt.Fprintln(a.Out, "["+strings.Join(parts, ",")+"]")
	case "tsv":
		fmt.Fprint(a.Out, format.TSV(v.fields, rows))
	default:
		for _, r := range rows {
			fmt.Fprintln(a.Out, r.Line())
		}
		fmt.Fprintf(a.Out, "total_items: %d\n", env.Total)
		if env.AppURL != "" {
			fmt.Fprintf(a.Out, "app_url: %s\n", env.AppURL)
		}
	}
}

func (a *App) alertCmd(o *opts) *cobra.Command {
	c := &cobra.Command{Use: "alert", Short: "Alert lookups and workflow"}
	get := a.getCmd(o, "get <alert-id|->", "Curated alert summary (get_alert); - reads IDs from stdin", "alert", "get_alert", "alert_id", nil, format.Alert)
	c.AddCommand(get)
	c.AddCommand(a.lifecycleCmds(o)...)
	return c
}

func (a *App) assetCmd(o *opts) *cobra.Command {
	c := &cobra.Command{Use: "asset", Short: "Asset lookups"}
	var modelType string
	get := a.getCmd(o, "get <asset-id|->", "Curated asset summary (get_asset_by_id); - reads IDs from stdin", "asset", "get_asset_by_id", "asset_id",
		func(m map[string]any) {
			if modelType != "" {
				m["model_type"] = modelType
			}
		}, format.Asset)
	get.Flags().StringVar(&modelType, "model-type", "", "Asset model type, e.g. AwsEc2Instance (default Inventory)")
	c.AddCommand(get)
	return c
}
