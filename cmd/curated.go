package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Deastrom/spyhop/internal/format"
	"github.com/Deastrom/spyhop/internal/mcp"
	"github.com/spf13/cobra"
)

var alertStatuses = []string{"open", "in_progress", "closed", "snoozed", "dismissed"}

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

func (a *App) printJSON(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	fmt.Fprintln(a.Out, string(b))
	return nil
}

// printOne prints the first record of env through curate, as text or JSON.
func (a *App) printOne(o *opts, env *format.Envelope, what string, curate func(format.Record) format.Curated) error {
	if len(env.Records) == 0 {
		return fmt.Errorf("%s not found", what)
	}
	c := curate(env.Records[0])
	if o.json {
		return a.printJSON(c.Map())
	}
	fmt.Fprint(a.Out, c.Text())
	return nil
}

func (a *App) searchCmd(o *opts) *cobra.Command {
	var limit int
	c := &cobra.Command{
		Use:   "search <phrase>",
		Short: "Natural-language search over alerts and assets (discovery_search)",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if limit < 1 || limit > 50 {
				return fmt.Errorf("--limit %d out of range; allowed 1-50", limit)
			}
			env, done, err := a.fetch(o, "discovery_search", map[string]any{"search_phrase": args[0], "limit": limit})
			if err != nil || done {
				return err
			}
			if o.json {
				rows := make([]map[string]any, len(env.Records))
				for i, r := range env.Records {
					rows[i] = format.SearchRow(r).Map()
				}
				return a.printJSON(rows)
			}
			for _, r := range env.Records {
				fmt.Fprintln(a.Out, format.SearchRow(r).Line())
			}
			fmt.Fprintf(a.Out, "total_items: %d\n", env.Total)
			if env.AppURL != "" {
				fmt.Fprintf(a.Out, "app_url: %s\n", env.AppURL)
			}
			return nil
		},
	}
	c.Flags().IntVar(&limit, "limit", 5, "Number of results (1-50)")
	return c
}

func (a *App) alertCmd(o *opts) *cobra.Command {
	c := &cobra.Command{Use: "alert", Short: "Alert lookups and workflow"}
	get := &cobra.Command{
		Use:   "get <alert-id>",
		Short: "Curated alert summary (get_alert)",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			env, done, err := a.fetch(o, "get_alert", map[string]any{"alert_id": args[0]})
			if err != nil || done {
				return err
			}
			return a.printOne(o, env, "alert "+args[0], format.Alert)
		},
	}
	var to string
	status := &cobra.Command{
		Use:   "status <alert-id> --to <status>",
		Short: "Set alert status (update_alert_status)",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			valid := false
			for _, s := range alertStatuses {
				valid = valid || s == to
			}
			if !valid {
				return fmt.Errorf("--to %q invalid; allowed: %s", to, strings.Join(alertStatuses, ", "))
			}
			res, err := a.callTool(o, "update_alert_status", map[string]any{"alert_id": args[0], "status": to})
			if err != nil {
				return err
			}
			if o.raw {
				fmt.Fprintln(a.Out, mcp.TextContent(res))
				return nil
			}
			if o.json {
				return a.printJSON(map[string]any{"alert_id": args[0], "status": to})
			}
			fmt.Fprintf(a.Out, "%s: %s\n", args[0], to)
			return nil
		},
	}
	status.Flags().StringVar(&to, "to", "", "New status: "+strings.Join(alertStatuses, ", "))
	_ = status.MarkFlagRequired("to")
	c.AddCommand(get, status)
	return c
}

func (a *App) assetCmd(o *opts) *cobra.Command {
	c := &cobra.Command{Use: "asset", Short: "Asset lookups"}
	var modelType string
	get := &cobra.Command{
		Use:   "get <asset-id>",
		Short: "Curated asset summary (get_asset_by_id)",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			toolArgs := map[string]any{"asset_id": args[0]}
			if modelType != "" {
				toolArgs["model_type"] = modelType
			}
			env, done, err := a.fetch(o, "get_asset_by_id", toolArgs)
			if err != nil || done {
				return err
			}
			return a.printOne(o, env, "asset "+args[0], format.Asset)
		},
	}
	get.Flags().StringVar(&modelType, "model-type", "", "Asset model type, e.g. AwsEc2Instance (default Inventory)")
	c.AddCommand(get)
	return c
}
