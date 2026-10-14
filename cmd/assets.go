package cmd

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/Deastrom/spyhop/internal/format"
	"github.com/Deastrom/spyhop/internal/mcp"
	"github.com/spf13/cobra"
)

var uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// jsonOnly validates flags for commands that support only text, --json and
// (optionally) --ids, and reports whether JSON output was requested.
func (o *opts) jsonOnly(ids, rawOK bool) (bool, error) {
	if o.fields != "" {
		return false, usagef("--fields is not supported by this command")
	}
	if o.format != "" && o.format != "text" && o.format != "json" {
		return false, usagef("--format %q is not supported by this command; allowed: text, json", o.format)
	}
	asJSON := o.json || o.format == "json"
	if o.raw && !rawOK {
		return false, usagef("--raw is not supported by this command")
	}
	if o.raw && (asJSON || ids) {
		return false, usagef("--raw cannot be combined with --json, --format or --ids")
	}
	if ids && asJSON {
		return false, usagef("--ids cannot be combined with --json or --format")
	}
	return asJSON, nil
}

// resolveAsset looks an asset up by any ID `asset get` accepts.
func (a *App) resolveAsset(o *opts, id string) (format.Record, error) {
	res, err := a.callTool(o, "get_asset_by_id", map[string]any{"asset_id": id})
	if err != nil {
		return format.Record{}, err
	}
	env, err := format.ParseEnvelope(mcp.TextContent(res))
	if err != nil {
		return format.Record{}, err
	}
	if len(env.Records) == 0 {
		return format.Record{}, errors.New("asset not found")
	}
	return env.Records[0], nil
}

// assetUUID returns the UUID tools taking `asset_id` need, skipping the
// lookup when the input already is one (D1).
func (a *App) assetUUID(o *opts, id string) (string, error) {
	if uuidRe.MatchString(id) {
		return id, nil
	}
	rec, err := a.resolveAsset(o, id)
	return rec.ID, err
}

func (a *App) assetFindCmd(o *opts) *cobra.Command {
	var limit int
	var ids bool
	var modelType string
	c := &cobra.Command{
		Use:   "find <name> [--limit 1-50] [--model-type T] [--ids]",
		Short: "Find assets by display-name substring (get_asset_by_name)",
		Args:  positional(cobra.ExactArgs(1)),
		RunE: func(_ *cobra.Command, args []string) error {
			v, err := o.resolveView(ids)
			if err != nil {
				return err
			}
			if limit < 1 || limit > 50 {
				return usagef("--limit %d out of range; allowed 1-50", limit)
			}
			toolArgs := map[string]any{"asset_name": args[0], "name_match_limit": limit}
			if modelType != "" {
				toolArgs["model_type"] = modelType
			}
			env, done, err := a.fetch(o, "get_asset_by_name", toolArgs)
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
	c.Flags().IntVar(&limit, "limit", 5, "Number of matches (1-50)")
	c.Flags().StringVar(&modelType, "model-type", "", "Asset model type, e.g. AwsEc2Instance (default Inventory)")
	c.Flags().BoolVar(&ids, "ids", false, "Print only asset_unique_id, one per line")
	return c
}

func (a *App) assetAlertsCmd(o *opts) *cobra.Command {
	var ids bool
	c := &cobra.Command{
		Use:   "alerts <asset-id> [--ids]",
		Short: "Open alert counts by risk level plus the top alerts for an asset",
		Args:  positional(cobra.ExactArgs(1)),
		RunE: func(_ *cobra.Command, args []string) error {
			asJSON, err := o.jsonOnly(ids, false)
			if err != nil {
				return err
			}
			uuid, err := a.assetUUID(o, args[0])
			if err != nil {
				return err
			}
			toolArgs := map[string]any{"asset_id": uuid}
			cres, err := a.callTool(o, "get_asset_alerts_count_grouped_by_risk_level", toolArgs)
			if err != nil {
				return err
			}
			counts, err := format.RiskCounts(mcp.TextContent(cres))
			if err != nil {
				return err
			}
			sres, err := a.callTool(o, "get_asset_related_alerts_summary", toolArgs)
			if err != nil {
				return err
			}
			rows, err := format.AlertSummaryRows(mcp.TextContent(sres))
			if err != nil {
				return err
			}
			switch {
			case ids:
				for _, r := range rows {
					if len(r) > 0 {
						fmt.Fprintln(a.Out, r[0].Value)
					}
				}
			case asJSON:
				parts := make([]string, len(rows))
				for i, r := range rows {
					parts[i] = r.JSON()
				}
				fmt.Fprintf(a.Out, `{"counts":%s,"alerts":[%s]}`+"\n", format.CountsJSON(counts), strings.Join(parts, ","))
			default:
				fmt.Fprintln(a.Out, format.CountsLine(counts))
				for _, r := range rows {
					fmt.Fprintln(a.Out, format.AlertSummaryLine(r))
				}
			}
			return nil
		},
	}
	c.Flags().BoolVar(&ids, "ids", false, "Print only alert names, one per line")
	return c
}

func (a *App) assetAttackPathsCmd(o *opts) *cobra.Command {
	return &cobra.Command{
		Use:   "attack-paths <asset-id>",
		Short: "Attack paths involving an asset, one line each (get_asset_related_attack_paths_summary)",
		Args:  positional(cobra.ExactArgs(1)),
		RunE: func(_ *cobra.Command, args []string) error {
			if _, err := o.jsonOnly(false, true); err != nil {
				return err
			}
			uuid, err := a.assetUUID(o, args[0])
			if err != nil {
				return err
			}
			res, err := a.callTool(o, "get_asset_related_attack_paths_summary", map[string]any{"asset_id": uuid})
			if err != nil {
				return err
			}
			text := mcp.TextContent(res)
			if o.raw {
				fmt.Fprintln(a.Out, text)
				return nil
			}
			lines, total, err := format.AttackPathLines(text)
			if err != nil {
				return err
			}
			for _, l := range lines {
				fmt.Fprintln(a.Out, l)
			}
			fmt.Fprintf(a.Out, "total_items: %d\n", total)
			return nil
		},
	}
}

// assetCrownJewelCmd is read-only by design: marking crown jewels is a
// leadership/central-team decision, so no write command exists.
func (a *App) assetCrownJewelCmd(o *opts) *cobra.Command {
	return &cobra.Command{
		Use:   "crown-jewel <asset-id>",
		Short: "Read an asset's crown jewel status (get_asset_crown_jewel_info)",
		Args:  positional(cobra.ExactArgs(1)),
		RunE: func(_ *cobra.Command, args []string) error {
			asJSON, err := o.jsonOnly(false, true)
			if err != nil {
				return err
			}
			rec, err := a.resolveAsset(o, args[0])
			if err != nil {
				return err
			}
			gid := rec.GroupUniqueID
			if gid == "" {
				gid, _ = rec.Fields["GroupUniqueId"].(string)
			}
			if gid == "" {
				return errors.New("asset has no group_unique_id")
			}
			res, err := a.callTool(o, "get_asset_crown_jewel_info", map[string]any{"group_unique_id": gid})
			if err != nil {
				return err
			}
			text := mcp.TextContent(res)
			if o.raw {
				fmt.Fprintln(a.Out, text)
				return nil
			}
			c, err := format.CrownJewel(text)
			if err != nil {
				return err
			}
			if asJSON {
				fmt.Fprintln(a.Out, c.JSON())
				return nil
			}
			fmt.Fprint(a.Out, c.Text())
			return nil
		},
	}
}
