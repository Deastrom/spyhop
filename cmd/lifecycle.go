package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/Deastrom/spyhop/internal/format"
	"github.com/Deastrom/spyhop/internal/mcp"
	"github.com/spf13/cobra"
)

// Reason enums from the live tool schemas (2026-10-14).
var (
	dismissReasons = []string{"False Positive", "Non-Actionable", "Non-Production", "Acceptable Risk", "Other"}
	snoozeReasons  = []string{"Temporarily deprioritized", "Awaiting further context or confirmation", "Non-Actionable", "Non-Production", "Other"}
	scoreReasons   = []string{"Non-Actionable", "Non-Production", "Acceptable Risk", "Organization preferences", "Other"}
)

// canonReason matches in case-insensitively and returns the canonical form.
func canonReason(in string, allowed []string) (string, error) {
	for _, r := range allowed {
		if strings.EqualFold(in, r) {
			return r, nil
		}
	}
	return "", usagef("--reason %q invalid; allowed: %s", in, strings.Join(allowed, ", "))
}

// gate enforces D1: without --yes the planned call is printed (exit 2).
func (a *App) gate(o *opts, tool string, args map[string]any, yes bool) error {
	if !yes {
		b, err := json.Marshal(struct {
			Tool string         `json:"tool"`
			Args map[string]any `json:"args"`
		}{tool, args})
		if err != nil {
			return err
		}
		fmt.Fprintln(a.Out, string(b))
		return &exitError{code: exitUsage, err: errors.New("pass --yes to execute")}
	}
	res, err := a.callTool(o, tool, args)
	if err != nil {
		return err
	}
	return a.printResult(o, res)
}

// writeCmd builds an alert write: one ID, validated flags, then the --yes gate.
// bind registers the command's flags and returns the argument builder.
func (a *App) writeCmd(o *opts, use, short, tool string, bind func(c *cobra.Command) func(id string) (map[string]any, error)) *cobra.Command {
	var yes bool
	c := &cobra.Command{Use: use, Short: short, Args: positional(cobra.ExactArgs(1))}
	build := bind(c)
	c.Flags().BoolVar(&yes, "yes", false, "Execute the write; without it the planned call is printed and the exit code is 2")
	c.RunE = func(_ *cobra.Command, args []string) error {
		if args[0] == "-" {
			return usagef("alert %s takes one alert ID", c.Name())
		}
		m, err := build(args[0])
		if err != nil {
			return err
		}
		return a.gate(o, tool, m, yes)
	}
	return c
}

// reasonFlags adds --reason/--justification and returns a function that
// copies them into args.
func reasonFlags(c *cobra.Command, allowed []string) func(args map[string]any) error {
	var reason, justification string
	c.Flags().StringVar(&reason, "reason", "", "Reason: "+strings.Join(allowed, ", "))
	c.Flags().StringVar(&justification, "justification", "", "Free-text justification for the audit trail")
	_ = c.RegisterFlagCompletionFunc("reason", fixedValues(allowed...))
	return func(args map[string]any) error {
		if reason != "" {
			canon, err := canonReason(reason, allowed)
			if err != nil {
				return err
			}
			args["reason"] = canon
		}
		if justification != "" {
			args["justification"] = justification
		}
		return nil
	}
}

func (a *App) lifecycleCmds(o *opts) []*cobra.Command {
	status := a.writeCmd(o, "status <alert-id> --to <status>", "Set alert status (update_alert_status)", "update_alert_status",
		func(c *cobra.Command) func(string) (map[string]any, error) {
			var to string
			c.Flags().StringVar(&to, "to", "", "New status: "+strings.Join(alertStatuses, ", "))
			_ = c.RegisterFlagCompletionFunc("to", fixedValues(alertStatuses...))
			_ = c.MarkFlagRequired("to")
			return func(id string) (map[string]any, error) {
				for _, s := range alertStatuses {
					if s == to {
						return map[string]any{"alert_id": id, "status": to}, nil
					}
				}
				return nil, usagef("--to %q invalid; allowed: %s", to, strings.Join(alertStatuses, ", "))
			}
		})

	comment := a.writeCmd(o, "comment <alert-id> --body <text>", "Add a comment (add_alert_comment)", "add_alert_comment",
		func(c *cobra.Command) func(string) (map[string]any, error) {
			var body string
			c.Flags().StringVar(&body, "body", "", "Comment text")
			return func(id string) (map[string]any, error) {
				if body == "" {
					return nil, usagef("--body is required")
				}
				return map[string]any{"alert_id": id, "comment": body}, nil
			}
		})

	snooze := a.writeCmd(o, "snooze <alert-id> --days N", "Snooze an alert for N days (snooze_alert)", "snooze_alert",
		func(c *cobra.Command) func(string) (map[string]any, error) {
			var days int
			c.Flags().IntVar(&days, "days", 0, "Days to snooze (>= 1)")
			rf := reasonFlags(c, snoozeReasons)
			return func(id string) (map[string]any, error) {
				if days < 1 {
					return nil, usagef("--days is required and must be at least 1")
				}
				m := map[string]any{"alert_id": id, "days": days}
				return m, rf(m)
			}
		})

	dismiss := a.writeCmd(o, "dismiss <alert-id>", "Permanently dismiss an alert (dismiss_alert)", "dismiss_alert",
		func(c *cobra.Command) func(string) (map[string]any, error) {
			rf := reasonFlags(c, dismissReasons)
			return func(id string) (map[string]any, error) {
				m := map[string]any{"alert_id": id}
				return m, rf(m)
			}
		})

	score := a.writeCmd(o, "score <alert-id> --score 0-10", "Override an alert's Orca score (change_alert_score)", "change_alert_score",
		func(c *cobra.Command) func(string) (map[string]any, error) {
			var score float64
			c.Flags().Float64Var(&score, "score", 0, "New Orca score, 0-10")
			rf := reasonFlags(c, scoreReasons)
			return func(id string) (map[string]any, error) {
				if !c.Flags().Changed("score") || score < 0 || score > 10 {
					return nil, usagef("--score is required and must be between 0 and 10")
				}
				m := map[string]any{"alert_id": id, "orca_score": score}
				return m, rf(m)
			}
		})

	verify := a.writeCmd(o, "verify <alert-id>", "Re-evaluate whether the alert's condition is still detected (verify_alert)", "verify_alert",
		func(*cobra.Command) func(string) (map[string]any, error) {
			return func(id string) (map[string]any, error) { return map[string]any{"alert_id": id}, nil }
		})

	return []*cobra.Command{status, comment, snooze, dismiss, score, verify, a.timelineCmd(o), a.attackPathCmd(o), a.similarCmd(o)}
}

func (a *App) timelineCmd(o *opts) *cobra.Command {
	return &cobra.Command{
		Use:   "timeline <alert-id>",
		Short: "Alert history, one line per event (get_alert_timeline); --json prints the event array",
		Args:  positional(cobra.ExactArgs(1)),
		RunE: func(_ *cobra.Command, args []string) error {
			res, err := a.callTool(o, "get_alert_timeline", map[string]any{"alert_id": args[0]})
			if err != nil {
				return err
			}
			text := mcp.TextContent(res)
			if o.raw {
				fmt.Fprintln(a.Out, text)
				return nil
			}
			events, raw, err := format.ParseTimeline(text)
			if err != nil {
				return err
			}
			if o.json {
				b, err := json.Marshal(raw)
				if err != nil {
					return err
				}
				fmt.Fprintln(a.Out, string(b))
				return nil
			}
			for _, e := range events {
				fmt.Fprintln(a.Out, e.Line())
			}
			return nil
		},
	}
}

func (a *App) attackPathCmd(o *opts) *cobra.Command {
	return &cobra.Command{
		Use:   "attack-path <alert-id>",
		Short: "Attack path records as JSON, then total_items (get_alert_attack_path_data)",
		Args:  positional(cobra.ExactArgs(1)),
		RunE: func(_ *cobra.Command, args []string) error {
			res, err := a.callTool(o, "get_alert_attack_path_data", map[string]any{"alert_id": args[0]})
			if err != nil {
				return err
			}
			text := mcp.TextContent(res)
			if o.raw {
				fmt.Fprintln(a.Out, text)
				return nil
			}
			records, total, err := format.AttackPath(text)
			if err != nil {
				return err
			}
			fmt.Fprintln(a.Out, records)
			fmt.Fprintf(a.Out, "total_items: %d\n", total)
			return nil
		},
	}
}

// alertRecord fetches one alert for its linking fields.
func (a *App) alertRecord(o *opts, id string) (format.Record, error) {
	res, err := a.callTool(o, "get_alert", map[string]any{"alert_id": id})
	if err != nil {
		return format.Record{}, err
	}
	env, err := format.ParseEnvelope(mcp.TextContent(res))
	if err != nil {
		return format.Record{}, err
	}
	if len(env.Records) == 0 {
		return format.Record{}, errors.New("alert not found")
	}
	return env.Records[0], nil
}

func (a *App) similarCmd(o *opts) *cobra.Command {
	var by, secretHash string
	c := &cobra.Command{
		Use:   "similar <alert-id> --by type|malware|secret",
		Short: "Alerts similar to this one, as search rows",
		Args:  positional(cobra.ExactArgs(1)),
		RunE: func(_ *cobra.Command, args []string) error {
			v, err := o.resolveView(false)
			if err != nil {
				return err
			}
			id := args[0]
			var tool string
			var toolArgs map[string]any
			switch by {
			case "":
				return usagef("--by is required: type, malware, secret")
			case "type":
				rec, err := a.alertRecord(o, id)
				if err != nil {
					return err
				}
				rt, _ := rec.Fields["RuleType"].(string)
				if rt == "" {
					return errors.New("alert has no RuleType")
				}
				tool, toolArgs = "get_alerts_with_similar_alert_type", map[string]any{"alert_id": id, "alert_type": rt}
			case "malware":
				rec, err := a.alertRecord(o, id)
				if err != nil {
					return err
				}
				inv, _ := rec.Fields["Inventory"].(map[string]any)
				asset, _ := inv["id"].(string)
				if asset == "" {
					return errors.New("alert has no Inventory.id")
				}
				tool, toolArgs = "get_alerts_with_similar_malware", map[string]any{"alert_id": id, "asset_id": asset}
			case "secret":
				if secretHash == "" {
					return usagef("--by secret requires --secret-hash")
				}
				tool, toolArgs = "get_other_secret_occurrences", map[string]any{"alert_id": id, "secret_hash": secretHash}
			default:
				return usagef("--by %q invalid; allowed: type, malware, secret", by)
			}
			env, done, err := a.fetch(o, tool, toolArgs)
			if err != nil || done {
				return err
			}
			a.printSearch(v, env)
			return nil
		},
	}
	c.Flags().StringVar(&by, "by", "", "Similarity: type, malware, secret")
	c.Flags().StringVar(&secretHash, "secret-hash", "", "Secret hash (required with --by secret)")
	_ = c.RegisterFlagCompletionFunc("by", fixedValues("type", "malware", "secret"))
	return c
}
