package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/Deastrom/spyhop/internal/format"
	"github.com/Deastrom/spyhop/internal/mcp"
	"github.com/spf13/cobra"
)

var cveRe = regexp.MustCompile(`(?i)^CVE-\d{4}-\d{4,}$`)

func (a *App) docsCmd(o *opts) *cobra.Command {
	return &cobra.Command{
		Use:   `docs "<question>"`,
		Short: "Ask the Orca documentation (documentation_search)",
		Args:  positional(cobra.ExactArgs(1)),
		RunE: func(_ *cobra.Command, args []string) error {
			res, err := a.callTool(o, "documentation_search", map[string]any{"question": args[0]})
			if err != nil {
				return err
			}
			text := mcp.TextContent(res)
			if o.raw {
				fmt.Fprintln(a.Out, text)
				return nil
			}
			answer, sources, err := format.Docs(text)
			if err != nil {
				return err
			}
			answer = format.StripHTML(answer)
			if o.json || o.format == "json" {
				if sources == nil {
					sources = []string{}
				}
				fmt.Fprintln(a.Out, format.Curated{{Key: "answer", Value: answer}, {Key: "sources", Value: sources}}.JSON())
				return nil
			}
			fmt.Fprintln(a.Out, answer)
			for _, s := range sources {
				fmt.Fprintf(a.Out, "source: %s\n", s)
			}
			return nil
		},
	}
}

func (a *App) cveCmd(o *opts) *cobra.Command {
	return &cobra.Command{
		Use:   "cve <CVE-id>",
		Short: "Look a CVE up in Orca's catalog (get_cve_from_catalog)",
		Args:  positional(cobra.ExactArgs(1)),
		RunE: func(_ *cobra.Command, args []string) error {
			if !cveRe.MatchString(args[0]) {
				return usagef("%q is not a CVE id; want CVE-YYYY-NNNN", args[0])
			}
			asJSON, err := o.jsonOnly(false, true)
			if err != nil {
				return err
			}
			res, err := a.callTool(o, "get_cve_from_catalog", map[string]any{"cve_id": strings.ToUpper(args[0])})
			if err != nil {
				return err
			}
			text := mcp.TextContent(res)
			if o.raw {
				fmt.Fprintln(a.Out, text)
				return nil
			}
			s, err := format.CVE(text)
			if err != nil {
				return err
			}
			if asJSON {
				fmt.Fprintln(a.Out, s.JSON())
				return nil
			}
			fmt.Fprint(a.Out, s.Text())
			return nil
		},
	}
}

func (a *App) queryCmd(o *opts) *cobra.Command {
	var limit, offset int
	var orderBy []string
	c := &cobra.Command{
		Use:   "query <file|->",
		Short: "Run a structured discovery query object (run_svl_query)",
		Args:  positional(cobra.ExactArgs(1)),
		RunE: func(_ *cobra.Command, args []string) error {
			v, err := o.resolveView(false)
			if err != nil {
				return err
			}
			if limit < 1 || limit > 200 {
				return usagef("--limit %d out of range; allowed 1-200", limit)
			}
			if offset < 0 {
				return usagef("--offset %d must be >= 0", offset)
			}
			var data []byte
			if args[0] == "-" {
				if a.In == nil {
					return usagef("no query on stdin")
				}
				data, err = io.ReadAll(a.In)
			} else {
				data, err = os.ReadFile(args[0])
			}
			if err != nil {
				return fmt.Errorf("read query: %w", err)
			}
			var query map[string]any
			if err := json.Unmarshal(data, &query); err != nil || query == nil {
				return usagef("query must be a JSON object")
			}
			toolArgs := map[string]any{"query": query, "limit": limit, "offset": offset}
			if len(orderBy) > 0 {
				toolArgs["order_by"] = orderBy
			}
			res, err := a.callTool(o, "run_svl_query", toolArgs)
			if err != nil {
				return err
			}
			if o.raw {
				fmt.Fprintln(a.Out, mcp.TextContent(res))
				return nil
			}
			if env := parseIfEnvelope(mcp.TextContent(res)); env != nil {
				a.printSearch(v, env)
				return nil
			}
			return a.printResult(o, res)
		},
	}
	c.Flags().IntVar(&limit, "limit", 50, "Records per page (1-200)")
	c.Flags().IntVar(&offset, "offset", 0, "Records to skip")
	c.Flags().StringArrayVar(&orderBy, "order-by", nil, "Sort field; prefix with - for descending (repeatable)")
	return c
}

// parseIfEnvelope returns the parsed envelope when text is one (an object
// with a status and a data array), else nil.
func parseIfEnvelope(text string) *format.Envelope {
	var probe struct {
		Status *string `json:"status"`
		Data   []any   `json:"data"`
	}
	if json.Unmarshal([]byte(text), &probe) != nil || probe.Status == nil || probe.Data == nil {
		return nil
	}
	env, err := format.ParseEnvelope(text)
	if err != nil {
		return nil
	}
	return env
}
