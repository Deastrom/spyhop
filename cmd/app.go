// Package cmd wires spyhop's cobra commands.
package cmd

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/Deastrom/spyhop/internal/auth"
	"github.com/Deastrom/spyhop/internal/mcp"
	"github.com/spf13/cobra"
)

// App carries the process edges so commands are testable.
type App struct {
	Out, Err io.Writer
	In       io.Reader // stdin, for `-` batches
	Getenv   func(string) string
	Open     func(url string) error // opens a browser; nil uses the OS default
	Version  string
}

type opts struct {
	json, raw bool
	region    string
	fields    string
	format    string
}

// New builds the root command.
func New(a *App) *cobra.Command {
	o := &opts{}
	root := &cobra.Command{
		Use:           "spyhop",
		Short:         "Orca Security CLI for AI agents, proxying the Orca MCP server",
		Version:       a.Version,
		SilenceUsage:  true,
		SilenceErrors: true,
		Long: `Orca Security CLI for AI agents, proxying the Orca MCP server.

Exit codes: 0 success, 1 error (including not found), 2 usage error,
4 unauthorized (run: spyhop auth login, or check ORCA_TOKEN).`,
	}
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return &exitError{code: 2, err: err} })
	root.SetOut(a.Out)
	root.SetErr(a.Err)
	root.PersistentFlags().BoolVar(&o.json, "json", false, "Output curated JSON")
	root.PersistentFlags().BoolVar(&o.raw, "raw", false, "Output the MCP tool result unchanged")
	root.PersistentFlags().StringVar(&o.fields, "fields", "", "Comma-separated top-level fields to print, in order (get/search)")
	root.PersistentFlags().StringVar(&o.format, "format", "", "Output format: text, json, tsv (--json is an alias for json)")
	root.PersistentFlags().StringVar(&o.region, "region", "", "Orca region for ORCA_TOKEN auth: us, eu, au, in, sa (default $ORCA_REGION or us)")
	_ = root.RegisterFlagCompletionFunc("region", fixedValues("us", "eu", "au", "in", "sa"))
	_ = root.RegisterFlagCompletionFunc("format", fixedValues("text", "json", "tsv"))
	root.AddCommand(a.authCmd(o), a.toolsCmd(o), a.callCmd(o), a.searchCmd(o), a.alertCmd(o), a.assetCmd(o))
	return root
}

// ExitCode runs the root command and returns the process exit code.
func ExitCode(a *App, args []string) int {
	root := New(a)
	root.SetArgs(args)
	if len(args) > 0 && strings.HasPrefix(args[0], "__complete") {
		root.SetErr(io.Discard) // completion output must stay clean
	}
	err := root.Execute()
	if err == nil {
		return 0
	}
	var ee *exitError
	if !(errors.As(err, &ee) && ee.silent) {
		fmt.Fprintln(a.Err, errMessage(err))
	}
	return codeOf(err)
}

// client resolves credentials and returns a ready MCP client plus the mode,
// for rewording 401s.
func (a *App) client(o *opts) (*mcp.Client, string, error) {
	s, err := auth.Resolve(a.Getenv, o.region)
	if err != nil {
		return nil, "", err
	}
	return mcp.New(s.AuthHeader, s.Endpoint), s.Mode, nil
}

func unauthorized(mode string, err error) error {
	if !errors.Is(err, mcp.ErrUnauthorized) {
		return err
	}
	if mode == auth.ModeToken {
		return &exitError{code: 4, err: errors.New("unauthorized; check ORCA_TOKEN")}
	}
	return &exitError{code: 4, err: errors.New("unauthorized; run: spyhop auth login")}
}

func (a *App) callTool(o *opts, name string, args map[string]any) (*mcp.ToolCallResult, error) {
	c, mode, err := a.client(o)
	if err != nil {
		return nil, err
	}
	res, err := c.CallTool(name, args)
	return res, unauthorized(mode, err)
}
