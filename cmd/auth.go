package cmd

import (
	"fmt"
	"time"

	"github.com/Deastrom/spyhop/internal/auth"
	"github.com/spf13/cobra"
)

func (a *App) authCmd(o *opts) *cobra.Command {
	c := &cobra.Command{Use: "auth", Short: "Manage Orca authentication"}
	c.AddCommand(
		&cobra.Command{
			Use:   "login",
			Short: "Log in via the browser (OAuth 2.1 + PKCE)",
			Args:  cobra.NoArgs,
			RunE: func(*cobra.Command, []string) error {
				resource := a.Getenv("SPYHOP_MCP_URL")
				existing, _ := auth.LoadTokens()
				clientID := ""
				if existing != nil {
					clientID = existing.ClientID
				}
				t, err := auth.Login(auth.LoginOptions{Resource: resource, Open: a.Open, Out: a.Out}, clientID)
				if err != nil {
					return err
				}
				if err := auth.SaveTokens(t); err != nil {
					return fmt.Errorf("save tokens: %w", err)
				}
				fmt.Fprintln(a.Out, "Login successful.")
				return nil
			},
		},
		&cobra.Command{
			Use:   "status",
			Short: "Show auth mode, endpoint and token expiry",
			Args:  cobra.NoArgs,
			RunE: func(*cobra.Command, []string) error {
				p, err := auth.MakePlan(a.Getenv, o.region)
				if err != nil {
					return err
				}
				fmt.Fprintf(a.Out, "%-12s %s\n%-12s %s\n", "mode:", p.Mode, "endpoint:", p.Endpoint)
				if p.Mode == auth.ModeToken {
					return nil
				}
				t, err := auth.LoadTokens()
				if err != nil {
					return err
				}
				if t == nil {
					fmt.Fprintln(a.Out, "status:      not logged in; run: spyhop auth login")
					return nil
				}
				fmt.Fprintf(a.Out, "%-12s %s\n", "expires_at:", t.ExpiresAt.UTC().Format(time.RFC3339))
				return nil
			},
		},
		&cobra.Command{
			Use:   "logout",
			Short: "Revoke the refresh token and delete stored tokens",
			Args:  cobra.NoArgs,
			RunE: func(*cobra.Command, []string) error {
				t, err := auth.LoadTokens()
				if err != nil {
					return err
				}
				if t != nil {
					if err := auth.Revoke(t); err != nil {
						fmt.Fprintf(a.Err, "warning: %v\n", err) // best effort
					}
				}
				if err := auth.ClearTokens(); err != nil {
					return err
				}
				fmt.Fprintln(a.Out, "Logged out.")
				return nil
			},
		},
	)
	return c
}
