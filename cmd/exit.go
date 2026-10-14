package cmd

import (
	"errors"
	"fmt"
	"strings"

	"github.com/Deastrom/spyhop/internal/auth"
	"github.com/Deastrom/spyhop/internal/mcp"
	"github.com/spf13/cobra"
)

// Exit codes follow gh: 0 success, 1 error, 2 usage, 4 unauthorized.
const (
	exitError1       = 1
	exitUsage        = 2
	exitUnauthorized = 4
)

// exitError carries an explicit exit code. silent means the message was
// already printed (batch runs print per-ID failures as they happen).
type exitError struct {
	code   int
	err    error
	silent bool
}

func (e *exitError) Error() string { return e.err.Error() }
func (e *exitError) Unwrap() error { return e.err }

func usagef(format string, a ...any) error {
	return &exitError{code: exitUsage, err: fmt.Errorf(format, a...)}
}

// cobraUsage lists cobra-generated messages that report bad invocation.
var cobraUsage = []string{"unknown command", "required flag", "unknown flag", "unknown shorthand", "accepts ", "requires "}

func codeOf(err error) int {
	var ee *exitError
	switch {
	case errors.As(err, &ee):
		return ee.code
	case errors.Is(err, mcp.ErrUnauthorized), errors.Is(err, auth.ErrUnauthorized):
		return exitUnauthorized
	case errors.Is(err, auth.ErrInvalidRegion):
		return exitUsage
	}
	for _, p := range cobraUsage {
		if strings.HasPrefix(err.Error(), p) {
			return exitUsage
		}
	}
	return exitError1
}

func errMessage(err error) string {
	var te *mcp.ToolError
	if errors.As(err, &te) {
		return te.Text
	}
	return err.Error()
}

// positional wraps a cobra arg validator so its failures are usage errors.
func positional(v cobra.PositionalArgs) cobra.PositionalArgs {
	return func(c *cobra.Command, args []string) error {
		if err := v(c, args); err != nil {
			return &exitError{code: exitUsage, err: err}
		}
		return nil
	}
}
