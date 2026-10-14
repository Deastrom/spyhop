// Package auth implements spyhop's credential handling: runtime OAuth
// discovery, dynamic client registration, PKCE login, refresh, and the
// ORCA_TOKEN override.
package auth

import (
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	// DefaultResource is the Orca MCP server, also the RFC 8707 resource indicator.
	DefaultResource = "https://mcp.orcasecurity.io/"

	// ModeToken authenticates with ORCA_TOKEN against the regional API endpoint.
	ModeToken = "token"
	// ModeOAuth authenticates with stored OAuth tokens against DefaultResource.
	ModeOAuth = "oauth"

	envToken    = "ORCA_TOKEN"
	envRegion   = "ORCA_REGION"
	envEndpoint = "SPYHOP_MCP_URL"

	loginHint = "run: spyhop auth login"
)

// ErrUnauthorized marks failures fixed by logging in again (exit code 4).
var ErrUnauthorized = errors.New("not authenticated")

// ErrInvalidRegion marks a region outside the supported set (usage error).
var ErrInvalidRegion = errors.New("invalid region")

var regions = []string{"us", "eu", "au", "in", "sa"}

// LoginOptions configures Login.
type LoginOptions struct {
	Resource string
	Open     func(url string) error // opens the browser; nil prints only
	Out      io.Writer
}

// Plan is the resolved auth mode and endpoint, before any credential I/O.
type Plan struct {
	Mode     string
	Endpoint string
	Token    string // ORCA_TOKEN in token mode
}

// Session is a Plan plus the Authorization header ready to send.
type Session struct {
	Plan
	AuthHeader string
	Tokens     *Tokens // nil in token mode
}

// MakePlan applies D4: ORCA_TOKEN set selects token auth against the
// regional endpoint, otherwise stored OAuth against DefaultResource.
// regionFlag overrides ORCA_REGION. SPYHOP_MCP_URL overrides the endpoint
// (test and incident use).
func MakePlan(getenv func(string) string, regionFlag string) (*Plan, error) {
	region := regionFlag
	if region == "" {
		region = getenv(envRegion)
	}
	if region == "" {
		region = "us"
	}
	valid := false
	for _, r := range regions {
		valid = valid || r == region
	}
	if !valid {
		return nil, fmt.Errorf("%w %q; valid regions: %s", ErrInvalidRegion, region, strings.Join(regions, ", "))
	}
	override := getenv(envEndpoint)
	if tok := getenv(envToken); tok != "" {
		host := "api." + region + ".orcasecurity.io"
		if region == "us" {
			host = "api.orcasecurity.io"
		}
		ep := "https://" + host + "/mcp"
		if override != "" {
			ep = override
		}
		return &Plan{Mode: ModeToken, Endpoint: ep, Token: tok}, nil
	}
	ep := DefaultResource
	if override != "" {
		ep = override
	}
	return &Plan{Mode: ModeOAuth, Endpoint: ep}, nil
}

// Resolve returns a ready Session, refreshing and persisting OAuth tokens
// when expired.
func Resolve(getenv func(string) string, regionFlag string) (*Session, error) {
	p, err := MakePlan(getenv, regionFlag)
	if err != nil {
		return nil, err
	}
	if p.Mode == ModeToken {
		return &Session{Plan: *p, AuthHeader: "Token " + p.Token}, nil
	}
	t, err := LoadTokens()
	if err != nil {
		return nil, err
	}
	if t == nil {
		return nil, fmt.Errorf("%w; %s", ErrUnauthorized, loginHint)
	}
	t, refreshed, err := EnsureValid(t)
	if err != nil {
		return nil, err
	}
	if refreshed {
		if err := SaveTokens(t); err != nil {
			return nil, fmt.Errorf("save refreshed tokens: %w", err)
		}
	}
	return &Session{Plan: *p, AuthHeader: "Bearer " + t.AccessToken, Tokens: t}, nil
}
