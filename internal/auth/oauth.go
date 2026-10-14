package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

const (
	callbackAddr = "127.0.0.1:19877"
	callbackPath = "/callback"
	redirectURI  = "http://" + callbackAddr + callbackPath
)

var httpClient = &http.Client{Timeout: 30 * time.Second}

// Metadata is the subset of RFC 8414 authorization server metadata we use.
type Metadata struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	RegistrationEndpoint  string `json:"registration_endpoint"`
	RevocationEndpoint    string `json:"revocation_endpoint"`
}

func getJSON(u string, v any) error {
	resp, err := httpClient.Get(u)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: status %d", u, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

// Discover resolves authorization server metadata at runtime: the resource's
// RFC 9728 protected-resource document names the authorization server, whose
// RFC 8414 document names the endpoints (D9).
func Discover(resource string) (*Metadata, error) {
	ru, err := url.Parse(resource)
	if err != nil || ru.Host == "" {
		return nil, fmt.Errorf("invalid resource URL %q", resource)
	}
	var pr struct {
		AuthorizationServers []string `json:"authorization_servers"`
	}
	if err := getJSON(ru.Scheme+"://"+ru.Host+"/.well-known/oauth-protected-resource", &pr); err != nil {
		return nil, fmt.Errorf("discover protected resource: %w", err)
	}
	if len(pr.AuthorizationServers) == 0 {
		return nil, errors.New("discover: no authorization_servers in protected resource metadata")
	}
	as := strings.TrimRight(pr.AuthorizationServers[0], "/")
	au, err := url.Parse(as)
	if err != nil {
		return nil, fmt.Errorf("discover: bad authorization server %q", as)
	}
	// RFC 8414 §3: well-known goes between host and issuer path.
	var md Metadata
	if err := getJSON(au.Scheme+"://"+au.Host+"/.well-known/oauth-authorization-server"+au.Path, &md); err != nil {
		return nil, fmt.Errorf("discover authorization server: %w", err)
	}
	if md.AuthorizationEndpoint == "" || md.TokenEndpoint == "" || md.RegistrationEndpoint == "" {
		return nil, errors.New("discover: authorization server metadata lacks authorization, token or registration endpoint")
	}
	return &md, nil
}

// register performs RFC 7591 dynamic registration as a public client.
func register(md *Metadata) (string, error) {
	body, _ := json.Marshal(map[string]any{
		"client_name":                "spyhop",
		"client_uri":                 "https://github.com/Deastrom/spyhop",
		"redirect_uris":              []string{redirectURI},
		"token_endpoint_auth_method": "none",
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
	})
	resp, err := httpClient.Post(md.RegistrationEndpoint, "application/json", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("register: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", fmt.Errorf("register: status %d: %s", resp.StatusCode, b)
	}
	var r struct {
		ClientID string `json:"client_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil || r.ClientID == "" {
		return "", errors.New("register: no client_id in response")
	}
	return r.ClientID, nil
}

// Login runs discovery, DCR (unless clientID is already known) and the PKCE
// S256 authorization code flow with the resource indicator.
func Login(opts LoginOptions, clientID string) (*Tokens, error) {
	if opts.Resource == "" {
		opts.Resource = DefaultResource
	}
	if opts.Out == nil {
		opts.Out = io.Discard
	}
	md, err := Discover(opts.Resource)
	if err != nil {
		return nil, err
	}
	if clientID == "" {
		if clientID, err = register(md); err != nil {
			return nil, err
		}
	}
	verifier, challenge, err := pkce()
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", callbackAddr)
	if err != nil {
		return nil, fmt.Errorf("callback listener (port in use?): %w", err)
	}

	state := randomString(16)
	authURL := md.AuthorizationEndpoint + "?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {state},
		"resource":              {opts.Resource},
	}.Encode()

	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)
	mux := http.NewServeMux()
	mux.HandleFunc(callbackPath, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		switch {
		case q.Get("state") != state:
			errCh <- errors.New("state mismatch")
			http.Error(w, "state mismatch", http.StatusBadRequest)
		case q.Get("code") == "":
			errCh <- fmt.Errorf("no code in callback (error=%q)", q.Get("error"))
			http.Error(w, "missing code", http.StatusBadRequest)
		default:
			fmt.Fprintln(w, "Login successful. You can close this tab.")
			codeCh <- q.Get("code")
		}
	})
	srv := &http.Server{Handler: mux, ReadTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(listener) }()
	defer srv.Shutdown(context.Background())

	fmt.Fprintf(opts.Out, "Open this URL to log in:\n%s\n", authURL)
	open := opts.Open
	if open == nil {
		open = openBrowser
	}
	_ = open(authURL)

	var code string
	select {
	case code = <-codeCh:
	case e := <-errCh:
		return nil, e
	case <-time.After(5 * time.Minute):
		return nil, errors.New("login timed out waiting for browser callback")
	}

	t, err := tokenRequest(md.TokenEndpoint, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {clientID},
		"code_verifier": {verifier},
		"redirect_uri":  {redirectURI},
		"resource":      {opts.Resource},
	})
	if err != nil {
		return nil, err
	}
	t.ClientID, t.Resource = clientID, opts.Resource
	t.TokenEndpoint, t.RevocationEndpoint = md.TokenEndpoint, md.RevocationEndpoint
	return t, nil
}

func tokenRequest(endpoint string, form url.Values) (*Tokens, error) {
	resp, err := httpClient.PostForm(endpoint, form)
	if err != nil {
		return nil, fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("token endpoint: status %d: %s", resp.StatusCode, b)
	}
	var tr struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil || tr.AccessToken == "" {
		return nil, errors.New("token endpoint: no access_token in response")
	}
	if tr.ExpiresIn == 0 {
		tr.ExpiresIn = 3600
	}
	return &Tokens{AccessToken: tr.AccessToken, RefreshToken: tr.RefreshToken,
		ExpiresAt: time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)}, nil
}

// EnsureValid returns t if fresh, else refreshes it. The bool reports whether
// a refresh happened; callers persist the result.
func EnsureValid(t *Tokens) (*Tokens, bool, error) {
	if !t.IsExpired() {
		return t, false, nil
	}
	if t.RefreshToken == "" {
		return nil, false, fmt.Errorf("%w: access token expired and no refresh token; %s", ErrUnauthorized, loginHint)
	}
	n, err := tokenRequest(t.TokenEndpoint, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {t.RefreshToken},
		"client_id":     {t.ClientID},
		"resource":      {t.Resource},
	})
	if err != nil {
		return nil, false, fmt.Errorf("%w: token refresh failed; %s: %v", ErrUnauthorized, loginHint, err)
	}
	n.ClientID, n.Resource, n.TokenEndpoint, n.RevocationEndpoint = t.ClientID, t.Resource, t.TokenEndpoint, t.RevocationEndpoint
	if n.RefreshToken == "" {
		n.RefreshToken = t.RefreshToken
	}
	return n, true, nil
}

// Revoke revokes the refresh token at the discovered revocation endpoint.
// A missing endpoint or token is a no-op; callers treat errors as best effort.
func Revoke(t *Tokens) error {
	if t.RevocationEndpoint == "" || t.RefreshToken == "" {
		return nil
	}
	resp, err := httpClient.PostForm(t.RevocationEndpoint, url.Values{
		"token":           {t.RefreshToken},
		"token_type_hint": {"refresh_token"},
		"client_id":       {t.ClientID},
	})
	if err != nil {
		return fmt.Errorf("revoke: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("revoke: status %d", resp.StatusCode)
	}
	return nil
}

func pkce() (verifier, challenge string, err error) {
	buf := make([]byte, 32)
	if _, err = rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("pkce rand: %w", err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

func randomString(n int) string {
	buf := make([]byte, n)
	_, _ = rand.Read(buf)
	return base64.RawURLEncoding.EncodeToString(buf)
}

func openBrowser(u string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", u).Start()
	case "linux":
		return exec.Command("xdg-open", u).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", u).Start()
	}
	return errors.New("unsupported platform")
}
