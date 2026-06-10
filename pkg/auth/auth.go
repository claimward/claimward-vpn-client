// Package auth abstracts the interactive sign-in flow behind a pluggable
// Provider, so the CLI and the platform apps work with several identity
// providers without caring which one is in use.
//
// The resulting Token carries an opaque bearer credential that the client sends
// to claimward-vpn-server in the Authorization header. The server's matching
// verifier decides how to validate it:
//
//   - github (default): a GitHub OAuth access token, obtained via the Device
//     Authorization Flow (no client secret, ideal for native/CLI clients).
//   - oidc: an OIDC ID token, obtained via Authorization Code + PKCE.
//
// Add a provider by implementing Provider and wiring it into New.
package auth

import (
	"context"
	"fmt"
	"time"
)

// Kind describes what sort of bearer a Token carries.
type Kind string

const (
	KindIDToken     Kind = "id_token"
	KindAccessToken Kind = "access_token"
)

// Token is the credential to present to the server.
type Token struct {
	Value   string
	Kind    Kind
	Expiry  time.Time
	Refresh string
}

// DevicePrompt is surfaced to the user during a device-code flow: they must
// visit VerificationURI and enter UserCode.
type DevicePrompt struct {
	VerificationURI string
	UserCode        string
	ExpiresIn       int
}

// Provider runs an interactive login.
type Provider interface {
	// Name is the provider id ("github", "oidc", …).
	Name() string
	// Login performs the flow and returns a bearer token. For device-code flows
	// onPrompt is invoked with the code/URL to display (it may be nil).
	Login(ctx context.Context, onPrompt func(DevicePrompt)) (*Token, error)
}

// Config selects and configures a Provider.
type Config struct {
	Provider string // "github" (default) | "oidc"

	// GitHub
	GitHubClientID string
	GitHubBaseURL  string // default https://github.com (set for GHE)
	GitHubScopes   []string

	// OIDC
	OIDCIssuer   string
	OIDCClientID string
}

// New builds the configured Provider.
func New(cfg Config) (Provider, error) {
	switch cfg.Provider {
	case "", "github":
		if cfg.GitHubClientID == "" {
			return nil, fmt.Errorf("github provider requires a client id")
		}
		scopes := cfg.GitHubScopes
		if len(scopes) == 0 {
			scopes = []string{"read:user", "user:email", "read:org"}
		}
		base := cfg.GitHubBaseURL
		if base == "" {
			base = "https://github.com"
		}
		return &githubProvider{clientID: cfg.GitHubClientID, baseURL: base, scopes: scopes}, nil
	case "oidc":
		if cfg.OIDCIssuer == "" || cfg.OIDCClientID == "" {
			return nil, fmt.Errorf("oidc provider requires issuer and client id")
		}
		return &oidcProvider{issuer: cfg.OIDCIssuer, clientID: cfg.OIDCClientID}, nil
	default:
		return nil, fmt.Errorf("unknown auth provider %q (want \"github\" or \"oidc\")", cfg.Provider)
	}
}
