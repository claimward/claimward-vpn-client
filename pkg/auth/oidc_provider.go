package auth

import (
	"context"

	"github.com/claimward/claimward-vpn-client/pkg/oidc"
)

// oidcProvider adapts the OIDC Authorization Code + PKCE flow to the Provider
// interface. It ignores onPrompt (the browser handles the whole interaction).
type oidcProvider struct {
	issuer   string
	clientID string
}

func (p *oidcProvider) Name() string { return "oidc" }

func (p *oidcProvider) Login(ctx context.Context, onPrompt func(DevicePrompt)) (*Token, error) {
	cfg := oidc.Config{Issuer: p.issuer, ClientID: p.clientID}
	if onPrompt != nil {
		// Surface the authorization URL so the UI can offer an "open sign-in page"
		// fallback if the automatic browser launch is blocked.
		cfg.OnAuthURL = func(u string) { onPrompt(DevicePrompt{VerificationURI: u}) }
	}
	toks, err := oidc.Login(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return &Token{
		Value:   toks.IDToken,
		Kind:    KindIDToken,
		Expiry:  toks.Expiry,
		Refresh: toks.RefreshToken,
	}, nil
}
