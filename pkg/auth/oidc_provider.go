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

func (p *oidcProvider) Login(ctx context.Context, _ func(DevicePrompt)) (*Token, error) {
	toks, err := oidc.Login(ctx, oidc.Config{Issuer: p.issuer, ClientID: p.clientID})
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
