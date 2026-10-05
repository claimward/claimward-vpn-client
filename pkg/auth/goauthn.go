package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// goauthnProvider signs in at a go-authn provider (go-authn/bridge) with the
// device flow, for the scopes "openid wireguard".
//
// The token it returns opens the provider's own WireGuard key registry, and
// nothing else: a go-authn provider addresses a token carrying one of its own
// scopes to itself alone, so it is never one a VPN server can be shown. The
// token for claimward-vpn-server comes from RegisterKey, after the key is
// registered: a refresh that asks for "openid" alone (RFC 6749 6).
type goauthnProvider struct {
	issuer   string
	clientID string
	hc       *http.Client
}

func (p *goauthnProvider) Name() string { return "go-authn" }

// scopes asked for at sign-in: the registry, and an identity.
var goauthnScopes = []string{"openid", "wireguard"}

func (p *goauthnProvider) endpoint(ctx context.Context) (oauth2.Endpoint, error) {
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, p.hc), p.issuer)
	if err != nil {
		return oauth2.Endpoint{}, fmt.Errorf("go-authn discovery for %q: %w", p.issuer, err)
	}
	return provider.Endpoint(), nil
}

func (p *goauthnProvider) Login(ctx context.Context, onPrompt func(DevicePrompt)) (*Token, error) {
	ep, err := p.endpoint(ctx)
	if err != nil {
		return nil, err
	}
	if ep.DeviceAuthURL == "" {
		return nil, errors.New("go-authn: the provider offers no device flow")
	}
	cfg := &oauth2.Config{ClientID: p.clientID, Endpoint: ep, Scopes: goauthnScopes}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, p.hc)
	da, err := cfg.DeviceAuth(ctx)
	if err != nil {
		return nil, fmt.Errorf("go-authn device authorization: %w", err)
	}
	if onPrompt != nil {
		uri := da.VerificationURIComplete
		if uri == "" {
			uri = da.VerificationURI
		}
		onPrompt(DevicePrompt{VerificationURI: uri, UserCode: da.UserCode, ExpiresIn: int(time.Until(da.Expiry).Seconds())})
	}
	tok, err := cfg.DeviceAccessToken(ctx, da)
	if err != nil {
		return nil, fmt.Errorf("go-authn sign-in: %w", err)
	}
	return &Token{Value: tok.AccessToken, Kind: KindAccessToken, Expiry: tok.Expiry, Refresh: tok.RefreshToken}, nil
}

// KeyRegistrar is a provider that keeps the devices' WireGuard keys itself:
// before enrolling, the device's PUBLIC key is registered there, and the
// token to show claimward-vpn-server is what RegisterKey returns.
type KeyRegistrar interface {
	RegisterKey(ctx context.Context, tok *Token, publicKey, device string) (*Token, error)
}

// RegisterKey registers the device's public key for the person tok is about
// -- renewing it when it is already theirs -- and returns a token for
// claimward-vpn-server. The refresh token in what it returns replaces the one
// in tok: a go-authn provider rotates them, and the old one is spent.
//
// ⛔ Only the public key. The private key never leaves the device.
func (p *goauthnProvider) RegisterKey(ctx context.Context, tok *Token, publicKey, device string) (*Token, error) {
	ep, err := p.endpoint(ctx)
	if err != nil {
		return nil, err
	}
	if tok.Refresh == "" {
		return nil, errors.New("go-authn: no refresh token, so no token for the VPN server can be had; the client needs refresh_lifetime at the provider")
	}
	registry, refresh := tok.Value, tok.Refresh
	if tok.Value == "" || time.Until(tok.Expiry) < time.Minute {
		// The sign-in token has lapsed: a refresh with no scope asks for all
		// that was granted, the registry included.
		t, err := p.refresh(ctx, ep.TokenURL, refresh, "")
		if err != nil {
			return nil, err
		}
		registry, refresh = t.Value, t.Refresh
	}
	if err := p.register(ctx, registry, publicKey, device); err != nil {
		return nil, err
	}
	return p.refresh(ctx, ep.TokenURL, refresh, "openid")
}

func (p *goauthnProvider) register(ctx context.Context, bearer, publicKey, device string) error {
	body, _ := json.Marshal(map[string]string{"public_key": publicKey, "device": device})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(p.issuer, "/")+"/wireguard/key", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Content-Type", "application/json")
	res, err := p.hc.Do(req)
	if err != nil {
		return fmt.Errorf("go-authn: registering the device key: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(res.Body, 4<<10))
		return fmt.Errorf("go-authn refused the device key (%s): %s", res.Status, strings.TrimSpace(string(msg)))
	}
	return nil
}

// refresh is RFC 6749 6, by hand: x/oauth2 cannot ask a refresh for less
// than was granted.
func (p *goauthnProvider) refresh(ctx context.Context, tokenURL, refresh, scope string) (*Token, error) {
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {p.clientID}}
	if scope != "" {
		form.Set("scope", scope)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := p.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("go-authn refresh: %w", err)
	}
	defer res.Body.Close()
	var out struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
		Error        string `json:"error"`
		Description  string `json:"error_description"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&out); err != nil {
		return nil, fmt.Errorf("go-authn refresh (%s): %w", res.Status, err)
	}
	if res.StatusCode != http.StatusOK || out.AccessToken == "" {
		return nil, fmt.Errorf("go-authn refresh refused (%s): %s %s", res.Status, out.Error, out.Description)
	}
	t := &Token{Value: out.AccessToken, Kind: KindAccessToken, Refresh: out.RefreshToken}
	if out.ExpiresIn > 0 {
		t.Expiry = time.Now().Add(time.Duration(out.ExpiresIn) * time.Second)
	}
	if t.Refresh == "" {
		t.Refresh = refresh
	}
	return t, nil
}
