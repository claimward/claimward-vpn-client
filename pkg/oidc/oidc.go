// Package oidc implements the OpenID Connect Authorization Code + PKCE flow used
// by claimward clients to authenticate the user against any standards-compliant
// identity provider (discovered via the issuer's /.well-known/openid-configuration).
//
// The flow opens the system browser and captures the redirect on a loopback
// listener, so it works for native/public clients without a client secret.
package oidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/claimward/claimward-vpn-client/pkg/browser"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Config describes the OIDC client registration.
type Config struct {
	Issuer       string   // e.g. https://accounts.google.com or https://keycloak/realms/claimward
	ClientID     string   // public/native client id
	ClientSecret string   // usually empty for native clients
	Scopes       []string // defaults to openid, profile, email, offline_access
	RedirectPort int      // 0 = pick a free loopback port
	// OnAuthURL, if set, is called with the authorization URL before the browser
	// is opened — so a UI can surface it (e.g. an "Open sign-in page" button) in
	// case the automatic browser launch fails.
	OnAuthURL func(string)
}

// Tokens is the set of tokens returned by a successful login.
type Tokens struct {
	IDToken      string
	AccessToken  string
	RefreshToken string
	Expiry       time.Time
}

// Login runs the interactive browser-based PKCE flow and returns the tokens.
// It blocks until the redirect is received, ctx is cancelled, or an error
// occurs.
func Login(ctx context.Context, cfg Config) (*Tokens, error) {
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery for %q: %w", cfg.Issuer, err)
	}

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", cfg.RedirectPort))
	if err != nil {
		return nil, fmt.Errorf("open loopback listener: %w", err)
	}
	defer ln.Close()
	redirectURL := fmt.Sprintf("http://%s/callback", ln.Addr().String())

	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "profile", "email", oidc.ScopeOfflineAccess}
	}

	oauthCfg := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  redirectURL,
		Scopes:       scopes,
	}

	state := randString(24)
	verifier := oauth2.GenerateVerifier()
	authURL := oauthCfg.AuthCodeURL(state,
		oauth2.AccessTypeOffline,
		oauth2.S256ChallengeOption(verifier),
	)

	type result struct {
		tok *oauth2.Token
		err error
	}
	resCh := make(chan result, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if e := q.Get("error"); e != "" {
			http.Error(w, e, http.StatusBadRequest)
			resCh <- result{err: fmt.Errorf("identity provider returned error: %s", e)}
			return
		}
		if q.Get("state") != state {
			http.Error(w, "state mismatch", http.StatusBadRequest)
			resCh <- result{err: fmt.Errorf("state mismatch (possible CSRF)")}
			return
		}
		tok, err := oauthCfg.Exchange(r.Context(), q.Get("code"), oauth2.VerifierOption(verifier))
		if err != nil {
			http.Error(w, "token exchange failed", http.StatusInternalServerError)
			resCh <- result{err: fmt.Errorf("token exchange: %w", err)}
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, successHTML)
		resCh <- result{tok: tok}
	})

	srv := &http.Server{Handler: mux}
	go srv.Serve(ln) //nolint:errcheck // closed via defer
	defer srv.Close()

	if cfg.OnAuthURL != nil {
		cfg.OnAuthURL(authURL)
	}
	if err := browser.Open(authURL); err != nil {
		fmt.Printf("Could not open a browser automatically. Open this URL to sign in:\n\n%s\n\n", authURL)
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-resCh:
		if res.err != nil {
			return nil, res.err
		}
		idToken, _ := res.tok.Extra("id_token").(string)
		return &Tokens{
			IDToken:      idToken,
			AccessToken:  res.tok.AccessToken,
			RefreshToken: res.tok.RefreshToken,
			Expiry:       res.tok.Expiry,
		}, nil
	}
}

func randString(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

const successHTML = `<!doctype html>
<html lang="fr"><head><meta charset="utf-8"><title>Claimward</title></head>
<body style="font-family:system-ui,-apple-system,sans-serif;text-align:center;padding-top:90px;color:#1a1a2e">
<h2>Authentification réussie ✅</h2>
<p>Vous pouvez fermer cet onglet et revenir à Claimward.</p>
</body></html>`
