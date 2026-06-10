package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// githubProvider implements the GitHub OAuth Device Authorization Flow.
//
// The device flow needs only a client id (no secret), which is exactly what a
// native/CLI client can safely ship. GitHub returns an OAuth access token; the
// server validates it against the GitHub API.
type githubProvider struct {
	clientID string
	baseURL  string
	scopes   []string
	http     *http.Client
}

func (p *githubProvider) Name() string { return "github" }

func (p *githubProvider) client() *http.Client {
	if p.http != nil {
		return p.http
	}
	return &http.Client{Timeout: 15 * time.Second}
}

func (p *githubProvider) Login(ctx context.Context, onPrompt func(DevicePrompt)) (*Token, error) {
	// 1. Request a device + user code.
	var dc struct {
		DeviceCode      string `json:"device_code"`
		UserCode        string `json:"user_code"`
		VerificationURI string `json:"verification_uri"`
		ExpiresIn       int    `json:"expires_in"`
		Interval        int    `json:"interval"`
		Error           string `json:"error"`
		ErrorDesc       string `json:"error_description"`
	}
	if err := p.form(ctx, "/login/device/code", url.Values{
		"client_id": {p.clientID},
		"scope":     {strings.Join(p.scopes, " ")},
	}, &dc); err != nil {
		return nil, err
	}
	if dc.Error != "" {
		return nil, fmt.Errorf("github device code: %s: %s", dc.Error, dc.ErrorDesc)
	}

	if onPrompt != nil {
		onPrompt(DevicePrompt{VerificationURI: dc.VerificationURI, UserCode: dc.UserCode, ExpiresIn: dc.ExpiresIn})
	}
	_ = openBrowser(dc.VerificationURI) // best effort

	// 2. Poll for the access token.
	interval := dc.Interval
	if interval <= 0 {
		interval = 5
	}
	deadline := time.Now().Add(time.Duration(dc.ExpiresIn) * time.Second)
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(interval) * time.Second):
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("device code expired before authorization")
		}

		var tr struct {
			AccessToken string `json:"access_token"`
			TokenType   string `json:"token_type"`
			Scope       string `json:"scope"`
			Error       string `json:"error"`
			ErrorDesc   string `json:"error_description"`
		}
		if err := p.form(ctx, "/login/oauth/access_token", url.Values{
			"client_id":   {p.clientID},
			"device_code": {dc.DeviceCode},
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		}, &tr); err != nil {
			return nil, err
		}

		switch tr.Error {
		case "":
			if tr.AccessToken == "" {
				return nil, fmt.Errorf("github returned an empty access token")
			}
			return &Token{Value: tr.AccessToken, Kind: KindAccessToken}, nil
		case "authorization_pending":
			// keep polling
		case "slow_down":
			interval += 5
		case "access_denied":
			return nil, fmt.Errorf("authorization was denied")
		case "expired_token":
			return nil, fmt.Errorf("device code expired before authorization")
		default:
			return nil, fmt.Errorf("github token: %s: %s", tr.Error, tr.ErrorDesc)
		}
	}
}

func (p *githubProvider) form(ctx context.Context, path string, values url.Values, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(p.baseURL, "/")+path, strings.NewReader(values.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := p.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(out)
}

func openBrowser(target string) error {
	var name string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		name, args = "open", []string{target}
	case "windows":
		name, args = "rundll32", []string{"url.dll,FileProtocolHandler", target}
	default:
		name, args = "xdg-open", []string{target}
	}
	return exec.Command(name, args...).Start()
}
