package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeBridge is a go-authn provider as far as the client sees one: the
// device flow, refresh tokens that rotate and may ask for less, and the
// WireGuard key registry, which takes only a token of the wireguard scope.
type fakeBridge struct {
	srv *httptest.Server

	mu       sync.Mutex
	keys     map[string]string // public key -> device
	refresh  map[string]bool   // live refresh tokens
	issued   int
	asked    []string // the scope of each refresh
	failKeys bool
}

func newFakeBridge(t *testing.T) *fakeBridge {
	t.Helper()
	b := &fakeBridge{keys: map[string]string{}, refresh: map[string]bool{}}
	mux := http.NewServeMux()
	b.srv = httptest.NewServer(mux)
	t.Cleanup(b.srv.Close)
	iss := b.srv.URL
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer": iss, "jwks_uri": iss + "/jwks", "authorization_endpoint": iss + "/authorize",
			"token_endpoint": iss + "/token", "device_authorization_endpoint": iss + "/device_authorization",
		})
	})
	mux.HandleFunc("POST /device_authorization", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.FormValue("scope") != "openid wireguard" || r.FormValue("client_id") != "claimward" {
			http.Error(w, "unexpected device request: "+r.Form.Encode(), http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"device_code": "dc", "user_code": "BCDF-GHJK",
			"verification_uri": iss + "/device", "verification_uri_complete": iss + "/device?user_code=BCDFGHJK", "expires_in": 600, "interval": 1})
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		b.mu.Lock()
		defer b.mu.Unlock()
		switch r.FormValue("grant_type") {
		case "urn:ietf:params:oauth:grant-type:device_code":
			b.tokenLocked(w, "openid wireguard")
		case "refresh_token":
			rt := r.FormValue("refresh_token")
			if !b.refresh[rt] {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]any{"error": "invalid_grant", "error_description": "spent"})
				return
			}
			delete(b.refresh, rt) // rotation: the old one is spent
			scope := r.FormValue("scope")
			b.asked = append(b.asked, scope)
			if scope == "" {
				scope = "openid wireguard"
			}
			b.tokenLocked(w, scope)
		default:
			http.Error(w, "grant", http.StatusBadRequest)
		}
	})
	mux.HandleFunc("POST /wireguard/key", func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.failKeys {
			http.Error(w, "this key is registered to somebody else", http.StatusConflict)
			return
		}
		// Only a token for the registry: "at-N:openid wireguard".
		if !strings.HasSuffix(r.Header.Get("Authorization"), ":openid wireguard") {
			http.Error(w, "this token may not register WireGuard keys", http.StatusForbidden)
			return
		}
		var req struct {
			PublicKey string `json:"public_key"`
			Device    string `json:"device"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		b.keys[req.PublicKey] = req.Device
		json.NewEncoder(w).Encode(map[string]any{"public_key": req.PublicKey, "expires_at": time.Now().Add(24 * time.Hour).Unix()})
	})
	return b
}

// tokenLocked issues an access token naming its scope, and a new refresh token.
func (b *fakeBridge) tokenLocked(w http.ResponseWriter, scope string) {
	b.issued++
	rt := "rt-" + strings.Repeat("x", b.issued)
	b.refresh[rt] = true
	json.NewEncoder(w).Encode(map[string]any{
		"access_token": "at-" + string(rune('0'+b.issued)) + ":" + scope, "token_type": "Bearer",
		"expires_in": 300, "refresh_token": rt, "scope": scope,
	})
}

func goauthn(t *testing.T, b *fakeBridge) Provider {
	t.Helper()
	p, err := New(Config{Provider: "go-authn", OIDCIssuer: b.srv.URL, OIDCClientID: "claimward"})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

const devicePub = "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw="

// Sign in once for the registry; register the key; get a token for the VPN
// server -- one that is not the registry's -- and keep the rotated refresh.
func TestGoAuthnRegistersTheKeyThenNarrows(t *testing.T) {
	b := newFakeBridge(t)
	p := goauthn(t, b)
	ctx := context.Background()
	var prompt DevicePrompt
	tok, err := p.Login(ctx, func(d DevicePrompt) { prompt = d })
	if err != nil {
		t.Fatal(err)
	}
	if prompt.UserCode != "BCDF-GHJK" || !strings.Contains(prompt.VerificationURI, "user_code=") {
		t.Errorf("the prompt: %+v", prompt)
	}
	if tok.Kind != KindAccessToken || !strings.HasSuffix(tok.Value, ":openid wireguard") || tok.Refresh == "" {
		t.Fatalf("the sign-in token: %+v", tok)
	}
	reg, ok := p.(KeyRegistrar)
	if !ok {
		t.Fatal("the go-authn provider registers no keys")
	}
	srv, err := reg.RegisterKey(ctx, tok, devicePub, "laptop")
	if err != nil {
		t.Fatal(err)
	}
	if b.keys[devicePub] != "laptop" {
		t.Errorf("the registry has %v", b.keys)
	}
	if !strings.HasSuffix(srv.Value, ":openid") || srv.Refresh == "" || srv.Refresh == tok.Refresh {
		t.Errorf("the server's token: %+v (sign-in refresh %q)", srv, tok.Refresh)
	}
	if len(b.asked) != 1 || b.asked[0] != "openid" {
		t.Errorf("the refreshes asked for %q", b.asked)
	}

	// Next connect, an hour later: the registry token has lapsed, so the
	// rotated refresh token buys a new one first, then the narrowed one.
	later := &Token{Value: tok.Value, Kind: KindAccessToken, Expiry: time.Now().Add(-time.Minute), Refresh: srv.Refresh}
	again, err := reg.RegisterKey(ctx, later, devicePub, "laptop")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(again.Value, ":openid") || len(b.asked) != 3 || b.asked[1] != "" || b.asked[2] != "openid" {
		t.Errorf("the second connect: %+v, refreshes %q", again, b.asked)
	}
}

func TestGoAuthnSaysWhyItCannot(t *testing.T) {
	b := newFakeBridge(t)
	p := goauthn(t, b).(KeyRegistrar)
	ctx := context.Background()
	// No refresh token: no token for the server can be had.
	if _, err := p.RegisterKey(ctx, &Token{Value: "at-1:openid wireguard", Expiry: time.Now().Add(time.Hour)}, devicePub, "x"); err == nil || !strings.Contains(err.Error(), "refresh_lifetime") {
		t.Errorf("no refresh token: %v", err)
	}
	// The registry refuses the key: said, with the provider's reason.
	b.mu.Lock()
	b.refresh["rt-live"], b.failKeys = true, true
	b.mu.Unlock()
	if _, err := p.RegisterKey(ctx, &Token{Value: "at-1:openid wireguard", Expiry: time.Now().Add(time.Hour), Refresh: "rt-live"}, devicePub, "x"); err == nil || !strings.Contains(err.Error(), "somebody else") {
		t.Errorf("a refused key: %v", err)
	}
	// A spent refresh token.
	if _, err := p.RegisterKey(ctx, &Token{Expiry: time.Now().Add(-time.Hour), Refresh: "rt-spent"}, devicePub, "x"); err == nil || !strings.Contains(err.Error(), "spent") {
		t.Errorf("a spent refresh token: %v", err)
	}
	// Configuration that cannot work.
	if _, err := New(Config{Provider: "go-authn", OIDCIssuer: b.srv.URL}); err == nil {
		t.Error("no client id was taken")
	}
	nowhere, _ := New(Config{Provider: "go-authn", OIDCIssuer: "http://127.0.0.1:1", OIDCClientID: "c"})
	if _, err := nowhere.Login(ctx, nil); err == nil {
		t.Error("a provider that is not there signed in")
	}
}
