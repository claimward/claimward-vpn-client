package appcore

import (
	"context"
	"errors"
	"testing"

	"github.com/claimward/claimward-vpn-client/pkg/auth"
	"github.com/claimward/claimward-vpn-client/pkg/tokenstore"
	"github.com/claimward/claimward-vpn-client/pkg/wgkey"
)

// plain is a provider that keeps no keys: GitHub or OIDC.
type plain struct{}

func (plain) Name() string { return "plain" }
func (plain) Login(context.Context, func(auth.DevicePrompt)) (*auth.Token, error) {
	return nil, nil
}

// registrar is a go-authn provider as the app sees one.
type registrar struct {
	plain
	got *auth.Token
	pub string
	err error
}

func (r *registrar) RegisterKey(_ context.Context, tok *auth.Token, pub, device string) (*auth.Token, error) {
	r.got, r.pub = tok, pub
	if r.err != nil {
		return nil, r.err
	}
	return &auth.Token{Value: "token-for-the-server", Refresh: "rotated"}, nil
}

func session(t *testing.T) (*tokenstore.Session, wgkey.Pair) {
	t.Helper()
	pair, err := wgkey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return &tokenstore.Session{Bearer: "registry-token", RefreshToken: "first", WGPrivateKey: pair.Private.String()}, pair
}

func TestAPlainProviderEnrollsWithTheSessionsToken(t *testing.T) {
	sess, _ := session(t)
	bearer, changed, err := bearerFor(context.Background(), plain{}, sess, "laptop")
	if err != nil || bearer != "registry-token" || changed {
		t.Errorf("bearer %q, changed %v, err %v", bearer, changed, err)
	}
}

// With go-authn, the device's PUBLIC key is registered first, the server is
// shown the token that returns, and the rotated refresh token is kept.
func TestGoAuthnRegistersThePublicKeyFirst(t *testing.T) {
	sess, pair := session(t)
	r := &registrar{}
	bearer, changed, err := bearerFor(context.Background(), r, sess, "laptop")
	if err != nil {
		t.Fatal(err)
	}
	if bearer != "token-for-the-server" || !changed || sess.RefreshToken != "rotated" {
		t.Errorf("bearer %q, changed %v, refresh %q", bearer, changed, sess.RefreshToken)
	}
	if r.pub != pair.Public.String() || r.pub == sess.WGPrivateKey {
		t.Errorf("registered %q, want the public key %q", r.pub, pair.Public)
	}
	if r.got.Value != "registry-token" || r.got.Refresh != "first" {
		t.Errorf("registered with %+v", r.got)
	}

	// A refusal stops the connection, and the session is left as it was.
	sess2, _ := session(t)
	if _, changed, err := bearerFor(context.Background(), &registrar{err: errors.New("this key is registered to somebody else")}, sess2, "laptop"); err == nil || changed || sess2.RefreshToken != "first" {
		t.Errorf("a refusal: changed %v, err %v, refresh %q", changed, err, sess2.RefreshToken)
	}
	// A session whose device key is not one.
	bad := &tokenstore.Session{Bearer: "x", WGPrivateKey: "not a key"}
	if _, _, err := bearerFor(context.Background(), &registrar{}, bad, "laptop"); err == nil {
		t.Error("a broken device key was registered")
	}
}

func TestGoAuthnIsAValidProvider(t *testing.T) {
	c := Config{ServerURL: "https://vpn.example.org", Provider: "go-authn", OIDCIssuer: "https://login.example.org"}
	if err := c.Validate(); err == nil {
		t.Error("go-authn without a client id was valid")
	}
	c.OIDCClientID = "claimward"
	if err := c.Validate(); err != nil {
		t.Error(err)
	}
}
