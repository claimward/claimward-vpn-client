package discovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/claimward/claimward-vpn-client/pkg/protocol"
)

const goodSVG = `<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"><rect width="1" height="1"/></svg>`

func sum(b string) string {
	s := sha256.Sum256([]byte(b))
	return hex.EncodeToString(s[:])
}

const doc = `{"version":2,"server_name":"Lab","exclusive":true,"providers":[` +
	`{"id":"gh","kind":"github","name":"GitHub","github_client_id":"Iv1.x"},` +
	`{"id":"uni","kind":"oidc","name":"Uni","oidc_issuer":"https://idp.example.org","oidc_client_id":"c"}]}`

func TestDecode(t *testing.T) {
	cfg, err := Decode([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ServerName != "Lab" || !cfg.Exclusive || len(cfg.Providers) != 2 || cfg.Providers[1].OIDCIssuer != "https://idp.example.org" {
		t.Errorf("decoded %+v", cfg)
	}
}

func TestDecodeRefuses(t *testing.T) {
	long := strings.Repeat("a", 65)
	for name, in := range map[string]string{
		"empty":            ``,
		"not json":         `nope`,
		"trailing":         doc + ` {}`,
		"trailing garbage": doc + `x`,
		"version 1":        `{"version":1,"providers":[{"id":"gh","kind":"github","name":"G","github_client_id":"x"}]}`,
		"version 3":        `{"version":3,"providers":[]}`,
		"no version":       `{"providers":[{"id":"gh","kind":"github","name":"G","github_client_id":"x"}]}`,
		"no providers":     `{"version":2,"providers":[]}`,
		"bad id":           `{"version":2,"providers":[{"id":"a b","kind":"github","name":"G","github_client_id":"x"}]}`,
		"empty id":         `{"version":2,"providers":[{"id":"","kind":"github","name":"G","github_client_id":"x"}]}`,
		"long id":          `{"version":2,"providers":[{"id":"` + long + `","kind":"github","name":"G","github_client_id":"x"}]}`,
		"duplicate id":     `{"version":2,"providers":[{"id":"a","kind":"github","name":"G","github_client_id":"x"},{"id":"a","kind":"github","name":"H","github_client_id":"x"}]}`,
		"unknown kind":     `{"version":2,"providers":[{"id":"a","kind":"saml","name":"G"}]}`,
		"github no client": `{"version":2,"providers":[{"id":"a","kind":"github","name":"G"}]}`,
		"oidc no issuer":   `{"version":2,"providers":[{"id":"a","kind":"oidc","name":"G","oidc_client_id":"c"}]}`,
		"oidc http issuer": `{"version":2,"providers":[{"id":"a","kind":"oidc","name":"G","oidc_issuer":"http://idp.example.org","oidc_client_id":"c"}]}`,
		"control in name":  `{"version":2,"providers":[{"id":"a","kind":"github","name":"G\u001b[31m","github_client_id":"x"}]}`,
		"bidi in name":     `{"version":2,"providers":[{"id":"a","kind":"github","name":"G‮","github_client_id":"x"}]}`,
		"empty name":       `{"version":2,"providers":[{"id":"a","kind":"github","name":"","github_client_id":"x"}]}`,
		"server name ctl":  `{"version":2,"server_name":"a\nb","providers":[{"id":"a","kind":"github","name":"G","github_client_id":"x"}]}`,
		"logo off-origin":  `{"version":2,"providers":[{"id":"a","kind":"github","name":"G","github_client_id":"x"}],"logo":{"path":"//evil.example/x.svg","sha256":"` + sum("x") + `"}}`,
		"logo scheme":      `{"version":2,"providers":[{"id":"a","kind":"github","name":"G","github_client_id":"x"}],"logo":{"path":"https://evil.example/x.svg","sha256":"` + sum("x") + `"}}`,
		"logo relative":    `{"version":2,"providers":[{"id":"a","kind":"github","name":"G","github_client_id":"x"}],"logo":{"path":"x.svg","sha256":"` + sum("x") + `"}}`,
		"logo upper sha":   `{"version":2,"providers":[{"id":"a","kind":"github","name":"G","github_client_id":"x"}],"logo":{"path":"/x.svg","sha256":"` + strings.ToUpper(sum("x")) + `"}}`,
		"logo short sha":   `{"version":2,"providers":[{"id":"a","kind":"github","name":"G","github_client_id":"x"}],"logo":{"path":"/x.svg","sha256":"abc"}}`,
		"logo non-hex sha": `{"version":2,"providers":[{"id":"a","kind":"github","name":"G","github_client_id":"x"}],"logo":{"path":"/x.svg","sha256":"` + strings.Repeat("z", 64) + `"}}`,
		"logo query":       `{"version":2,"providers":[{"id":"a","kind":"github","name":"G","github_client_id":"x"}],"logo":{"path":"/x.svg?a","sha256":"` + sum("x") + `"}}`,
	} {
		if cfg, err := Decode([]byte(in)); err == nil {
			t.Errorf("%s: accepted: %+v", name, cfg)
		}
	}
}

func TestDecodeVersionErrorIsTyped(t *testing.T) {
	_, err := Decode([]byte(`{"version":9,"providers":[]}`))
	var ve *VersionError
	if !errors.As(err, &ve) || ve.Got != 9 {
		t.Fatalf("err = %v", err)
	}
}

func TestDecodeRefusesTooManyProviders(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"version":2,"providers":[`)
	for i := 0; i <= MaxProviders; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"id":"p` + string(rune('a'+i%26)) + string(rune('a'+i/26)) + `","kind":"github","name":"G","github_client_id":"x"}`)
	}
	b.WriteString(`]}`)
	if _, err := Decode([]byte(b.String())); err == nil {
		t.Error("accepted")
	}
}

func TestMaxAge(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"public, max-age=300": 300 * time.Second,
		"max-age=0":           0,
		"max-age=-5":          0,
		"max-age=abc":         0,
		"no-store":            0,
		"no-cache, max-age=9": 0,
		"private, max-age=9":  0,
		"":                    0,
		"public":              0,
		"max-age=999999999":   MaxCacheAge,
		"MAX-AGE=60":          60 * time.Second,
	} {
		if got := maxAge(in); got != want {
			t.Errorf("maxAge(%q) = %v, want %v", in, got, want)
		}
	}
}

// server serves doc, counting its fetches, with the given Cache-Control.
func server(t *testing.T, cacheControl string, extra http.HandlerFunc) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == protocol.PathWellKnownConfiguration {
			n.Add(1)
			if cacheControl != "" {
				w.Header().Set("Cache-Control", cacheControl)
			}
			_, _ = w.Write([]byte(doc))
			return
		}
		if extra != nil {
			extra(w, r)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, &n
}

func TestGetIsCachedForTheServersMaxAge(t *testing.T) {
	srv, n := server(t, "public, max-age=300", nil)
	c := New(nil)
	now := time.Unix(1_000_000, 0)
	c.now = func() time.Time { return now }
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := c.Get(ctx, srv.URL); err != nil {
			t.Fatal(err)
		}
	}
	if n.Load() != 1 {
		t.Fatalf("%d fetches inside max-age, want 1", n.Load())
	}
	now = now.Add(299 * time.Second)
	_, _ = c.Get(ctx, srv.URL)
	if n.Load() != 1 {
		t.Fatalf("%d fetches at 299 s", n.Load())
	}
	now = now.Add(2 * time.Second)
	if _, err := c.Get(ctx, srv.URL); err != nil || n.Load() != 2 {
		t.Fatalf("%d fetches after max-age, %v; want 2", n.Load(), err)
	}
}

func TestGetWithoutMaxAgeIsNotCached(t *testing.T) {
	srv, n := server(t, "", nil)
	c := New(nil)
	for i := 0; i < 3; i++ {
		if _, err := c.Get(context.Background(), srv.URL); err != nil {
			t.Fatal(err)
		}
	}
	if n.Load() != 3 {
		t.Errorf("%d fetches, want 3", n.Load())
	}
	if _, ok := c.Cached(srv.URL); !ok {
		t.Error("the last document is still known, for display")
	}
	if _, ok := c.Fresh(srv.URL); ok {
		t.Error("and not fresh")
	}
}

func TestAFailedRefreshKeepsTheCachedDocument(t *testing.T) {
	var fail atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			http.Error(w, "down", 503)
			return
		}
		_, _ = w.Write([]byte(doc))
	}))
	defer srv.Close()
	c := New(nil)
	if _, err := c.Refresh(context.Background(), srv.URL); err != nil {
		t.Fatal(err)
	}
	fail.Store(true)
	if _, err := c.Refresh(context.Background(), srv.URL); err == nil {
		t.Fatal("a 503 was accepted")
	}
	if cfg, ok := c.Cached(srv.URL); !ok || cfg.ServerName != "Lab" {
		t.Error("the cached document was lost")
	}
	c.Forget(srv.URL)
	if _, ok := c.Cached(srv.URL); ok {
		t.Error("Forget kept it")
	}
}

func TestFetchRefuses(t *testing.T) {
	for name, h := range map[string]http.HandlerFunc{
		"404":      func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) },
		"redirect": func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "http://127.0.0.1:1/x", http.StatusFound) },
		"html":     func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("<html>")) },
		"version":  func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"version":3,"providers":[]}`)) },
		"huge":     func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(strings.Repeat(" ", MaxDocumentBytes+1))) },
	} {
		srv := httptest.NewServer(h)
		_, err := New(nil).Get(context.Background(), srv.URL)
		srv.Close()
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := New(nil).Get(context.Background(), "http://vpn.example.org"); err == nil {
		t.Error("cleartext http to a non-loopback host was accepted")
	}
	if _, err := New(nil).Get(context.Background(), "ftp://x"); err == nil {
		t.Error("ftp accepted")
	}
}

func TestFetchTimesOut(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := New(nil).Get(ctx, srv.URL); err == nil || time.Since(start) > 3*time.Second {
		t.Fatalf("err = %v after %v", err, time.Since(start))
	}
}

// logoServer serves a document advertising a logo with the given bytes and hash.
func logoServer(t *testing.T, svg, advertised, path string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var logoGets atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case protocol.PathWellKnownConfiguration:
			_, _ = w.Write([]byte(`{"version":2,"providers":[{"id":"a","kind":"github","name":"G","github_client_id":"x"}],"logo":{"path":"` + path + `","sha256":"` + advertised + `"}}`))
		case protocol.PathWellKnownLogo:
			logoGets.Add(1)
			_, _ = w.Write([]byte(svg))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &logoGets
}

func TestLogo(t *testing.T) {
	srv, gets := logoServer(t, goodSVG, sum(goodSVG), protocol.PathWellKnownLogo)
	c := New(nil)
	cfg, err := c.Refresh(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		b, err := c.Logo(context.Background(), srv.URL, cfg)
		if err != nil || string(b) != goodSVG {
			t.Fatalf("logo = %q, %v", b, err)
		}
	}
	if gets.Load() != 1 {
		t.Errorf("%d logo fetches, want 1 (kept while the hash holds)", gets.Load())
	}
}

func TestLogoFailuresAreNoLogo(t *testing.T) {
	evil := `<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`
	for name, tc := range map[string]struct{ svg, advertised, path string }{
		"hash mismatch": {goodSVG, sum("other"), protocol.PathWellKnownLogo},
		"unsafe svg":    {evil, sum(evil), protocol.PathWellKnownLogo},
		"not svg":       {"GIF89a", sum("GIF89a"), protocol.PathWellKnownLogo},
		"missing":       {goodSVG, sum(goodSVG), "/nope.svg"},
		"too big":       {goodSVG + strings.Repeat(" ", MaxLogoBytes), sum(goodSVG + strings.Repeat(" ", MaxLogoBytes)), protocol.PathWellKnownLogo},
	} {
		srv, _ := logoServer(t, tc.svg, tc.advertised, tc.path)
		c := New(nil)
		cfg, err := c.Refresh(context.Background(), srv.URL)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if b, err := c.Logo(context.Background(), srv.URL, cfg); err == nil || b != nil {
			t.Errorf("%s: logo %q, %v; want none and a reason", name, b, err)
		}
	}
}

func TestNoLogoIsNotAnError(t *testing.T) {
	srv, _ := server(t, "", nil)
	c := New(nil)
	cfg, _ := c.Refresh(context.Background(), srv.URL)
	if b, err := c.Logo(context.Background(), srv.URL, cfg); b != nil || err != nil {
		t.Errorf("%q, %v", b, err)
	}
}

func TestLogoNeverLeavesTheOrigin(t *testing.T) {
	var hit atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit.Add(1)
		_, _ = w.Write([]byte(goodSVG))
	}))
	defer other.Close()
	// A redirect from the logo path to another host is not followed.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == protocol.PathWellKnownConfiguration {
			_, _ = w.Write([]byte(`{"version":2,"providers":[{"id":"a","kind":"github","name":"G","github_client_id":"x"}],"logo":{"path":"/l.svg","sha256":"` + sum(goodSVG) + `"}}`))
			return
		}
		http.Redirect(w, r, other.URL+"/l.svg", http.StatusFound)
	}))
	defer srv.Close()
	c := New(nil)
	cfg, _ := c.Refresh(context.Background(), srv.URL)
	if b, err := c.Logo(context.Background(), srv.URL, cfg); b != nil || err == nil {
		t.Errorf("a redirected logo was taken: %q, %v", b, err)
	}
	if hit.Load() != 0 {
		t.Error("the other host was contacted")
	}
}
