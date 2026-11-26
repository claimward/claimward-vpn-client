// Package discovery reads, at run time, what a claimward-vpn-server says
// about itself: its discovery document (protocol.PathWellKnownConfiguration)
// and its logo. The person types only the server's URL; the identity
// providers to sign in with, whether the server is exclusive, its name and its
// logo all come from here.
//
// ⛔ Everything fetched is untrusted input. The document is capped, decoded
// strictly and validated before anything uses it; nothing is followed to
// another host (no redirect is taken, the logo is read from the SAME origin);
// the logo's SHA-256 must be the one the document states and its bytes must
// pass pkg/svgsafe. A logo that fails any of it is no logo: never an error that
// stops the person from connecting.
package discovery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/claimward/claimward-vpn-client/pkg/protocol"
	"github.com/claimward/claimward-vpn-client/pkg/secureurl"
	"github.com/claimward/claimward-vpn-client/pkg/svgsafe"
)

// Limits on what a server may make the client read or hold.
const (
	// MaxDocumentBytes caps the discovery document (a few providers: well under 8 KiB in practice).
	MaxDocumentBytes = 64 << 10
	// MaxLogoBytes is the server's own cap on its logo.
	MaxLogoBytes = 64 << 10
	// Timeout bounds one fetch, connection to last byte.
	Timeout = 10 * time.Second
	// MaxProviders bounds the providers of one server.
	MaxProviders = 32
	// MaxCacheAge bounds how long a document is kept whatever the server says.
	MaxCacheAge = 24 * time.Hour

	maxNameRunes = 100
	maxLogoPath  = 256
	maxIssuerLen = 2048
	maxClientID  = 512
)

// VersionError is a discovery document of a version this client does not read.
type VersionError struct{ Got int }

func (e *VersionError) Error() string {
	return fmt.Sprintf("discovery version %d is not supported (this client reads version %d): update the client", e.Got, protocol.ConfigurationVersion)
}

// Decode parses and validates a discovery document. A document of another
// version, over MaxDocumentBytes, with trailing data, with no provider, with a
// provider the client cannot sign in with, or with a logo pointing outside the
// server is refused.
func Decode(b []byte) (*protocol.Configuration, error) {
	if len(b) > MaxDocumentBytes {
		return nil, fmt.Errorf("discovery document larger than %d bytes", MaxDocumentBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	var cfg protocol.Configuration
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("discovery document: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("discovery document: trailing data")
	}
	if cfg.Version != protocol.ConfigurationVersion {
		return nil, &VersionError{Got: cfg.Version}
	}
	if err := validate(&cfg); err != nil {
		return nil, fmt.Errorf("discovery document: %w", err)
	}
	return &cfg, nil
}

func validate(cfg *protocol.Configuration) error {
	if err := displayText("server_name", cfg.ServerName, true); err != nil {
		return err
	}
	if len(cfg.Providers) == 0 {
		return errors.New("no identity provider")
	}
	if len(cfg.Providers) > MaxProviders {
		return fmt.Errorf("%d providers (at most %d)", len(cfg.Providers), MaxProviders)
	}
	seen := map[string]bool{}
	for i, p := range cfg.Providers {
		if !protocol.ValidProviderID(p.ID) {
			return fmt.Errorf("provider %d: invalid id %q", i, truncate(p.ID))
		}
		if seen[p.ID] {
			return fmt.Errorf("provider id %q listed twice", p.ID)
		}
		seen[p.ID] = true
		if err := displayText("provider name", p.Name, false); err != nil {
			return fmt.Errorf("provider %q: %w", p.ID, err)
		}
		switch p.Kind {
		case protocol.KindGitHub:
			if p.GitHubClientID == "" || len(p.GitHubClientID) > maxClientID {
				return fmt.Errorf("provider %q: github_client_id missing or too long", p.ID)
			}
		case protocol.KindOIDC, protocol.KindGoAuthn:
			if p.OIDCClientID == "" || len(p.OIDCClientID) > maxClientID {
				return fmt.Errorf("provider %q: oidc_client_id missing or too long", p.ID)
			}
			if len(p.OIDCIssuer) > maxIssuerLen {
				return fmt.Errorf("provider %q: oidc_issuer too long", p.ID)
			}
			if err := secureurl.Check(p.OIDCIssuer); err != nil {
				return fmt.Errorf("provider %q: oidc_issuer: %w", p.ID, err)
			}
		default:
			return fmt.Errorf("provider %q: unknown kind %q", p.ID, truncate(p.Kind))
		}
	}
	if l := cfg.Logo; l != nil {
		if err := validLogoPath(l.Path); err != nil {
			return fmt.Errorf("logo path: %w", err)
		}
		if len(l.SHA256) != 64 || strings.ToLower(l.SHA256) != l.SHA256 {
			return errors.New("logo sha256: want 64 lower-case hex digits")
		}
		if _, err := hex.DecodeString(l.SHA256); err != nil {
			return errors.New("logo sha256: want 64 lower-case hex digits")
		}
	}
	return nil
}

// displayText refuses text a window would show that is too long, not UTF-8 or
// holds a control character (a terminal-escape or bidi trick in a name).
func displayText(what, s string, optional bool) error {
	if s == "" {
		if optional {
			return nil
		}
		return fmt.Errorf("%s is empty", what)
	}
	if !utf8.ValidString(s) {
		return fmt.Errorf("%s is not UTF-8", what)
	}
	if utf8.RuneCountInString(s) > maxNameRunes {
		return fmt.Errorf("%s longer than %d characters", what, maxNameRunes)
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return fmt.Errorf("%s holds a control character", what)
		}
	}
	return nil
}

func validLogoPath(p string) error {
	switch {
	case len(p) == 0 || len(p) > maxLogoPath:
		return errors.New("empty or too long")
	case p[0] != '/' || strings.HasPrefix(p, "//"):
		return errors.New("must be an absolute path on the server")
	}
	for i := 0; i < len(p); i++ {
		if p[i] <= ' ' || p[i] == 0x7f || p[i] == '\\' || p[i] == '#' || p[i] == '?' || p[i] >= 0x80 {
			return errors.New("holds a character a path cannot")
		}
	}
	return nil
}

func truncate(s string) string {
	if len(s) > 40 {
		return s[:40] + "…"
	}
	return s
}

// maxAge is the lifetime a Cache-Control header gives the document, 0 when it
// gives none (or forbids keeping it). It is held within MaxCacheAge.
func maxAge(h string) time.Duration {
	var age time.Duration
	for _, d := range strings.Split(h, ",") {
		d = strings.ToLower(strings.TrimSpace(d))
		switch {
		case d == "no-store" || d == "no-cache" || d == "private":
			return 0
		case strings.HasPrefix(d, "max-age="):
			n, err := strconv.ParseInt(strings.Trim(strings.TrimPrefix(d, "max-age="), `"`), 10, 64)
			if err != nil || n <= 0 {
				return 0
			}
			age = time.Duration(min(n, int64(MaxCacheAge/time.Second))) * time.Second
		}
	}
	return age
}

type entry struct {
	cfg     *protocol.Configuration
	expires time.Time
	// logo is the validated SVG whose SHA-256 is logoSum.
	logo    []byte
	logoSum string
}

// Client fetches and caches discovery documents and logos, per server.
// It is safe for concurrent use. The zero value is not usable: use New.
type Client struct {
	http *http.Client
	now  func() time.Time

	mu    sync.Mutex
	cache map[string]*entry
}

// New returns a Client. hc may be nil: a client that takes no redirect and
// gives up after Timeout. A given one is used as is, except that redirects are
// still refused.
func New(hc *http.Client) *Client {
	if hc == nil {
		hc = &http.Client{Timeout: Timeout}
	}
	c := *hc
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{http: &c, now: time.Now, cache: map[string]*entry{}}
}

// Get is the server's discovery document: the cached one while the server's
// Cache-Control max-age holds, else a fresh fetch. server is a canonical URL
// (secureurl.Canonical).
func (c *Client) Get(ctx context.Context, server string) (*protocol.Configuration, error) {
	if cfg, ok := c.Fresh(server); ok {
		return cfg, nil
	}
	return c.Refresh(ctx, server)
}

// Fresh is the cached document if it has not expired. It never touches the
// network.
func (c *Client) Fresh(server string) (*protocol.Configuration, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.cache[server]; e != nil && c.now().Before(e.expires) {
		return e.cfg, true
	}
	return nil, false
}

// Cached is the last document fetched, however old; for showing something
// while offline. It never touches the network.
func (c *Client) Cached(server string) (*protocol.Configuration, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.cache[server]; e != nil {
		return e.cfg, true
	}
	return nil, false
}

// Forget drops what is cached for server.
func (c *Client) Forget(server string) {
	c.mu.Lock()
	delete(c.cache, server)
	c.mu.Unlock()
}

// Refresh fetches the document now, whatever the cache holds. A failure
// leaves the cached document, if any, in place.
func (c *Client) Refresh(ctx context.Context, server string) (*protocol.Configuration, error) {
	origin, err := originOf(server)
	if err != nil {
		return nil, err
	}
	body, hdr, err := c.fetch(ctx, origin+protocol.PathWellKnownConfiguration, MaxDocumentBytes)
	if err != nil {
		return nil, fmt.Errorf("discovery at %s: %w", origin, err)
	}
	cfg, err := Decode(body)
	if err != nil {
		return nil, fmt.Errorf("discovery at %s: %w", origin, err)
	}
	c.mu.Lock()
	e := &entry{cfg: cfg, expires: c.now().Add(maxAge(hdr.Get("Cache-Control")))}
	if old := c.cache[server]; old != nil && cfg.Logo != nil && old.logoSum == cfg.Logo.SHA256 {
		e.logo, e.logoSum = old.logo, old.logoSum
	}
	c.cache[server] = e
	c.mu.Unlock()
	return cfg, nil
}

// Logo is the server's validated SVG, or nil when it has none or it failed
// any check; the reason is the error, which the caller logs and goes on. The
// image is fetched from the same origin as the document, its SHA-256 must be
// the document's, and it must pass svgsafe. A validated logo is kept until
// the document's hash changes.
func (c *Client) Logo(ctx context.Context, server string, cfg *protocol.Configuration) ([]byte, error) {
	if cfg == nil || cfg.Logo == nil {
		return nil, nil
	}
	c.mu.Lock()
	if e := c.cache[server]; e != nil && e.logo != nil && e.logoSum == cfg.Logo.SHA256 {
		b := e.logo
		c.mu.Unlock()
		return b, nil
	}
	c.mu.Unlock()
	origin, err := originOf(server)
	if err != nil {
		return nil, err
	}
	if err := validLogoPath(cfg.Logo.Path); err != nil {
		return nil, fmt.Errorf("logo path: %w", err)
	}
	// origin ends at the host and the path starts with a single '/', so the
	// result cannot name another host; check it all the same.
	u, err := url.Parse(origin + cfg.Logo.Path)
	if err != nil {
		return nil, err
	}
	if o, _ := url.Parse(origin); u.Scheme != o.Scheme || u.Host != o.Host {
		return nil, errors.New("logo is not on the server's origin")
	}
	b, _, err := c.fetch(ctx, u.String(), MaxLogoBytes)
	if err != nil {
		return nil, fmt.Errorf("logo: %w", err)
	}
	sum := sha256.Sum256(b)
	if got := hex.EncodeToString(sum[:]); got != cfg.Logo.SHA256 {
		return nil, fmt.Errorf("logo: sha256 %s is not the advertised %s", got, cfg.Logo.SHA256)
	}
	if err := svgsafe.Validate(b); err != nil {
		return nil, fmt.Errorf("logo: %w", err)
	}
	c.mu.Lock()
	if e := c.cache[server]; e != nil && e.cfg.Logo != nil && e.cfg.Logo.SHA256 == cfg.Logo.SHA256 {
		e.logo, e.logoSum = b, cfg.Logo.SHA256
	}
	c.mu.Unlock()
	return b, nil
}

func originOf(server string) (string, error) {
	canon, err := secureurl.Canonical(server)
	if err != nil {
		return "", err
	}
	return secureurl.Origin(canon)
}

// fetch GETs raw, reads at most limit bytes and refuses a longer answer.
func (c *Client) fetch(ctx context.Context, raw string, limit int64) ([]byte, http.Header, error) {
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Accept", "application/json, image/svg+xml")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > limit {
		return nil, nil, fmt.Errorf("answer larger than %d bytes", limit)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, nil, err
	}
	if int64(len(b)) > limit {
		return nil, nil, fmt.Errorf("answer larger than %d bytes", limit)
	}
	return b, resp.Header, nil
}
