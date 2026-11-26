package discovery

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/claimward/claimward-vpn-client/pkg/protocol"
	"github.com/claimward/claimward-vpn-client/pkg/secureurl"
)

func TestDecodeRefusesADocumentOverTheCapEvenWhenItParses(t *testing.T) {
	if _, err := Decode([]byte(doc + strings.Repeat(" ", MaxDocumentBytes))); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("err = %v", err)
	}
	if _, err := Decode([]byte(doc + strings.Repeat(" ", 100))); err != nil {
		t.Fatalf("a padded document under the cap: %v", err)
	}
}

func TestDecodeNamesWhatIsNotJSON(t *testing.T) {
	_, err := Decode([]byte(`nope`))
	if err == nil || !strings.Contains(err.Error(), "invalid character") {
		t.Fatalf("err = %v", err)
	}
}

func TestDecodeSaysWhyItRefuses(t *testing.T) {
	gh := `{"id":"a","kind":"github","name":"G","github_client_id":"x"}`
	for want, in := range map[string]string{
		"oidc_client_id":       `{"version":2,"providers":[{"id":"a","kind":"oidc","name":"G","oidc_issuer":"https://idp.example.org"}]}`,
		"missing or too long":  `{"version":2,"providers":[{"id":"a","kind":"go-authn","name":"G","oidc_issuer":"https://idp.example.org","oidc_client_id":"` + strings.Repeat("c", maxClientID+1) + `"}]}`,
		"oidc_issuer too long": `{"version":2,"providers":[{"id":"a","kind":"oidc","name":"G","oidc_issuer":"https://` + strings.Repeat("h", maxIssuerLen) + `.example.org","oidc_client_id":"c"}]}`,
		"longer than":          `{"version":2,"server_name":"` + strings.Repeat("n", maxNameRunes+1) + `","providers":[` + gh + `]}`,
	} {
		_, err := Decode([]byte(in))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("want a refusal naming %q, got %v", want, err)
		}
	}
	// A name of exactly the cap is fine.
	if _, err := Decode([]byte(`{"version":2,"server_name":"` + strings.Repeat("n", maxNameRunes) + `","providers":[` + gh + `]}`)); err != nil {
		t.Errorf("a name at the cap: %v", err)
	}
}

// JSON decoding repairs invalid UTF-8, so displayText is checked on its own.
func TestDisplayTextRefusesWhatIsNotUTF8(t *testing.T) {
	if err := displayText("name", "a\xffb", false); err == nil || !strings.Contains(err.Error(), "UTF-8") {
		t.Fatalf("err = %v", err)
	}
	if err := displayText("name", strings.Repeat("é", maxNameRunes), false); err != nil {
		t.Fatalf("a name of %d runes: %v", maxNameRunes, err)
	}
}

func TestTruncateKeepsFortyBytes(t *testing.T) {
	long := strings.Repeat("x", 41)
	if got := truncate(long); got != strings.Repeat("x", 40)+"…" {
		t.Errorf("truncate = %q", got)
	}
	if got := truncate(strings.Repeat("x", 40)); got != strings.Repeat("x", 40) {
		t.Errorf("a string of 40 bytes was cut: %q", got)
	}
}

func TestRefreshSaysWhyItFailed(t *testing.T) {
	c := New(nil)
	if _, err := c.Refresh(context.Background(), "http://vpn.example.org"); err == nil || strings.Contains(err.Error(), "discovery at") {
		t.Errorf("a cleartext server: %v", err)
	}
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	if _, err := c.Refresh(context.Background(), srv.URL); err == nil || !strings.Contains(err.Error(), "HTTP 404") {
		t.Errorf("a 404: %v", err)
	}
	gone := httptest.NewServer(http.NotFoundHandler())
	url := gone.URL
	gone.Close()
	if _, err := c.Refresh(context.Background(), url); err == nil {
		t.Error("a server that is gone answered")
	}
}

func TestLogoNeedsNothingWhenThereIsNone(t *testing.T) {
	c := New(nil)
	if b, err := c.Logo(context.Background(), "https://vpn.example.org", nil); b != nil || err != nil {
		t.Errorf("no document: %q, %v", b, err)
	}
	if b, err := c.Logo(context.Background(), "https://vpn.example.org", &protocol.Configuration{}); b != nil || err != nil {
		t.Errorf("no logo: %q, %v", b, err)
	}
}

func TestLogoSaysWhyItFailed(t *testing.T) {
	good := &protocol.Logo{Path: protocol.PathWellKnownLogo, SHA256: sum(goodSVG)}
	c := New(nil)
	if _, err := c.Logo(context.Background(), "http://vpn.example.org", &protocol.Configuration{Logo: good}); err == nil || strings.HasPrefix(err.Error(), "logo") {
		t.Errorf("a cleartext server: %v", err)
	}
	srv, gets := logoServer(t, goodSVG, sum(goodSVG), protocol.PathWellKnownLogo)
	for want, path := range map[string]string{"logo path": "//evil.example/x.svg", "logo:": "/%zz", "HTTP 404": "/nope.svg"} {
		_, err := c.Logo(context.Background(), srv.URL, &protocol.Configuration{Logo: &protocol.Logo{Path: path, SHA256: good.SHA256}})
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("path %q: want %q, got %v", path, want, err)
		}
	}
	if gets.Load() != 0 {
		t.Errorf("%d fetches of the logo for paths that are not it", gets.Load())
	}
}

func TestOriginOfPassesTheURLsOwnRefusal(t *testing.T) {
	_, want := secureurl.Canonical("http://vpn.example.org")
	_, got := originOf("http://vpn.example.org")
	if want == nil || got == nil || got.Error() != want.Error() {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestFetchSaysWhyItRefuses(t *testing.T) {
	c := New(nil)
	ctx := context.Background()
	if _, _, err := c.fetch(ctx, "http://a\x7f/", 10); err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Errorf("a malformed URL: %v", err)
	}
	gone := httptest.NewServer(http.NotFoundHandler())
	url := gone.URL
	gone.Close()
	if b, _, err := c.fetch(ctx, url, 10); err == nil || b != nil {
		t.Errorf("a server that is gone: %q, %v", b, err)
	}

	// A declared length over the cap is refused before the body is read.
	declared := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(101))
		_, _ = w.Write([]byte("short"))
	}))
	defer declared.Close()
	if _, _, err := c.fetch(ctx, declared.URL, 100); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("a declared length over the cap: %v", err)
	}

	// A body over the cap, length not declared, is refused.
	chunked := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.(http.Flusher).Flush()
		_, _ = w.Write([]byte(strings.Repeat("x", 101)))
	}))
	defer chunked.Close()
	if _, _, err := c.fetch(ctx, chunked.URL, 100); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("a streamed body over the cap: %v", err)
	}

	// A body cut short is an error, not a short answer.
	cut := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "50")
		_, _ = w.Write([]byte("only ten b"))
	}))
	defer cut.Close()
	if b, _, err := c.fetch(ctx, cut.URL, 100); err == nil || b != nil {
		t.Errorf("a body cut short: %q, %v", b, err)
	}

	// Not an OK answer.
	nf := httptest.NewServer(http.NotFoundHandler())
	defer nf.Close()
	if _, _, err := c.fetch(ctx, nf.URL, 100); err == nil || !strings.Contains(err.Error(), "HTTP 404") {
		t.Errorf("a 404: %v", err)
	}
	// The cap itself is allowed.
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 100)))
	}))
	defer ok.Close()
	if b, _, err := c.fetch(ctx, ok.URL, 100); err != nil || len(b) != 100 {
		t.Errorf("a body at the cap: %d bytes, %v", len(b), err)
	}
}
