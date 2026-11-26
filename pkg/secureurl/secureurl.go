// Package secureurl decides which server URLs the client may talk to.
package secureurl

import (
	"errors"
	"net/netip"
	"net/url"
	"strings"
)

// Check accepts an absolute https URL, or an http one to a loopback address
// (development): the bearer and the enrollment answer must not cross a
// network in the clear. Userinfo is refused.
func Check(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Host == "" || u.User != nil {
		return errors.New("not an absolute URL without credentials")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if host == "localhost" {
			return nil
		}
		if ip, err := netip.ParseAddr(host); err == nil && ip.IsLoopback() {
			return nil
		}
	}
	return errors.New("must be https (http only for a loopback address)")
}

// Canonical is the one spelling of a server URL that keys everything the
// client keeps per server (its configuration entry, its sessions, its
// tunnel): Check must accept it; the scheme and host are lower-cased, the
// default port (443 for https, 80 for http) and any trailing slash are
// dropped. A query or a fragment is refused: a server is an origin plus an
// optional path, and a URL that differs only by one would key a second
// session for the same server.
func Canonical(raw string) (string, error) {
	if err := Check(raw); err != nil {
		return "", err
	}
	u, _ := url.Parse(raw) // Check parsed it already: it cannot fail here
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(raw, "#") {
		return "", errors.New("a server URL has no query or fragment")
	}
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		port = ""
	}
	if strings.Contains(host, ":") { // an IPv6 literal
		host = "[" + host + "]"
	}
	if port != "" {
		host += ":" + port
	}
	return u.Scheme + "://" + host + strings.TrimRight(u.EscapedPath(), "/"), nil
}

// Origin is the scheme and host of a canonical server URL, where the
// well-known documents are served (RFC 8615 §3: at the root of the origin).
func Origin(canonical string) (string, error) {
	u, err := url.Parse(canonical)
	if err != nil || u.Host == "" {
		return "", errors.New("not an absolute URL")
	}
	return u.Scheme + "://" + u.Host, nil
}
