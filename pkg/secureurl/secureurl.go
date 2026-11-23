// Package secureurl decides which server URLs the client may talk to.
package secureurl

import (
	"errors"
	"net/netip"
	"net/url"
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
