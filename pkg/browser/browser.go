// Package browser opens a URL in the user's default browser.
//
// It uses absolute paths to the platform opener so it works from GUI apps
// launched by LaunchServices, whose PATH may not include /usr/bin.
package browser

import (
	"errors"
	"fmt"
	"net/url"
	"os/exec"
	"runtime"
)

// start spawns the opener; replaced by tests.
var start = func(name string, args ...string) error {
	return exec.Command(name, args...).Start()
}

// checkURL accepts an absolute http or https URL with a host, and nothing
// else: the URLs handed to Open come from an identity provider's documents,
// and a file:, UNC or custom-scheme URL would make the opener launch a local
// file or handler. Having a scheme, an accepted URL can never start with "-",
// so it cannot become an option of the opener.
func checkURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("only http and https URLs are opened")
	}
	if u.Host == "" {
		return errors.New("URL has no host")
	}
	return nil
}

// Open launches url in the default browser. It returns once the opener has been
// spawned (it does not wait for the browser). Only http(s) URLs are opened.
func Open(url string) error {
	if err := checkURL(url); err != nil {
		return fmt.Errorf("open %q: %w", url, err)
	}
	var name string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		name, args = "/usr/bin/open", []string{url}
	case "windows":
		name, args = "rundll32", []string{"url.dll,FileProtocolHandler", url}
	default: // linux, *bsd
		name, args = "xdg-open", []string{url}
	}
	if err := start(name, args...); err != nil {
		return fmt.Errorf("open %q: %w", url, err)
	}
	return nil
}
