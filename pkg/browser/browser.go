// Package browser opens a URL in the user's default browser.
//
// It uses absolute paths to the platform opener so it works from GUI apps
// launched by LaunchServices, whose PATH may not include /usr/bin.
package browser

import (
	"fmt"
	"os/exec"
	"runtime"
)

// Open launches url in the default browser. It returns once the opener has been
// spawned (it does not wait for the browser).
func Open(url string) error {
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
	if err := exec.Command(name, args...).Start(); err != nil {
		return fmt.Errorf("open %q: %w", url, err)
	}
	return nil
}
