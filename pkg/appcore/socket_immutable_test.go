package appcore

import (
	"path/filepath"
	"testing"
)

// The socket the app talks to is fixed at start: UpdateConfig (what a UI's
// "save settings" ends in) cannot change it, neither live nor on disk.
func TestUpdateConfigCannotChangeTheHelperSocket(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("AppData", filepath.Join(home, "AppData"))

	c := New(&Config{ServerURL: "https://vpn.example.org", Provider: "github", GitHubClientID: "x", SocketPath: "/run/real.sock"})
	err := c.UpdateConfig(Config{ServerURL: "https://other.example.org", Provider: "github", GitHubClientID: "y", SocketPath: "/tmp/evil.sock"})
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Config().SocketPath; got != "/run/real.sock" {
		t.Fatalf("live socket_path = %q", got)
	}
	if got := c.Config().ServerURL; got != "https://other.example.org" {
		t.Fatalf("the rest of the update was not applied: %q", got)
	}
	_, h := c.deps()
	if h.SocketPath != "/run/real.sock" {
		t.Fatalf("helper client socket = %q", h.SocketPath)
	}
}
