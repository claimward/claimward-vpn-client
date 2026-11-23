package appcore

import "testing"

func TestValidateRefusesACleartextServer(t *testing.T) {
	c := Config{Provider: "github", GitHubClientID: "id", ServerURL: "http://vpn.example.org"}
	if err := c.Validate(); err == nil {
		t.Fatal("an http:// server_url was accepted")
	}
	c.ServerURL = "https://vpn.example.org"
	if err := c.Validate(); err != nil {
		t.Fatalf("an https:// server_url was refused: %v", err)
	}
}
