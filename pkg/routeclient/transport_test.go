package routeclient

import (
	"testing"

	"google.golang.org/grpc/credentials/insecure"
)

// The token goes over TLS everywhere but loopback.
func TestTheTransportIsTLSButOnLoopback(t *testing.T) {
	for ep, plain := range map[string]bool{
		"vpn.example.org:8444": false,
		"10.80.0.1:8444":       false,
		"[2001:db8::1]:8444":   false,
		"127.0.0.1:8444":       true,
		"[::1]:8444":           true,
		"localhost:8444":       true,
	} {
		c, err := transport(ep)
		if err != nil {
			t.Fatalf("%s: %v", ep, err)
		}
		isPlain := c.Info().SecurityProtocol == insecure.NewCredentials().Info().SecurityProtocol
		if isPlain != plain {
			t.Errorf("%s: plaintext %v, want %v (%s)", ep, isPlain, plain, c.Info().SecurityProtocol)
		}
	}
	if _, err := transport("no-port"); err == nil {
		t.Error("an endpoint with no port was taken")
	}
}
