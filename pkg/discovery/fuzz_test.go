package discovery

import (
	"encoding/json"
	"testing"

	"github.com/claimward/claimward-vpn-client/pkg/protocol"
)

// FuzzDecode feeds arbitrary bytes to the discovery decoder, the way a hostile
// server would. It must not panic, and a document it accepts must meet every
// bound the rest of the client relies on.
func FuzzDecode(f *testing.F) {
	f.Add([]byte(doc))
	f.Add([]byte(`{"version":2,"providers":[{"id":"a","kind":"github","name":"G","github_client_id":"x"}],"logo":{"path":"/.well-known/claimward-logo.svg","sha256":"` + sum("x") + `"}}`))
	f.Add([]byte(`{"version":2,"providers":null}`))
	f.Add([]byte(`{"version":"2"}`))
	f.Add([]byte(`{"version":2,"providers":[{"id":"\u0000","kind":"oidc"}]}`))
	f.Add([]byte(`[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[`))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, b []byte) {
		cfg, err := Decode(b)
		if err != nil {
			return
		}
		if cfg.Version != protocol.ConfigurationVersion || len(cfg.Providers) == 0 || len(cfg.Providers) > MaxProviders {
			t.Fatalf("accepted out of bounds: %+v", cfg)
		}
		for _, p := range cfg.Providers {
			if !protocol.ValidProviderID(p.ID) {
				t.Fatalf("accepted provider id %q", p.ID)
			}
		}
		if cfg.Logo != nil {
			if err := validLogoPath(cfg.Logo.Path); err != nil || len(cfg.Logo.SHA256) != 64 {
				t.Fatalf("accepted logo %+v", cfg.Logo)
			}
		}
		// What is accepted is stable: encoded and decoded again it is still accepted.
		again, merr := json.Marshal(cfg)
		if merr != nil {
			t.Fatal(merr)
		}
		if _, err := Decode(again); err != nil {
			t.Fatalf("re-encoded document refused: %v\n%s", err, again)
		}
	})
}
