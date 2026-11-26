package protocol

import (
	"encoding/json"
	"testing"
)

func TestPathWellKnownConfiguration(t *testing.T) {
	// RFC 8615 §3: /.well-known/ followed by ONE segment, at the root.
	if PathWellKnownConfiguration != "/.well-known/claimward-configuration" {
		t.Errorf("PathWellKnownConfiguration = %q", PathWellKnownConfiguration)
	}
}

func TestConfigurationOmitsWhatIsAbsent(t *testing.T) {
	// RFC 8414 §3.2: a claim with no value is omitted, never sent empty.
	b, err := json.Marshal(Configuration{Version: ConfigurationVersion, Provider: "oidc"})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"server_name", "github_client_id", "oidc_issuer", "oidc_client_id"} {
		if _, ok := m[k]; ok {
			t.Errorf("%s present in %s, want it omitted", k, b)
		}
	}
	for _, k := range []string{"version", "provider", "exclusive"} {
		if _, ok := m[k]; !ok {
			t.Errorf("%s missing from %s", k, b)
		}
	}
}

func TestConfigurationRoundTrip(t *testing.T) {
	in := Configuration{
		Version: ConfigurationVersion, ServerName: "Lab", Provider: "github",
		GitHubClientID: "Iv1.abc", OIDCIssuer: "https://i", OIDCClientID: "c", Exclusive: true,
	}
	b, _ := json.Marshal(in)
	var out Configuration
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Errorf("round trip: %+v != %+v", out, in)
	}
}
