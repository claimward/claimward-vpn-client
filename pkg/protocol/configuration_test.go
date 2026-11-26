package protocol

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestPathWellKnownConfiguration(t *testing.T) {
	// RFC 8615 §3: /.well-known/ followed by ONE segment, at the root.
	if PathWellKnownConfiguration != "/.well-known/claimward-configuration" {
		t.Errorf("PathWellKnownConfiguration = %q", PathWellKnownConfiguration)
	}
}

func TestTheProviderHeaderAndMetadataKeyAgree(t *testing.T) {
	// gRPC lower-cases metadata keys: the two names must be one name.
	if HeaderProvider != "Claimward-Provider" || MetadataProvider != "claimward-provider" {
		t.Errorf("%q / %q", HeaderProvider, MetadataProvider)
	}
}

func TestConfigurationOmitsWhatIsAbsent(t *testing.T) {
	// RFC 8414 §3.2: a claim with no value is omitted, never sent empty.
	b, err := json.Marshal(Configuration{
		Version:   ConfigurationVersion,
		Providers: []Provider{{ID: "uni", Kind: KindOIDC, Name: "Université X"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Providers []map[string]any `json:"providers"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	var top map[string]any
	_ = json.Unmarshal(b, &top)
	if _, ok := top["server_name"]; ok {
		t.Errorf("server_name present in %s, want it omitted", b)
	}
	for _, k := range []string{"version", "providers", "exclusive"} {
		if _, ok := top[k]; !ok {
			t.Errorf("%s missing from %s", k, b)
		}
	}
	for _, k := range []string{"github_client_id", "oidc_issuer", "oidc_client_id"} {
		if _, ok := m.Providers[0][k]; ok {
			t.Errorf("%s present in %s, want it omitted", k, b)
		}
	}
	for _, k := range []string{"id", "kind", "name"} {
		if _, ok := m.Providers[0][k]; !ok {
			t.Errorf("%s missing from %s", k, b)
		}
	}
}

func TestConfigurationRoundTrip(t *testing.T) {
	in := Configuration{
		Version: ConfigurationVersion, ServerName: "Lab", Exclusive: true,
		Providers: []Provider{
			{ID: "github", Kind: KindGitHub, Name: "GitHub", GitHubClientID: "Iv1.abc"},
			{ID: "uni-x", Kind: KindOIDC, Name: "Université X", OIDCIssuer: "https://i", OIDCClientID: "c"},
		},
	}
	b, _ := json.Marshal(in)
	var out Configuration
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(out, in) {
		t.Errorf("round trip: %+v != %+v", out, in)
	}
}
