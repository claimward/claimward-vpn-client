package helper

import (
	"encoding/xml"
	"os"
	"testing"
)

// The polkit action file shipped in the package names the action the helper
// asks about (the linux code's PolkitAction) and wants an administrator each
// time, whatever the session.
func TestThePolkitPolicyMatchesTheCode(t *testing.T) {
	b, err := os.ReadFile("../../packaging/polkit/com.claimward.helper.approve-server.policy")
	if err != nil {
		t.Fatal(err)
	}
	var p struct {
		Actions []struct {
			ID            string `xml:"id,attr"`
			AllowAny      string `xml:"defaults>allow_any"`
			AllowInactive string `xml:"defaults>allow_inactive"`
			AllowActive   string `xml:"defaults>allow_active"`
		} `xml:"action"`
	}
	if err := xml.Unmarshal(b, &p); err != nil {
		t.Fatal(err)
	}
	if len(p.Actions) != 1 || p.Actions[0].ID != "com.claimward.helper.approve-server" {
		t.Fatalf("actions: %+v", p.Actions)
	}
	a := p.Actions[0]
	if a.AllowAny != "auth_admin" || a.AllowInactive != "auth_admin" || a.AllowActive != "auth_admin" {
		t.Errorf("defaults: %+v", a)
	}
}
