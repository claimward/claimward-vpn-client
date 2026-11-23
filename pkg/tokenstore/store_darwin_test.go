package tokenstore

import (
	"os"
	"testing"
)

// The login Keychain, for real. It touches the person's Keychain, so it runs
// only on request: CLAIMWARD_KEYCHAIN_TEST=1.
func TestKeychainRoundTrip(t *testing.T) {
	if os.Getenv("CLAIMWARD_KEYCHAIN_TEST") != "1" {
		t.Skip("set CLAIMWARD_KEYCHAIN_TEST=1 to use the login Keychain")
	}
	kc := keychain{}
	if err := kc.del(); err != nil {
		t.Fatal(err)
	}
	defer kc.del()
	if _, err := kc.get(); err != errNotFound {
		t.Fatalf("get on an empty keychain = %v, want errNotFound", err)
	}
	if err := kc.set("00ff"); err != nil {
		t.Fatal(err)
	}
	if v, err := kc.get(); err != nil || v != "00ff" {
		t.Fatalf("get = %q, %v", v, err)
	}
	if err := kc.set("11ee"); err != nil { // -U updates in place
		t.Fatal(err)
	}
	if v, _ := kc.get(); v != "11ee" {
		t.Fatalf("get after update = %q", v)
	}
}
