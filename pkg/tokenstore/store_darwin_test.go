package tokenstore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func withSecurity(t *testing.T, env map[string]string) {
	t.Helper()
	old := securityCmd
	securityCmd = fakeCLI(t, env)
	t.Cleanup(func() { securityCmd = old })
}

func TestKeychainGet(t *testing.T) {
	withSecurity(t, map[string]string{"FAKE_CLI_OUT": " 00ff\n"})
	if v, err := (keychain{}).get(); err != nil || v != "00ff" {
		t.Errorf("get = %q, %v", v, err)
	}
	withSecurity(t, map[string]string{"FAKE_CLI_EXIT": "44"})
	if _, err := (keychain{}).get(); err != errNotFound {
		t.Errorf("exit 44: get = %v, want errNotFound", err)
	}
	withSecurity(t, map[string]string{"FAKE_CLI_EXIT": "1", "FAKE_CLI_STDERR": "boom\n"})
	_, err := keychain{}.get()
	if err == nil || err == errNotFound || !strings.Contains(err.Error(), "boom") {
		t.Errorf("exit 1: get = %v, want an error carrying the tool's message", err)
	}
}

func TestKeychainSetSendsTheKeyOnStdinNotArgv(t *testing.T) {
	dir := t.TempDir()
	in, args := filepath.Join(dir, "in"), filepath.Join(dir, "args")
	withSecurity(t, map[string]string{"FAKE_CLI_STDIN_FILE": in, "FAKE_CLI_ARGS_FILE": args})
	if err := (keychain{}).set("abcd1234"); err != nil {
		t.Fatal(err)
	}
	gotIn, _ := os.ReadFile(in)
	if want := "add-generic-password -U -s claimward -a session-key -w abcd1234\n"; string(gotIn) != want {
		t.Errorf("stdin = %q, want %q", gotIn, want)
	}
	gotArgs, _ := os.ReadFile(args)
	if string(gotArgs) != "-i" {
		t.Errorf("argv = %q, want just -i", gotArgs)
	}
	withSecurity(t, map[string]string{"FAKE_CLI_EXIT": "1"})
	if err := (keychain{}).set("x"); err == nil {
		t.Error("a failing security was not reported")
	}
}

func TestKeychainDel(t *testing.T) {
	withSecurity(t, map[string]string{"FAKE_CLI_EXIT": "44"})
	if err := (keychain{}).del(); err != nil {
		t.Errorf("deleting a missing item: %v", err)
	}
	withSecurity(t, map[string]string{"FAKE_CLI_EXIT": "1"})
	if err := (keychain{}).del(); err == nil {
		t.Error("a failing security was not reported")
	}
}

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
