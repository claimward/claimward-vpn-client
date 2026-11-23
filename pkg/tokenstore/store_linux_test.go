package tokenstore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func withSecretTool(t *testing.T, env map[string]string) {
	t.Helper()
	old := secretToolCmd
	secretToolCmd = fakeCLI(t, env)
	t.Cleanup(func() { secretToolCmd = old })
}

func TestSecretServiceGet(t *testing.T) {
	withSecretTool(t, map[string]string{"FAKE_CLI_OUT": "00ff\n"})
	if v, err := (secretService{}).get(); err != nil || v != "00ff" {
		t.Errorf("get = %q, %v", v, err)
	}
	withSecretTool(t, map[string]string{"FAKE_CLI_EXIT": "1"})
	if _, err := (secretService{}).get(); err != errNotFound {
		t.Errorf("a failing lookup: get = %v, want errNotFound", err)
	}
	withSecretTool(t, map[string]string{"FAKE_CLI_OUT": " \n"})
	if _, err := (secretService{}).get(); err != errNotFound {
		t.Errorf("an empty lookup: get = %v, want errNotFound", err)
	}
}

func TestSecretServiceSetSendsTheKeyOnStdinNotArgv(t *testing.T) {
	dir := t.TempDir()
	in, args := filepath.Join(dir, "in"), filepath.Join(dir, "args")
	withSecretTool(t, map[string]string{"FAKE_CLI_STDIN_FILE": in, "FAKE_CLI_ARGS_FILE": args})
	if err := (secretService{}).set("abcd1234"); err != nil {
		t.Fatal(err)
	}
	if gotIn, _ := os.ReadFile(in); string(gotIn) != "abcd1234" {
		t.Errorf("stdin = %q", gotIn)
	}
	gotArgs, _ := os.ReadFile(args)
	if strings.Contains(string(gotArgs), "abcd1234") || !strings.Contains(string(gotArgs), "store") {
		t.Errorf("argv = %q", gotArgs)
	}
	withSecretTool(t, map[string]string{"FAKE_CLI_EXIT": "1", "FAKE_CLI_STDERR": "boom"})
	if err := (secretService{}).set("x"); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Errorf("set = %v, want the tool's message", err)
	}
}

func TestSecretServiceDel(t *testing.T) {
	withSecretTool(t, nil)
	if err := (secretService{}).del(); err != nil {
		t.Error(err)
	}
	withSecretTool(t, map[string]string{"FAKE_CLI_EXIT": "1"})
	if err := (secretService{}).del(); err == nil {
		t.Error("a failing secret-tool was not reported")
	}
}

func TestPlatformBackendNeedsSecretTool(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if _, ok := platformBackend().(noStore); !ok {
		t.Errorf("without secret-tool: %T, want noStore", platformBackend())
	}
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "secret-tool"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	if _, ok := platformBackend().(sealedBackend); !ok {
		t.Errorf("with secret-tool: %T, want sealedBackend", platformBackend())
	}
}
