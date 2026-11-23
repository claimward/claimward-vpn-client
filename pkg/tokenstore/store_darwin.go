package tokenstore

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

const (
	kcService = "claimward"
	kcAccount = "session-key"
	// securityNotFound is /usr/bin/security's exit status for "no such item".
	securityNotFound = 44
)

func platformBackend() backend { return sealedBackend{kr: keychain{}} }

// keychain keeps the sealing key in the login Keychain. The key goes to
// `security -i` on standard input, never on the command line.
type keychain struct{}

func (keychain) run(stdin string, args ...string) (string, error) {
	cmd := exec.Command("/usr/bin/security", args...)
	cmd.Stdin = strings.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) && ee.ExitCode() == securityNotFound {
		return "", errNotFound
	}
	if err != nil {
		return "", fmt.Errorf("security: %v: %s", err, strings.TrimSpace(errb.String()))
	}
	return strings.TrimSpace(out.String()), nil
}

func (keychain) get() (string, error) {
	return keychain{}.run("", "find-generic-password", "-s", kcService, "-a", kcAccount, "-w")
}

func (keychain) set(v string) error {
	// A hex key needs no quoting inside the interactive command line.
	_, err := keychain{}.run("add-generic-password -U -s "+kcService+" -a "+kcAccount+" -w "+v+"\n", "-i")
	return err
}

func (keychain) del() error {
	_, err := keychain{}.run("", "delete-generic-password", "-s", kcService, "-a", kcAccount)
	if errors.Is(err, errNotFound) {
		return nil
	}
	return err
}
