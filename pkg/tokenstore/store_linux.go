package tokenstore

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// platformBackend uses the Secret Service through secret-tool when it is
// installed, and otherwise only the opt-in 0600 file.
func platformBackend() backend {
	if _, err := exec.LookPath("secret-tool"); err != nil {
		return noStore{}
	}
	return sealedBackend{kr: secretService{}}
}

// secretService keeps the sealing key in the Secret Service. secret-tool reads
// the secret from standard input, never from the command line.
type secretService struct{}

var ssAttrs = []string{"service", "claimward", "account", "session-key"}

func (secretService) run(stdin string, args ...string) (string, error) {
	cmd := exec.Command("secret-tool", args...)
	cmd.Stdin = strings.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("secret-tool: %v: %s", err, strings.TrimSpace(errb.String()))
	}
	return out.String(), nil
}

func (s secretService) get() (string, error) {
	// lookup exits non-zero with no output when the item does not exist.
	// A failing lookup (no daemon, locked collection) reads as nothing stored:
	// set then reports the real failure.
	out, err := s.run("", append([]string{"lookup"}, ssAttrs...)...)
	if err != nil || strings.TrimSpace(out) == "" {
		return "", errNotFound
	}
	return strings.TrimSpace(out), nil
}

func (s secretService) set(v string) error {
	_, err := s.run(v, append([]string{"store", "--label=Claimward session key"}, ssAttrs...)...)
	return err
}

func (s secretService) del() error {
	_, err := s.run("", append([]string{"clear"}, ssAttrs...)...)
	return err
}
