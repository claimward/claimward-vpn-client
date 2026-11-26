package helper

import (
	"errors"
	"os"
	"testing"
)

func TestParseStartTime(t *testing.T) {
	// A command name with spaces and parentheses must not shift the fields.
	stat := "123 (a (weird) name) S 1 123 123 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 987654 1000 10 18446744073709551615"
	got, err := parseStartTime(stat)
	if err != nil || got != 987654 {
		t.Errorf("start time: %d %v", got, err)
	}
	for _, bad := range []string{"", "no parenthesis", "1 (x) S 1 2"} {
		if _, err := parseStartTime(bad); err == nil {
			t.Errorf("%q was parsed", bad)
		}
	}
	// Our own process reads.
	if _, err := procStartTime(os.Getpid()); err != nil {
		t.Errorf("own start time: %v", err)
	}
}

func TestPolkitDecision(t *testing.T) {
	if err := polkitDecision(polkitResult{IsAuthorized: true}); err != nil {
		t.Errorf("authorized: %v", err)
	}
	for name, r := range map[string]polkitResult{
		"no":        {},
		"challenge": {IsChallenge: true},
		"dismissed": {IsChallenge: true, Details: map[string]string{"polkit.dismissed": "true"}},
	} {
		if err := polkitDecision(r); !errors.Is(err, ErrDenied) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
