package macauth

import (
	"errors"
	"strings"
	"testing"
)

func TestStatusErr(t *testing.T) {
	if err := statusErr("x", 0); err != nil {
		t.Errorf("success: %v", err)
	}
	if err := statusErr("x", -60005); err == nil || !strings.Contains(err.Error(), "-60005") {
		t.Errorf("failure: %v", err)
	}
}

func TestVerifyRefusesAWrongLength(t *testing.T) {
	for _, n := range []int{0, FormLength - 1, FormLength + 1} {
		if err := Verify(make([]byte, n)); !errors.Is(err, ErrNotAuthorized) && !errors.Is(err, ErrUnavailable) {
			t.Errorf("length %d: %v", n, err)
		}
	}
}

// Off macOS or without cgo nothing is ever authorized.
func TestStubsFailClosed(t *testing.T) {
	if err := Verify(make([]byte, FormLength)); err == nil {
		t.Error("an all-zero token was verified")
	}
}
