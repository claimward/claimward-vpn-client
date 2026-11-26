package macauth

import (
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

// Off macOS or without cgo nothing is ever authorized.
func TestStubsFailClosed(t *testing.T) {
	if err := Verify(make([]byte, FormLength)); err == nil {
		t.Error("an all-zero token was verified")
	}
}
