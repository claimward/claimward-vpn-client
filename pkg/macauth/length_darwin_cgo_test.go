//go:build darwin && cgo

package macauth

import (
	"strings"
	"testing"
)

// The length is refused before the system is asked, whatever the bytes.
func TestVerifyNamesTheLengthItRefuses(t *testing.T) {
	for _, n := range []int{FormLength - 1, FormLength + 1} {
		if err := Verify(make([]byte, n)); err == nil || !strings.Contains(err.Error(), "external form is") {
			t.Errorf("length %d: %v", n, err)
		}
	}
}
