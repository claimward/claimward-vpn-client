package helper

import (
	"context"
	"errors"
	"testing"

	"github.com/claimward/claimward-vpn-client/pkg/macauth"
)

func TestTheMacAuthorizerRefusesWhatTheSystemDoesNotGrant(t *testing.T) {
	a := authServicesAuthorizer{}
	if err := a.Authorize(context.Background(), Approval{Server: "https://x"}); !errors.Is(err, ErrDenied) {
		t.Errorf("no credential: %v", err)
	}
	if err := a.Authorize(context.Background(), Approval{Server: "https://x", Credential: make([]byte, macauth.FormLength)}); !errors.Is(err, ErrDenied) {
		t.Errorf("a forged credential: %v", err)
	}
}
