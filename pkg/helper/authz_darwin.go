//go:build darwin

package helper

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/claimward/claimward-vpn-client/pkg/macauth"
)

// DefaultAuthorizer on macOS is Authorization Services: the app obtained an
// authorization for our own right (an administrator authenticated in the
// system's dialog) and handed its external form in Approval.Credential; the
// system, not the helper, says whether it holds. The helper also creates the
// right in the policy database the first time (best effort: it may exist).
func DefaultAuthorizer() Authorizer {
	if err := macauth.EnsureRight(); err != nil {
		slog.Warn("cannot create the approval right; approving a server will be refused until it exists", "err", err)
	}
	return authServicesAuthorizer{}
}

type authServicesAuthorizer struct{}

func (authServicesAuthorizer) Authorize(_ context.Context, a Approval) error {
	if len(a.Credential) == 0 {
		return fmt.Errorf("%w: no authorization was given (the app must obtain one from the system first)", ErrDenied)
	}
	if err := macauth.Verify(a.Credential); err != nil {
		return fmt.Errorf("%w: %v", ErrDenied, err)
	}
	return nil
}
