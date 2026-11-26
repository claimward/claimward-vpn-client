// Package macauth is the macOS half of server approval: Authorization
// Services, which Apple documents for exactly this split between an
// unprivileged app and a privileged helper.
//
// The app calls Obtain: the system shows its authentication dialog, an
// administrator types a name and password, and what comes back is an
// AuthorizationExternalForm, a 32-byte token for an authorization the system
// holds. The helper calls Verify with it: the system answers whether that
// authorization carries Right, and the helper destroys it, so a token buys
// one approval. Nothing in the token is a claim -- it names a record in
// authd -- so an app that fabricates one gets a refusal.
//
// Without cgo, or off macOS, every function fails closed.
package macauth

import (
	"errors"
	"fmt"
)

// statusErr is an OSStatus as an error: nil for success (0).
func statusErr(what string, st int) error {
	if st == 0 {
		return nil
	}
	return fmt.Errorf("%s: OSStatus %d", what, st)
}

// Right is the authorization right of our own. The helper creates it in the
// system policy database (EnsureRight) with the rule authenticate-admin-
// nonshared: an administrator's name and password every time, never a
// credential another prompt left behind.
const Right = "com.claimward.helper.approve-server"

// Rule is the policy rule Right is created with.
const Rule = "authenticate-admin-nonshared"

// FormLength is the size of an external form (kAuthorizationExternalFormLength).
const FormLength = 32

// ErrUnavailable is returned where Authorization Services cannot be used.
var ErrUnavailable = errors.New("macOS Authorization Services are not available in this build")

// ErrNotAuthorized is returned by Verify when the system does not grant Right
// to the token.
var ErrNotAuthorized = errors.New("the system does not grant the approval right to this authorization")
