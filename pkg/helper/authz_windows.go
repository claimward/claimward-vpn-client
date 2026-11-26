//go:build windows

package helper

import (
	"context"
	"errors"
	"fmt"
)

// DefaultAuthorizer on Windows is the operating system's own elevation. The
// consent is a connection on the approval socket (ListenElevated), whose DACL
// admits an elevated token alone: a standard user reaches it only through
// the UAC credential prompt (an administrator's name and password), and a
// hostile process of the same user cannot present that on the person's
// behalf without the prompt appearing on the secure desktop. Nothing in the
// request (Approval.Credential) is read.
func DefaultAuthorizer() Authorizer { return elevationAuthorizer{} }

type elevationAuthorizer struct{}

func (elevationAuthorizer) Authorize(_ context.Context, a Approval) error {
	if !a.Elevated {
		return fmt.Errorf("%w: approving %s takes an elevated process (run the approval from the administrator prompt)", ErrDenied, a.Server)
	}
	if a.Server == "" {
		return errors.New("no server to approve")
	}
	return nil
}
