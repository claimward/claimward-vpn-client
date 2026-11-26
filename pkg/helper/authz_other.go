//go:build !darwin && !linux && !windows

package helper

// DefaultAuthorizer is nil where no system consent is implemented: approving
// a server is refused, and only the administrator's configuration names one.
func DefaultAuthorizer() Authorizer { return nil }
