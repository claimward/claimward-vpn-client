//go:build !(darwin && cgo)

package macauth

// Obtain fails closed: there is no Authorization Services in this build.
func Obtain(string) ([]byte, error) { return nil, ErrUnavailable }

// Verify fails closed.
func Verify([]byte) error { return ErrUnavailable }

// EnsureRight fails closed.
func EnsureRight() error { return ErrUnavailable }
