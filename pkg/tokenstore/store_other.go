//go:build !darwin && !windows && !linux

package tokenstore

// platformBackend: no secret store is known on this platform, so only the
// opt-in 0600 file exists.
func platformBackend() backend { return noStore{} }
