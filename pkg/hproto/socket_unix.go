//go:build !windows

package hproto

// DefaultSocketPath is where the privileged helper listens.
const DefaultSocketPath = "/var/run/claimward-helper.sock"
