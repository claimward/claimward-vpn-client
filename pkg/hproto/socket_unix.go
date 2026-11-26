//go:build !windows

package hproto

// DefaultSocketPath is where the privileged helper listens.
const DefaultSocketPath = "/var/run/claimward-helper.sock"

// DefaultElevatedSocketPath is empty off Windows: approval is obtained from
// polkit (Linux) or Authorization Services (macOS), not from a second socket.
const DefaultElevatedSocketPath = ""
