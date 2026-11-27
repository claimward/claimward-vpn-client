//go:build !linux && !darwin && !freebsd && !windows

package helper

import "net"

// DefaultPeerSource on a platform with no peer-credential call wired in
// identifies nobody: every caller is the unidentified one (Peer.ID empty), who
// sees only what unidentified callers connected.
func DefaultPeerSource(net.Conn) (Peer, error) { return Peer{}, nil }
