//go:build !linux && !darwin && !freebsd && !windows

package helper

import (
	"errors"
	"net"
)

// DefaultPeerSource on a platform with no peer-credential call wired in cannot
// identify anybody, so every caller is refused (fail closed): sharing one pool
// of unidentified callers would show one user another's tunnels.
func DefaultPeerSource(net.Conn) (Peer, error) {
	return Peer{}, errors.New("this platform has no peer-credential call")
}
