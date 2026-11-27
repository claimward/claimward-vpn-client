package helper

import (
	"errors"
	"fmt"
	"net"
	"strconv"

	"golang.org/x/sys/unix"
)

// DefaultPeerSource reads the caller's uid from the kernel: SO_PEERCRED, the
// same call peerPID makes, as unix(7) says "the credentials of the peer
// process connected to this socket", those in effect when it connected.
func DefaultPeerSource(c net.Conn) (Peer, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return Peer{}, errors.New("the connection is not a unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return Peer{}, err
	}
	var cred *unix.Ucred
	var serr error
	if err := raw.Control(func(fd uintptr) {
		cred, serr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return Peer{}, err
	}
	if serr != nil {
		return Peer{}, fmt.Errorf("SO_PEERCRED: %w", serr)
	}
	return unixPeer(cred.Uid), nil
}

func unixPeer(uid uint32) Peer {
	return Peer{ID: "uid:" + strconv.FormatUint(uint64(uid), 10), Admin: uid == 0}
}
