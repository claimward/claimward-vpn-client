//go:build darwin || freebsd

package helper

import (
	"errors"
	"fmt"
	"net"
	"strconv"

	"golang.org/x/sys/unix"
)

// DefaultPeerSource reads the caller's uid from the kernel: LOCAL_PEERCRED,
// whose xucred holds the credentials the client had when it called connect(2)
// (unix(4)).
func DefaultPeerSource(c net.Conn) (Peer, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return Peer{}, errors.New("the connection is not a unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return Peer{}, err
	}
	var cred *unix.Xucred
	var serr error
	if err := raw.Control(func(fd uintptr) {
		cred, serr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return Peer{}, err
	}
	if serr != nil {
		return Peer{}, fmt.Errorf("LOCAL_PEERCRED: %w", serr)
	}
	return unixPeer(cred.Uid), nil
}

func unixPeer(uid uint32) Peer {
	return Peer{ID: "uid:" + strconv.FormatUint(uint64(uid), 10), Admin: uid == 0}
}
