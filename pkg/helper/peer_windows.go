//go:build windows

package helper

import (
	"errors"
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

// sioAFUnixGetPeerPID is SIO_AF_UNIX_GETPEERPID from the SDK's afunix.h
// (_WSAIOR(IOC_VENDOR, 256)): WSAIoctl on a connected AF_UNIX socket, output a
// ULONG, the peer's process id. The control code is not on the Winsock IOCTL
// page of learn.microsoft.com; a Windows that does not know it answers
// WSAEINVAL or WSAEOPNOTSUPP, and the caller is then refused (since v0.12.2
// the helper fails closed: an error, never a shared pool of unidentified
// callers).
const sioAFUnixGetPeerPID = 0x58000100

// DefaultPeerSource identifies the caller from its process: the peer's pid
// (SIO_AF_UNIX_GETPEERPID), then that process's access token -- its user SID
// is the owner, and SYSTEM or an elevated member of Administrators is an
// admin. The token is the process's own, as the system holds it, never
// anything the request says.
func DefaultPeerSource(c net.Conn) (Peer, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return Peer{}, errors.New("the connection is not a unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return Peer{}, err
	}
	var pid, n uint32
	var ierr error
	if err := raw.Control(func(fd uintptr) {
		ierr = windows.WSAIoctl(windows.Handle(fd), sioAFUnixGetPeerPID, nil, 0,
			(*byte)(unsafe.Pointer(&pid)), 4, &n, nil, 0)
	}); err != nil {
		return Peer{}, err
	}
	if ierr != nil {
		if errors.Is(ierr, windows.WSAEINVAL) || errors.Is(ierr, windows.WSAEOPNOTSUPP) {
			// Fail closed: a caller nobody can name is refused, never pooled.
			return Peer{}, fmt.Errorf("SIO_AF_UNIX_GETPEERPID is not supported: %w", ierr)
		}
		return Peer{}, fmt.Errorf("SIO_AF_UNIX_GETPEERPID: %w", ierr)
	}
	return processPeer(pid)
}

// processPeer is the identity of process pid's token.
func processPeer(pid uint32) (Peer, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return Peer{}, fmt.Errorf("open the caller's process %d: %w", pid, err)
	}
	defer windows.CloseHandle(h)
	var tok windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE, &tok); err != nil {
		return Peer{}, fmt.Errorf("open the caller's token: %w", err)
	}
	defer tok.Close()
	u, err := tok.GetTokenUser()
	if err != nil {
		return Peer{}, fmt.Errorf("the caller's user: %w", err)
	}
	p := Peer{ID: u.User.Sid.String()}
	if system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid); err == nil && u.User.Sid.Equals(system) {
		p.Admin = true
		return p, nil
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return Peer{}, err
	}
	// CheckTokenMembership wants an impersonation token and counts only an
	// ENABLED group: an administrator who is not elevated has the group
	// deny-only, and is a standard user here.
	var dup windows.Token
	if err := windows.DuplicateTokenEx(tok, windows.TOKEN_QUERY, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &dup); err != nil {
		return Peer{}, fmt.Errorf("duplicate the caller's token: %w", err)
	}
	defer dup.Close()
	member, err := dup.IsMember(admins)
	if err != nil {
		return Peer{}, err
	}
	p.Admin = member
	return p, nil
}
