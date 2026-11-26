package helper

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

// PolkitAction is the polkit action the helper checks before it trusts a new
// server; the package ships its definition (packaging/polkit), which asks for
// an administrator's authentication every time (auth_admin, not _keep).
const PolkitAction = "com.claimward.helper.approve-server"

const (
	polkitName   = "org.freedesktop.PolicyKit1"
	polkitPath   = "/org/freedesktop/PolicyKit1/Authority"
	polkitMethod = "org.freedesktop.PolicyKit1.Authority.CheckAuthorization"
	// allowUserInteraction: CheckAuthorizationFlags 0x1, which lets polkit
	// have an authentication agent in the person's session ask them. Passed
	// because ActionApprove is the person's own action.
	allowUserInteraction = 1
)

// DefaultAuthorizer asks polkit, over the system bus, whether the process on
// the other end of the app's connection is authorized for PolkitAction --
// which, for an unprivileged person, means an administrator authenticated in
// the authentication agent of their session. The helper is the caller, so the
// prompt names the server the helper read, in words the helper chose
// (polkit.message may be set by root alone).
func DefaultAuthorizer() Authorizer { return polkitAuthorizer{} }

type polkitAuthorizer struct{}

func (polkitAuthorizer) Authorize(ctx context.Context, a Approval) error {
	pid, err := peerPID(a.Peer)
	if err != nil {
		return err
	}
	start, err := procStartTime(pid)
	if err != nil {
		return err
	}
	bus, err := dbus.SystemBus()
	if err != nil {
		return fmt.Errorf("polkit: system bus: %w", err)
	}
	subject := polkitSubject{Kind: "unix-process", Details: map[string]dbus.Variant{
		"pid":        dbus.MakeVariant(uint32(pid)),
		"start-time": dbus.MakeVariant(start),
	}}
	details := map[string]string{
		"polkit.message": "Authentication is required to trust the VPN server $(server)",
		"server":         displayServer(a),
	}
	var res polkitResult
	call := bus.Object(polkitName, polkitPath).CallWithContext(ctx, polkitMethod, 0,
		subject, PolkitAction, details, uint32(allowUserInteraction), "")
	if call.Err != nil {
		return fmt.Errorf("polkit: %w", call.Err)
	}
	if err := call.Store(&res); err != nil {
		return fmt.Errorf("polkit: %w", err)
	}
	return polkitDecision(res)
}

// polkitSubject and polkitResult are the (sa{sv}) and (bba{ss}) structures of
// CheckAuthorization.
type polkitSubject struct {
	Kind    string
	Details map[string]dbus.Variant
}

type polkitResult struct {
	IsAuthorized bool
	IsChallenge  bool
	Details      map[string]string
}

// polkitDecision is the verdict: only an authorization is a yes. A challenge
// is "could be, with authentication nobody gave" and a dismissal is a no.
func polkitDecision(r polkitResult) error {
	if r.IsAuthorized {
		return nil
	}
	if r.Details["polkit.dismissed"] != "" {
		return fmt.Errorf("%w: the authentication was dismissed", ErrDenied)
	}
	if r.IsChallenge {
		return fmt.Errorf("%w: authentication is required and was not given (is an authentication agent running in your session?)", ErrDenied)
	}
	return ErrDenied
}

// displayServer is the server as the prompt shows it: its name, when it has
// one, and always its URL.
func displayServer(a Approval) string {
	if a.Name == "" {
		return a.Server
	}
	return a.Name + " (" + a.Server + ")"
}

// peerPID is the process on the other end of an AF_UNIX connection, as the
// kernel reports it (SO_PEERCRED), not as the peer says.
func peerPID(c net.Conn) (int, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, errors.New("the app's connection is not a unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *unix.Ucred
	var serr error
	if err := raw.Control(func(fd uintptr) {
		cred, serr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if serr != nil {
		return 0, fmt.Errorf("SO_PEERCRED: %w", serr)
	}
	return int(cred.Pid), nil
}

// procStartTime is when process pid started, in clock ticks since boot: what
// polkit pairs with the pid so that a pid reused by another process is not
// taken for the first.
func procStartTime(pid int) (uint64, error) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, err
	}
	return parseStartTime(string(b))
}

// parseStartTime reads field 22 of /proc/<pid>/stat. The command name, field
// 2, may hold spaces and parentheses, so the fields are counted from the last
// ')'.
func parseStartTime(stat string) (uint64, error) {
	i := strings.LastIndexByte(stat, ')')
	if i < 0 {
		return 0, errors.New("/proc stat: no command name")
	}
	f := strings.Fields(stat[i+1:])
	// f[0] is field 3 (state); field 22 is f[19].
	if len(f) < 20 {
		return 0, errors.New("/proc stat: too few fields")
	}
	return strconv.ParseUint(f[19], 10, 64)
}
