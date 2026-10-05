//go:build !windows

package helper

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
)

// DefaultGroup may use the socket beside root: on macOS the administrators
// (the person at a laptop usually is one), on Linux a dedicated group the
// installer creates and adds the person to.
var DefaultGroup = map[bool]string{true: "admin", false: "claimward"}[runtime.GOOS == "darwin"]

// Listen opens the helper's socket: owned by root and group, mode 0660.
//
// ⛔ The mode is set on a socket created inside a directory only root can
// write, and before anybody is accepted: a socket that exists, even for a
// moment, with a wider mode is one a process can connect to in that moment.
func Listen(path, group string) (net.Listener, error) {
	g, err := user.LookupGroup(group)
	if err != nil {
		return nil, fmt.Errorf("the helper's group %q: %w", group, err)
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return nil, err
	}
	if err := checkDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	old := syscall.Umask(0o177) // the socket is born 0600
	ln, err := net.Listen("unix", path)
	syscall.Umask(old)
	if err != nil {
		return nil, err
	}
	if err := os.Chown(path, 0, gid); err != nil {
		ln.Close()
		return nil, err
	}
	if err := os.Chmod(path, 0o660); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

// checkDir refuses a socket directory somebody other than root could write:
// they could replace the socket with their own, and the app would hand them
// its bearer token.
func checkDir(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if st.Uid != 0 || fi.Mode().Perm()&0o022 != 0 && fi.Mode()&os.ModeSticky == 0 {
		return fmt.Errorf("%s may be written by somebody other than root; the helper's socket would not be its own", dir)
	}
	return nil
}

// checkOwner refuses a configuration file anybody but root could have
// written: whoever writes it chooses the server the helper trusts.
func checkOwner(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if st.Uid != rootUID || fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("must be owned by root and writable by root alone (owner %d, mode %v)", st.Uid, fi.Mode().Perm())
	}
	return nil
}

// rootUID is 0; a variable so that tests run by a person can stand in for it.
var rootUID uint32 = 0
