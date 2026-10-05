//go:build windows

package helper

import (
	"errors"
	"net"
	"os"
	"path/filepath"
)

// DefaultGroup is unused on Windows: who may reach the socket is the ACL of
// its directory, under ProgramData, which the installer sets.
var DefaultGroup = ""

// Listen opens the helper's AF_UNIX socket. Access is the directory's ACL.
func Listen(path, _ string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return net.Listen("unix", path)
}

// checkOwner is the installer's job on Windows: the configuration lives
// under ProgramData with an ACL that lets Administrators alone write it.
func checkOwner(path string) error {
	_, err := os.Stat(path)
	return err
}
