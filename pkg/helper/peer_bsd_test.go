//go:build darwin || freebsd

package helper

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// A socket that is not connected has no peer: LOCAL_PEERCRED fails (ENOTCONN)
// and the caller is an error, not an identity.
func TestDefaultPeerSourceRefusesAnUnconnectedSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "cwp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	c, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: filepath.Join(dir, "d.sock"), Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if p, err := DefaultPeerSource(c); err == nil {
		t.Errorf("an unconnected socket was identified as %+v", p)
	}
}
