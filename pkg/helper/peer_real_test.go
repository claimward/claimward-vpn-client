//go:build linux || darwin || freebsd || windows

package helper

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// The real credentials source against a real AF_UNIX connection, on every OS
// lane: the peer is this very process, so its identity is ours.
func TestDefaultPeerSourceReadsTheKernelsCredentials(t *testing.T) {
	// A short path: an AF_UNIX socket's is limited (104 bytes on macOS).
	dir, err := os.MkdirTemp("", "cwp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "p.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			close(got)
			return
		}
		got <- c
	}()
	cl, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	srv, ok := <-got
	if !ok {
		t.Fatal("no connection accepted")
	}
	defer srv.Close()

	p, err := DefaultPeerSource(srv)
	if err != nil {
		t.Fatal(err)
	}
	want := selfPeer(t)
	if p.ID != want.ID {
		t.Errorf("peer %+v, want %+v", p, want)
	}
	if p.Admin != want.Admin {
		t.Errorf("admin %v, want %v (peer %+v)", p.Admin, want.Admin, p)
	}
	if _, err := DefaultPeerSource(&net.TCPConn{}); err == nil {
		t.Error("a TCP connection was identified")
	}
	// A connection that cannot be asked, or that is already closed, is an
	// error, never an identity (an empty one would be the unidentified caller).
	if p, err := DefaultPeerSource(&net.UnixConn{}); err == nil {
		t.Errorf("a zero connection was identified as %+v", p)
	}
	srv.Close()
	if p, err := DefaultPeerSource(srv); err == nil {
		t.Errorf("a closed connection was identified as %+v", p)
	}
}
