package helper

import (
	"bytes"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"
)

// Audit 2026-11-23, finding 4a: a request on the helper's socket is decoded
// with no size bound. Any member of the socket's group can make the root
// helper buffer as much as it sends for the 2-minute deadline, on as many
// connections as it opens. The helper must give up after a bounded amount.
func TestHelperBoundsTheRequestItReads(t *testing.T) {
	const limit = 1 << 20    // what a request may reasonably be
	const offered = 64 << 20 // what the client is willing to send
	s := New(Config{Servers: []string{"https://vpn.example.org"}}, "test", "test", slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv, cli := net.Pipe()
	done := make(chan struct{})
	go func() { s.handle(srv); close(done) }()
	go func() { _, _ = io.Copy(io.Discard, cli) }() // the reply, if it comes

	chunk := bytes.Repeat([]byte("a"), 64<<10)
	sent := 0
	_, _ = cli.Write([]byte(`{"action":"`))
	_ = cli.SetWriteDeadline(time.Now().Add(20 * time.Second))
	for sent < offered {
		n, err := cli.Write(chunk)
		sent += n
		if err != nil {
			break
		}
	}
	cli.Close()
	<-done
	if sent > limit {
		t.Fatalf("the helper read %d bytes of a single request (limit %d)", sent, limit)
	}
}
