package helper

import (
	"io"
	"log/slog"
	"net"
	"testing"
	"time"
)

// FuzzHelperRequest feeds arbitrary bytes to the helper's socket handler, the
// decoder of the one untrusted input a root process takes. It must neither
// panic nor hang, and must hold no more than maxRequestBytes. The server list
// is empty, so no request can reach the network.
func FuzzHelperRequest(f *testing.F) {
	for _, seed := range []string{
		``, `{}`, `{"action":"status"}`, `{"action":"down"}`, `{"action":"nope"}`,
		`{"action":"connect","connect":null}`,
		`{"action":"connect","connect":{"server_url":"https://x","bearer":"b","private_key":"!!"}}`,
		`{"action":"tenants","connect":{"bearer":"b"}}`, `{"action":"renew"}`,
		`[1,2,3]`, `"a"`, `{"action":`, "\x00\xff\xfe",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		s := New(Config{}, "test", "test", slog.New(slog.NewTextHandler(io.Discard, nil)))
		srv, cli := net.Pipe()
		done := make(chan struct{})
		go func() { s.handle(srv, false); close(done) }()
		go func() { _, _ = io.Copy(io.Discard, cli) }()
		go func() { _, _ = cli.Write(data); cli.Close() }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("the handler did not return")
		}
		cli.Close()
	})
}
