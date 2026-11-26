package helper

import (
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
)

// An oversized request is answered with an error, not served: the bound is
// only worth something if the request that crosses it is refused.
func TestHelperRefusesAnOversizedRequest(t *testing.T) {
	s := New(Config{Servers: []string{"https://vpn.example.org"}}, "test", "test", slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv, cli := net.Pipe()
	go s.handle(srv, false)
	go func() {
		// A well-formed request, but larger than maxRequestBytes.
		_, _ = io.WriteString(cli, `{"action":"status","pad":"`+strings.Repeat("a", 2*maxRequestBytes)+`"}`)
	}()
	var resp struct {
		OK    bool
		Error string
	}
	if err := json.NewDecoder(cli).Decode(&resp); err != nil {
		t.Fatalf("no reply: %v", err)
	}
	cli.Close()
	if resp.OK || !strings.Contains(resp.Error, "bad request") {
		t.Fatalf("an oversized request was served: %+v", resp)
	}
}
