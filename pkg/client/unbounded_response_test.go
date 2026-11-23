package client

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Audit 2026-11-23, finding 4b: the server's answer is read whole with
// io.ReadAll, so a hostile or impersonated server (see finding 6, http://)
// makes the root helper buffer whatever it sends for the 30 s timeout.
func TestClientBoundsTheResponseItReads(t *testing.T) {
	const limit = 1 << 20
	const offered = 64 << 20
	var written int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		chunk := bytes.Repeat([]byte("a"), 64<<10)
		for written < offered {
			n, err := w.Write(chunk)
			written += n
			if err != nil {
				return
			}
		}
	}))
	defer srv.Close()
	_, err := New(srv.URL).Tenants(context.Background(), "bearer")
	if se, ok := err.(*ServerError); ok && len(se.Message) > limit {
		t.Fatalf("the client buffered %d bytes of one answer (limit %d)", len(se.Message), limit)
	}
}
