package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/claimward/claimward-vpn-client/pkg/protocol"
	"github.com/claimward/claimward-vpn-client/pkg/wgkey"
)

// FuzzServerResponse feeds arbitrary answers to the client the way a hostile
// or impersonated server would, and then to TunnelConfig, which turns an
// enroll answer into what the root helper acts on. Neither may panic.
func FuzzServerResponse(f *testing.F) {
	f.Add(200, []byte(`[{"id":"a","name":"A"}]`))
	f.Add(200, []byte(`{"endpoint":"192.0.2.1:51820","server_public_key":"AAAA","assigned_ip":"10.0.0.2/32","allowed_ips":["10.0.0.0/8"],"mtu":1280}`))
	f.Add(500, []byte(`{"error":"boom","message":"x"}`))
	f.Add(401, []byte(`not json`))
	f.Add(200, []byte(`{"allowed_ips":[1,2],"dns":null}`))
	f.Add(200, []byte(``))
	f.Fuzz(func(t *testing.T, status int, body []byte) {
		if status < 100 || status > 599 {
			return
		}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
			_, _ = w.Write(body)
		}))
		defer srv.Close()
		c := New(srv.URL)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = c.Tenants(ctx, "bearer")
		pair, err := wgkey.Generate()
		if err != nil {
			t.Fatal(err)
		}
		resp, err := c.Enroll(ctx, "bearer", pair.Public, protocol.DeviceInfo{Name: "d"}, "")
		if err == nil {
			_, _ = TunnelConfig(resp, pair.Private)
		}
	})
}
