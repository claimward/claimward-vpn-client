// Package client is the high-level claimward client API shared by the CLI and
// the platform apps. It speaks the protocol package against claimward-vpn-server
// and converts an EnrollResponse into a ready-to-use wgtun.Config.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/claimward/claimward-vpn-client/pkg/protocol"
	"github.com/claimward/claimward-vpn-client/pkg/wgkey"
	"github.com/claimward/claimward-vpn-client/pkg/wgtun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Client talks to a claimward-vpn-server instance.
type Client struct {
	BaseURL string
	HTTP    *http.Client
}

// New returns a Client for the given server base URL (e.g. https://vpn.acme.com).
func New(baseURL string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		HTTP:    &http.Client{Timeout: 30 * time.Second},
	}
}

// Enroll registers the device's public key and returns the tunnel parameters.
// idToken is the OIDC ID token obtained from the oidc package.
func (c *Client) Enroll(ctx context.Context, idToken string, pub wgtypes.Key, dev protocol.DeviceInfo) (*protocol.EnrollResponse, error) {
	req := protocol.EnrollRequest{PublicKey: pub.String(), Device: dev}
	var resp protocol.EnrollResponse
	if err := c.do(ctx, http.MethodPost, protocol.PathEnroll, idToken, req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Heartbeat renews the lease for an enrolled peer.
func (c *Client) Heartbeat(ctx context.Context, idToken string, pub wgtypes.Key) (*protocol.HeartbeatResponse, error) {
	req := protocol.HeartbeatRequest{PublicKey: pub.String()}
	var resp protocol.HeartbeatResponse
	if err := c.do(ctx, http.MethodPost, protocol.PathHeartbeat, idToken, req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Deregister removes the peer from the gateway.
func (c *Client) Deregister(ctx context.Context, idToken string, pub wgtypes.Key) error {
	req := protocol.DeregisterRequest{PublicKey: pub.String()}
	return c.do(ctx, http.MethodPost, protocol.PathDeregister, idToken, req, nil)
}

// TunnelConfig converts an EnrollResponse plus the device private key into a
// wgtun.Config ready to hand to wgtun.Up.
func TunnelConfig(resp *protocol.EnrollResponse, priv wgtypes.Key) (wgtun.Config, error) {
	serverPub, err := wgkey.ParsePublic(resp.ServerPublicKey)
	if err != nil {
		return wgtun.Config{}, fmt.Errorf("parse server public key: %w", err)
	}
	return wgtun.Config{
		PrivateKey:      priv,
		ServerPublicKey: serverPub,
		Endpoint:        resp.Endpoint,
		AllowedIPs:      resp.AllowedIPs,
		Address:         resp.AssignedIP,
		DNS:             resp.DNS,
		MTU:             resp.MTU,
		Keepalive:       resp.PersistentKeepalive,
	}, nil
}

func (c *Client) do(ctx context.Context, method, path, bearer string, body, out any) error {
	var rdr io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, rdr)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		var e protocol.ErrorResponse
		if json.Unmarshal(data, &e) == nil && e.Error != "" {
			return fmt.Errorf("server %d: %s: %s", resp.StatusCode, e.Error, e.Message)
		}
		return fmt.Errorf("server %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}
