// Package protocol defines the wire contract between the claimward VPN clients
// (the CLI in this repo and the platform apps such as claimward-vpn-app-osx)
// and claimward-vpn-server.
//
// It is the single source of truth for request/response shapes and is imported
// by both the client and the server so the two cannot drift.
package protocol

import "time"

// API paths exposed by claimward-vpn-server.
const (
	PathEnroll     = "/api/v1/enroll"
	PathHeartbeat  = "/api/v1/heartbeat"
	PathDeregister = "/api/v1/deregister"
	PathHealthz    = "/healthz"
)

// EnrollRequest is sent by a client to obtain a WireGuard tunnel configuration.
//
// The OIDC ID token is passed in the HTTP Authorization header as a bearer
// token ("Authorization: Bearer <id_token>"), never in the body.
type EnrollRequest struct {
	// PublicKey is the client's WireGuard public key in standard wg base64 encoding.
	PublicKey string `json:"public_key"`
	// Device describes the enrolling device, for audit and display in the admin UI.
	Device DeviceInfo `json:"device"`
}

// DeviceInfo identifies the device performing an enrollment.
type DeviceInfo struct {
	Name     string `json:"name"`     // user-facing hostname
	OS       string `json:"os"`       // darwin, linux, windows
	Platform string `json:"platform"` // app-osx, cli, ...
}

// EnrollResponse contains everything the client needs to bring up its tunnel.
type EnrollResponse struct {
	// AssignedIP is the client's address inside the VPN in CIDR form, e.g. "10.80.0.5/32".
	AssignedIP string `json:"assigned_ip"`
	// ServerPublicKey is the gateway's WireGuard public key (base64).
	ServerPublicKey string `json:"server_public_key"`
	// Endpoint is the public host:port of the WireGuard gateway.
	Endpoint string `json:"endpoint"`
	// AllowedIPs are the destination CIDRs routed through the tunnel.
	AllowedIPs []string `json:"allowed_ips"`
	// DNS servers to use while connected (optional).
	DNS []string `json:"dns,omitempty"`
	// GRPCEndpoint is the host:port of the server's RouteService (gRPC), which the
	// client can Watch for live route updates. Empty disables dynamic routes.
	GRPCEndpoint string `json:"grpc_endpoint,omitempty"`
	// PersistentKeepalive in seconds (0 = disabled).
	PersistentKeepalive int `json:"persistent_keepalive"`
	// MTU for the tunnel interface (0 = wireguard default).
	MTU int `json:"mtu,omitempty"`
	// LeaseExpiresAt is when the client must heartbeat or re-enroll before its
	// peer is removed from the gateway.
	LeaseExpiresAt time.Time `json:"lease_expires_at"`
}

// HeartbeatRequest keeps a previously enrolled peer alive. Bearer auth as above.
type HeartbeatRequest struct {
	PublicKey string `json:"public_key"`
}

// HeartbeatResponse renews the lease.
type HeartbeatResponse struct {
	LeaseExpiresAt time.Time `json:"lease_expires_at"`
}

// DeregisterRequest removes a peer from the gateway. Bearer auth as above.
type DeregisterRequest struct {
	PublicKey string `json:"public_key"`
}

// ErrorResponse is the JSON body returned on any non-2xx response.
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}
