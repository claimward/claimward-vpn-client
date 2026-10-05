// Package hproto is the line protocol between an unprivileged Claimward app
// and its privileged helper: one JSON request per connection, one JSON
// response back. Kept tiny because the helper runs as root (or SYSTEM), and
// every action here is something any process allowed on its socket can ask.
package hproto

import "time"

// Action values.
//
// ⛔ There is no action that takes a tunnel configuration. An earlier helper
// had "up" (any peer, any routes) and "update-routes"; on a socket every
// local process could reach, that was a way to send all of the machine's
// traffic anywhere. The tunnel is configured only from what a server the
// helper's own configuration names answered at enrollment.
const (
	// ActionConnect makes the helper enroll with the server, bring the
	// tunnel up and watch for route pushes. The server comms live in the
	// helper: macOS "Local Network" privacy blocks the unprivileged app
	// from reaching a server on the LAN, and root is exempt.
	ActionConnect = "connect"
	ActionDown    = "down"
	ActionStatus  = "status"
	// ActionTenants lists the tenants the bearer may connect to, through the
	// helper for the same reason as ActionConnect.
	ActionTenants = "tenants"
	// ActionRenew hands the helper a fresh bearer for the tunnel it holds
	// and renews its lease now. It names no server, key or tenant: the
	// helper renews only the enrollment it made itself, with the server it
	// made it with.
	ActionRenew = "renew"
)

// Request is sent by the app to the helper.
type Request struct {
	Action  string       `json:"action"`
	Connect *ConnectSpec `json:"connect,omitempty"` // ActionConnect, ActionTenants, ActionRenew (Bearer only)
}

// ConnectSpec is what the helper needs to enroll.
type ConnectSpec struct {
	// ServerURL must be one the helper's configuration allows.
	ServerURL  string `json:"server_url"`
	Bearer     string `json:"bearer"`
	PrivateKey string `json:"private_key,omitempty"` // device WireGuard private key (base64); not for ActionTenants
	DeviceName string `json:"device_name,omitempty"`
	// Tenant is the one chosen for this session; empty lets the server use
	// the person's only one.
	Tenant string `json:"tenant,omitempty"`
}

// Tenant is one the person may connect to.
type Tenant struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Response is returned by the helper.
//
// The lease is the server's: a peer whose lease ends is removed from the
// gateway. The helper renews it while the tunnel is up (pkg/helper).
type Response struct {
	OK         bool     `json:"ok"`
	Error      string   `json:"error,omitempty"`
	Connected  bool     `json:"connected"`
	Interface  string   `json:"interface,omitempty"`
	AssignedIP string   `json:"assigned_ip,omitempty"`
	Tenant     string   `json:"tenant,omitempty"`
	Tenants    []Tenant `json:"tenants,omitempty"`
	// LeaseExpiresAt is when the server removes the peer unless renewed.
	LeaseExpiresAt *time.Time `json:"lease_expires_at,omitempty"`
	// LastError is why the helper last failed to keep the tunnel: a renewal
	// the server refused, a re-enrollment that failed. Cleared by a
	// successful connect.
	LastError string `json:"last_error,omitempty"`
}
