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
//
// The helper holds one tunnel per server. Whether two servers may be up
// together is its own decision (a server's discovery document says whether it
// is exclusive), never the request's.
const (
	// ActionConnect makes the helper enroll with the server, bring its tunnel
	// up and watch for route pushes. The server comms live in the helper:
	// macOS "Local Network" privacy blocks the unprivileged app from reaching
	// a server on the LAN, and root is exempt.
	ActionConnect = "connect"
	// ActionDown takes down the tunnel of the server ConnectSpec.ServerURL
	// names, or every tunnel when the request carries no ConnectSpec.
	ActionDown   = "down"
	ActionStatus = "status"
	// ActionTenants lists the tenants the bearer may connect to, through the
	// helper for the same reason as ActionConnect.
	ActionTenants = "tenants"
	// ActionRenew hands the helper a fresh bearer for the tunnel it holds to
	// the server ConnectSpec.ServerURL names, and renews that lease now. It
	// names no key or tenant: the helper renews only the enrollment it made
	// itself, with the server it made it with.
	ActionRenew = "renew"
)

// Error codes a Response can carry beside its Error text.
const (
	// ErrExclusive: the connection was refused because one of the two servers
	// is exclusive. Response.BlockedBy names the other one.
	ErrExclusive = "exclusive_conflict"
	// ErrDiscovery: the helper could not read the server's discovery
	// document, so it could not tell whether the server is exclusive and
	// refused (it fails closed).
	ErrDiscovery = "discovery_failed"
)

// Request is sent by the app to the helper.
type Request struct {
	Action  string       `json:"action"`
	Connect *ConnectSpec `json:"connect,omitempty"` // every action but ActionStatus
}

// ConnectSpec is what the helper needs to enroll.
type ConnectSpec struct {
	// ServerURL must be one the helper's configuration allows.
	ServerURL string `json:"server_url"`
	// Provider is the id of the identity provider that issued Bearer; the
	// helper sends it to the server in Claimward-Provider.
	Provider   string `json:"provider,omitempty"`
	Bearer     string `json:"bearer,omitempty"`
	PrivateKey string `json:"private_key,omitempty"` // device WireGuard private key (base64); ActionConnect only
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

// Tunnel is one live tunnel, to one server.
type Tunnel struct {
	// ServerURL is the server as the helper's configuration spells it.
	ServerURL  string `json:"server_url"`
	ServerName string `json:"server_name,omitempty"`
	Exclusive  bool   `json:"exclusive,omitempty"`
	Interface  string `json:"interface,omitempty"`
	AssignedIP string `json:"assigned_ip,omitempty"`
	Tenant     string `json:"tenant,omitempty"`
	// LeaseExpiresAt is when the server removes the peer unless renewed.
	LeaseExpiresAt *time.Time `json:"lease_expires_at,omitempty"`
}

// Response is returned by the helper.
//
// The lease is the server's: a peer whose lease ends is removed from the
// gateway. The helper renews it while the tunnel is up (pkg/helper).
type Response struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	// ErrorCode is a stable name for the refusals an app tells apart
	// (ErrExclusive, ErrDiscovery); empty for any other error.
	ErrorCode string `json:"error_code,omitempty"`
	// BlockedBy is the name (or URL) of the connected server that stands in
	// the way, with ErrExclusive.
	BlockedBy string `json:"blocked_by,omitempty"`
	// Tunnels are the live tunnels, one per connected server.
	Tunnels []Tunnel `json:"tunnels,omitempty"`
	Tenants []Tenant `json:"tenants,omitempty"`
	// LastErrors is, per server, why the helper last failed to keep its
	// tunnel: a renewal the server refused, a re-enrollment that failed.
	// Cleared by a successful connect to that server.
	LastErrors map[string]string `json:"last_errors,omitempty"`
}
