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
	// ActionApprove asks the helper to trust the server ConnectSpec.ServerURL
	// names. The helper reads the server's discovery document, then obtains a
	// SYSTEM authorization itself (polkit on Linux; Authorization Services on
	// macOS, from ConnectSpec.Authorization; a connection on the elevated
	// socket on Windows) before it remembers the server. An app cannot
	// approve by saying so: nothing in the request counts as consent but what
	// the operating system vouches for.
	ActionApprove = "approve"
	// ActionRevoke makes the helper forget an approved server, and take its
	// tunnel down. It only narrows what the helper trusts, so it needs no
	// authorization. A server the administrator's configuration names cannot
	// be revoked from here.
	ActionRevoke = "revoke"
	// ActionApproved lists the servers the helper trusts, as Response.Approved.
	ActionApproved = "approved"
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
	// ErrNotApproved: the server is neither in the administrator's
	// configuration nor approved. The app answers with ActionApprove, which
	// asks the person for the system's consent, and tries again.
	ErrNotApproved = "server_not_approved"
	// ErrIdentityChanged: the server was approved, but what it now says it is
	// (its name and identity providers) differs from what was approved. It
	// must be approved again.
	ErrIdentityChanged = "server_identity_changed"
	// ErrApprovalDenied: the system's consent was refused, dismissed or
	// unavailable.
	ErrApprovalDenied = "approval_denied"
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
	// Authorization is, with ActionApprove on macOS, the 32 bytes of an
	// AuthorizationExternalForm the app obtained for the right
	// "com.claimward.helper.approve-server". It is not a claim: the helper
	// hands it to Authorization Services, which says whether the right was
	// granted. Ignored on the other platforms.
	Authorization []byte `json:"authorization,omitempty"`
}

// Approved is one server the helper trusts.
type Approved struct {
	ServerURL  string    `json:"server_url"`
	ServerName string    `json:"server_name,omitempty"`
	ApprovedAt time.Time `json:"approved_at,omitzero"`
	// Admin: named in the administrator's configuration; it cannot be revoked
	// through the socket.
	Admin bool `json:"admin,omitempty"`
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

	// What follows is read-only status of the tunnel; no key is among it.
	// Endpoint is the peer's host:port, AllowedIPs the CIDRs routed into the
	// tunnel (they change with a route push), DNS the servers the server
	// assigned and MTU the interface's.
	Endpoint   string   `json:"endpoint,omitempty"`
	AllowedIPs []string `json:"allowed_ips,omitempty"`
	DNS        []string `json:"dns,omitempty"`
	MTU        int      `json:"mtu,omitempty"`
	// RxBytes is what this device has received from the peer and TxBytes what
	// it has sent, since the tunnel came up, as the device counts them.
	RxBytes uint64 `json:"rx_bytes"`
	TxBytes uint64 `json:"tx_bytes"`
	// LastHandshake is the last completed handshake with the peer; absent
	// until there has been one.
	LastHandshake *time.Time `json:"last_handshake,omitempty"`
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
	// Approved are the servers the helper trusts (ActionApproved, and the
	// answer to ActionApprove and ActionRevoke).
	Approved []Approved `json:"approved,omitempty"`
	// LastErrors is, per server, why the helper last failed to keep its
	// tunnel: a renewal the server refused, a re-enrollment that failed.
	// Cleared by a successful connect to that server.
	LastErrors map[string]string `json:"last_errors,omitempty"`
}
