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
	PathTenants    = "/api/v1/tenants"
	PathHealthz    = "/healthz"

	// PathWellKnownConfiguration is the public discovery document (RFC 8615 §3:
	// a single-segment name under /.well-known/, at the root of the path).
	PathWellKnownConfiguration = "/.well-known/claimward-configuration"
)

// HeaderProvider names, on every authenticated request, the identity provider
// that issued the bearer token: its Provider.ID from the discovery document.
// The server verifies the token with that provider only. gRPC carries it in
// the metadata key MetadataProvider.
const (
	HeaderProvider   = "Claimward-Provider"
	MetadataProvider = "claimward-provider" // gRPC metadata keys are lower case
)

// ValidProviderID reports whether s can be a Provider.ID: 1 to 64 bytes of
// ASCII letters, digits, '.', '_', '~' and '-' (url-safe). A client sends the
// id in a header and keys its stored session by it, so it accepts nothing else.
func ValidProviderID(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '_', c == '~', c == '-':
		default:
			return false
		}
	}
	return true
}

// Error codes of a 401 that concerns the provider (ErrorResponse.Error).
const (
	ErrMissingProvider = "missing_provider"
	ErrUnknownProvider = "unknown_provider"
)

// Provider kinds.
const (
	KindGitHub  = "github"
	KindOIDC    = "oidc"
	KindGoAuthn = "go-authn"
)

// ConfigurationVersion is the version of the discovery document's shape.
// Version 2 replaced the single provider by a list.
const ConfigurationVersion = 2

// Configuration is the public discovery document served, unauthenticated, at
// PathWellKnownConfiguration. It holds public values only: never a secret.
// The server decides which identity providers it accepts; a client needs only
// the server's URL.
//
// Like RFC 8414 §3.2, a claim without a value is omitted, not sent empty.
type Configuration struct {
	// Version is ConfigurationVersion at the time the server was built.
	Version int `json:"version"`
	// ServerName is the operator's display name for the server (optional).
	ServerName string `json:"server_name,omitempty"`
	// Providers are the identity providers the server accepts, in the order the
	// operator listed them; the person picks one to sign in with.
	Providers []Provider `json:"providers"`
	// Exclusive: this server refuses to share the machine with other Claimward
	// tunnels. Clients refuse to connect it alongside others, and refuse others
	// while it is connected.
	Exclusive bool `json:"exclusive"`
	// Logo is the server's logo, present only when the operator configured one.
	Logo *Logo `json:"logo,omitempty"`
}

// PathWellKnownLogo is where the server's SVG logo is served.
const PathWellKnownLogo = "/.well-known/claimward-logo.svg"

// Logo says where the server's SVG logo is and what it must hash to. A client
// fetches Path from the SAME origin as the discovery document (never another
// host), checks the SHA-256, and validates the image with pkg/svgsafe before
// showing it.
type Logo struct {
	// Path is a path on the server, PathWellKnownLogo.
	Path string `json:"path"`
	// SHA256 is the lower-case hex SHA-256 of the SVG's bytes.
	SHA256 string `json:"sha256"`
}

// Provider is one identity provider a server accepts.
type Provider struct {
	// ID is stable and url-safe; it is what HeaderProvider carries.
	ID string `json:"id"`
	// Kind is KindGitHub, KindOIDC or KindGoAuthn.
	Kind string `json:"kind"`
	// Name is the display name to show on the sign-in choice, e.g. "GitHub".
	Name string `json:"name"`
	// GitHubClientID is the public client ID of the server's GitHub OAuth app
	// (kind "github").
	GitHubClientID string `json:"github_client_id,omitempty"`
	// OIDCIssuer and OIDCClientID identify the OIDC provider (kinds "oidc" and
	// "go-authn").
	OIDCIssuer   string `json:"oidc_issuer,omitempty"`
	OIDCClientID string `json:"oidc_client_id,omitempty"`
}

// TenantInfo identifies a tenant the authenticated user may connect to.
type TenantInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// EnrollRequest is sent by a client to obtain a WireGuard tunnel configuration.
//
// The OIDC ID token is passed in the HTTP Authorization header as a bearer
// token ("Authorization: Bearer <id_token>"), never in the body.
type EnrollRequest struct {
	// PublicKey is the client's WireGuard public key in standard wg base64 encoding.
	PublicKey string `json:"public_key"`
	// Device describes the enrolling device, for audit and display in the admin UI.
	Device DeviceInfo `json:"device"`
	// Tenant is the ID of the tenant the user chose to connect to. The user must
	// be a member of it. Empty lets the server pick when the user has exactly one.
	Tenant string `json:"tenant,omitempty"`
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
