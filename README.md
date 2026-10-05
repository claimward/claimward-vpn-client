# claimward-vpn-client


The shared Go **client library** for the Claimward VPN: sign-in, the enrollment
wire protocol, the userspace WireGuard tunnel, and the live route-push client.

This module ships **no binary**. It is imported by:

- [`claimward-vpn-server`](https://github.com/claimward/claimward-vpn-server) — for the shared wire types (`pkg/protocol`) and gRPC route stubs (`pkg/routespb`);
- the platform apps — [`claimward-vpn-app-osx`](https://github.com/claimward/claimward-vpn-app-osx) (`cmd/claimward-app` + the privileged `cmd/claimward-helper`), and the `-linux` / `-windows` apps — which own the actual runnable binaries.

Looking for something to run? Build one of the app repos above; this repo is the
library they share.

## Packages

| Package | Purpose |
|---------|---------|
| `pkg/protocol` | Wire contract (`/enroll`, `/heartbeat`, `/deregister`) — the single source of truth shared with the server |
| `pkg/auth` | Interactive sign-in behind a pluggable `Provider`: **GitHub** device-authorization flow (default), **OIDC** Authorization Code + PKCE, or **go-authn** device flow, whose provider also registers the device's WireGuard key (`KeyRegistrar`). Returns the bearer `Token` sent to the server |
| `pkg/oidc` | The OIDC Authorization Code + PKCE flow (issuer discovery, loopback redirect capture) used by the `oidc` auth provider |
| `pkg/browser` | Opens a URL in the user's default browser using absolute opener paths, so it works from GUI apps launched by LaunchServices |
| `pkg/client` | High-level client: `Enroll`/`Heartbeat`/`Deregister`/`Tenants` against the server, plus `TunnelConfig` to turn an `EnrollResponse` into a `wgtun.Config` |
| `pkg/wgkey` | WireGuard key generation / parsing |
| `pkg/wgtun` | Userspace WireGuard tunnel via `wireguard-go` (+ darwin/linux interface & route setup); needs elevated privileges |
| `pkg/routeclient` | Watches the server's RouteService (gRPC) and reports live route updates without re-enrolling |
| `pkg/routespb` | Generated gRPC/protobuf stubs for the RouteService (shared with the server) |
| `pkg/appcore` | The app's business logic, shared by the macOS, Linux and Windows apps: sign-in, the **tenant chosen for the session**, connect/disconnect through the helper, status for the UI |
| `pkg/helper` | The privileged helper (root / SYSTEM), shared by the three apps: enrolls, owns the tunnel, watches route pushes. Each app's helper binary is a `main` that loads its configuration and listens |
| `pkg/hproto`, `pkg/helperclient` | The helper's socket protocol and the app's client for it |
| `pkg/tokenstore` | 0600 on-disk session store (auth tokens + device key); the macOS app graduates this to the Keychain |

## Architecture (end to end)

```
app  --auth Provider-->  IdP              (GitHub device flow / OIDC PKCE → bearer token)
app  --POST /enroll (Bearer token, wg pubkey)-->  server
server  --wgctrl-->  wg0 kernel iface     (adds peer, allocates IP)
app  <--assigned IP, server pubkey, endpoint, routes--  server
app  --wireguard-go-->  utunN             (tunnel up)
app  --gRPC RouteService.Watch-->  server (optional: live route updates)
```

## Library usage

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/claimward/claimward-vpn-client/pkg/auth"
	"github.com/claimward/claimward-vpn-client/pkg/client"
	"github.com/claimward/claimward-vpn-client/pkg/protocol"
	"github.com/claimward/claimward-vpn-client/pkg/routeclient"
	"github.com/claimward/claimward-vpn-client/pkg/wgkey"
)

func main() {
	ctx := context.Background()

	// 1. Interactive sign-in. Default provider is GitHub (device flow); set
	//    Provider "oidc" with OIDCIssuer/OIDCClientID for an OIDC issuer.
	provider, err := auth.New(auth.Config{
		Provider:       "github",
		GitHubClientID: "Iv1.0123456789abcdef",
	})
	if err != nil {
		log.Fatal(err)
	}
	tok, err := provider.Login(ctx, func(p auth.DevicePrompt) {
		fmt.Printf("visit %s and enter code %s\n", p.VerificationURI, p.UserCode)
	})
	if err != nil {
		log.Fatal(err)
	}

	// 2. Generate a WireGuard keypair and enroll with the server.
	keys, err := wgkey.Generate()
	if err != nil {
		log.Fatal(err)
	}
	// With go-authn, the PUBLIC key is registered at the provider first, and
	// the token for the server is the one RegisterKey returns. Keep its
	// Refresh: the provider rotates refresh tokens.
	if reg, ok := provider.(auth.KeyRegistrar); ok {
		if tok, err = reg.RegisterKey(ctx, tok, keys.Public.String(), "laptop"); err != nil {
			log.Fatal(err)
		}
	}
	c := client.New("https://vpn.example.com")
	resp, err := c.Enroll(ctx, tok.Value, keys.Public,
		protocol.DeviceInfo{Name: "laptop", OS: "darwin", Platform: "cli"}, "")
	if err != nil {
		log.Fatal(err)
	}

	// 3. Turn the enrollment response into a tunnel config. Bring it up with
	//    pkg/wgtun (wgtun.Up), which needs elevated privileges.
	tun, err := client.TunnelConfig(resp, keys.Private)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("tunnel address:", tun.Address)

	// 4. Optionally watch the server for live route changes over gRPC.
	if resp.GRPCEndpoint != "" {
		go routeclient.Watch(ctx, resp.GRPCEndpoint, tok.Value, keys.Public.String(),
			func(u routeclient.Update) {
				fmt.Println("routes updated:", u.AllowedIPs)
			})
	}
}
```

## With go-authn

`Provider: "go-authn"`, with `OIDCIssuer` and `OIDCClientID`, signs in at a
[go-authn](https://github.com/go-authn/bridge) provider: an OpenID Connect
provider in front of a SAML federation such as RENATER or eduGAIN, which also
keeps **whose each WireGuard key is**. claimward-vpn-server then enrolls a key
only if its owner registered it there (`AUTH_PROVIDER=go-authn` on the
server). The flow is:

1. `Login`: the device flow, scope `openid wireguard`. The token opens the
   provider's key registry and nothing else; a go-authn provider addresses
   such a token to itself alone;
2. `RegisterKey` (the `KeyRegistrar` interface):
   - registers the device's **public** key (`POST /wireguard/key`), renewing it
     when it is already the person's;
   - then refreshes asking for `openid` alone (RFC 6749 §6), which gives the
     token for claimward-vpn-server;
   - when the sign-in token has lapsed, it first refreshes with no scope, which
     asks for everything granted;
   - it returns the rotated refresh token, which replaces the old one, since
     the old one is spent;
3. `Enroll` with that token.

The private key never leaves the device. The provider's client needs
`wireguard_keys = true` and a `refresh_lifetime`.

## The privileged helper

The helper runs as root (or SYSTEM). Any process that can reach its socket can
make it act, so what it does is bounded by **its own** configuration, never by
the request:

- **It enrolls only with a server its configuration names.** A helper that
  took the server from the request would let any local process point it at a
  server of its own, answering with routes for `0.0.0.0/0`: every packet of
  the machine, sent where that process chose.
- **It takes no tunnel configuration from a request.** The tunnel is what that
  server answered. The earlier `up` and `update-routes` actions, which took
  one, are gone.
- **Its socket is `0660`**, owned by root and one group (`admin` on macOS,
  `claimward` on Linux), in a directory only root can write. The earlier
  helper's socket was `0666`.
- **Its configuration must be root's**, and writable by root alone, or the
  helper does not start.

```json
{
  "servers": ["https://vpn.example.org"],
  "group": "claimward"
}
```

A route watch (`pkg/routeclient`) carries the bearer token, so it runs over
**TLS** except to a loopback address. Against a server whose gRPC is not TLS,
the handshake fails before the token is sent, and the tunnel stays up
without live route updates.

## Tenants

A person may belong to several tenants and chooses one per session.
`appcore.Core`:
- **`Tenants`** asks the server, through the helper, which tenants the person
  may join;
- **`SetTenant`** records the choice in the session; a new sign-in forgets it;
- **`Connect`** enrolls into that tenant. A person in several who has not
  chosen gets `ErrTenantRequired`, with the tenants in `Status()`.

## Notes

- The session store (`pkg/tokenstore`) is a 0600 JSON file under the user's
  config dir. The macOS app graduates this to the Keychain.
- Creating the tun device and changing routes (`pkg/wgtun`) require elevated
  privileges; the macOS app delegates this to its privileged helper.
- `pkg/wgtun` implements macOS and Linux; Windows lives in the app repo.
- DNS push from the server is carried in the protocol but not yet applied by
  `wgtun` — TODO.

## License

BSD 3-Clause — see [LICENSE](LICENSE).
