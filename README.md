# claimward-vpn-client

[![Go Reference](https://pkg.go.dev/badge/github.com/claimward/claimward-vpn-client.svg)](https://pkg.go.dev/github.com/claimward/claimward-vpn-client) [![Go Report Card](https://goreportcard.com/badge/github.com/claimward/claimward-vpn-client)](https://goreportcard.com/report/github.com/claimward/claimward-vpn-client) [![License: BSD-3-Clause](https://img.shields.io/badge/License-BSD--3--Clause-blue.svg)](LICENSE)

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
| `pkg/auth` | Interactive sign-in behind a pluggable `Provider`: **GitHub** device-authorization flow (default) or **OIDC** Authorization Code + PKCE. Returns the bearer `Token` sent to the server |
| `pkg/oidc` | The OIDC Authorization Code + PKCE flow (issuer discovery, loopback redirect capture) used by the `oidc` auth provider |
| `pkg/browser` | Opens a URL in the user's default browser using absolute opener paths, so it works from GUI apps launched by LaunchServices |
| `pkg/client` | High-level client: `Enroll`/`Heartbeat`/`Deregister`/`Tenants` against the server, plus `TunnelConfig` to turn an `EnrollResponse` into a `wgtun.Config` |
| `pkg/wgkey` | WireGuard key generation / parsing |
| `pkg/wgtun` | Userspace WireGuard tunnel via `wireguard-go` (+ darwin/linux interface & route setup); needs elevated privileges |
| `pkg/routeclient` | Watches the server's RouteService (gRPC) and reports live route updates without re-enrolling |
| `pkg/routespb` | Generated gRPC/protobuf stubs for the RouteService (shared with the server) |
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
