# claimward-vpn-client

Shared Go client core **and** the cross-platform CLI for the Claimward VPN.

This module is imported by [`claimward-vpn-server`](https://github.com/claimward/claimward-vpn-server)
(for the wire protocol types) and by the platform apps
([`claimward-vpn-app-osx`](https://github.com/claimward/claimward-vpn-app-osx), `-linux`, `-windows`).

## What's in here

| Package | Purpose |
|---------|---------|
| `pkg/protocol` | Wire contract (`/enroll`, `/heartbeat`, `/deregister`) — the single source of truth shared with the server |
| `pkg/oidc` | OIDC Authorization Code + PKCE browser login against any compliant issuer (discovery) |
| `pkg/wgkey` | WireGuard key generation / parsing |
| `pkg/wgtun` | Userspace WireGuard tunnel via `wireguard-go` (+ darwin/linux interface & route setup) |
| `pkg/client` | High-level client: enroll → `wgtun.Config` |
| `pkg/tokenstore` | 0600 on-disk session store (OIDC tokens + device key) |
| `cmd/claimward` | The CLI |

## Architecture (end to end)

```
app / CLI  --OIDC PKCE-->  IdP            (browser login → id_token)
app / CLI  --POST /enroll (Bearer id_token, wg pubkey)-->  server
server     --wgctrl-->  wg0 kernel iface  (adds peer, allocates IP)
app / CLI  <--assigned IP, server pubkey, endpoint, routes--  server
app / CLI  --wireguard-go-->  utunN       (tunnel up)
```

## CLI usage

```sh
go build -o bin/claimward ./cmd/claimward

export CLAIMWARD_SERVER=https://vpn.example.com
export CLAIMWARD_OIDC_ISSUER=https://accounts.google.com   # or Keycloak/Okta/Entra…
export CLAIMWARD_OIDC_CLIENT_ID=xxxx.apps.example.com

claimward login            # browser OIDC login (no root)
sudo -E claimward connect  # enroll + bring up tunnel (root; -E keeps env)
claimward status
claimward logout
```

`connect` runs in the foreground and tears the tunnel down (and deregisters the
peer) on Ctrl-C.

## Notes / MVP scope

- The session store is a 0600 JSON file under `$XDG_CONFIG_HOME/claimward`. The
  macOS app graduates this to the Keychain.
- DNS push from the server is carried in the protocol but not yet applied by
  `wgtun` — TODO.
- `wgtun` implements macOS and Linux; Windows lives in the app repo.
