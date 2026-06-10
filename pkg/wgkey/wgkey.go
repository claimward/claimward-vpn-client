// Package wgkey is a thin helper around WireGuard key generation and parsing,
// shared by the CLI, the platform apps and (for the server's public key) the
// enrollment flow.
package wgkey

import "golang.zx2c4.com/wireguard/wgctrl/wgtypes"

// Pair is a WireGuard private/public key pair.
type Pair struct {
	Private wgtypes.Key
	Public  wgtypes.Key
}

// Generate creates a fresh Curve25519 key pair.
func Generate() (Pair, error) {
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return Pair{}, err
	}
	return Pair{Private: priv, Public: priv.PublicKey()}, nil
}

// ParsePrivate decodes a base64 private key and derives its public key.
func ParsePrivate(b64 string) (Pair, error) {
	priv, err := wgtypes.ParseKey(b64)
	if err != nil {
		return Pair{}, err
	}
	return Pair{Private: priv, Public: priv.PublicKey()}, nil
}

// ParsePublic decodes a base64 public key.
func ParsePublic(b64 string) (wgtypes.Key, error) {
	return wgtypes.ParseKey(b64)
}
