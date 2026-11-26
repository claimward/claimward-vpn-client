package wgtun

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"strings"
)

// Interface names. One tunnel per server means one interface per server, and
// the name has to be the same every time for the same server (so that a
// crashed helper's leftover is found and replaced rather than piling up) and
// different for different servers (so that two tunnels can be up at once).
// The name is derived from the key, a hash, so that whatever a server's URL
// looks like it fits the platform's bound and carries nothing the server
// chose into a command line.

// linuxIfNameMax is IFNAMSIZ-1: the kernel refuses a longer name.
const linuxIfNameMax = 15

// linuxIfName is "cw-" and ten hex digits of the key's SHA-256: 13 bytes.
func linuxIfName(key string) string {
	sum := sha256.Sum256([]byte(key))
	return "cw-" + hex.EncodeToString(sum[:])[:10]
}

// windowsHostMax bounds the readable part of an adapter's name.
const windowsHostMax = 40

// windowsAdapterName is what Windows shows the person in its network
// settings: "Claimward <host> <6 hex>". The host is only for reading
// (restricted to letters, digits, '.' and '-'); the hash makes the name
// unique per key.
func windowsAdapterName(key string) string {
	host := key
	if u, err := url.Parse(key); err == nil && u.Hostname() != "" {
		host = u.Hostname()
	}
	var b strings.Builder
	for _, r := range host {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
		if b.Len() >= windowsHostMax {
			break
		}
	}
	sum := sha256.Sum256([]byte(key))
	if b.Len() == 0 {
		return "Claimward " + hex.EncodeToString(sum[:])[:6]
	}
	return "Claimward " + b.String() + " " + hex.EncodeToString(sum[:])[:6]
}
