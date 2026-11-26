// Package exclusive is the one rule about sharing a machine between servers: a
// server whose discovery document says "exclusive" refuses to be connected
// beside any other, and any other refuses to be connected beside it. It is
// applied twice, by the app (pkg/appcore) to refuse early with a reason, and
// by the privileged helper (pkg/helper), which does not trust the app.
//
// There is no routing policy: two non-exclusive servers may be connected at
// once, and what each one routes is its own business.
package exclusive

import "fmt"

// Member is a server, connected or about to be.
type Member struct {
	// URL is the server's canonical URL (secureurl.Canonical).
	URL string
	// Name is its display name (server_name), possibly empty.
	Name string
	// Exclusive is the server's own claim.
	Exclusive bool
}

// Label is what a person is told to call the server: its name, or its URL.
func (m Member) Label() string {
	if m.Name != "" {
		return m.Name
	}
	return m.URL
}

// Error is a refusal. It says which server is refused, which one blocks it,
// and which of the two is the exclusive one.
type Error struct {
	// Server is the server that was refused.
	Server Member
	// Blocker is the connected server that stands in the way.
	Blocker Member
	// Reason, when set, is the text the refusing party gave (the helper's);
	// it replaces the one built from the two members.
	Reason string
}

func (e *Error) Error() string {
	if e.Reason != "" {
		return e.Reason
	}
	if e.Server.Exclusive {
		return fmt.Sprintf("%s is exclusive and cannot be connected while %s is connected: disconnect %s first",
			e.Server.Label(), e.Blocker.Label(), e.Blocker.Label())
	}
	return fmt.Sprintf("%s is exclusive and is connected: it refuses any other server, disconnect %s first",
		e.Blocker.Label(), e.Blocker.Label())
}

// BlockedBy is the name (or URL) of the server in the way.
func (e *Error) BlockedBy() string { return e.Blocker.Label() }

// Check says whether target may be connected while connected are. A server
// already in connected is not its own blocker. It returns an *Error, or nil.
func Check(target Member, connected []Member) error {
	for _, c := range connected {
		if c.URL == target.URL {
			continue
		}
		if target.Exclusive || c.Exclusive {
			return &Error{Server: target, Blocker: c}
		}
	}
	return nil
}
