package helper

import "net"

// Peer is who is on the other end of a connection to the helper's socket, as
// the operating system says -- never as the request says.
//
// ⛔ It is what decides whose tunnels a connection may see and act on: a
// tunnel belongs to the Peer that connected it (Peer.ID), and Admin sees and
// acts on all of them. Nothing in hproto.Request takes part.
type Peer struct {
	// ID is the caller's identity: "uid:<n>" on Unix (SO_PEERCRED,
	// LOCAL_PEERCRED), the token user's SID on Windows. A caller the system
	// cannot identify is refused by the server (hproto.ErrCallerUnidentified),
	// never given an empty ID that would pool it with others.
	ID string
	// Admin is root (uid 0) on Unix, SYSTEM or an elevated Administrator on
	// Windows, or any caller of the elevated socket.
	Admin bool
}

// PeerSource tells who is on the other end of conn. It is read from the
// kernel; tests replace it (UsePeerCredentials) with a fake.
type PeerSource func(conn net.Conn) (Peer, error)

// UsePeerCredentials replaces how the caller is identified
// (DefaultPeerSource by default): for tests.
func (s *Server) UsePeerCredentials(f PeerSource) { s.peers = f }

// sees says whether p may see, and act on, a tunnel owner owns.
func (p Peer) sees(owner string) bool { return p.Admin || p.ID == owner }
