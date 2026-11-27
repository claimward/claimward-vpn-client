package helper

import (
	"github.com/claimward/claimward-vpn-client/pkg/exclusive"
	"github.com/claimward/claimward-vpn-client/pkg/hproto"
)

// The tests that predate ownership call the helper's actions directly, as an
// administrator: they are about what the actions do, not about who may ask.
// owner_test.go is about who.

var rootPeer = Peer{ID: "uid:0", Admin: true}

func (s *Server) connect(spec *hproto.ConnectSpec) hproto.Response {
	return s.connectAs(rootPeer, spec)
}
func (s *Server) status() hproto.Response                       { return s.statusFor(rootPeer) }
func (s *Server) down(spec *hproto.ConnectSpec) hproto.Response { return s.downAs(rootPeer, spec) }
func (s *Server) renewNow(spec *hproto.ConnectSpec) hproto.Response {
	return s.renewAs(rootPeer, spec)
}
func (s *Server) revoke(spec *hproto.ConnectSpec) hproto.Response { return s.revokeAs(rootPeer, spec) }
func (s *Server) enroll(spec *hproto.ConnectSpec, gen uint64, m *exclusive.Member) hproto.Response {
	return s.enrollAs(rootPeer, spec, gen, m)
}
