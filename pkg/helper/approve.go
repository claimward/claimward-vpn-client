package helper

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/claimward/claimward-vpn-client/pkg/hproto"
	"github.com/claimward/claimward-vpn-client/pkg/secureurl"
)

// approveTimeout is how long the person has to answer the system's prompt.
const approveTimeout = 3 * time.Minute

// approve is ActionApprove: read what the server says it is, obtain the
// system's consent to trusting it, and remember it.
//
// ⛔ Nothing in spec is consent. The server URL is what is asked about; what
// answers is the Authorizer, which asks the operating system (and, on macOS,
// hands it the app's credential for it to judge).
func (s *Server) approve(conn net.Conn, elevated bool, spec *hproto.ConnectSpec) hproto.Response {
	if spec == nil || spec.ServerURL == "" {
		return hproto.Response{Error: "missing server"}
	}
	server, err := secureurl.Canonical(spec.ServerURL)
	if err != nil {
		return hproto.Response{Error: fmt.Sprintf("server %q: %v", spec.ServerURL, err)}
	}
	if s.adminServer(server) {
		return s.approvedList() // already trusted: nothing to ask
	}
	// One prompt at a time: a process that asks in a loop is refused, not
	// queued behind the person's patience.
	if !s.approving.TryLock() {
		return hproto.Response{Error: "an approval is already waiting for the person's answer", ErrorCode: hproto.ErrApprovalDenied}
	}
	defer s.approving.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), approveTimeout)
	defer cancel()
	dctx, dcancel := context.WithTimeout(ctx, s.enrollTimeout)
	doc, err := s.discover(dctx, server)
	dcancel()
	if err == nil && doc == nil {
		err = errors.New("empty answer")
	}
	if err != nil {
		return hproto.Response{Error: "discovery: " + err.Error(), ErrorCode: hproto.ErrDiscovery}
	}
	if s.authz == nil {
		return hproto.Response{Error: "no way to obtain the system's authorization on this platform", ErrorCode: hproto.ErrApprovalDenied}
	}
	if err := s.authz.Authorize(ctx, Approval{
		Server: server, Name: doc.ServerName, Peer: conn, Elevated: elevated, Credential: spec.Authorization,
	}); err != nil {
		s.log.Warn("server approval refused", "server", server, "err", err)
		return hproto.Response{Error: "approval refused: " + err.Error(), ErrorCode: hproto.ErrApprovalDenied}
	}
	if err := s.approvals.add(approvedEntry{URL: server, Identity: Identity(doc), Name: doc.ServerName, ApprovedAt: time.Now().UTC()}); err != nil {
		return hproto.Response{Error: "remember the approval: " + err.Error()}
	}
	s.log.Info("server approved", "server", server, "name", doc.ServerName, "identity", Identity(doc))
	return s.approvedList()
}

// revoke is ActionRevoke: forget an approved server and take down its tunnel.
//
// ⛔ Taking down a tunnel is a disconnect: another user's tunnel is not the
// caller's to take down, so a revocation that would do it is refused (an
// administrator may).
func (s *Server) revokeAs(p Peer, spec *hproto.ConnectSpec) hproto.Response {
	if spec == nil || spec.ServerURL == "" {
		return hproto.Response{Error: "missing server"}
	}
	server, err := secureurl.Canonical(spec.ServerURL)
	if err != nil {
		return hproto.Response{Error: fmt.Sprintf("server %q: %v", spec.ServerURL, err)}
	}
	s.mu.Lock()
	if cur := s.sessions[server]; cur != nil && !p.sees(cur.owner) {
		s.mu.Unlock()
		return notOwner()
	}
	s.mu.Unlock()
	if s.adminServer(server) {
		return hproto.Response{Error: fmt.Sprintf("server %q is approved by the administrator's configuration; remove it there", spec.ServerURL)}
	}
	if _, err := s.approvals.remove(server); err != nil {
		return hproto.Response{Error: "forget the approval: " + err.Error()}
	}
	s.mu.Lock()
	old := s.stopLocked(server)
	s.clearErrLocked(server)
	s.mu.Unlock()
	if old != nil {
		s.deregister(old)
	}
	s.log.Info("server approval revoked", "server", server)
	return s.approvedList()
}

// approvedList is ActionApproved: the servers the helper trusts.
func (s *Server) approvedList() hproto.Response {
	resp := hproto.Response{OK: true}
	for _, u := range s.cfg.Servers {
		if c, err := secureurl.Canonical(u); err == nil {
			resp.Approved = append(resp.Approved, hproto.Approved{ServerURL: c, Admin: true})
		}
	}
	es, err := s.approvals.list()
	if err != nil {
		return hproto.Response{Error: "approved servers: " + err.Error()}
	}
	for _, e := range es {
		resp.Approved = append(resp.Approved, hproto.Approved{ServerURL: e.URL, ServerName: e.Name, ApprovedAt: e.ApprovedAt})
	}
	slices.SortStableFunc(resp.Approved, func(a, b hproto.Approved) int { return strings.Compare(a.ServerURL, b.ServerURL) })
	return resp
}
