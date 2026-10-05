// Package routeclient watches the server's RouteService over gRPC and reports
// route updates, so a connected client can apply gateway route changes live
// without re-enrolling.
package routeclient

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"github.com/claimward/claimward-vpn-client/pkg/routespb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// Update is a route set pushed by the server.
type Update struct {
	AllowedIPs []string
	DNS        []string
	Serial     uint64
}

// Watch connects to the gRPC endpoint, authenticates with the bearer token, and
// calls onUpdate for the initial route set and every subsequent change, until
// ctx is cancelled or the stream fails (the returned error is then non-nil).
//
// ⛔ The bearer token travels in the stream's metadata, so the transport is
// TLS, checked against the system's roots -- except to a loopback address,
// which has no link to listen on. It used to be plaintext everywhere: every
// route watch sent the person's token in the clear. Against a server that
// does not speak TLS the handshake fails before any metadata is sent; the
// tunnel stays up, without live route updates.
func Watch(ctx context.Context, endpoint, bearer, publicKey string, onUpdate func(Update)) error {
	creds, err := transport(endpoint)
	if err != nil {
		return err
	}
	conn, err := grpc.NewClient(endpoint, grpc.WithTransportCredentials(creds))
	if err != nil {
		return fmt.Errorf("dial gRPC %s: %w", endpoint, err)
	}
	defer conn.Close()

	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+bearer)
	stream, err := routespb.NewRouteServiceClient(conn).Watch(ctx, &routespb.WatchRequest{PublicKey: publicKey})
	if err != nil {
		return fmt.Errorf("watch routes: %w", err)
	}
	for {
		u, err := stream.Recv()
		if err != nil {
			return err
		}
		onUpdate(Update{AllowedIPs: u.GetAllowedIps(), DNS: u.GetDns(), Serial: u.GetSerial()})
	}
}

// transport is TLS for the endpoint's host, or plaintext for loopback.
func transport(endpoint string) (credentials.TransportCredentials, error) {
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, fmt.Errorf("gRPC endpoint %q: %w", endpoint, err)
	}
	if ip := net.ParseIP(host); (ip != nil && ip.IsLoopback()) || host == "localhost" {
		return insecure.NewCredentials(), nil
	}
	return credentials.NewTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}), nil
}
