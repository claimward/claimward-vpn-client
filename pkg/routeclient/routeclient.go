// Package routeclient watches the server's RouteService over gRPC and reports
// route updates, so a connected client can apply gateway route changes live
// without re-enrolling.
package routeclient

import (
	"context"
	"fmt"

	"github.com/claimward/claimward-vpn-client/pkg/routespb"
	"google.golang.org/grpc"
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
// Transport is plaintext (h2c) for now — run gRPC behind TLS in production.
func Watch(ctx context.Context, endpoint, bearer, publicKey string, onUpdate func(Update)) error {
	conn, err := grpc.NewClient(endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
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
