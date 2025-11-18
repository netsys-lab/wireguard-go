package scion_paths

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/scionproto/scion/pkg/addr"
	daemonpb "github.com/scionproto/scion/pkg/proto/daemon"
	"github.com/scionproto/scion/pkg/segment/iface"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"
)

type SciondRetriever struct {
	client daemonpb.DaemonServiceClient
}

func NewSciondRetriever() (*SciondRetriever, error) {
	daemonAddr := getDaemonAddr()

	// Short timeout for connection to avoid hanging the UI/Tunnel
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := dialGRPC(ctx, daemonAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("connect to daemon (%s): %w", daemonAddr, err)
	}

	client := daemonpb.NewDaemonServiceClient(conn)
	return &SciondRetriever{client: client}, nil
}

// RetrievePaths fetches paths from SCIOND and converts them to snet.Path objects
// ready for the PathPool.
func (r *SciondRetriever) RetrievePaths(ctx context.Context, srcIA, dstIA addr.IA) ([]snet.Path, error) {
	req := &daemonpb.PathsRequest{
		SourceIsdAs:      uint64(srcIA),
		DestinationIsdAs: uint64(dstIA),
		Refresh:          false,
		Hidden:           false,
	}

	resp, err := r.client.Paths(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("sciond paths request error: %w", err)
	}

	paths := make([]snet.Path, 0, len(resp.Paths))

	for _, p := range resp.Paths {
		// 1. Parse Expiration
		var expiry time.Time
		if p.Expiration != nil {
			expiry = p.Expiration.AsTime()
		}

		// 2. Parse Interfaces
		// The Daemon returns interfaces in the correct order for the path
		ifaces := make([]snet.PathInterface, len(p.Interfaces))
		for i, pi := range p.Interfaces {
			// Note: We cast explicitly to snet.PathInterfaceID if available,
			// but since it's undefined in your version, we assume the struct
			// expects the underlying type (usually uint64 or common.IFIDType).
			// We use simple assignment which works if the type is compatible.
			ifaces[i] = snet.PathInterface{
				ID: iface.ID(pi.Id), // If this fails, remove snet.PathInterfaceID cast
				IA: addr.IA(pi.IsdAs),
			}
		}

		// 3. Parse NextHop (Router)
		// The 'Interface' field in the Path struct usually contains the Border Router info.
		var nextHop *net.UDPAddr

		// Check if the Interface field is present (it holds the BR address)
		if p.Interface != nil && p.Interface.Address != nil {
			// The Address field inside Interface is an 'Underlay' struct with an Address string
			nextHop = parseUDPAddr(p.Interface.Address.Address)
		}

		// 4. Construct the snet.Path implementation
		// We use the 'path' package's concrete implementation
		sp := path.Path{
			Src: srcIA,
			Dst: dstIA,
			// Initialize with empty DataplanePath; we set it below
			DataplanePath: path.SCION{Raw: p.Raw},
			NextHop:       nextHop,
			Meta: snet.PathMetadata{
				Interfaces: ifaces,
				MTU:        uint16(p.Mtu),
				Expiry:     expiry,
			},
		}

		// 5. Verify Dataplane Path
		if len(p.Raw) == 0 {
			continue
		}

		paths = append(paths, sp)
	}

	return paths, nil
}

// parseUDPAddr parses the address string returned by SCIOND
func parseUDPAddr(s string) *net.UDPAddr {
	if addr, err := net.ResolveUDPAddr("udp", s); err == nil {
		return addr
	}
	return nil
}

// helpers from your script (Unchanged)
func getDaemonAddr() string {
	if v := os.Getenv("SCION_DAEMON_ADDRESS"); v != "" {
		return v
	}
	const defaultSock = "/run/shm/sciond/default.sock"
	if _, err := os.Stat(defaultSock); err == nil {
		return "unix://" + defaultSock
	}
	return "127.0.0.12:30255"
}

func dialGRPC(ctx context.Context, target string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	if strings.HasPrefix(target, "unix://") {
		dialer := func(ctx context.Context, addr string) (net.Conn, error) {
			addr = strings.TrimPrefix(addr, "unix://")
			addr = strings.TrimPrefix(addr, "unix:")
			return (&net.Dialer{}).DialContext(ctx, "unix", addr)
		}
		opts = append(opts, grpc.WithContextDialer(dialer))
	}
	return grpc.DialContext(ctx, target, opts...)
}
