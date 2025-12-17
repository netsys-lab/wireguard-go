package daemon

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
	client daemonpb.DaemonServiceClient // sciond grpc client
}

func NewSciondRetriever() (*SciondRetriever, error) {
	daemonAddr := getDaemonAddr()

	// dont block forever
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := dialGRPC(ctx, daemonAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("connect to daemon (%s): %w", daemonAddr, err)
	}

	return &SciondRetriever{
		client: daemonpb.NewDaemonServiceClient(conn),
	}, nil
}

// get paths from sciond
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
		var expiry time.Time
		if p.Expiration != nil {
			expiry = p.Expiration.AsTime()
		}

		// interfaces in order
		ifaces := make([]snet.PathInterface, len(p.Interfaces))
		for i, pi := range p.Interfaces {
			ifaces[i] = snet.PathInterface{
				ID: iface.ID(pi.Id),
				IA: addr.IA(pi.IsdAs),
			}
		}

		var nextHop *net.UDPAddr
		if p.Interface != nil && p.Interface.Address != nil {
			nextHop = parseUDPAddr(p.Interface.Address.Address)
		}

		// no raw path -> useless
		if len(p.Raw) == 0 {
			continue
		}

		sp := path.Path{
			Src: srcIA,
			Dst: dstIA,
			DataplanePath: path.SCION{
				Raw: p.Raw,
			},
			NextHop: nextHop,
			Meta: snet.PathMetadata{
				Interfaces: ifaces,
				MTU:        uint16(p.Mtu),
				Expiry:     expiry,
			},
		}

		paths = append(paths, sp)
	}

	return paths, nil
}

// best effort parse
func parseUDPAddr(s string) *net.UDPAddr {
	if addr, err := net.ResolveUDPAddr("udp", s); err == nil {
		return addr
	}
	return nil
}

// daemon addr lookup
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

// grpc dial helper
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
