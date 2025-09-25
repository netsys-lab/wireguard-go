package scion_paths

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/scionproto/scion/pkg/addr"
	daemonpb "github.com/scionproto/scion/pkg/proto/daemon"
)

type SciondRetriever struct {
	client daemonpb.DaemonServiceClient
}

func NewSciondRetriever() (*SciondRetriever, error) {
	daemonAddr := getDaemonAddr()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := dialGRPC(ctx, daemonAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("connect to daemon (%s): %w", daemonAddr, err)
	}

	client := daemonpb.NewDaemonServiceClient(conn)
	return &SciondRetriever{client: client}, nil
}

func (r *SciondRetriever) RetrievePaths(ctx context.Context, srcIA, dstIA addr.IA) ([]PathInfo, error) {
	req := &daemonpb.PathsRequest{
		SourceIsdAs:      uint64(srcIA),
		DestinationIsdAs: uint64(dstIA),
		Refresh:          false,
		Hidden:           false,
	}

	resp, err := r.client.Paths(ctx, req)
	if err != nil {
		return nil, err
	}

	infos := make([]PathInfo, 0, len(resp.Paths))
	for _, p := range resp.Paths {
		exp := ""
		if p.Expiration != nil {
			exp = p.Expiration.AsTime().Format(time.RFC3339)
		}

		infos = append(infos, PathInfo{
			Raw:        p.Raw,
			Interfaces: len(p.Interfaces),
			MTU:        p.Mtu,
			Expiration: exp,
		})
		_ = hex.EncodeToString(p.Raw) // could log if needed
	}
	return infos, nil
}

// helpers from your script
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
