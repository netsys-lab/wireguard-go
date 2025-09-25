package scion_paths

import (
	"context"
	"fmt"

	"google.golang.org/grpc"

	pathsrvpb "golang.zx2c4.com/wireguard/translator/scion_paths/scionproto"
)

// DirectPathRetriever fetches paths directly from the Path Server gRPC API
type DirectPathRetriever struct {
	client pathsrvpb.PathServiceClient
}

// NewDirectPathRetriever connects to the Path Server at the given address
func NewDirectPathRetriever(psAddr string) (*DirectPathRetriever, error) {
	conn, err := grpc.Dial(psAddr, grpc.WithInsecure()) // TODO: use TLS for production
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Path Server: %w", err)
	}
	return &DirectPathRetriever{
		client: pathsrvpb.NewPathServiceClient(conn),
	}, nil
}

// RetrievePaths fetches paths from srcIA to dstIA
func (d *DirectPathRetriever) RetrievePaths(ctx context.Context, srcIA, dstIA string) ([]PathInfo, error) {
	req := &pathsrvpb.PathsRequest{
		SrcIa: srcIA,
		DstIa: dstIA,
	}

	resp, err := d.client.Paths(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("path request failed: %w", err)
	}

	var paths []PathInfo
	for _, p := range resp.Paths {
		// parse expiration string to time.Time

		paths = append(paths, PathInfo{
			Raw:        p.Raw,
			Interfaces: len(p.Interfaces),
			MTU:        p.Mtu,
			Expiration: "expTime Place Holder",
		})
	}

	return paths, nil
}
