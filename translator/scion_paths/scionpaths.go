package scion_paths

import (
    "context"

    "github.com/scionproto/scion/pkg/addr"
    //daemonpb "github.com/scionproto/scion/pkg/proto/daemon"
)

// PathInfo is a light wrapper around the daemon’s PathsResponse.Path.
type PathInfo struct {
    Raw        []byte
    Interfaces int
    MTU        uint32
    Expiration string
}

// PathRetriever abstracts how SCION paths are retrieved.
type PathRetriever interface {
    RetrievePaths(ctx context.Context, srcIA, dstIA addr.IA) ([]PathInfo, error)
}
