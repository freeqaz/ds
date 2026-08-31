// SPDX-License-Identifier: Apache-2.0

package dualrun

import (
	"context"
	"fmt"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

// InProcess returns a Dialer that stands up the given gRPC service registration
// on an in-process bufconn listener and dials a client at it. Both the real
// implementation and the generated fake are wired through this same Dialer, so
// the only thing that varies between the two dual-run passes is the registered
// server — the transport, codec, and client are identical. That is what makes a
// divergence attributable to the contract, not the plumbing.
//
// register is the generated RegisterXxxServiceServer call bound to the server
// under test, e.g.:
//
//	dualrun.InProcess(func(s grpc.ServiceRegistrar) {
//	    hostagentv1.RegisterHostAgentServiceServer(s, impl)
//	})
func InProcess(register func(s grpc.ServiceRegistrar)) Dialer {
	return &inProcessDialer{register: register}
}

type inProcessDialer struct {
	register func(s grpc.ServiceRegistrar)
}

const bufSize = 1 << 20 // 1 MiB in-process pipe buffer

func (d *inProcessDialer) Dial(ctx context.Context) (*grpc.ClientConn, func(), error) {
	lis := bufconn.Listen(bufSize)
	srv := grpc.NewServer()
	d.register(srv)

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(lis) }()

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		srv.Stop()
		<-serveErr
		return nil, nil, fmt.Errorf("dualrun: in-process dial: %w", err)
	}

	stop := func() {
		_ = conn.Close()
		srv.GracefulStop()
		<-serveErr
		_ = lis.Close()
	}
	return conn, stop, nil
}
