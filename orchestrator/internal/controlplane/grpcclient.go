package controlplane

// grpcclient.go is the ONE place this package adapts the generated hypervisor.v1 gRPC
// CLIENT onto the package's narrow DriverClient seam. The generated client's methods
// carry the `opts ...grpc.CallOption` tail (the gRPC wire shape); DriverClient uses the
// generated-FAKE shape (no options tail) so the fake satisfies it natively in tests
// (D50). ClientShim bridges the two: it wraps a generated HypervisorDriverServiceClient
// and drops the (unused) call-options tail. main.go wraps each dialed host driver in a
// ClientShim; tests use the fake directly. This confines the gRPC dependency to this
// file + main.go — the rest of the package is gRPC-free, exercised against the fake.

import (
	"context"

	hypervisorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hypervisor/v1"
)

// ClientShim adapts a generated hypervisor.v1 HypervisorDriverServiceClient onto the
// package's DriverClient seam (the generated-fake method shape). It is the production
// bridge main.go wraps each dialed per-host driver client in. The call-options tail the
// generated client exposes is dropped (the host driver verbs need none here).
type ClientShim struct {
	// Client is the generated per-host hypervisor.v1 driver gRPC client (main.go dials
	// it over the host's driver endpoint). The shim forwards the four verbs DriverClient
	// declares, dropping the variadic call-options.
	Client hypervisorv1.HypervisorDriverServiceClient
}

// CloneFromImage forwards to the generated client (§4.1 step 4).
func (s ClientShim) CloneFromImage(ctx context.Context, in *hypervisorv1.CloneFromImageRequest) (*hypervisorv1.CloneFromImageResponse, error) {
	return s.Client.CloneFromImage(ctx, in)
}

// IssueAttachHandle forwards to the generated client (§4.1 step 10).
func (s ClientShim) IssueAttachHandle(ctx context.Context, in *hypervisorv1.IssueAttachHandleRequest) (*hypervisorv1.IssueAttachHandleResponse, error) {
	return s.Client.IssueAttachHandle(ctx, in)
}

// Suspend forwards to the generated client (the §3 quarantine / §4.3 suspend).
func (s ClientShim) Suspend(ctx context.Context, in *hypervisorv1.SuspendRequest) (*hypervisorv1.SuspendResponse, error) {
	return s.Client.Suspend(ctx, in)
}

// Destroy forwards to the generated client (the §4.2 teardown / rollback).
func (s ClientShim) Destroy(ctx context.Context, in *hypervisorv1.DestroyRequest) (*hypervisorv1.DestroyResponse, error) {
	return s.Client.Destroy(ctx, in)
}

// Compile-time proof the shim satisfies the package's DriverClient seam — so a dialed
// generated client (wrapped in a ClientShim) drops straight into the DriverRegistry
// main.go supplies.
var _ DriverClient = ClientShim{}
