// Module path follows the repo-wide scheme:
// github.com/dream-serpent/dream-serpent/<tree>.
//
// LEAN DEFAULT — recorded as this workstream's first revisitable decision
// (design Part 3): one Go module for the whole vm/ tree. If the guest-side
// entrypoint and the host-side disk tooling diverge in dependency weight,
// splitting them is a cheap follow-on; do not pre-split.
//
// Dependency policy: STANDARD LIBRARY ONLY for the disk-tooling side; the ONE
// legal cross-tree import below arrived with the M0 runtime/v1 freeze:
//
//   - github.com/dream-serpent/dream-serpent/proto/gen/go — the ONLY
//     cross-tree Go import this module may ever take; arrived when
//     dreamserpent.runtime.v1 FROZE at M0 (D38, 2026-06-15). The guest-side
//     entrypoint (entrypoint/) binds it in the SINGLE proto-bound file
//     runtimev1_bridge.go; grpc/protobuf ride in as that dependency's transitive
//     deps (the EntrypointService client + the EntrypointConfig wire decode).
//     The require + replace below cover standalone (GOWORK=off) builds; go.work
//     covers workspace builds.
//   - libguestfs / qemu-nbd / qemu-img are invoked as host-side TOOLS
//     (exec), not Go dependencies (D29, disk/README.md).
//   - golang.org/x/sys — DIRECT (promoted from indirect by the m1vsock wave): the
//     guest-side attach forwarder (attachfwd/) binds an AF_VSOCK listener via
//     golang.org/x/sys/unix (the M1 host<->guest attach carriage; vsock replaces the
//     TCP GuestIP:4242 leg, off the egress dataplane). Linux-only, in-guest runtime.
//
// Never depended on from here: libvirt bindings — the libvirt driver
// lives in the host agent (orchestrator/internal/hypervisor/libvirt,
// doc 15 §5.1), NOT in this tree.
module github.com/dream-serpent/dream-serpent/vm

go 1.25.11

require (
	github.com/dream-serpent/dream-serpent/proto/gen/go v0.0.0
	golang.org/x/sys v0.42.0
	google.golang.org/grpc v1.81.1
	google.golang.org/protobuf v1.36.11
)

require (
	golang.org/x/net v0.51.0 // indirect
	golang.org/x/text v0.34.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260226221140-a57be14db171 // indirect
)

// Unpublished monorepo sibling — resolved by path (the one legal cross-tree
// import); go.work covers workspace builds, this replace covers standalone ones.
replace github.com/dream-serpent/dream-serpent/proto/gen/go => ../proto/gen/go
