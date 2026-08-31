// Module path follows the repo-wide proto/module scheme:
// github.com/dream-serpent/dream-serpent/<tree>.
//
// Dependency policy: STANDARD LIBRARY ONLY until a contract freeze lands;
// the M0 hostagent/hypervisor freeze HAS landed, so proto/gen/go is now a
// declared dependency (the host-agent heartbeat/RecoverSessions consumer,
// internal/hostagent — doc 15 §5.1/§5.2). Pinned choices still pending their
// owner-landed first use are recorded here, not declared:
//
//   - github.com/dream-serpent/dream-serpent/proto/gen/go — the ONLY
//     cross-tree Go import this module may ever take (generated stubs +
//     generated fakes; design Part 2 / proto/README.md). DECLARED below.
//   - golang.org/x/sys — DIRECT (promoted from indirect by the U5 authz
//     hardening): cmd/host-agent's session-token shim binds a host-side
//     AF_VSOCK listener (sessiontokenvsock_linux.go) via golang.org/x/sys/unix
//     to authorize the guest token fetch by its unforgeable peer CID. Same
//     version already present transitively (vm/ uses it the same way for the
//     attach carriage); a normal third-party dep, NOT a cross-tree import.
//   - google.golang.org/grpc — arrives with proto/gen/go; DIRECT here (the
//     internal/hostagent seam asserts the generated heartbeat client stream
//     satisfies HeartbeatSender). google.golang.org/protobuf is also DIRECT
//     (internal/policylog, internal/sessions, and the libvirt entrypoint-config
//     producer marshal proto messages directly).
//   - libvirt.org/go/libvirt — host-agent libvirt driver (doc 15 §5.1).
//   - database/sql + a Postgres driver behind internal/store's
//     repository interface (D6/D33) — driver choice is owner-landed.
//
// Never depended on from here: dataplane/ crate sources (the Go↔Rust edge
// is the ds-nft C-ABI staticlib via internal/nftbridge, not a Go module),
// boundary/ (the harness is never built with production code), paid/.
module github.com/dream-serpent/dream-serpent/orchestrator

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
