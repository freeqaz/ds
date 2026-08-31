module github.com/dream-serpent/dream-serpent/assurance/conformance-adapter

go 1.25.11

// Zero dependencies at skeleton time (standard library only).
// When the first adapter lands, this module gains a test-scoped dependency on
// github.com/dream-serpent/dream-serpent/boundary (the harness seam interfaces) — see README.md.
// boundary/ stays out of go.work; production trees must never depend on this module.

require (
	github.com/dream-serpent/dream-serpent/boundary v0.0.0
	github.com/dream-serpent/dream-serpent/identity/grant-service v0.0.0
	github.com/dream-serpent/dream-serpent/proto/gen/go v0.0.0
	google.golang.org/grpc v1.81.1
	google.golang.org/protobuf v1.36.11
)

require (
	github.com/dream-serpent/dream-serpent/identity/kv-client v0.0.0 // indirect
	golang.org/x/net v0.51.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
	golang.org/x/text v0.34.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260226221140-a57be14db171 // indirect
)

// Unpublished monorepo sibling — resolved by path (the one legal cross-tree
// import); go.work covers workspace builds, this replace covers standalone ones.
replace github.com/dream-serpent/dream-serpent/proto/gen/go => ../../proto/gen/go

// boundary/ is the executable spec (D26) and is DELIBERATELY out of go.work; the
// tlsproxyinspect adapter implements its exported tlsproxy seams, so this
// path-replace is required for the standalone build the go.mod header anticipated.
// This is a TEST-SCOPED dependency of an OSS adapter no production tree imports
// (the import-boundary CI gate keeps boundary out of production builds).
replace github.com/dream-serpent/dream-serpent/boundary => ../../boundary

// identity/grant-service is the standalone Identity grant-fetch module (deliberately
// outside go.work, its own go.mod). The grantfetchconform adapter stands its real
// GrantFetchServiceServer up on an in-process bufconn so the CENTRAL dual-run dials
// the actual server, not an honest in-test responder (01KV4KBZYF). go.work covers
// the workspace build; this replace covers the standalone (GOWORK=off) one. kv-client
// is grant-service's own transitive Backend sibling and needs the same path-replace
// here because a dependency's replaces do not apply to the main module.
replace github.com/dream-serpent/dream-serpent/identity/grant-service => ../../identity/grant-service

replace github.com/dream-serpent/dream-serpent/identity/kv-client => ../../identity/kv-client
