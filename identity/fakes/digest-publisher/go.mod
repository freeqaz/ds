// The behavioral digest-publisher FAKE (doc 14 §7 / D73): ships with the
// Stage-0 identity.v1 freeze PR per proto/FREEZE.md ("fake publisher in the
// same PR") and proto/README.md (runs as a local process, speaks the frozen
// protos). LANGUAGE NOTE: this binds the FAKE's implementation language only —
// the identity/ tree's product-language decision stays the workstream's own
// (identity/README.md); the contract this fake drives is the .proto + the
// digest-publisher README spec, not this module.
//
// Deliberately OUTSIDE go.work (the harness/fake rule: never built with the
// workspace). Its CI lane is the `off-workspace-modules` job in
// .github/workflows/go.yml, which runs `GOWORK=off go build/vet/test` here and
// in identity/mint/ — the only gate that keeps these two modules from rotting.
module github.com/dream-serpent/dream-serpent/identity/fakes/digest-publisher

go 1.25.11

require (
	github.com/dream-serpent/dream-serpent/proto/gen/go v0.0.0
	google.golang.org/grpc v1.81.1
	google.golang.org/protobuf v1.36.11
)

require (
	golang.org/x/net v0.51.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
	golang.org/x/text v0.34.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260226221140-a57be14db171 // indirect
)

replace github.com/dream-serpent/dream-serpent/proto/gen/go => ../../../proto/gen/go
