module github.com/dream-serpent/dream-serpent/assurance/contract-harness

go 1.25.11

// The dual-codegen fake-generation pipeline + the run-the-suite-against-real-AND-fake
// harness (doc 06 §2.1, doc 15 §5.6/§11). It depends on the one legal cross-tree import,
// proto/gen/go (the generated stubs it both consumes and emits programmable fakes beside),
// and on grpc — the dual-run dials real and fake over an in-process bufconn so a single
// conformance suite exercises both ends of a seam. This tree holds the PIPELINE and the
// RUNNER; the generated fakes themselves land under proto/gen/go (README.md).
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

// Unpublished monorepo sibling — resolved by path (the one legal cross-tree import);
// go.work covers workspace builds, this replace covers standalone ones.
replace github.com/dream-serpent/dream-serpent/proto/gen/go => ../../proto/gen/go
