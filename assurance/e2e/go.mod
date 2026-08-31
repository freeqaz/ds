module github.com/dream-serpent/dream-serpent/assurance/e2e

go 1.25.11

// The D24 (b) session-lifecycle suite (README.md). It drives the FROZEN
// dreamserpent.identity.v1 client over the proto seam, so it depends on
// proto/gen/go (the one legal cross-tree import, D80) plus grpc/protobuf for
// the live-endpoint dial. Like assurance/guardrail-conformance and the
// identity/* modules it is deliberately NOT in the repo go.work `use` list: it
// is run standalone (GOWORK=off go build/vet/test ./...), keeping the e2e tier
// independent of production build state. No third-party deps beyond the proto
// toolchain (D50: synthetic fixtures + in-process fakes, no live services in
// the wave).

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

// Unpublished monorepo sibling — resolved by path (the one legal cross-tree
// import, D80); go.work covers workspace builds, this replace covers the
// standalone (GOWORK=off) build this tier runs under.
replace github.com/dream-serpent/dream-serpent/proto/gen/go => ../../proto/gen/go
