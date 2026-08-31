// The M0 identity-mint service SHIM (doc 16 §2/§4, D22 substrate progression).
//
// This is the M0 throwaway substrate of the Identity mint service: it wires the
// two Stage-0 grpc seams (`Validate`, `MintInterceptionCA`) against the frozen
// `dreamserpent.identity.v1` stubs and implements the two reserved native seams
// (`MintWorkloadIdentity`, `RevokeSession`) directly. Throwaway-by-design behind
// the frozen `Validate` contract (D22: M0 shim -> M1 own CA -> M3 SPIFFE).
//
// LANGUAGE: Go, per identity/README.md (the Stage-0-freeze trigger is met).
// Deliberately OUTSIDE go.work — same standalone-module pattern as
// identity/fakes/digest-publisher: a substrate swap must not perturb the
// workspace, and the only legal cross-tree import is proto/gen/go via replace.
//
// DEPS ARE MINIMAL (the wave's constraint): proto/gen/go + grpc + protobuf
// arrive with the Stage-0 stubs; everything else is Go stdlib (crypto/x509,
// crypto/ecdsa, encoding/json, encoding/base64 cover the CA + cert + JWT work).
// No JWT library — stdlib is sufficient for the compact JWS the shim emits.
// No real key material anywhere — synthetic fixtures only (D50). The lone
// exception is github.com/spiffe/go-spiffe/v2, vendored SOLELY for the live SPIRE
// Workload-API leg (DialSpireWorkloadAPI, spire_live.go) — an env-gated DEFERRED
// manual dial that is NEVER exercised in CI; the synthetic fake (spire_fake.go)
// remains the only in-CI SVIDSource.
module github.com/dream-serpent/dream-serpent/identity/mint

go 1.25.11

require (
	github.com/biscuit-auth/biscuit-go/v2 v2.2.0
	github.com/dream-serpent/dream-serpent/proto/gen/go v0.0.0
	github.com/spiffe/go-spiffe/v2 v2.8.0
	google.golang.org/grpc v1.81.1
)

require (
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/go-jose/go-jose/v4 v4.1.4 // indirect
	golang.org/x/net v0.51.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
	golang.org/x/text v0.34.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260226221140-a57be14db171 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

replace github.com/dream-serpent/dream-serpent/proto/gen/go => ../../proto/gen/go
