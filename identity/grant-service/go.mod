// The Identity grant service (doc 16 §5.1/§5.4/§9; D39/D52/D55/D83).
//
// The Identity-owned service the ds-tlsproxy SWAP EXECUTOR fetches grants from,
// fronting the D39 key store. OSS substrate (D85): the backing store is a LOCAL
// file/KV FAKE — never a live Vault/OpenBao (that is the higher-tier
// OpenBao-compatible KV via ../kv-client/, behind the same grant-fetch seam).
// Per-session fetch, never per-request; cache ≤ session; a store outage stalls
// NEW grant fetches only while in-flight sessions ride their cached grants
// (§5.1). Grants evict on the suspend signal and survive park/resume with
// liveness/TTL re-validation (§5.4).
//
// Deliberately OUTSIDE go.work — the same standalone-module pattern as
// ../mint and ../fakes/digest-publisher (a substrate swap must not perturb the
// workspace). The local file/KV fake backend and the session cache are STDLIB-ONLY;
// the §9 grant-FETCH wire seam to the swap executor FROZE additively in
// dreamserpent.identity.v1 (proto/dreamserpent/identity/v1/grant_fetch.proto,
// 2026-06-13), so this module now imports proto/gen/go (the ONE legal cross-tree
// import, D80) via require+replace — the same way ../mint takes the dep — to repoint
// the in-process Go model onto the FROZEN GrantFetchService generated types
// (wire.go). grpc/protobuf arrive transitively with those generated types; no other
// third-party deps. No real key material anywhere — synthetic fixtures only (D50).
module github.com/dream-serpent/dream-serpent/identity/grant-service

go 1.25.11

require (
	github.com/dream-serpent/dream-serpent/identity/kv-client v0.0.0
	github.com/dream-serpent/dream-serpent/proto/gen/go v0.0.0
	google.golang.org/grpc v1.81.1
)

require (
	golang.org/x/net v0.51.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
	golang.org/x/text v0.34.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260226221140-a57be14db171 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

replace github.com/dream-serpent/dream-serpent/identity/kv-client => ../kv-client

replace github.com/dream-serpent/dream-serpent/proto/gen/go => ../../proto/gen/go
