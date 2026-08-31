// The PRODUCTION secret-digest producer (doc 16 §6; D39/D73/D84) — the real
// replacement for the Stage-0 fake in identity/fakes/digest-publisher.
//
// It runs INSIDE the D39 secret-store trust zone (off the virtual-metal host):
// it is the only component besides the key store that touches credential
// plaintext, and it touches it ONLY to compute keyed HMAC-SHA-256 digests of
// every encoding variant (RAW/BASE64/URLENC/HEX). Plaintext NEVER crosses the
// feed — only the truncated digest bytes + key id + variant tag do (doc 14 §7).
// It drives the SAME frozen dreamserpent.identity.v1.DigestFeedService seam the
// fake drove; it invents no new cross-service contract (proto bodies HANDS-OFF).
//
// Also home to the SecretMatcher's producer-side reference: the boundary-side
// matching predicate (HMAC the wire candidate, truncate, set-membership) is
// modeled here so the producer can PROVE its digests are matchable pre-egress
// over synthetic secrets — the round2/08 test-6 anchor (digests matchable before
// first egress byte). The real consumer/SecretMatcher trait is Boundary's
// (dataplane/, docs 11–14); this is the producer's matchability proof, not a
// second enforcement plane.
//
// Deliberately OUTSIDE go.work — the same standalone-module pattern as
// ../mint, ../grant-service, and ../fakes/digest-publisher (a substrate swap
// must not perturb the workspace). The only legal cross-tree import is
// proto/gen/go via replace. STDLIB + the Stage-0 proto/grpc deps only; no real
// key material anywhere — synthetic fixtures only (D50).
module github.com/dream-serpent/dream-serpent/identity/digest

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

replace github.com/dream-serpent/dream-serpent/proto/gen/go => ../../proto/gen/go
