// SPDX-License-Identifier: Apache-2.0

// The Go<->wire repoint onto the FROZEN GrantFetchService generated types (doc
// 16 §5.1/§5.2/§9; D39/D55/D80; proto/dreamserpent/identity/v1/grant_fetch.proto).
//
// WHAT THIS IS. The grant-FETCH wire (GrantFetchService.Fetch(GrantFetchRequest)
// -> GrantFetchResponse + FetchedCredential / CredentialClass / GrantFetchReason)
// FROZE additively in dreamserpent.identity.v1 on 2026-06-13 (proto/FREEZE.md).
// This file is the SEPARATE mechanical follow-up FREEZE.md flags: it repoints the
// in-process Go model in this module onto those generated types so the two agree
// FIELD-FOR-FIELD, WITHOUT changing any in-process behavior. proto/gen/go is the
// one legal cross-tree import (D80); it arrives via the go.mod require+replace
// alongside identity/mint's standalone pattern. This module stays GOWORK=off.
//
// THE MAPPING (the §9 grant-fetch contract, made explicit and test-pinned):
//   - Service.Fetch(sessionUUID, serviceID, grantRef, grantExpiry)(Credential,
//     error)        ==  GrantFetchService.Fetch(GrantFetchRequest)->GrantFetchResponse
//   - Credential{Secret, Location}                ==  FetchedCredential{secret, location}
//   - the five Go errors                          ==  the in-band GrantFetchReason
//     deny/stall split (open-question default #2 — the executor distinguishes a
//     STALL it RETRIES from a DENY it FAILS CLOSED on, on the wire):
//     ErrStoreUnavailable -> GRANT_FETCH_REASON_STORE_UNAVAILABLE  (stall/retry)
//     ErrGrantNotFound    -> GRANT_FETCH_REASON_GRANT_NOT_FOUND    (deny)
//     ErrSessionNotLive   -> GRANT_FETCH_REASON_SESSION_NOT_LIVE   (deny)
//     errParkedSession    -> GRANT_FETCH_REASON_SESSION_PARKED     (deny)
//     ErrGrantRefMismatch -> GRANT_FETCH_REASON_GRANT_REF_MISMATCH (deny)
//     nil (success)       -> GRANT_FETCH_REASON_OK
//
// OPEN-QUESTION DEFAULTS honored (FREEZE.md / grant_fetch.proto): (1) FETCH-ONLY
// — only Fetch is on the seam; Suspend/Park/Resume/RegisterSession stay
// orchestrator-driven over other seams and are NOT exposed here; (2) IN-BAND
// reason — the error split rides GrantFetchResponse.reason, not a gRPC status; (3)
// grant_expiry is a request INPUT (the caller already knows it from the preceding
// Validate ALLOW) AND a response ECHO (so the response is self-contained). The
// store carries no expiry, so the echo is the request value clamped by nothing
// here — the caller-side cache clamp lives in service.go.
//
// STORE-AGNOSTIC SEAM (§11.3). The wire carries NO store field: which store backs
// the fetch (the OSS local file/KV fake here, an OpenBao-compatible KV at higher
// tiers) stays a Backend choice, never a wire concern. This file touches only the
// fetch surface; the Backend seam is unchanged.
package grantservice

import (
	"errors"
	"time"

	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
)

// CredentialToWire maps the in-process Credential onto the frozen
// FetchedCredential field-for-field: Secret -> secret, Location -> location. The
// returned message is the real credential the off-VM swap executor substitutes
// (doc 16 §5.2; D8 — it crosses only to a recipient already outside the VM).
//
// A defensive copy of Secret is taken so the returned message can never alias a
// cached secret in this process.
func CredentialToWire(c Credential) *identityv1.FetchedCredential {
	return &identityv1.FetchedCredential{
		Secret:   append([]byte(nil), c.Secret...),
		Location: c.Location,
	}
}

// CredentialFromWire is the inverse of CredentialToWire: it maps a frozen
// FetchedCredential back onto the in-process Credential field-for-field. A nil
// message maps to the zero Credential (an empty fetch result), mirroring the
// success precondition that credential is populated only on REASON_OK.
func CredentialFromWire(fc *identityv1.FetchedCredential) Credential {
	if fc == nil {
		return Credential{}
	}
	return Credential{
		Secret:   append([]byte(nil), fc.GetSecret()...),
		Location: fc.GetLocation(),
	}
}

// reasonForErr maps a Service.Fetch error onto the in-band GrantFetchReason
// deny/stall split (open-question default #2). A nil error is REASON_OK. An error
// outside the documented five is REASON_UNSPECIFIED — the buf-standard
// "never deliberately set" zero, distinguishable from a chosen reason so an
// unexpected error is never silently rendered as a known deny.
func reasonForErr(err error) identityv1.GrantFetchReason {
	switch {
	case err == nil:
		return identityv1.GrantFetchReason_GRANT_FETCH_REASON_OK
	case errors.Is(err, ErrStoreUnavailable):
		return identityv1.GrantFetchReason_GRANT_FETCH_REASON_STORE_UNAVAILABLE
	case errors.Is(err, ErrGrantNotFound):
		return identityv1.GrantFetchReason_GRANT_FETCH_REASON_GRANT_NOT_FOUND
	case errors.Is(err, ErrSessionNotLive):
		return identityv1.GrantFetchReason_GRANT_FETCH_REASON_SESSION_NOT_LIVE
	case errors.Is(err, errParkedSession):
		return identityv1.GrantFetchReason_GRANT_FETCH_REASON_SESSION_PARKED
	case errors.Is(err, ErrGrantRefMismatch):
		return identityv1.GrantFetchReason_GRANT_FETCH_REASON_GRANT_REF_MISMATCH
	default:
		return identityv1.GrantFetchReason_GRANT_FETCH_REASON_UNSPECIFIED
	}
}

// reasonKind is the stall/deny/neither classification of a GrantFetchReason. It is
// the SINGLE in-tree authority the ReasonIsStall/ReasonIsDeny predicates derive
// from, so the §5.1 retry-only-a-stall split is spelled out exactly once for the
// grant-service module rather than re-derived at each call site.
//
// D80 (proto/gen/go is the only legal cross-tree import) forbids the assurance
// conformance trees importing this module, so the central dual-run
// (assurance/contract-harness/dualrun) cannot call ReasonIsStall — it MIRRORS this
// split against the frozen enum and guards it with its own enum-completeness pin.
// The two halves are kept in lockstep by the completeness assertions in each tree
// (init below here; TestGrantFetchReason_StallClassificationIsExhaustive there), so
// a NEW retryable reason (a second stall) added to the frozen proto cannot silently
// drift the trees apart.
type reasonKind uint8

const (
	reasonNeither reasonKind = iota // REASON_OK — neither a retryable stall nor a deny
	reasonStall                     // retryable: the key store is transiently unreachable
	reasonDeny                      // definitive fail-closed (incl. the UNSPECIFIED fail-closed default)
)

// reasonKinds is the EXHAUSTIVE classification of every GrantFetchReason — the
// single source the stall/deny predicates read. Every member of the frozen enum
// MUST appear exactly once; the init() below asserts the table covers the whole
// enum, so a new member added to the frozen proto that is not classified here
// PANICS at package init (a loud CI failure in this tree) rather than being
// silently mis-split.
var reasonKinds = map[identityv1.GrantFetchReason]reasonKind{
	identityv1.GrantFetchReason_GRANT_FETCH_REASON_OK:                 reasonNeither,
	identityv1.GrantFetchReason_GRANT_FETCH_REASON_STORE_UNAVAILABLE:  reasonStall,
	identityv1.GrantFetchReason_GRANT_FETCH_REASON_GRANT_NOT_FOUND:    reasonDeny,
	identityv1.GrantFetchReason_GRANT_FETCH_REASON_SESSION_NOT_LIVE:   reasonDeny,
	identityv1.GrantFetchReason_GRANT_FETCH_REASON_SESSION_PARKED:     reasonDeny,
	identityv1.GrantFetchReason_GRANT_FETCH_REASON_GRANT_REF_MISMATCH: reasonDeny,
	// UNSPECIFIED is the fail-closed default: an unrecognized outcome is treated as a
	// deny (never ridden), matching the prior ReasonIsDeny default arm.
	identityv1.GrantFetchReason_GRANT_FETCH_REASON_UNSPECIFIED: reasonDeny,
}

// init is the grant-service half of the cross-tree single-source guard (D80): the
// classification table MUST cover the whole frozen GrantFetchReason enum. Every key
// is a typed enum constant and the map admits no duplicates, so equal cardinality
// with the generated GrantFetchReason_name is exact coverage. If the frozen proto
// ever grows a member left out of reasonKinds, this panics at package init —
// tripping every grant-service test — so a new reason (e.g. a second stall) cannot
// be silently mis-classified. The assurance dual-run carries the mirror guard.
func init() {
	if len(reasonKinds) != len(identityv1.GrantFetchReason_name) {
		panic("grantservice: GrantFetchReason classification table is not exhaustive — a frozen-enum member is unclassified; update reasonKinds in wire.go (and mirror the split in the assurance dual-run)")
	}
}

// ReasonIsStall reports whether a GrantFetchReason is the RETRYABLE stall
// (the store is unreachable) as opposed to a definitive DENY. It encodes the §5.1
// "outage stalls only NEW fetches" contract on the wire: the executor RETRIES a
// stall and FAILS CLOSED on a deny. Exposed so a wire consumer can branch without
// re-deriving the enum split; derived from the single reasonKinds authority.
func ReasonIsStall(r identityv1.GrantFetchReason) bool {
	return reasonKinds[r] == reasonStall
}

// ReasonIsDeny reports whether a GrantFetchReason is a definitive DENY (the
// executor fails closed): not-found, not-live, parked, or grant_ref mismatch.
// REASON_OK and the stall are not denies; REASON_UNSPECIFIED is treated as a deny
// (fail-closed default) since an unrecognized outcome must never be ridden. Derived
// from the single reasonKinds authority: a value absent from the table (an
// out-of-enum int) also fails closed as a deny.
func ReasonIsDeny(r identityv1.GrantFetchReason) bool {
	k, ok := reasonKinds[r]
	return !ok || k == reasonDeny
}

// FetchWire is the wire-shaped adapter over Service.Fetch: it accepts the frozen
// GrantFetchRequest, drives the in-process Fetch field-for-field, and returns the
// frozen GrantFetchResponse — the per-session fetch the ds-tlsproxy swap executor
// calls (doc 16 §9; GrantFetchService.Fetch). It is a pure adapter: it adds NO
// behavior over Service.Fetch, so every cache/outage/lifecycle property the
// existing Service tests pin holds unchanged through the wire.
//
// MAPPING:
//   - request session_uuid/service_id/grant_ref build the frozen grant RECORD
//     (GrantRecord{GrantRef, ServiceId}) ONCE and dispatch through the
//     record-keyed FetchForRecord — the *GrantRecord the served RPC ultimately
//     keys on reaches the real call site here, rather than being re-derived
//     inside the string-keyed Fetch adapter. The record keys the D39 store lookup
//     on its own grant_ref and the session cache on its own service_id, so this
//     resolves to the IDENTICAL Backend.Fetch call and cache entry the string
//     path did (service_test.go's shared-cache assertion). grant_expiry maps as
//     wall-clock UNIX seconds <-> time.Time; a zero/negative value maps to the
//     zero time, the "no caller-supplied TTL" case the existing service.go expiry
//     clamp already handles;
//   - on success the response carries the real FetchedCredential, REASON_OK, the
//     ISSUED{service_id} binding echoed as issued_service_id, the request's
//     grant_expiry echoed back (open-question default #3), and
//     CREDENTIAL_CLASS_SWAP (the OSS file fake is swap-class-only, backend.go);
//   - on error the response carries the matching in-band reason and an empty
//     credential, so the caller branches via ReasonIsStall/ReasonIsDeny.
//
// A nil request is treated as an empty request (all-zero fields), which fails
// closed through the existing Fetch guards (grant_ref mismatch / not live).
func (s *Service) FetchWire(req *identityv1.GrantFetchRequest) *identityv1.GrantFetchResponse {
	if req == nil {
		req = &identityv1.GrantFetchRequest{}
	}
	grantExpiry := unixToTime(req.GetGrantExpiryUnixSeconds())

	// Build the frozen grant RECORD from the request fields ONCE and dispatch
	// through the record-keyed FetchForRecord: the *GrantRecord now reaches the
	// actual gRPC call site instead of being reconstructed inside string-keyed
	// Fetch. Keyed on the record's own grant_ref (D39 store key) and service_id
	// (cache axis), this resolves to the IDENTICAL Backend.Fetch/cache entry as
	// the prior string path — a pure dispatch change, no behavior added.
	rec := &GrantRecord{GrantRef: req.GetGrantRef(), ServiceId: req.GetServiceId()}
	cred, err := s.FetchForRecord(req.GetSessionUuid(), rec, grantExpiry)
	if err != nil {
		return &identityv1.GrantFetchResponse{Reason: reasonForErr(err)}
	}
	return &identityv1.GrantFetchResponse{
		Credential:             CredentialToWire(cred),
		CredentialClass:        identityv1.CredentialClass_CREDENTIAL_CLASS_SWAP,
		IssuedServiceId:        req.GetServiceId(),
		GrantExpiryUnixSeconds: req.GetGrantExpiryUnixSeconds(),
		Reason:                 identityv1.GrantFetchReason_GRANT_FETCH_REASON_OK,
	}
}

// unixToTime maps wall-clock UNIX seconds onto a time.Time, mapping a
// zero/negative value to the zero time so the "no caller-supplied TTL" case
// flows through the existing service.go expiry clamp unchanged (the house
// ca_mint/grants/validate UNIX-seconds convention).
func unixToTime(sec int64) time.Time {
	if sec <= 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0).UTC()
}
