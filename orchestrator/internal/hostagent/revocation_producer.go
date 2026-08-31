// SPDX-License-Identifier: Apache-2.0

package hostagent

// revocation_producer.go is the host agent's CROSS-PROCESS PRODUCER half of the
// POST-COMMIT REVOCATION-DELTA feed (doc 12 §8 revocation sweep, doc 13 §5 / §9,
// D72/D53). It is the host-agent (Go) ENCODER + DELIVERY half of the same wire
// ds-tlsproxy already CONSUMES (dataplane/services/ds-tlsproxy/src/main.rs
// serve_revocation_feed / spawn_revocation_feed, behind DS_REVOCATION_FEED_LIVE).
//
// After the host completes the D72 two-phase apply (all three consumers committed
// vN+1), it computes the vN→vN+1 REVOKED SET — the (session, dst-keys, rung) tuples
// the new version newly denies — and fans it host-ward over a host-local UDS the
// ds-tlsproxy subscriber binds. A delivered SEVERING-RUNG (block-or-higher) delta
// tears down the established CONNECT tunnel AND drops the session's pooled upstream
// sockets at the proxy; an allow+log (sub-block) delta severs nothing (D53). Without
// this producer the proxy's SeveringRegistry is built but never fed a delta, so an
// established tunnel cannot be severed live — THIS is the missing post-commit driver.
//
// THE CROSS-PROCESS REVOCATION-DELTA WIRE CONTRACT (binding — mirrored BYTE-FOR-BYTE
// from the Rust consumer's RevocationDeltaWire in main.rs). Every message is a
// length-prefixed FRAME: a 4-byte BIG-ENDIAN body length, then the body. Body layout
// (all multi-byte ints big-endian):
//
//	seq:           u64
//	revoked_count: u32
//	repeated revoked_count times:
//	  session_uuid:        len(u32) + utf8 bytes
//	  host_id:             len(u32) + utf8 bytes
//	  host_session_index:  u32
//	  tap_name:            len(u32) + utf8 bytes
//	  rung:                u8  (0=allow+log, 1=block+log, 2=suspend+ask, 3=kill+snapshot)
//	  dst_count:           u32
//	  repeated dst_count times:
//	    dst_key:           len(u32) + utf8 bytes   (the DstKey inner string)
//
// A body over revocationFrameMaxBody (64*1024, == RevocationDeltaWire::MAX_FRAME_BODY)
// is a malformed frame the consumer drops fail-closed; the producer therefore refuses
// to emit one (it would be silently dropped — and a dropped severing delta is a missed
// sever). The two services share NO crate (D40/D67) — there is no gRPC/tonic in the
// dataplane workspace, no FFI, no shared type; this producer must match the
// bytes-on-the-wire shape EXACTLY or the consumer drops the stream and severs nothing.
//
// THE RUNG BYTE TABLE IS SINGLE-SOURCED THROUGH THE CONFORMANCE FIXTURE. The D53 rung
// → wire byte map (allow+log=0 · block+log=1 · suspend+ask=2 · kill+snapshot=3) is the
// SINGLE point a ladder change could silently UNDER-SEVER (a host-side kill+snapshot
// arriving as a no-op allow+log because the byte numbering drifted). Because the
// orchestrator module may import ONLY proto/gen/go cross-tree (CLAUDE.md), this
// producer cannot import the assurance/conformance-adapter/revocationwire package at
// runtime; instead the conformance fixture is the single artifact the producer's table
// is PINNED against — revocationwire.RungToWireByte and the Rust
// ds_tlsproxy::Rung::rung_to_wire_byte freeze the IDENTICAL explicit byte values, and
// the conformance suite (revocationwire_test.go) + the Rust pin test make any drift on
// either side a test failure. rungWireByte below writes the SAME frozen bytes
// explicitly (never derived from the Go iota), so a reorder of the Rung constants here
// cannot renumber the wire, exactly as the fixture's RungToWireByte does.
//
// WHERE IT IS DRIVEN (the prepare/commit barrier, doc 13 §5.2 / apply.go): the delta is
// fanned out ONLY after the host completes the D72 two-phase apply admitter-LAST — the
// SAME barrier point feedwriter.go / dnsfeed_carrier.go fan their snapshots behind.
// RevocationProducer satisfies the apply.go Sweeper seam, so wiring it into the
// post-commit SweeperChain places the revocation fan-out EXACTLY behind the commit
// barrier (a version never severs a tunnel before the host is serving vN+1). It is the
// REVOCATION leg of the chain — composed BEFORE the feed/carrier producers so the host
// is swept onto vN+1 (apply_seq advances post-sweep, D72) before any consumer reads the
// new version.
//
// DEFAULT-OFF / BYTE-IDENTICAL. The live UDS dial is reached ONLY behind
// DS_REVOCATION_FEED_LIVE (the SAME presence-only gate the consumer's
// revocation_feed_live_enabled reads). With the gate UNSET (the default launch path)
// the producer's Sweep is a clean no-op — no socket is dialed, no frame is built, and
// the host-agent daemon is byte-identical to the pre-producer build. The gate ARMS the
// live cross-process delivery; the encode + frame shape are unit-proven over a synthetic
// in-process server regardless of the gate (revocation_producer_test.go).
//
// NEVER-LOG-THE-SECRET (D73): nothing here logs a composed policy document or any
// snapshot byte — the revocation delta carries only session join-keys, dst-key strings,
// and the rung; error paths name only the seq + the structural defect, never payload.

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sort"
	"sync"
	"time"

	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
)

// ── the D53 rung ladder (producer mirror; single-sourced via the conformance fixture) ──

// Rung is the D53 enforcement-action ladder, modelled here exactly as the Rust
// ds_tlsproxy::Rung enum and the assurance/conformance-adapter/revocationwire.Rung
// fixture are (doc 13 §2/§3 vocabulary; doc 12 §8). The ordinal values of THIS Go enum
// are deliberately NOT the wire bytes — the wire bytes are the explicit table in
// rungWireByte below — so a reorder here cannot renumber the wire. The ladder order
// (allow < block < suspend < kill) matches both the Rust enum and the fixture purely
// for readability. The orchestrator module cannot import the fixture cross-tree
// (CLAUDE.md: only proto/gen/go), so this is a faithful re-statement the conformance
// suite pins; it never diverges because both halves write the SAME frozen bytes out.
type Rung int

const (
	// RungAllowLog — `allow + log`: the flow is permitted; nothing severs (D53).
	RungAllowLog Rung = iota
	// RungBlockLog — `block + log`: denied. The first rung that severs.
	RungBlockLog
	// RungSuspendAsk — `suspend + ask`: held for a human; severs (above block).
	RungSuspendAsk
	// RungKillSnapshot — `kill + snapshot`: terminal; severs (above block).
	RungKillSnapshot
)

// rungWireByte maps a rung to its FROZEN revocation-delta wire byte — the value the
// ds-tlsproxy consumer's RevocationDeltaWire::rung_from_byte decodes back to a
// ds_tlsproxy::Rung. The bytes are written out EXPLICITLY (never byte(r)), so reordering
// the Rung constants above cannot silently renumber the wire — exactly the posture
// revocationwire.RungToWireByte and ds_tlsproxy::Rung::rung_to_wire_byte take. It MUST
// agree byte-for-byte with both (the conformance suite + the Rust pin test enforce it):
//
//	allow+log = 0 · block+log = 1 · suspend+ask = 2 · kill+snapshot = 3.
//
// The second return is false for a rung outside the defined ladder — surfaced (the
// encoder refuses to emit a frame) rather than guessing a byte, so an encoder bug fails
// LOUD rather than serving a wrong rung the proxy would mis-enforce.
func rungWireByte(r Rung) (byte, bool) {
	switch r {
	case RungAllowLog:
		return 0, true
	case RungBlockLog:
		return 1, true
	case RungSuspendAsk:
		return 2, true
	case RungKillSnapshot:
		return 3, true
	default:
		return 0, false
	}
}

// Severs reports whether a rung is block-or-higher — the D53 threshold at which a
// delivered revocation delta tears down the established tunnel + drops pooled sockets at
// the proxy (doc 12 §8). allow+log does not sever; block/suspend/kill do. Mirrors the
// Rust ds_tlsproxy::Rung::is_block_or_higher and the fixture's Rung.Severs. It is the
// producer's view of the threshold the proxy ultimately enforces — informational on the
// wire (the proxy re-derives it), but a producer that wants to know "will this delta
// sever?" reads it here.
func (r Rung) Severs() bool { return r >= RungBlockLog }

// ── the revoked-set the host computed (the vN→vN+1 diff) ──

// RevokedAdmission is ONE revoked (session, dst-keys, rung) tuple the host computed from
// the vN→vN+1 policy diff — the producer-side mirror of the Rust RevokedAdmission the
// consumer decodes into. The four session join-keys are the doc 14 §2/§4 SessionRef
// quartet (session_uuid / host_id / host_session_index / tap_name); dst_keys are the
// DstKey inner strings the new version newly denies; rung is the D53 severing rung the
// denying rule assigns. Empty dst_keys is a no-op sweep entry on the consumer side; a
// sub-block rung leaves established flows untouched (D53).
type RevokedAdmission struct {
	// SessionUUID is the orchestrator session UUID — the global identity.
	SessionUUID string
	// HostID is the host the session runs on.
	HostID string
	// HostSessionIndex is the host-local session index (its 14-bit residue rides the mark).
	HostSessionIndex uint32
	// TapName is the never-recycled `dstap-<idx>` tap name — the authoritative join key.
	TapName string
	// Rung is the D53 rung the revoking rule assigns. Severing is gated on this at the proxy.
	Rung Rung
	// DstKeys are the destination keys revoked (the DstKey inner strings). Empty = no-op entry.
	DstKeys []string
}

// RevocationDelta is the (seq, revoked-set) the host fans host-ward after committing
// vN+1 — the producer-side mirror of the Rust RevocationDelta. Seq is the policy_log
// version this delta belongs to (the consumer re-keys it onto its committed ApplyToken;
// a not-yet-committed seq is fail-closed UnknownToken at the consumer, and the host
// re-drives once the commit barrier reaches that seq). Revoked is the sweep input.
type RevocationDelta struct {
	Seq     uint64
	Revoked []RevokedAdmission
}

// RevokedSetSource supplies the vN→vN+1 REVOKED SET the host computed for a just-
// committed version — the seam the post-commit RevocationProducer reads to know WHAT to
// fan out. It exists because the frozen boundaryv1.PolicySnapshot carries only (seq,
// content_hash, opaque document): the structured revoked admission tuples are the host's
// own diff of the prior admitted set against the new one, NOT a proto field. A real host
// agent's diff engine satisfies this seam; a test fake returns a fixed set
// (revocation_producer_test.go). RevokedFor returns the revoked admissions the version
// at snap.Seq newly denies (possibly empty — a version that denies nothing is a clean
// no-fan-out), or a non-nil error if the diff could not be computed (which HOLDS the
// post-commit sweep, fail-closed: a committed version whose revoked-set is unknown must
// not advance apply_seq, because a tunnel that should sever might be missed).
type RevokedSetSource interface {
	RevokedFor(ctx context.Context, snap *boundaryv1.PolicySnapshot) ([]RevokedAdmission, error)
}

// RevokedSetFunc adapts a plain function to the RevokedSetSource seam (the package's
// func-adapter idiom), so a caller with a closure over its diff engine need not declare
// a named type.
type RevokedSetFunc func(ctx context.Context, snap *boundaryv1.PolicySnapshot) ([]RevokedAdmission, error)

// RevokedFor calls f.
func (f RevokedSetFunc) RevokedFor(ctx context.Context, snap *boundaryv1.PolicySnapshot) ([]RevokedAdmission, error) {
	return f(ctx, snap)
}

// ── the REAL vN→vN+1 diff engine (the RevokedSetSource production impl) ──
//
// RevokedSetDiffEngine is the host's real RevokedSetSource: it computes the vN→vN+1
// REVOKED SET by DIFFING successive committed policy snapshots' admitted sets — the
// (session, dst-key) flows the NEW version newly SEVERS relative to the version the host
// last applied. It is the structured diff the frozen boundaryv1.PolicySnapshot cannot
// carry as a proto field (the document is an OPAQUE payload, policy_stream.pb.go: "the
// on-wire encoding of the document body itself is free implementation behind this opaque
// payload"), so the host derives the revoked tuples ITSELF from two consecutive admitted
// sets rather than reading them off the wire.
//
// HOW THE DIFF SEVERS (D53, doc 12 §8). For each (SessionRef quartet, dst-key) flow that
// the PRIOR version admitted at a NON-severing rung, the engine emits a RevokedAdmission
// at the new version's rung when EITHER:
//
//   - the flow is GONE from vN+1 (the new version no longer admits it at all) — a full
//     removal severs at the configured removal rung (block+log by default: a removed
//     allow is now denied); OR
//   - the flow's rung was RAISED to block-or-higher in vN+1 (an allow that became a
//     block/suspend/kill) — the established tunnel must tear down at the NEW rung.
//
// A flow that stays admitted at the SAME (or a lower) non-severing rung produces NO
// revoked entry (nothing to sever — the consumer side leaves established flows untouched
// for a sub-block rung, D53). The revoked tuples are grouped per SessionRef quartet so a
// session that lost MULTIPLE dst-keys at the same rung fans out as ONE RevokedAdmission
// carrying all its revoked dst-keys (the wire's per-admission dst_count list), matching
// the consumer's per-session sweep input.
//
// THE DOCUMENT DECODE IS AN INJECTED SEAM. Because the document schema is "free
// implementation", the engine never hard-codes a parse: it reads the admitted set through
// an AdmittedSetDecoder the caller injects (a real host wires the POL-1 v0 decoder; a test
// fake returns a fixed set). The engine owns only the DIFF — the stateful vN→vN+1
// comparison — not the wire schema.
//
// FORWARD-ONLY, STATEFUL. The engine remembers the LAST admitted set it diffed against
// (keyed by the seq it belongs to). A snapshot at a seq AT OR BELOW the held version is a
// re-delivery: the diff is computed against the SAME held prior (idempotent — the same
// revoked set the first delivery produced), and the held prior is NOT rewound. A snapshot
// STRICTLY PAST the held version advances the held prior to it after the diff. The FIRST
// snapshot the engine ever sees has no prior to diff against — it SEEDS the prior and
// emits an EMPTY revoked set (there is nothing the host was serving before to sever; the
// first version's denies are enforced by the apply itself, not a revocation delta).
//
// FAIL-CLOSED. A decode fault is RETURNED (RevokedFor's error contract): the post-commit
// sweep HOLDS apply_seq rather than advancing past a version whose revoked-set could not be
// computed (a tunnel that should sever might be missed). The held prior is left UNCHANGED
// on a decode fault, so a re-drive re-diffs against the same baseline.
//
// NEVER-LOG-THE-SECRET (D73): the engine logs nothing; RevokedFor errors name only the seq
// and the decoder's structural defect, never a document byte or an admitted dst-key.
type RevokedSetDiffEngine struct {
	decode AdmittedSetDecoder
	// removalRung is the rung a flow REMOVED in vN+1 (admitted in vN, absent in vN+1)
	// severs at. A removed allow is now denied, so block+log is the natural default; a
	// deployment that wants a removal to suspend-or-kill overrides it at construction.
	removalRung Rung

	mu       sync.Mutex
	prior    AdmittedSet // the admitted set the host last diffed against (the held vN)
	priorSeq uint64      // the seq `prior` belongs to
	seeded   bool        // false until the first snapshot seeds the held prior
}

// AdmittedAdmission is ONE admitted (SessionRef quartet, dst-key, rung) flow in a decoded
// policy version's admitted set — the structured row the diff engine compares across
// versions. It mirrors the join-keys RevokedAdmission carries (the doc 14 §2/§4 SessionRef
// quartet) plus the single dst-key + rung the version admits that flow at. The decoder
// produces these from the opaque document; the engine never re-derives them.
type AdmittedAdmission struct {
	// SessionUUID / HostID / HostSessionIndex / TapName are the SessionRef quartet
	// (doc 14 §2/§4) — the join keys a revoked tuple carries verbatim.
	SessionUUID      string
	HostID           string
	HostSessionIndex uint32
	TapName          string
	// DstKey is the destination key (the DstKey inner string) this flow admits.
	DstKey string
	// Rung is the D53 rung this version admits the flow at (allow+log on a permitted
	// flow; a denying version admits at block-or-higher or drops the flow entirely).
	Rung Rung
}

// AdmittedSet is a decoded policy version's full admitted set — the (SessionRef, dst-key)
// → rung map the diff engine compares across versions. The engine reads it through the
// decoder seam; it is the STRUCTURED projection of the opaque document, NOT the document
// itself.
type AdmittedSet []AdmittedAdmission

// AdmittedSetDecoder projects an opaque PolicySnapshot.document into the structured
// AdmittedSet the diff engine compares. It is an INJECTED seam because the document's
// internal schema is free implementation behind the frozen (seq, content_hash, document)
// identity (policy_stream.pb.go): a real host wires the POL-1 v0 document decoder; a test
// fake returns a fixed set. A decode fault is fail-closed at the engine (it HOLDS
// apply_seq). The decoder MUST NOT log a document byte (D73).
type AdmittedSetDecoder interface {
	Decode(ctx context.Context, snap *boundaryv1.PolicySnapshot) (AdmittedSet, error)
}

// AdmittedSetDecoderFunc adapts a plain function to the AdmittedSetDecoder seam (the
// package's func-adapter idiom).
type AdmittedSetDecoderFunc func(ctx context.Context, snap *boundaryv1.PolicySnapshot) (AdmittedSet, error)

// Decode calls f.
func (f AdmittedSetDecoderFunc) Decode(ctx context.Context, snap *boundaryv1.PolicySnapshot) (AdmittedSet, error) {
	return f(ctx, snap)
}

// NewRevokedSetDiffEngine builds the real diff engine over decode (the document →
// admitted-set seam). A nil decoder is rejected fail-closed (an engine with no way to read
// an admitted set could never compute a diff). The removal rung — the rung a flow REMOVED
// in vN+1 severs at — defaults to RungBlockLog (a removed allow is now denied); pass an
// out-of-ladder rung and construction is rejected (the engine never carries a rung it
// could not encode).
func NewRevokedSetDiffEngine(decode AdmittedSetDecoder) (*RevokedSetDiffEngine, error) {
	return NewRevokedSetDiffEngineWithRemovalRung(decode, RungBlockLog)
}

// NewRevokedSetDiffEngineWithRemovalRung is NewRevokedSetDiffEngine with an EXPLICIT
// removal rung (the rung a flow admitted in vN but ABSENT in vN+1 severs at). A nil decoder
// or an out-of-ladder removal rung is rejected fail-closed.
func NewRevokedSetDiffEngineWithRemovalRung(decode AdmittedSetDecoder, removalRung Rung) (*RevokedSetDiffEngine, error) {
	if decode == nil {
		return nil, fmt.Errorf("hostagent: NewRevokedSetDiffEngine: nil admitted-set decoder (no way to read a version's admitted set)")
	}
	if _, ok := rungWireByte(removalRung); !ok {
		return nil, fmt.Errorf("hostagent: NewRevokedSetDiffEngine: removal rung %d is outside the D53 ladder", removalRung)
	}
	return &RevokedSetDiffEngine{decode: decode, removalRung: removalRung}, nil
}

// admittedKey is the per-flow identity the diff engine maps across versions: the SessionRef
// quartet + the dst-key. Two versions' flows are "the same flow" iff their admittedKey is
// equal; the diff compares the rung (and presence) of each flow across the two versions.
type admittedKey struct {
	sessionUUID      string
	hostID           string
	hostSessionIndex uint32
	tapName          string
	dstKey           string
}

func keyOf(a AdmittedAdmission) admittedKey {
	return admittedKey{
		sessionUUID:      a.SessionUUID,
		hostID:           a.HostID,
		hostSessionIndex: a.HostSessionIndex,
		tapName:          a.TapName,
		dstKey:           a.DstKey,
	}
}

// sessionKey is the SessionRef quartet alone (no dst-key) — the grouping key for the
// fanned-out RevocationDelta: all the dst-keys a single session lost at the same severing
// rung ride ONE RevokedAdmission (the wire's per-admission dst_count list).
type sessionKey struct {
	sessionUUID      string
	hostID           string
	hostSessionIndex uint32
	tapName          string
	rung             Rung
}

// RevokedFor computes the vN→vN+1 revoked set for the just-committed snapshot — the
// RevokedSetSource the post-commit RevocationProducer reads. It decodes snap's admitted
// set, diffs it against the held prior version, and returns the (session, dst-keys, rung)
// tuples the new version newly SEVERS (a removed flow at the removal rung; a flow whose
// rung rose to block-or-higher at the new rung). The FIRST snapshot seeds the prior and
// returns an empty set; a re-delivery diffs against the same prior idempotently. A decode
// fault is returned (the post-commit sweep HOLDS apply_seq, fail-closed) and the held prior
// is unchanged.
func (e *RevokedSetDiffEngine) RevokedFor(ctx context.Context, snap *boundaryv1.PolicySnapshot) ([]RevokedAdmission, error) {
	if snap == nil {
		return nil, fmt.Errorf("hostagent: diff engine: nil snapshot")
	}
	seq := snap.GetSeq()
	next, err := e.decode.Decode(ctx, snap)
	if err != nil {
		// Fail-closed: a version whose admitted set could not be decoded HOLDS apply_seq
		// (the sweep does not advance past a version whose revoked set is unknown). The
		// held prior is left unchanged so a re-drive re-diffs against the same baseline.
		return nil, fmt.Errorf("hostagent: diff engine: decode admitted set for seq %d: %w", seq, err)
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// The first snapshot the engine ever sees has no prior to diff against — SEED the held
	// prior and emit an empty revoked set (there is nothing the host was serving before to
	// sever; the first version's denies are enforced by the apply itself). A seq that is
	// STRICTLY PAST the held version advances the held prior after the diff; a re-delivery
	// (seq at or below the held version) diffs against the SAME prior and does not rewind it.
	if !e.seeded {
		e.prior = next
		e.priorSeq = seq
		e.seeded = true
		return nil, nil
	}

	revoked := diffAdmittedSets(e.prior, next, e.removalRung)

	if seq > e.priorSeq {
		// Forward-only advance: roll the held baseline to vN+1 so the NEXT diff is vN+1→vN+2.
		e.prior = next
		e.priorSeq = seq
	}
	return revoked, nil
}

// diffAdmittedSets computes the revoked set of prior→next: the flows prior admitted at a
// NON-severing rung that next either DROPS (severs at removalRung) or RAISES to
// block-or-higher (severs at the new rung). Flows that stay at the same/lower non-severing
// rung produce nothing. The result groups dst-keys per (SessionRef quartet, severing rung)
// so a session that lost several flows at one rung fans out as ONE RevokedAdmission. The
// output is DETERMINISTIC (sorted by the session quartet then dst-key) so the encoded wire
// bytes are stable across runs (the cross-process test pins exact bytes).
func diffAdmittedSets(prior, next AdmittedSet, removalRung Rung) []RevokedAdmission {
	// Index next by flow key so a prior flow's fate (gone / raised / unchanged) is an O(1)
	// lookup. A flow admitted twice in next (a malformed decode) keeps the LAST — the diff
	// is defensive, not a validator (the decoder owns schema validity).
	nextByKey := make(map[admittedKey]AdmittedAdmission, len(next))
	for _, a := range next {
		nextByKey[keyOf(a)] = a
	}

	// Group revoked dst-keys per (session quartet, severing rung). A session that lost
	// flows at TWO different rungs fans out as TWO RevokedAdmissions (one per rung) — the
	// wire carries a single rung per admission, so distinct severing rungs cannot share one.
	grouped := make(map[sessionKey][]string)
	for _, was := range prior {
		// Only flows the prior version admitted at a NON-severing rung can be NEWLY severed
		// by next. A flow prior already severed (block-or-higher) is not "newly" revoked by
		// this version — it was already torn down when prior committed.
		if was.Rung.Severs() {
			continue
		}
		now, stillThere := nextByKey[keyOf(was)]
		var severAt Rung
		switch {
		case !stillThere:
			// Gone from vN+1 — a removed allow is now denied. Sever at the removal rung.
			severAt = removalRung
		case now.Rung.Severs():
			// Still present but RAISED to block-or-higher — sever at the NEW rung.
			severAt = now.Rung
		default:
			// Still admitted at a non-severing rung — nothing to sever (D53 leaves
			// established sub-block flows untouched).
			continue
		}
		sk := sessionKey{
			sessionUUID:      was.SessionUUID,
			hostID:           was.HostID,
			hostSessionIndex: was.HostSessionIndex,
			tapName:          was.TapName,
			rung:             severAt,
		}
		grouped[sk] = append(grouped[sk], was.DstKey)
	}

	if len(grouped) == 0 {
		return nil
	}

	// Deterministic output: sort the session-rung groups, and each group's dst-keys, so the
	// fanned-out delta (and its encoded wire bytes) is stable across runs.
	out := make([]RevokedAdmission, 0, len(grouped))
	for sk, dstKeys := range grouped {
		sort.Strings(dstKeys)
		out = append(out, RevokedAdmission{
			SessionUUID:      sk.sessionUUID,
			HostID:           sk.hostID,
			HostSessionIndex: sk.hostSessionIndex,
			TapName:          sk.tapName,
			Rung:             sk.rung,
			DstKeys:          dstKeys,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.SessionUUID != b.SessionUUID {
			return a.SessionUUID < b.SessionUUID
		}
		if a.HostID != b.HostID {
			return a.HostID < b.HostID
		}
		if a.HostSessionIndex != b.HostSessionIndex {
			return a.HostSessionIndex < b.HostSessionIndex
		}
		if a.TapName != b.TapName {
			return a.TapName < b.TapName
		}
		return a.Rung < b.Rung
	})
	return out
}

// Compile-time proof the diff engine satisfies the RevokedSetSource seam the
// RevocationProducer reads.
var _ RevokedSetSource = (*RevokedSetDiffEngine)(nil)

// ── the wire codec (byte-for-byte the consumer's RevocationDeltaWire) ──

// revocationFrameMaxBody is the hard cap on a single revocation-delta frame body — MUST
// match RevocationDeltaWire::MAX_FRAME_BODY (64*1024) in the ds-tlsproxy consumer. A
// body over the cap is a malformed frame the consumer drops fail-closed, so the producer
// REFUSES to emit one (emitting it would silently drop a — possibly severing — delta).
const revocationFrameMaxBody = 64 * 1024

// encodeRevocationDelta encodes a delta body (NO frame length prefix), the exact layout
// the consumer's RevocationDeltaWire::decode_delta parses — the byte-for-byte inverse of
// the Rust decoder. The rung is mapped through the single-sourced rungWireByte table; a
// rung outside the defined ladder is rejected (the encoder never emits a guessed byte).
// A field whose length does not fit a u32 is rejected (the consumer's len-prefixes are
// u32) — unreachable for well-formed session/dst-key strings, but guarded so an oversized
// input fails loud rather than wrapping.
func encodeRevocationDelta(delta *RevocationDelta) ([]byte, error) {
	if delta == nil {
		return nil, fmt.Errorf("hostagent: revocation producer: nil delta")
	}
	if len(delta.Revoked) > maxU32 {
		return nil, fmt.Errorf("hostagent: revocation producer: revoked_count %d exceeds u32", len(delta.Revoked))
	}
	out := make([]byte, 0, 12)
	out = binary.BigEndian.AppendUint64(out, delta.Seq)
	out = binary.BigEndian.AppendUint32(out, uint32(len(delta.Revoked)))
	for i := range delta.Revoked {
		adm := &delta.Revoked[i]
		var err error
		if out, err = putWireStr(out, adm.SessionUUID); err != nil {
			return nil, fmt.Errorf("hostagent: revocation producer: encode session_uuid: %w", err)
		}
		if out, err = putWireStr(out, adm.HostID); err != nil {
			return nil, fmt.Errorf("hostagent: revocation producer: encode host_id: %w", err)
		}
		out = binary.BigEndian.AppendUint32(out, adm.HostSessionIndex)
		if out, err = putWireStr(out, adm.TapName); err != nil {
			return nil, fmt.Errorf("hostagent: revocation producer: encode tap_name: %w", err)
		}
		b, ok := rungWireByte(adm.Rung)
		if !ok {
			return nil, fmt.Errorf("hostagent: revocation producer: rung %d is outside the D53 ladder (refusing to emit a guessed wire byte)", adm.Rung)
		}
		out = append(out, b)
		if len(adm.DstKeys) > maxU32 {
			return nil, fmt.Errorf("hostagent: revocation producer: dst_count %d exceeds u32", len(adm.DstKeys))
		}
		out = binary.BigEndian.AppendUint32(out, uint32(len(adm.DstKeys)))
		for _, dst := range adm.DstKeys {
			if out, err = putWireStr(out, dst); err != nil {
				return nil, fmt.Errorf("hostagent: revocation producer: encode dst_key: %w", err)
			}
		}
	}
	return out, nil
}

// maxU32 is the largest value a u32 length-prefix can carry. Field lengths are checked
// against it so an oversized input fails loud rather than wrapping a u32 cast.
const maxU32 = int(^uint32(0))

// putWireStr appends a length-prefixed string (len(u32 BE) + utf8 bytes) — the SAME
// put_str the consumer's take_str reads. A string whose byte length does not fit a u32
// is rejected (unreachable for a real session/dst-key, guarded for safety).
func putWireStr(out []byte, s string) ([]byte, error) {
	if len(s) > maxU32 {
		return nil, fmt.Errorf("string length %d exceeds u32", len(s))
	}
	out = binary.BigEndian.AppendUint32(out, uint32(len(s)))
	out = append(out, s...)
	return out, nil
}

// writeRevocationFrame writes ONE length-prefixed frame (a 4-byte big-endian body length
// + the body) to w — the SAME framing the consumer's read_revocation_frame expects. A
// body over revocationFrameMaxBody is rejected BEFORE any byte is written (the consumer
// would drop it fail-closed, dropping a — possibly severing — delta), so the producer
// never half-writes an over-cap frame.
func writeRevocationFrame(w net.Conn, body []byte) error {
	if len(body) > revocationFrameMaxBody {
		return fmt.Errorf("hostagent: revocation producer: frame body %d over cap %d (consumer would drop it fail-closed)", len(body), revocationFrameMaxBody)
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(body)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	if _, err := w.Write(body); err != nil {
		return err
	}
	return nil
}

// ── the env gate + endpoint (single-sourced with the consumer) ──

// revocationFeedLiveEnv is the host-integration gate that ARMS the live UDS dial. MUST
// match REVOCATION_FEED_LIVE_ENV in the ds-tlsproxy consumer (main.rs): UNSET keeps the
// producer a no-op (byte-identical default); SET arms the cross-process delivery.
// Presence-only (the value is never read), like the consumer's gate.
const revocationFeedLiveEnv = "DS_REVOCATION_FEED_LIVE"

// revocationFeedEndpointEnv is the env var that single-sources the revocation-delta feed
// UDS endpoint path. Unset/empty => RevocationFeedDefaultEndpoint. MUST match
// REVOCATION_FEED_ENDPOINT_ENV in the consumer (main.rs), so the producer dials EXACTLY
// the path the subscriber binds.
const revocationFeedEndpointEnv = "DS_TLSPROXY_REVOCATION_LISTEN"

// RevocationFeedDefaultEndpoint is the default host-local UDS the producer dials and the
// ds-tlsproxy subscriber binds when neither side overrides it. MUST match
// REVOCATION_FEED_DEFAULT_ENDPOINT in the consumer (main.rs); the ONE place the path
// resolves on each side single-sources it (RevocationFeedEndpoint here /
// revocation_feed_endpoint there).
const RevocationFeedDefaultEndpoint = "/run/ds-tlsproxy/revocation.sock"

// RevocationFeedLiveEnabled reports whether the host-integration gate is set — the
// kill-switch that arms the live UDS dial. Presence-only (mirrors the consumer's
// revocation_feed_live_enabled); UNSET keeps the producer a no-op (byte-identical
// default). The live e2e (revocation_producer_test.go, gated on this env) exercises the
// real cross-process delivery only when the operator opts in.
func RevocationFeedLiveEnabled() bool {
	_, set := os.LookupEnv(revocationFeedLiveEnv)
	return set
}

// RevocationFeedEndpoint resolves the UDS endpoint the producer dials — the env override
// (revocationFeedEndpointEnv) when set non-empty, else RevocationFeedDefaultEndpoint. The
// ONE place the path resolves on the producer side (mirrors the consumer's
// revocation_feed_endpoint), so the producer dials the path the subscriber binds.
func RevocationFeedEndpoint() string {
	if v := os.Getenv(revocationFeedEndpointEnv); v != "" {
		return v
	}
	return RevocationFeedDefaultEndpoint
}

// ── the producer (a post-commit Sweeper) ──

// defaultRevocationDialTimeout bounds the live UDS connect so a wedged / absent
// ds-tlsproxy listener never hangs the post-commit sweep indefinitely. The dial is a
// host-LOCAL UDS connect (no network), so a healthy listener connects in microseconds; a
// few seconds is a generous ceiling that still fails the sweep promptly (fail-closed: the
// host holds apply_seq and re-drives) when the listener is down.
const defaultRevocationDialTimeout = 3 * time.Second

// RevocationProducer is the host-local POST-COMMIT REVOCATION-DELTA producer (doc 12 §8):
// on each committed version it reads the vN→vN+1 revoked set from its RevokedSetSource,
// encodes the RevocationDeltaWire frame byte-for-byte, and (behind DS_REVOCATION_FEED_LIVE)
// DIALS the ds-tlsproxy subscriber's UDS and delivers the frame — so a severing-rung delta
// tears down the established tunnel + drops pooled upstream sockets at the proxy NOW.
//
// It satisfies the apply.go Sweeper seam, so it is composed into the post-commit
// SweeperChain (feedwriter.go BindFeedProducers passes the REAL revocation Sweeper as its
// `revocation` arg) FIRST — the host is swept onto vN+1 before the feed/carrier fan the
// new version out (D72: apply_seq advances post-sweep).
//
// DEFAULT-OFF: with DS_REVOCATION_FEED_LIVE unset, Sweep is a clean no-op (no dial, no
// frame built) — byte-identical to the pre-producer daemon. The encode + frame shape are
// unit-proven regardless of the gate (the live e2e is the gated cross-process leg).
type RevocationProducer struct {
	// source supplies the vN→vN+1 revoked set per committed version (the host's diff).
	source RevokedSetSource
	// endpoint is the resolved UDS path the producer dials (RevocationFeedEndpoint by
	// default; overridable for tests via NewRevocationProducerAt).
	endpoint string
	// live gates the cross-process dial. When false, Sweep is a no-op after reading the
	// revoked set (the gate-unset default). Captured at construction from the env gate.
	live bool
	// dialTimeout bounds the live UDS connect.
	dialTimeout time.Duration
}

// NewRevocationProducer builds the producer over source, resolving the endpoint
// (RevocationFeedEndpoint) and the live gate (RevocationFeedLiveEnabled) from the env —
// the production constructor the host-agent daemon calls. A nil source is rejected
// fail-closed (a producer with no diff engine could never know what to revoke). The
// daemon passes the returned producer as the SweeperChain's revocation leg (feedwriter.go).
func NewRevocationProducer(source RevokedSetSource) (*RevocationProducer, error) {
	return NewRevocationProducerAt(source, RevocationFeedEndpoint(), RevocationFeedLiveEnabled())
}

// NewRevocationProducerAt builds the producer over source with an EXPLICIT endpoint +
// live gate — the seam the live e2e (and the production constructor) build over so a test
// can dial a temp UDS without setting process env, and the daemon can single-source the
// endpoint with the deployment. A nil source is rejected fail-closed; an empty endpoint
// with live==true is rejected (a live producer with no path could never deliver). The
// dial timeout defaults to defaultRevocationDialTimeout.
func NewRevocationProducerAt(source RevokedSetSource, endpoint string, live bool) (*RevocationProducer, error) {
	if source == nil {
		return nil, fmt.Errorf("hostagent: NewRevocationProducer: nil revoked-set source (no diff engine to compute the vN→vN+1 revoked set)")
	}
	if live && endpoint == "" {
		return nil, fmt.Errorf("hostagent: NewRevocationProducer: live producer with empty endpoint (set %s or pass an explicit path)", revocationFeedEndpointEnv)
	}
	return &RevocationProducer{
		source:      source,
		endpoint:    endpoint,
		live:        live,
		dialTimeout: defaultRevocationDialTimeout,
	}, nil
}

// Live reports whether the cross-process dial is armed (DS_REVOCATION_FEED_LIVE set, or
// live==true passed to NewRevocationProducerAt). False on the default-OFF path.
func (p *RevocationProducer) Live() bool { return p.live }

// Endpoint returns the resolved UDS path the producer dials — the value a deployment must
// single-source with the ds-tlsproxy subscriber's DS_TLSPROXY_REVOCATION_LISTEN so the two
// halves resolve the same socket.
func (p *RevocationProducer) Endpoint() string { return p.endpoint }

// Sweep satisfies the apply.go Sweeper seam: the ApplyCoordinator invokes Sweep(ctx, snap)
// ONLY after a fully-successful commit (all three consumers flipped vN+1 admitter-LAST),
// which is EXACTLY the barrier the revocation delta must be fanned out behind (doc 13
// §5.2). It reads the vN→vN+1 revoked set from the source, and — behind the live gate —
// encodes + delivers the RevocationDeltaWire frame to the proxy UDS. It returns
// snap.GetSeq() as the swept seq on success so the coordinator advances apply_seq
// post-fan-out (D72).
//
// FAIL-CLOSED. A source error (the diff could not be computed) is returned so the
// coordinator HOLDS apply_seq at the prior version — a committed version whose revoked-set
// is unknown must not advance the resume cursor, because a tunnel that should sever might
// be missed. On the LIVE path a dial/encode/write failure is likewise returned (the host
// holds apply_seq and re-drives); a delivered-but-not-yet-committed seq is fail-closed at
// the CONSUMER (UnknownToken), and the host re-drives once the commit barrier reaches it.
//
// EMPTY REVOKED SET: a version that denies nothing produces an empty delta. On the live
// path a delta with zero revoked admissions is STILL delivered (a well-formed frame the
// consumer decodes to an empty sweep — a no-op on its side), so the wire stream stays a
// faithful per-commit record; the no-op is cheap. On the default-OFF path nothing is
// dialed regardless.
func (p *RevocationProducer) Sweep(ctx context.Context, snap *boundaryv1.PolicySnapshot) (uint64, error) {
	if snap == nil {
		return 0, fmt.Errorf("hostagent: revocation producer: Sweep on nil snapshot")
	}
	seq := snap.GetSeq()
	revoked, err := p.source.RevokedFor(ctx, snap)
	if err != nil {
		// The host could not compute the vN→vN+1 revoked set — HOLD apply_seq (a missed
		// sever is worse than a held seq the host re-drives). NEVER-LOG-THE-SECRET: the
		// error names only the seq + the source defect.
		return 0, fmt.Errorf("hostagent: revocation producer: compute revoked set for seq %d: %w", seq, err)
	}
	if !p.live {
		// Default-OFF: the gate is unset — no socket is dialed, no frame is built. The
		// host-agent daemon is byte-identical to the pre-producer build. (We still read the
		// revoked set above so the source seam is exercised identically on both paths; a
		// source error still holds apply_seq.)
		return seq, nil
	}
	if err := p.deliver(ctx, &RevocationDelta{Seq: seq, Revoked: revoked}); err != nil {
		return 0, fmt.Errorf("hostagent: revocation producer: deliver delta for seq %d: %w", seq, err)
	}
	return seq, nil
}

// deliver dials the ds-tlsproxy subscriber's UDS, encodes the RevocationDeltaWire frame,
// and writes it — the live cross-process leg (behind DS_REVOCATION_FEED_LIVE). The encode
// runs BEFORE the dial so an encode defect (an out-of-ladder rung, an over-cap body) fails
// without touching the socket. The dial is bounded by p.dialTimeout (a wedged/absent
// listener never hangs the post-commit sweep); the connection is closed after the single
// frame is written (one delta per connection — the consumer's serve_revocation_feed drains
// every framed delta until the peer closes, so a one-frame-then-close producer is the
// simplest faithful peer). The ctx deadline (if any, sooner than the dial timeout) bounds
// the connect too.
func (p *RevocationProducer) deliver(ctx context.Context, delta *RevocationDelta) error {
	body, err := encodeRevocationDelta(delta)
	if err != nil {
		return err
	}
	if len(body) > revocationFrameMaxBody {
		// The frame would be dropped fail-closed at the consumer (a missed — possibly
		// severing — delta). Refuse to deliver it; the host re-drives (a real diff this
		// large is a bug worth surfacing, not silently truncating).
		return fmt.Errorf("revocation delta body %d over cap %d (consumer would drop it fail-closed)", len(body), revocationFrameMaxBody)
	}
	dialer := net.Dialer{Timeout: p.dialTimeout}
	conn, err := dialer.DialContext(ctx, "unix", p.endpoint)
	if err != nil {
		return fmt.Errorf("dial revocation feed %q: %w", p.endpoint, err)
	}
	defer conn.Close()
	// Bound the write by the ctx deadline when one is set (a wedged consumer never hangs
	// the sweep); an unset ctx deadline leaves the write blocking (the host-serial sweep
	// pump owns the cadence). A SetWriteDeadline error is non-fatal (some conns may not
	// support it) — the write below still fails loud on a real fault.
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetWriteDeadline(deadline)
	}
	if err := writeRevocationFrame(conn, body); err != nil {
		return fmt.Errorf("write revocation frame to %q: %w", p.endpoint, err)
	}
	return nil
}

// Compile-time proof the producer satisfies the apply.go Sweeper seam so it composes into
// the post-commit SweeperChain (feedwriter.go) as the revocation leg.
var _ Sweeper = (*RevocationProducer)(nil)
