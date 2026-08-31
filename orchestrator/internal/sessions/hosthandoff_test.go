// SPDX-License-Identifier: Apache-2.0

// Host-handoff digest-continuity integration test (doc 16 §6.3 default d; doc
// 15 — the orchestrator-owned redeploy choreography).
//
// THE GAP THIS CLOSES. The identity side already proves the SINGLE-consumer
// re-key ordering: identity/digest/keys_test.go (TestLiveRekeyHasNoGap_*) and
// rotation_test.go (TestLiveRekeyFleet*) show a host re-pushing every live
// digest under the new key and acking it BEFORE the old key is retired, so a
// session is never unshadowed. The SCOPE FENCE in identity/digest/rotation.go
// lines 15-18 leaves the larger redeploy choreography — "which sessions are
// live, and the larger redeploy choreography, are the orchestrator's (doc 15)"
// — explicitly to THIS tree. That residual is a TWO-HOST property the
// single-consumer identity test cannot express: when a boundary host is
// REDEPLOYED, the orchestrator must observe the freshly-stood-up NEW host
// LOADED + ACKED with the re-pushed new-key digest set BEFORE the OLD host's
// digest set is revoked / torn down. Otherwise there is an instant in which
// neither host shadows a live session — exactly the mint-before-attach gap,
// applied across a host swap rather than across a key flip on one host.
//
// WHAT THIS TEST ASSERTS. It drives the PRODUCTION controller in hosthandoff.go
// (runHostHandoff over the FROZEN dreamserpent.identity.v1.DigestFeedService
// seam) against TWO DISTINCT host states, each a hostConsumer (the in-process
// DigestFeedService stand-in for the D109 host-agent ack-er):
//
//   - oldHost — the host being retired, already LOADED with the old-key digests
//     for every live session (the original mint-before-attach publish).
//   - newHost — the freshly redeployed host, starts EMPTY and must be loaded
//     with the new-key digest set and ack committed.
//
// It runs the orchestrator-owned host-handoff sequence — re-publish to the NEW
// host, gate on its committed ack, and ONLY THEN revoke the OLD host — and
// asserts, against a single recorded event journal across BOTH consumers, that
// the new host is observed loaded+acked STRICTLY BEFORE the old host's digests
// are revoked, with no instant at which neither host shadows a session. It also
// proves the fail-closed leg: an incomplete new-host registration (an
// uncommitted ack, a transport error, or a short load) leaves the OLD host
// loaded and untouched — no gap, the redeploy is retried or aborted.
//
// SCOPE. This is an ORCHESTRATOR-OWNED choreography test. It does NOT import
// identity/digest (the only legal cross-tree import is proto/gen/go, D80): the
// controller it exercises drives the FROZEN proto seam directly and re-derives
// the "no-gap" property from the wire, exactly as the orchestrator's redeploy
// controller observes it. The identity-side digest computation + the per-host
// re-key ordering are proven on that side; here we prove the orchestrator never
// opens a host-swap gap. SYNTHETIC ONLY (D50): every credential id is a
// `ds-synth-*` token; there is no live host, no live boundary, no live claude.
// Any live host-redeploy leg is env-gated and skipped (a deferred manual step).
package sessions

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
)

// ---- synthetic fixtures (D50) --------------------------------------------

// synthOldKeyID / synthNewKeyID are the per-host per-epoch HMAC key ids (doc 16
// §6.3) the pre-redeploy and post-redeploy digest sets are stamped under. They
// are opaque ids on the wire — the orchestrator never holds key material — so a
// synthetic string id is the whole truth this seam sees. They MUST differ: a
// redeploy advances the generation so a host never reuses a key.
const (
	synthOldKeyID = "ds-synth-dk-host-old-e0-g0"
	synthNewKeyID = "ds-synth-dk-host-new-e0-g1"
)

// synthLiveSessions is the live-session set under handoff — the residual the
// identity scope fence leaves to this tree (doc 15 is the authority for which
// sessions are live). Each carries SYNTHETIC ds-synth-* credential tokens
// (D50): the controller routes opaque entries and never touches real material.
func synthLiveSessions() []synthLiveSession {
	return []synthLiveSession{
		{uuid: "00000000-0000-4000-8000-0000000ho001", creds: []string{
			"ds-synth-sessA-github-pat",
			"ds-synth-sessA-canary",
		}},
		{uuid: "00000000-0000-4000-8000-0000000ho002", creds: []string{
			"ds-synth-sessB-aws-key",
		}},
	}
}

// ---- test plumbing -------------------------------------------------------

// dialHostFeed stands up an in-process gRPC server for a host consumer and
// returns a connected client, tearing both down via t.Cleanup. Same in-process
// shape the identity-side digest tests use (no live boundary — the wave rule).
func dialHostFeed(t *testing.T, h *hostConsumer) identityv1.DigestFeedServiceClient {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	identityv1.RegisterDigestFeedServiceServer(srv, h)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return identityv1.NewDigestFeedServiceClient(conn)
}

// preloadOldHost puts the old-key digest set on the old host for every live
// session — the pre-redeploy state (the original mint-before-attach publish at
// session create). It bypasses the journal's handoff semantics intentionally:
// this is setup, not part of the choreography under test.
func preloadOldHost(t *testing.T, oldHost identityv1.DigestFeedServiceClient, sessions []synthLiveSession) {
	t.Helper()
	for _, s := range sessions {
		resp, err := oldHost.DigestPublish(context.Background(), &identityv1.DigestPublishRequest{
			Session: &identityv1.DigestSessionRef{SessionUuid: s.uuid},
			Entries: synthEntriesFor(synthOldKeyID, s.creds),
			BatchId: "init-" + s.uuid,
		})
		if err != nil || !resp.GetCommitted() {
			t.Fatalf("preload old host for %q: err=%v committed=%v", s.uuid, err, resp.GetCommitted())
		}
	}
}

// ==========================================================================
// TESTS
// ==========================================================================

// TestHostHandoff_NewHostLoadedAndAckedBeforeOldHostRevoked is the core
// acceptance proof. A boundary host redeploy: the freshly stood-up NEW host is
// loaded with the new-key digest set and acks committed for EVERY live session,
// and ONLY THEN is the OLD host's digest set revoked — with no instant at which
// a session is shadowed by neither host. The shared journal makes the ordering
// (new-host committed publish strictly before old-host revoke, per session)
// directly checkable.
func TestHostHandoff_NewHostLoadedAndAckedBeforeOldHostRevoked(t *testing.T) {
	j := &handoffJournal{}
	oldH := newHostConsumer("old", j)
	newH := newHostConsumer("new", j)
	oldClient := dialHostFeed(t, oldH)
	newClient := dialHostFeed(t, newH)

	sessions := synthLiveSessions()

	// Pre-redeploy: the OLD host shadows every live session under the old key.
	preloadOldHost(t, oldClient, sessions)
	for _, s := range sessions {
		if !oldH.shadows(s.uuid) {
			t.Fatalf("old host does not shadow %q before handoff", s.uuid)
		}
		if newH.shadows(s.uuid) {
			t.Fatalf("new host already shadows %q before handoff (should start empty)", s.uuid)
		}
	}

	out, err := runHostHandoff(context.Background(), newClient, oldClient, newH.loadedCountUnder, sessions, synthNewKeyID, synthOldKeyID)
	if err != nil {
		t.Fatalf("runHostHandoff happy path: %v", err)
	}
	if !out.newHostHandedOff || !out.oldHostRevoked {
		t.Fatalf("happy-path handoff incomplete: %+v", out)
	}

	for _, s := range sessions {
		// ORDERING (the no-gap proof): the new host's COMMITTED publish for this
		// session must be recorded strictly BEFORE the old host's revoke for it.
		newPubIdx := j.firstIndex("new", "publish", s.uuid, true /*committedOnly*/)
		oldRevIdx := j.firstIndex("old", "revoke", s.uuid, false)
		if newPubIdx < 0 {
			t.Fatalf("no committed new-host publish recorded for %q", s.uuid)
		}
		if oldRevIdx < 0 {
			t.Fatalf("no old-host revoke recorded for %q", s.uuid)
		}
		if !(newPubIdx < oldRevIdx) {
			t.Errorf("ordering violated for %q: new-host load+ack at %d, old-host revoke at %d — want load+ack STRICTLY before revoke (no-gap)",
				s.uuid, newPubIdx, oldRevIdx)
		}

		// END STATE: the new host shadows the session, the old host no longer does.
		if !newH.shadows(s.uuid) {
			t.Errorf("after handoff, new host does not shadow %q", s.uuid)
		}
		if oldH.shadows(s.uuid) {
			t.Errorf("after handoff, old host still shadows %q (not torn down)", s.uuid)
		}

		// NO DIGEST DROPPED: the new host loaded the FULL set under the new key.
		wantN := len(sessionCredsByUUID(sessions, s.uuid))
		if got := newH.loadedCountUnder(s.uuid, synthNewKeyID); got != wantN {
			t.Errorf("new host loaded %d entries for %q under %q, want %d (no digest dropped)",
				got, s.uuid, synthNewKeyID, wantN)
		}

		// FULL FROZEN doc 14 §7 SHAPE: every entry the new host loaded carries the
		// complete wire shape — key_id, algo (HMAC-SHA-256 + truncation length),
		// digest, cred_class (ISSUED{service_id} | FORBIDDEN), scope, expiry,
		// variant_tag — and the loaded set spans BOTH cred_class oneof arms across
		// the session's tokens. This proves the routing/continuity path carries the
		// full frozen entry shape, not the under-modelled subset, so a controller
		// mishandling a cred_class-tagged entry would surface.
		assertFrozenEntryShape(t, s.uuid, newH.entriesUnder(s.uuid, synthNewKeyID), synthNewKeyID)
	}

	// Across the whole live set, the new host's loaded entries must span BOTH
	// cred_class arms (ISSUED{service_id} AND FORBIDDEN) — the fixture exercises
	// the full §7 oneof, not just one branch.
	assertCredClassSpansBothArms(t, newH, sessions, synthNewKeyID)

	// GLOBAL ordering: the LAST committed new-host publish across all sessions
	// precedes the FIRST old-host revoke — the orchestrator never starts tearing
	// the old host down until the whole new host is loaded+acked.
	lastNewPub := -1
	firstOldRev := len(j.events)
	for i, e := range j.events {
		if e.host == "new" && e.op == "publish" && e.committed {
			if i > lastNewPub {
				lastNewPub = i
			}
		}
		if e.host == "old" && e.op == "revoke" && i < firstOldRev {
			firstOldRev = i
		}
	}
	if lastNewPub < 0 {
		t.Fatal("no committed new-host publish recorded at all")
	}
	if !(lastNewPub < firstOldRev) {
		t.Errorf("global no-gap violated: last new-host load+ack at %d, first old-host revoke at %d — the old host began teardown before the new host was fully loaded",
			lastNewPub, firstOldRev)
	}
}

// TestHostHandoff_NoInstantWithNeitherHostShadowing walks the choreography
// step by step and asserts the no-gap INVARIANT directly: at every observable
// point, every live session is shadowed by at least one host. It checks the
// invariant (a) before the handoff (old shadows), (b) after the new host is
// loaded but before the old is revoked (BOTH shadow), and (c) after the old is
// revoked (new shadows) — there is never a window in which neither does.
func TestHostHandoff_NoInstantWithNeitherHostShadowing(t *testing.T) {
	j := &handoffJournal{}
	oldH := newHostConsumer("old", j)
	newH := newHostConsumer("new", j)
	oldClient := dialHostFeed(t, oldH)
	newClient := dialHostFeed(t, newH)
	sessions := synthLiveSessions()

	preloadOldHost(t, oldClient, sessions)

	assertEveryShadowed := func(when string) {
		for _, s := range sessions {
			if !oldH.shadows(s.uuid) && !newH.shadows(s.uuid) {
				t.Fatalf("%s: session %q shadowed by NEITHER host — a continuity gap", when, s.uuid)
			}
		}
	}

	// (a) before handoff: old host shadows.
	assertEveryShadowed("pre-handoff")

	// (b) load the new host (step 1) WITHOUT yet revoking the old — both shadow.
	for _, s := range sessions {
		resp, err := newClient.DigestPublish(context.Background(), &identityv1.DigestPublishRequest{
			Session: &identityv1.DigestSessionRef{SessionUuid: s.uuid},
			Entries: synthEntriesFor(synthNewKeyID, s.creds),
			BatchId: "handoff-" + s.uuid,
		})
		if err != nil || !resp.GetCommitted() {
			t.Fatalf("new-host load for %q: err=%v committed=%v", s.uuid, err, resp.GetCommitted())
		}
		// The instant the new host is loaded, the old host MUST still be loaded.
		if !oldH.shadows(s.uuid) {
			t.Fatalf("old host stopped shadowing %q during the new-host load — a gap", s.uuid)
		}
		assertEveryShadowed("new-host-loaded, old-host-not-yet-revoked")
	}

	// (c) only now revoke the old host, session by session — after each revoke
	// the new host still shadows, so no session ever goes dark.
	for _, s := range sessions {
		resp, err := oldClient.DigestRevoke(context.Background(), &identityv1.DigestRevokeRequest{
			Session: &identityv1.DigestSessionRef{SessionUuid: s.uuid},
			KeyIds:  []string{synthOldKeyID},
			Scope:   identityv1.DigestScope_DIGEST_SCOPE_SESSION,
		})
		if err != nil || !resp.GetCommitted() {
			t.Fatalf("old-host revoke for %q: err=%v committed=%v", s.uuid, err, resp.GetCommitted())
		}
		if !newH.shadows(s.uuid) {
			t.Fatalf("after revoking old host for %q the new host does not shadow it — a gap", s.uuid)
		}
		assertEveryShadowed("old-host-revoked")
	}
}

// svCell is one cell of the doc 14 §7 scope x variant_tag cross-product: a
// sub-test name plus the DigestScope + DigestVariantTag the entries are stamped
// under for that cell.
type svCell struct {
	name    string
	scope   identityv1.DigestScope
	variant identityv1.DigestVariantTag
}

// scopeVariantMatrix is the full doc 14 §7 scope x variant_tag cross-product the
// continuity path must hold across: DigestScope SESSION|FLEET (the two real arms;
// UNSPECIFIED is not a pushed scope) x DigestVariantTag RAW|BASE64|URLENC|HEX (all
// four real encodings) — 8 cells. It is the single source of cells for the matrix
// tests so adding a §7 enum value here surfaces every continuity test that must
// cover it.
func scopeVariantMatrix() []svCell {
	scopes := []struct {
		name  string
		scope identityv1.DigestScope
	}{
		{"SESSION", identityv1.DigestScope_DIGEST_SCOPE_SESSION},
		{"FLEET", identityv1.DigestScope_DIGEST_SCOPE_FLEET},
	}
	variants := []struct {
		name string
		tag  identityv1.DigestVariantTag
	}{
		{"RAW", identityv1.DigestVariantTag_DIGEST_VARIANT_TAG_RAW},
		{"BASE64", identityv1.DigestVariantTag_DIGEST_VARIANT_TAG_BASE64},
		{"URLENC", identityv1.DigestVariantTag_DIGEST_VARIANT_TAG_URLENC},
		{"HEX", identityv1.DigestVariantTag_DIGEST_VARIANT_TAG_HEX},
	}
	out := make([]svCell, 0, len(scopes)*len(variants))
	for _, sc := range scopes {
		for _, v := range variants {
			out = append(out, svCell{name: sc.name + "/" + v.name, scope: sc.scope, variant: v.tag})
		}
	}
	return out
}

// TestHostHandoff_Continuity_ScopeVariantMatrix is the unit's primary proof: the
// DIRECT runHostHandoff continuity path (the happy-path choreography +
// loadedCountUnder full-set verify + the no-gap ordering) holds IDENTICALLY across
// the full doc 14 §7 scope x variant_tag cross-product — SESSION+FLEET x
// {RAW,BASE64,URLENC,HEX}. The existing core acceptance tests
// (TestHostHandoff_NewHostLoadedAndAckedBeforeOldHostRevoked /
// _NoInstantWithNeitherHostShadowing) exercise only the default SESSION/RAW shape,
// and the FU6 matrix proof covers only the RETRY-to-convergence loop
// (TestHostHandoff_RetryToConvergence_ScopeAndVariantOpacity); this proves the
// CONTROLLER ITSELF is opaque to both scope and encoding on the primary (non-retry)
// path. For every cell it:
//
//	(happy path) drives runHostHandoff to completion (newHostHandedOff +
//	    oldHostRevoked) — the choreography is unchanged by scope/encoding;
//	(no-gap, per session) the new host's COMMITTED publish precedes the old host's
//	    revoke in the shared journal — load+ack STRICTLY before teardown;
//	(no-gap, global) the LAST committed new-host publish precedes the FIRST
//	    old-host revoke — the old host is never touched until the whole new host is
//	    loaded+acked;
//	(full-set) loadedCountUnder == the full credential set for the session under
//	    the new key — no digest dropped in any encoding;
//	(end state) the new host shadows every session, the old host none;
//	(opacity) every loaded entry carries the PARAMETERIZED scope + variant_tag
//	    unchanged — a controller that rewrote either (or that special-cased a
//	    FLEET/HEX entry off the routing path) would surface; and the canary
//	    (FORBIDDEN cred_class) is present in EVERY variant, the D73
//	    canary-never-egresses-in-any-pushed-variant anchor at the routing layer;
//	(both arms) the loaded set spans BOTH §7 cred_class oneof arms.
//
// SYNTHETIC ONLY (D50): two in-process hostConsumers, ds-synth-* tokens, no live
// host/boundary/claude. Additive: it leaves the SESSION/RAW core tests untouched.
func TestHostHandoff_Continuity_ScopeVariantMatrix(t *testing.T) {
	for _, cell := range scopeVariantMatrix() {
		t.Run(cell.name, func(t *testing.T) {
			j := &handoffJournal{}
			oldH := newHostConsumer("old", j)
			newH := newHostConsumer("new", j)
			oldClient := dialHostFeed(t, oldH)
			newClient := dialHostFeed(t, newH)

			// The live-session set stamped under THIS cell's scope + variant. The
			// controller routes entries opaquely, so a FLEET-scoped, HEX-tagged
			// handoff must converge exactly as the default SESSION/RAW one.
			sessions := scopedVariantSessions(cell.scope, cell.variant)

			// Pre-redeploy: the OLD host shadows every live session under the old key.
			// The preload uses the SESSION/RAW synthEntriesFor (the original
			// mint-before-attach publish shape); the handoff under test stamps the
			// NEW-key set under the cell's scope+variant via the production
			// synthEntriesForVariant. The continuity property is about COUNTS +
			// ORDERING, which are scope/variant-agnostic, so the preload shape does
			// not matter — only that the old host shadows the full set first.
			preloadOldHost(t, oldClient, sessions)
			for _, s := range sessions {
				if !oldH.shadows(s.uuid) {
					t.Fatalf("%s: old host does not shadow %q before handoff", cell.name, s.uuid)
				}
				if newH.shadows(s.uuid) {
					t.Fatalf("%s: new host already shadows %q before handoff (should start empty)", cell.name, s.uuid)
				}
			}

			out, err := runHostHandoff(context.Background(), newClient, oldClient, newH.loadedCountUnder, sessions, synthNewKeyID, synthOldKeyID)
			if err != nil {
				t.Fatalf("%s: runHostHandoff happy path: %v", cell.name, err)
			}
			if !out.newHostHandedOff || !out.oldHostRevoked {
				t.Fatalf("%s: happy-path handoff incomplete: %+v", cell.name, out)
			}

			for _, s := range sessions {
				// (no-gap, per session) committed new-host publish strictly before the
				// old-host revoke.
				newPubIdx := j.firstIndex("new", "publish", s.uuid, true /*committedOnly*/)
				oldRevIdx := j.firstIndex("old", "revoke", s.uuid, false)
				if newPubIdx < 0 {
					t.Fatalf("%s: no committed new-host publish recorded for %q", cell.name, s.uuid)
				}
				if oldRevIdx < 0 {
					t.Fatalf("%s: no old-host revoke recorded for %q", cell.name, s.uuid)
				}
				if !(newPubIdx < oldRevIdx) {
					t.Errorf("%s: ordering violated for %q: new-host load+ack at %d, old-host revoke at %d — want load+ack STRICTLY before revoke (no-gap)",
						cell.name, s.uuid, newPubIdx, oldRevIdx)
				}

				// (end state) the new host shadows the session, the old host no longer.
				if !newH.shadows(s.uuid) {
					t.Errorf("%s: after handoff, new host does not shadow %q", cell.name, s.uuid)
				}
				if oldH.shadows(s.uuid) {
					t.Errorf("%s: after handoff, old host still shadows %q (not torn down)", cell.name, s.uuid)
				}

				// (full-set) the new host loaded the FULL set under the new key — no
				// digest dropped in this encoding.
				wantN := len(sessionCredsByUUID(sessions, s.uuid))
				if got := newH.loadedCountUnder(s.uuid, synthNewKeyID); got != wantN {
					t.Errorf("%s: new host loaded %d entries for %q under %q, want %d (no digest dropped in this scope/variant)",
						cell.name, got, s.uuid, synthNewKeyID, wantN)
				}

				// (opacity + full frozen shape) every loaded entry carries the
				// PARAMETERIZED scope + variant_tag unchanged + the full §7 shape.
				assertFrozenEntryShapeForCell(t, cell.name, s.uuid, newH.entriesUnder(s.uuid, synthNewKeyID), synthNewKeyID, cell.scope, cell.variant)
			}

			// (both arms) across the live set the loaded entries span BOTH cred_class
			// oneof arms — ISSUED{service_id} AND FORBIDDEN (the canary) — in THIS
			// variant encoding (D73: the canary registers in any pushed variant).
			assertCredClassSpansBothArms(t, newH, sessions, synthNewKeyID)

			// (no-gap, global) the LAST committed new-host publish precedes the FIRST
			// old-host revoke — the old host is never torn down until the whole new
			// host is loaded+acked, identically across the scope/variant matrix.
			lastNewPub := -1
			firstOldRev := len(j.events)
			for i, e := range j.events {
				if e.host == "new" && e.op == "publish" && e.committed {
					if i > lastNewPub {
						lastNewPub = i
					}
				}
				if e.host == "old" && e.op == "revoke" && i < firstOldRev {
					firstOldRev = i
				}
			}
			if lastNewPub < 0 {
				t.Fatalf("%s: no committed new-host publish recorded at all", cell.name)
			}
			if !(lastNewPub < firstOldRev) {
				t.Errorf("%s: global no-gap violated: last new-host load+ack at %d, first old-host revoke at %d — the old host began teardown before the new host was fully loaded",
					cell.name, lastNewPub, firstOldRev)
			}
		})
	}
}

// TestHostHandoff_NoInstant_ScopeVariantMatrix re-runs the step-by-step no-gap
// INVARIANT walk (every live session shadowed by at least one host at every
// observable point) across the full doc 14 §7 scope x variant_tag cross-product —
// SESSION+FLEET x {RAW,BASE64,URLENC,HEX}. It is the per-instant companion to
// TestHostHandoff_Continuity_ScopeVariantMatrix's ordering proof: it drives the
// publish/revoke steps directly (not the controller) under each scope+variant and
// asserts there is never a window in which a session is shadowed by NEITHER host,
// proving the per-instant continuity property is scope/encoding-agnostic. SYNTHETIC
// ONLY (D50); additive (the SESSION/RAW _NoInstantWithNeitherHostShadowing test is
// untouched).
func TestHostHandoff_NoInstant_ScopeVariantMatrix(t *testing.T) {
	for _, cell := range scopeVariantMatrix() {
		t.Run(cell.name, func(t *testing.T) {
			j := &handoffJournal{}
			oldH := newHostConsumer("old", j)
			newH := newHostConsumer("new", j)
			oldClient := dialHostFeed(t, oldH)
			newClient := dialHostFeed(t, newH)
			sessions := scopedVariantSessions(cell.scope, cell.variant)

			preloadOldHost(t, oldClient, sessions)

			assertEveryShadowed := func(when string) {
				for _, s := range sessions {
					if !oldH.shadows(s.uuid) && !newH.shadows(s.uuid) {
						t.Fatalf("%s: %s: session %q shadowed by NEITHER host — a continuity gap", cell.name, when, s.uuid)
					}
				}
			}

			// (a) before handoff: old host shadows.
			assertEveryShadowed("pre-handoff")

			// (b) load the new host (step 1) under the cell's scope+variant WITHOUT yet
			// revoking the old — both shadow at every instant.
			for _, s := range sessions {
				resp, err := newClient.DigestPublish(context.Background(), &identityv1.DigestPublishRequest{
					Session: &identityv1.DigestSessionRef{SessionUuid: s.uuid},
					Entries: synthEntriesForVariant(synthNewKeyID, s.creds, cell.scope, cell.variant),
					BatchId: "handoff-" + s.uuid,
				})
				if err != nil || !resp.GetCommitted() {
					t.Fatalf("%s: new-host load for %q: err=%v committed=%v", cell.name, s.uuid, err, resp.GetCommitted())
				}
				if !oldH.shadows(s.uuid) {
					t.Fatalf("%s: old host stopped shadowing %q during the new-host load — a gap", cell.name, s.uuid)
				}
				assertEveryShadowed("new-host-loaded, old-host-not-yet-revoked")
			}

			// (c) only now revoke the old host, session by session, under the cell's
			// scope — after each revoke the new host still shadows, so no gap.
			for _, s := range sessions {
				resp, err := oldClient.DigestRevoke(context.Background(), &identityv1.DigestRevokeRequest{
					Session: &identityv1.DigestSessionRef{SessionUuid: s.uuid},
					KeyIds:  []string{synthOldKeyID},
					Scope:   s.sessionScope(),
				})
				if err != nil || !resp.GetCommitted() {
					t.Fatalf("%s: old-host revoke for %q: err=%v committed=%v", cell.name, s.uuid, err, resp.GetCommitted())
				}
				if !newH.shadows(s.uuid) {
					t.Fatalf("%s: after revoking old host for %q the new host does not shadow it — a gap", cell.name, s.uuid)
				}
				assertEveryShadowed("old-host-revoked")
			}
		})
	}
}

// TestHostHandoff_FailClosed_IncompleteNewHostLeavesOldHostLoaded proves the
// fail-closed leg: if the NEW host fails to fully register (uncommitted ack,
// transport error, or a short load), the choreography STOPS and NEVER revokes
// the old host — every session stays shadowed under the old host (no gap), and
// the redeploy is retried or aborted.
func TestHostHandoff_FailClosed_IncompleteNewHostLeavesOldHostLoaded(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(newH *hostConsumer)
	}{
		{"uncommitted-ack", func(newH *hostConsumer) { newH.ackCommitted = false }},
		{"transport-error", func(newH *hostConsumer) { newH.publishErr = errSyntheticTransport }},
		// short-load (drop=1): on the single-cred session this drops to zero
		// entries; on the multi-cred session it leaves a PARTIAL set that still
		// shadows (≥1) but is incomplete. The controller must catch BOTH by
		// verifying the loaded COUNT equals the full set, not merely that ≥1
		// entry shadows — a partial load that still shadows would otherwise
		// revoke the old host while a dropped credential goes unprotected.
		{"short-load", func(newH *hostConsumer) { newH.dropEntries = 1 }}, // acks committed but loads less
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			j := &handoffJournal{}
			oldH := newHostConsumer("old", j)
			newH := newHostConsumer("new", j)
			tc.mutate(newH)
			oldClient := dialHostFeed(t, oldH)
			newClient := dialHostFeed(t, newH)
			sessions := synthLiveSessions()

			preloadOldHost(t, oldClient, sessions)

			out, err := runHostHandoff(context.Background(), newClient, oldClient, newH.loadedCountUnder, sessions, synthNewKeyID, synthOldKeyID)
			if err == nil {
				t.Fatalf("%s: want a fail-closed error from runHostHandoff, got nil (out=%+v)", tc.name, out)
			}
			if _, ok := err.(incompleteHandoffError); !ok {
				t.Errorf("%s: want incompleteHandoffError, got %T: %v", tc.name, err, err)
			}
			if out.oldHostRevoked {
				t.Fatalf("%s: old host was revoked despite an incomplete new-host load — a gap", tc.name)
			}
			// The OLD host MUST still shadow every session — never torn down.
			for _, s := range sessions {
				if !oldH.shadows(s.uuid) {
					t.Errorf("%s: old host stopped shadowing %q on a failed handoff — gap risk", tc.name, s.uuid)
				}
				// And the journal records NO old-host revoke for it.
				if j.has("old", "revoke", s.uuid) {
					t.Errorf("%s: a revoke was issued to the old host for %q despite the incomplete handoff", tc.name, s.uuid)
				}
			}
		})
	}
}

// TestHostHandoff_FailClosed_PartialLoadThatStillShadows is the sharp edge of
// the short-load hazard: a MULTI-credential session whose new-host load drops
// ONE entry but keeps the rest. The new host still SHADOWS the session (≥1
// entry loaded), so a controller that gated only on "shadows ≥ 1" would pass it
// and revoke the old host — leaving the dropped credential unprotected on the
// new host (a per-credential continuity gap). The controller MUST instead
// verify the FULL loaded count and fail closed, leaving the old host untouched.
func TestHostHandoff_FailClosed_PartialLoadThatStillShadows(t *testing.T) {
	j := &handoffJournal{}
	oldH := newHostConsumer("old", j)
	newH := newHostConsumer("new", j)
	newH.dropEntries = 1 // drop exactly one entry; a multi-cred session still shadows
	oldClient := dialHostFeed(t, oldH)
	newClient := dialHostFeed(t, newH)

	// A SINGLE multi-credential session: dropping one entry leaves it partially
	// loaded (1 of 2) yet still shadowing — the case a ≥1 check would miss.
	sessions := []synthLiveSession{
		{uuid: "00000000-0000-4000-8000-0000000ho001", creds: []string{
			"ds-synth-sessA-github-pat",
			"ds-synth-sessA-canary",
		}},
	}
	preloadOldHost(t, oldClient, sessions)

	out, err := runHostHandoff(context.Background(), newClient, oldClient, newH.loadedCountUnder, sessions, synthNewKeyID, synthOldKeyID)
	if err == nil {
		t.Fatalf("partial-load-still-shadows: want a fail-closed error, got nil (out=%+v) — the dropped credential would go unprotected", out)
	}
	if _, ok := err.(incompleteHandoffError); !ok {
		t.Errorf("partial-load-still-shadows: want incompleteHandoffError, got %T: %v", err, err)
	}
	if out.oldHostRevoked {
		t.Fatalf("partial-load-still-shadows: old host revoked despite a partial new-host load — the dropped credential is now unshadowed")
	}
	// The new host genuinely still shadows (so the weaker ≥1 check would have
	// passed) — yet the loaded count is short, which is what the controller caught.
	if !newH.shadows(sessions[0].uuid) {
		t.Fatalf("test setup invalid: new host should still shadow after dropping only one of two entries")
	}
	if got := newH.loadedCountUnder(sessions[0].uuid, synthNewKeyID); got != 1 {
		t.Fatalf("test setup invalid: new host should have loaded a partial set (1 of 2), got %d", got)
	}
	// The old host stays fully loaded — no gap.
	if !oldH.shadows(sessions[0].uuid) {
		t.Errorf("partial-load-still-shadows: old host stopped shadowing on a failed handoff — gap risk")
	}
	if j.has("old", "revoke", sessions[0].uuid) {
		t.Errorf("partial-load-still-shadows: a revoke was issued to the old host despite the incomplete handoff")
	}
}

// TestHostHandoff_LiveRedeployLeg_SkippedWithoutEnvGate documents and gates the
// only leg this test cannot exercise in-process: a REAL boundary host redeploy
// (standing up a fresh KVM host, re-pushing over the live DigestFeedService
// endpoint, observing the live host-agent ack). It is a DEFERRED MANUAL STEP
// (D50: no live host / boundary / claude in the wave). It runs only when
// DS_DIGEST_HANDOFF_LIVE is set and is skipped otherwise — the in-process tests
// above are the green proof of the ordering; this names the manual follow-up.
func TestHostHandoff_LiveRedeployLeg_SkippedWithoutEnvGate(t *testing.T) {
	if os.Getenv("DS_DIGEST_HANDOFF_LIVE") == "" {
		t.Skip("live host-redeploy leg is a deferred manual step (set DS_DIGEST_HANDOFF_LIVE to run against a real boundary host; D50 forbids it in the wave)")
	}
	t.Fatal("live host-redeploy leg not implemented in-tree: stand up two real boundary hosts and re-run the handoff ordering against live host-agent acks (deferred manual step)")
}

// TestHostHandoff_PartialOldHostRevoke_NoGap proves the COMPENSATING step-2 leg:
// after the new host is fully loaded+acked (step 1 done for every session), a
// revoke on the OLD host fails PARTWAY through step 2 (session A revoked, session
// B's revoke errors). This is the one step-2 fail-closed leg the FailClosed_*
// tests (which all fail in step 1) do not cover.
//
// It is NOT a continuity gap: by step 2 the new host shadows EVERY session, so a
// partially-torn-down old host is pure redundancy — no session is ever
// unshadowed. The controller MUST still fail closed: return incompleteHandoffError
// with oldHostRevoked=false (the old host is only partially revoked, not
// "revoked"), so the caller retries the (idempotent) handoff. It asserts:
//
//	(a) the new host shadows EVERY session throughout (loaded in step 1, never
//	    torn down — the no-gap property holds even on the failed teardown);
//	(b) runHostHandoff returns incompleteHandoffError and out.oldHostRevoked
//	    stays false;
//	(c) the journal shows ALL new-host loads precede ANY old-host revoke (step 1
//	    fully precedes step 2, exactly as the happy path).
func TestHostHandoff_PartialOldHostRevoke_NoGap(t *testing.T) {
	j := &handoffJournal{}
	oldH := newHostConsumer("old", j)
	newH := newHostConsumer("new", j)
	// The old host commits the FIRST session's revoke, then errors on the next —
	// a genuine MID-loop step-2 failure (not a first-call failure).
	oldH.revokeErr = errSyntheticRevoke
	oldH.revokeErrAfter = 1
	oldClient := dialHostFeed(t, oldH)
	newClient := dialHostFeed(t, newH)

	sessions := synthLiveSessions()
	if len(sessions) < 2 {
		t.Fatalf("test needs >=2 sessions to fail revoke MID-loop, got %d", len(sessions))
	}

	// Pre-redeploy: the OLD host shadows every live session under the old key.
	preloadOldHost(t, oldClient, sessions)

	out, err := runHostHandoff(context.Background(), newClient, oldClient, newH.loadedCountUnder, sessions, synthNewKeyID, synthOldKeyID)

	// (b) fail closed: incompleteHandoffError, oldHostRevoked stays false.
	if err == nil {
		t.Fatalf("want a fail-closed error from a partial old-host revoke, got nil (out=%+v)", out)
	}
	if _, ok := err.(incompleteHandoffError); !ok {
		t.Errorf("want incompleteHandoffError on partial old-host revoke, got %T: %v", err, err)
	}
	if out.oldHostRevoked {
		t.Fatalf("oldHostRevoked must stay false when the old-host revoke fails partway: %+v", out)
	}
	// Step 1 did complete (the new host was fully loaded+acked) — the failure is
	// purely on the step-2 teardown, which is the leg under test.
	if !out.newHostHandedOff {
		t.Fatalf("newHostHandedOff should be true: step 1 completed before the step-2 revoke failed (%+v)", out)
	}

	// (a) the new host shadows EVERY session throughout — step 1 loaded all of
	// them and step 2 never touches the new host, so the no-gap property holds
	// even though the old host's teardown failed partway.
	for _, s := range sessions {
		if !newH.shadows(s.uuid) {
			t.Errorf("new host does not shadow %q after a partial old-host revoke — a continuity gap", s.uuid)
		}
		// Full set still loaded on the new host (nothing was dropped).
		wantN := len(sessionCredsByUUID(sessions, s.uuid))
		if got := newH.loadedCountUnder(s.uuid, synthNewKeyID); got != wantN {
			t.Errorf("new host loaded %d entries for %q under %q, want %d (no digest dropped)",
				got, s.uuid, synthNewKeyID, wantN)
		}
	}

	// (c) journal ordering: ALL new-host committed loads precede ANY old-host
	// revoke (committed OR errored) — step 1 fully precedes step 2, the same
	// no-gap ordering the happy path proves, here on the failed-teardown path.
	lastNewPub := -1
	firstOldRevTouch := len(j.events)
	for i, e := range j.events {
		if e.host == "new" && e.op == "publish" && e.committed {
			if i > lastNewPub {
				lastNewPub = i
			}
		}
		if e.host == "old" && (e.op == "revoke" || e.op == "revoke-err") && i < firstOldRevTouch {
			firstOldRevTouch = i
		}
	}
	if lastNewPub < 0 {
		t.Fatal("no committed new-host publish recorded at all")
	}
	if firstOldRevTouch == len(j.events) {
		t.Fatal("no old-host revoke attempt recorded — step 2 never ran")
	}
	if !(lastNewPub < firstOldRevTouch) {
		t.Errorf("ordering violated: last new-host load+ack at %d, first old-host revoke attempt at %d — the old host began teardown before the new host was fully loaded",
			lastNewPub, firstOldRevTouch)
	}

	// The old host's teardown is PARTIAL: exactly one session was revoked
	// (revokeErrAfter=1) before the error fired. The first session is no longer
	// shadowed there, but the new host still shadows it (asserted above), so
	// there is no gap; the still-loaded sessions keep the old host as redundancy.
	committedOldRevokes := 0
	erroredOldRevokes := 0
	for _, e := range j.events {
		if e.host == "old" && e.op == "revoke" {
			committedOldRevokes++
		}
		if e.host == "old" && e.op == "revoke-err" {
			erroredOldRevokes++
		}
	}
	if committedOldRevokes != 1 {
		t.Errorf("want exactly 1 committed old-host revoke before the failure (revokeErrAfter=1), got %d", committedOldRevokes)
	}
	if erroredOldRevokes != 1 {
		t.Errorf("want exactly 1 errored old-host revoke (the mid-loop failure), got %d", erroredOldRevokes)
	}
}

// ==========================================================================
// RETRY-TO-CONVERGENCE (the caller half of the fail-closed contract)
// ==========================================================================

// TestHostHandoff_RetryToConvergence_TransientNewHostFault proves the bounded,
// idempotent retry-to-convergence loop. runHostHandoff fails CLOSED on a partial
// new-host load (here a TRANSIENT transport fault on the first attempt) and
// documents that the caller must retry the idempotent handoff — runHostHandoff
// alone drives NO retry. runHostHandoffToConvergence is that caller: it re-runs
// the handoff until oldHostRevoked=true or the attempt budget exhausts.
//
// The scenario: attempt 1 hits newH.publishErr (a transport fault reaching the
// freshly stood-up new host) and fails closed (incompleteHandoffError,
// oldHostRevoked=false, the old host untouched). The onAttempt hook clears the
// fault before attempt 2, which converges. It asserts:
//
//	(convergence) the loop converges — converged=true, oldHostRevoked=true — in
//	    exactly 2 attempts;
//	(i) idempotent re-publish: the new host's loaded count under the new key
//	    still equals the full set (additive/idempotent re-confirm, NOT a
//	    duplicate-shadow — a second publish does not double the loaded set on the
//	    converging attempt because attempt 1 never loaded anything);
//	(iii) the no-gap invariant holds across EVERY attempt: in the shared journal,
//	    every committed new-host publish precedes every old-host revoke, and the
//	    old host is never revoked on the failed attempt (it stays fully shadowed
//	    throughout the transient outage).
func TestHostHandoff_RetryToConvergence_TransientNewHostFault(t *testing.T) {
	j := &handoffJournal{}
	oldH := newHostConsumer("old", j)
	newH := newHostConsumer("new", j)
	newH.publishErr = errSyntheticTransport // attempt 1 cannot reach the new host
	oldClient := dialHostFeed(t, oldH)
	newClient := dialHostFeed(t, newH)

	sessions := synthLiveSessions()
	preloadOldHost(t, oldClient, sessions)

	// Clear the transient fault before attempt 2 so the handoff converges; assert
	// attempt 1 left the old host fully shadowed (no gap during the outage).
	cleared := false
	onAttempt := func(attempt int) {
		if attempt >= 2 {
			newH.publishErr = nil
			cleared = true
		}
		// During/after the transient outage the old host must STILL shadow every
		// session — the fail-closed leg never tears it down.
		for _, s := range sessions {
			if !oldH.shadows(s.uuid) {
				t.Errorf("attempt %d: old host stopped shadowing %q during the transient outage — a gap", attempt, s.uuid)
			}
		}
	}

	res := runHostHandoffToConvergence(
		context.Background(),
		newClient, oldClient, newH.loadedCountUnder,
		sessions, synthNewKeyID, synthOldKeyID,
		handoffRetryPolicy{maxAttempts: 5, backoff: 0},
		noSleep, onAttempt,
	)

	// (convergence)
	if !cleared {
		t.Fatal("onAttempt never saw a retry — the loop did not retry the transient fault")
	}
	if !res.converged || res.err != nil {
		t.Fatalf("want convergence, got converged=%v err=%v (out=%+v)", res.converged, res.err, res.out)
	}
	if !res.out.oldHostRevoked {
		t.Fatalf("converged run must have oldHostRevoked=true: %+v", res.out)
	}
	if res.attempts != 2 {
		t.Errorf("want convergence in exactly 2 attempts (fault on 1, cleared for 2), got %d", res.attempts)
	}

	assertConvergenceInvariants(t, j, newH, oldH, sessions, synthNewKeyID)
}

// TestHostHandoff_RetryToConvergence_TransientOldHostRevokeFault proves the
// retry loop heals the STEP-2 fail-closed leg (a mid-teardown old-host revoke
// error) and re-revoking an already-revoked session is a no-op. Attempt 1
// completes step 1 (the new host is fully loaded+acked), then the old-host revoke
// errors PARTWAY through step 2 (revokeErrAfter=1): session A is revoked, session
// B's revoke errors → incompleteHandoffError, oldHostRevoked=false. The onAttempt
// hook clears the revoke fault before attempt 2, which RE-REVOKES session A (a
// no-op: its key is already gone — DigestRevoke on an absent key is harmless and
// still commits) and revokes the rest, converging. It asserts:
//
//	(convergence) converged=true, oldHostRevoked=true;
//	(ii) re-revoke of an already-revoked session is a no-op: the old host shadows
//	    NOTHING after convergence and the re-revoke neither errors nor un-does the
//	    new host;
//	(i) idempotent re-publish keeps the new host's loaded count == want across
//	    the retry (step 1 re-runs on attempt 2 but does NOT duplicate-shadow);
//	(iii) the no-gap invariant holds across EVERY attempt.
func TestHostHandoff_RetryToConvergence_TransientOldHostRevokeFault(t *testing.T) {
	j := &handoffJournal{}
	oldH := newHostConsumer("old", j)
	newH := newHostConsumer("new", j)
	// Attempt 1: commit the first revoke, then error — a genuine MID-loop step-2
	// failure (oldHostRevoked stays false; old host is PARTIALLY torn down).
	oldH.revokeErr = errSyntheticRevoke
	oldH.revokeErrAfter = 1
	oldClient := dialHostFeed(t, oldH)
	newClient := dialHostFeed(t, newH)

	sessions := synthLiveSessions()
	if len(sessions) < 2 {
		t.Fatalf("test needs >=2 sessions to fail revoke MID-loop, got %d", len(sessions))
	}
	preloadOldHost(t, oldClient, sessions)

	onAttempt := func(attempt int) {
		if attempt >= 2 {
			oldH.mu.Lock()
			oldH.revokeErr = nil // heal the old-host transport before the retry
			oldH.mu.Unlock()
		}
		// On EVERY attempt the new host must already shadow every session once
		// step 1 has run — step 1 completes on attempt 1 (the revoke failed, not
		// the publish), so even the partially-torn-down old host is pure
		// redundancy; no session is ever unshadowed.
		if attempt >= 2 {
			for _, s := range sessions {
				if !newH.shadows(s.uuid) {
					t.Errorf("attempt %d: new host does not shadow %q before the retry — a gap", attempt, s.uuid)
				}
			}
		}
	}

	res := runHostHandoffToConvergence(
		context.Background(),
		newClient, oldClient, newH.loadedCountUnder,
		sessions, synthNewKeyID, synthOldKeyID,
		handoffRetryPolicy{maxAttempts: 5, backoff: 0},
		noSleep, onAttempt,
	)

	if !res.converged || res.err != nil {
		t.Fatalf("want convergence after healing the old-host revoke fault, got converged=%v err=%v (out=%+v)", res.converged, res.err, res.out)
	}
	if !res.out.oldHostRevoked {
		t.Fatalf("converged run must have oldHostRevoked=true: %+v", res.out)
	}
	if res.attempts != 2 {
		t.Errorf("want convergence in exactly 2 attempts, got %d", res.attempts)
	}

	// (ii) re-revoke of an already-revoked session is a no-op: after convergence
	// the old host shadows NOTHING (the re-revoke of session A — already torn down
	// on attempt 1 — committed harmlessly) and the new host shadows everything.
	for _, s := range sessions {
		if oldH.shadows(s.uuid) {
			t.Errorf("after convergence the old host still shadows %q — re-revoke did not converge it to empty", s.uuid)
		}
	}
	assertConvergenceInvariants(t, j, newH, oldH, sessions, synthNewKeyID)
}

// TestHostHandoff_RetryToConvergence_ExhaustsAttempts proves the loop is BOUNDED:
// a PERSISTENT new-host fault (never cleared) exhausts the attempt budget and the
// loop gives up fail-closed — converged=false, oldHostRevoked=false, the last
// error an incompleteHandoffError, and the old host left fully shadowed (no gap
// even on a redeploy that never succeeds).
func TestHostHandoff_RetryToConvergence_ExhaustsAttempts(t *testing.T) {
	j := &handoffJournal{}
	oldH := newHostConsumer("old", j)
	newH := newHostConsumer("new", j)
	newH.publishErr = errSyntheticTransport // never cleared — a persistent outage
	oldClient := dialHostFeed(t, oldH)
	newClient := dialHostFeed(t, newH)

	sessions := synthLiveSessions()
	preloadOldHost(t, oldClient, sessions)

	const budget = 3
	res := runHostHandoffToConvergence(
		context.Background(),
		newClient, oldClient, newH.loadedCountUnder,
		sessions, synthNewKeyID, synthOldKeyID,
		handoffRetryPolicy{maxAttempts: budget, backoff: 0},
		noSleep, nil,
	)

	if res.converged {
		t.Fatalf("a persistent fault must NOT converge: %+v", res)
	}
	if res.attempts != budget {
		t.Errorf("want exactly %d attempts before giving up, got %d", budget, res.attempts)
	}
	if res.err == nil {
		t.Fatal("exhausted loop must surface the last error")
	}
	if _, ok := res.err.(incompleteHandoffError); !ok {
		t.Errorf("want a fail-closed incompleteHandoffError after exhaustion, got %T: %v", res.err, res.err)
	}
	if res.out.oldHostRevoked {
		t.Fatalf("oldHostRevoked must stay false on exhaustion: %+v", res.out)
	}
	// No gap even when the redeploy never succeeds: the old host stays fully
	// shadowed and is NEVER revoked.
	for _, s := range sessions {
		if !oldH.shadows(s.uuid) {
			t.Errorf("old host stopped shadowing %q on a never-converging redeploy — gap risk", s.uuid)
		}
		if j.has("old", "revoke", s.uuid) {
			t.Errorf("a revoke was issued to the old host for %q despite the handoff never converging", s.uuid)
		}
	}
}

// TestHostHandoff_RetryToConvergence_ContextCancelled proves the loop is
// context-cancellable: a context cancelled before the run ends the loop promptly
// with ctx.Err() and never converges or revokes the old host.
func TestHostHandoff_RetryToConvergence_ContextCancelled(t *testing.T) {
	j := &handoffJournal{}
	oldH := newHostConsumer("old", j)
	newH := newHostConsumer("new", j)
	newH.publishErr = errSyntheticTransport
	oldClient := dialHostFeed(t, oldH)
	newClient := dialHostFeed(t, newH)

	sessions := synthLiveSessions()
	preloadOldHost(t, oldClient, sessions)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancelled before the loop even starts

	res := runHostHandoffToConvergence(
		ctx,
		newClient, oldClient, newH.loadedCountUnder,
		sessions, synthNewKeyID, synthOldKeyID,
		handoffRetryPolicy{maxAttempts: 10, backoff: time.Hour}, // huge backoff: only cancellation ends it
		nil, nil, // default ctx-aware sleep
	)

	if res.converged {
		t.Fatalf("a cancelled context must not converge: %+v", res)
	}
	if res.err != context.Canceled {
		t.Errorf("want context.Canceled, got %v", res.err)
	}
	if res.attempts != 0 {
		t.Errorf("a context cancelled before the first attempt should run 0 attempts, got %d", res.attempts)
	}
	if res.out.oldHostRevoked {
		t.Fatalf("oldHostRevoked must stay false on cancellation: %+v", res.out)
	}
	for _, s := range sessions {
		if !oldH.shadows(s.uuid) {
			t.Errorf("old host stopped shadowing %q on a cancelled redeploy — gap risk", s.uuid)
		}
	}
}

// TestHostHandoff_RetryToConvergence_ScopeAndVariantOpacity is the FOLDED FU6
// proof: the retry-to-convergence loop is OPAQUE to BOTH the digest scope
// (SESSION vs FLEET) and ALL FOUR variant_tag encodings (RAW|BASE64|URLENC|HEX).
// For every (scope, variant) cell it stamps the live-session set under that
// scope+encoding, drives a transient-failure-then-recovery handoff, and asserts
// the SAME convergence + the three invariants hold — controller opacity is
// scope/encoding-agnostic across the retry loop. The entries that actually
// crossed the wire are asserted to carry the parameterized scope + variant, so a
// controller that silently rewrote either would surface.
func TestHostHandoff_RetryToConvergence_ScopeAndVariantOpacity(t *testing.T) {
	scopes := []struct {
		name  string
		scope identityv1.DigestScope
	}{
		{"SESSION", identityv1.DigestScope_DIGEST_SCOPE_SESSION},
		{"FLEET", identityv1.DigestScope_DIGEST_SCOPE_FLEET},
	}
	variants := []struct {
		name string
		tag  identityv1.DigestVariantTag
	}{
		{"RAW", identityv1.DigestVariantTag_DIGEST_VARIANT_TAG_RAW},
		{"BASE64", identityv1.DigestVariantTag_DIGEST_VARIANT_TAG_BASE64},
		{"URLENC", identityv1.DigestVariantTag_DIGEST_VARIANT_TAG_URLENC},
		{"HEX", identityv1.DigestVariantTag_DIGEST_VARIANT_TAG_HEX},
	}

	for _, sc := range scopes {
		for _, v := range variants {
			t.Run(sc.name+"/"+v.name, func(t *testing.T) {
				j := &handoffJournal{}
				oldH := newHostConsumer("old", j)
				newH := newHostConsumer("new", j)
				newH.publishErr = errSyntheticTransport // transient: cleared on retry
				oldClient := dialHostFeed(t, oldH)
				newClient := dialHostFeed(t, newH)

				sessions := scopedVariantSessions(sc.scope, v.tag)
				preloadOldHost(t, oldClient, sessions)

				onAttempt := func(attempt int) {
					if attempt >= 2 {
						newH.publishErr = nil
					}
				}

				res := runHostHandoffToConvergence(
					context.Background(),
					newClient, oldClient, newH.loadedCountUnder,
					sessions, synthNewKeyID, synthOldKeyID,
					handoffRetryPolicy{maxAttempts: 5, backoff: 0},
					noSleep, onAttempt,
				)

				if !res.converged || res.err != nil || !res.out.oldHostRevoked {
					t.Fatalf("scope=%s variant=%s: want convergence, got converged=%v err=%v out=%+v",
						sc.name, v.name, res.converged, res.err, res.out)
				}
				assertConvergenceInvariants(t, j, newH, oldH, sessions, synthNewKeyID)

				// The wire actually carried the parameterized scope + variant on the
				// loaded set — the controller never rewrote either (opacity).
				for _, s := range sessions {
					for i, e := range newH.entriesUnder(s.uuid, synthNewKeyID) {
						if e.GetScope() != sc.scope {
							t.Errorf("scope=%s variant=%s: %s entry %d loaded with scope %v, want %v — controller is not opaque to scope",
								sc.name, v.name, s.uuid, i, e.GetScope(), sc.scope)
						}
						if e.GetVariantTag() != v.tag {
							t.Errorf("scope=%s variant=%s: %s entry %d loaded with variant %v, want %v — controller is not opaque to encoding",
								sc.name, v.name, s.uuid, i, e.GetVariantTag(), v.tag)
						}
					}
				}
			})
		}
	}
}

// ---- convergence helpers -------------------------------------------------

// noSleep is the no-op backoff realization for the retry loop in tests: it never
// waits (the loop stays bounded + cancellable without burning wall-clock), and it
// still honors a cancelled context so the cancellable shape is exercised.
func noSleep(ctx context.Context, _ time.Duration) error { return ctx.Err() }

// scopedVariantSessions builds the live-session set stamped under a given
// DigestScope + variant_tag — the FU6 fixture parameterization. It reuses the
// canonical synthLiveSessions tokens (so the cred_class oneof still spans both
// arms via the canary) and only overrides the scope + variant, proving the
// retry/convergence path is scope/encoding-agnostic.
func scopedVariantSessions(scope identityv1.DigestScope, variant identityv1.DigestVariantTag) []synthLiveSession {
	base := synthLiveSessions()
	out := make([]synthLiveSession, 0, len(base))
	for _, s := range base {
		s.scope = scope
		s.variant = variant
		out = append(out, s)
	}
	return out
}

// assertConvergenceInvariants asserts the three convergence properties on a
// CONVERGED retry run: (i) the new host's loaded count under the new key equals
// the full set for every session (idempotent re-publish re-confirms the set — it
// is additive/idempotent, NOT a duplicate-shadow that doubles the loaded count);
// (ii) the old host shadows NOTHING (every session torn down, re-revoke of an
// already-revoked session was a harmless no-op); and (iii) the NO-GAP invariant
// holds across EVERY attempt in the shared journal — every committed new-host
// publish precedes every old-host revoke (so the new host was loaded+acked
// strictly before the old host was torn down on the converging attempt, and the
// old host was never revoked on a failed attempt).
func assertConvergenceInvariants(t *testing.T, j *handoffJournal, newH, oldH *hostConsumer, sessions []synthLiveSession, newKeyID string) {
	t.Helper()

	for _, s := range sessions {
		// (i) idempotent re-publish keeps loadedCountUnder == want (not doubled).
		want := len(sessionCredsByUUID(sessions, s.uuid))
		if got := newH.loadedCountUnder(s.uuid, newKeyID); got != want {
			t.Errorf("new host loaded %d entries for %q under %q, want %d — re-publish must be idempotent (additive re-confirm, not a duplicate-shadow)",
				got, s.uuid, newKeyID, want)
		}
		if !newH.shadows(s.uuid) {
			t.Errorf("after convergence the new host does not shadow %q", s.uuid)
		}
		// (ii) re-revoke of already-revoked is a no-op: the old host ends EMPTY.
		if oldH.shadows(s.uuid) {
			t.Errorf("after convergence the old host still shadows %q (re-revoke did not converge it to empty)", s.uuid)
		}
	}

	// (iii) no-gap across EVERY attempt. A converging run replays step 1 (publish
	// the new host) then step 2 (revoke the old host) on each attempt, so a GLOBAL
	// "last publish before first revoke" ordering does NOT hold (a later attempt's
	// publishes follow an earlier attempt's revokes). The attempt-agnostic no-gap
	// invariant is: at the instant the old host is revoked for a session, the new
	// host already shadows it — i.e. EVERY old-host revoke (committed OR errored)
	// for a session is preceded in the journal by a COMMITTED new-host publish for
	// that SAME session. This holds within every attempt (its step 1 fully
	// precedes its step 2) and therefore across the whole converging run, so the
	// old host is never torn down before the new host is loaded+acked on ANY
	// attempt.
	sawOldRevoke := false
	for i, e := range j.events {
		if e.host != "old" || (e.op != "revoke" && e.op != "revoke-err") {
			continue
		}
		sawOldRevoke = true
		precededByCommittedPublish := false
		for k := 0; k < i; k++ {
			p := j.events[k]
			if p.host == "new" && p.op == "publish" && p.committed && p.session == e.session {
				precededByCommittedPublish = true
				break
			}
		}
		if !precededByCommittedPublish {
			t.Errorf("no-gap violated at journal index %d: old-host %s for %q has no PRECEDING committed new-host publish — the old host was torn down before the new host shadowed the session",
				i, e.op, e.session)
		}
	}
	if !sawOldRevoke {
		t.Fatal("no old-host revoke attempt recorded — step 2 never ran on the converging run")
	}
}

// ---- small helpers -------------------------------------------------------

var errSyntheticTransport = &syntheticTransportError{}

type syntheticTransportError struct{}

func (*syntheticTransportError) Error() string { return "ds-synth: transport error reaching new host" }

var errSyntheticRevoke = &syntheticRevokeError{}

type syntheticRevokeError struct{}

func (*syntheticRevokeError) Error() string { return "ds-synth: transport error revoking old host" }

func sessionCredsByUUID(sessions []synthLiveSession, uuid string) []string {
	for _, s := range sessions {
		if s.uuid == uuid {
			return s.creds
		}
	}
	return nil
}

// assertFrozenEntryShape asserts a loaded entry set carries the FULL frozen doc
// 14 §7 wire shape — key_id, algo (HMAC-SHA-256 + truncation length), digest,
// cred_class (ISSUED{service_id} | FORBIDDEN), scope, expiry, variant_tag — for
// every entry. It is fixture-fidelity verification: the controller routes
// entries opaquely, but the synthetic producer must emit the complete §7 shape
// so the routing/continuity path is exercised against the real wire, not a subset.
func assertFrozenEntryShape(t *testing.T, sessionUUID string, entries []*identityv1.DigestEntry, wantKeyID string) {
	t.Helper()
	if len(entries) == 0 {
		t.Fatalf("%s: no entries to check shape against", sessionUUID)
	}
	for i, e := range entries {
		if e.GetKeyId() != wantKeyID {
			t.Errorf("%s entry %d: key_id=%q, want %q", sessionUUID, i, e.GetKeyId(), wantKeyID)
		}
		// algo: present, HMAC-SHA-256 family, non-zero truncation length.
		algo := e.GetAlgo()
		if algo == nil {
			t.Errorf("%s entry %d: algo is nil — frozen §7 requires algo (HMAC-SHA-256 + truncation length)", sessionUUID, i)
		} else {
			if algo.GetFamily() != identityv1.DigestAlgo_FAMILY_HMAC_SHA256 {
				t.Errorf("%s entry %d: algo family=%v, want FAMILY_HMAC_SHA256", sessionUUID, i, algo.GetFamily())
			}
			if algo.GetTruncationLenBytes() == 0 {
				t.Errorf("%s entry %d: algo truncation_len_bytes=0, want a non-zero truncation length", sessionUUID, i)
			}
		}
		// digest bytes present (synthetic, non-empty).
		if len(e.GetDigest()) == 0 {
			t.Errorf("%s entry %d: digest is empty — §7 requires the truncated digest bytes", sessionUUID, i)
		}
		// cred_class: present and exactly one oneof arm set.
		cc := e.GetCredClass()
		if cc == nil {
			t.Errorf("%s entry %d: cred_class is nil — frozen §7 requires ISSUED{service_id} | FORBIDDEN", sessionUUID, i)
		} else {
			issued := cc.GetIssued()
			forbidden := cc.GetForbidden()
			switch {
			case issued != nil && forbidden == nil:
				if issued.GetServiceId() == "" {
					t.Errorf("%s entry %d: ISSUED cred_class with empty service_id — §7 ISSUED carries a service_id", sessionUUID, i)
				}
			case forbidden != nil && issued == nil:
				// FORBIDDEN carries no payload — valid.
			default:
				t.Errorf("%s entry %d: cred_class oneof not exactly one arm (issued=%v forbidden=%v)", sessionUUID, i, issued, forbidden)
			}
		}
		// scope SESSION (this seam), variant_tag set, expiry present.
		if e.GetScope() != identityv1.DigestScope_DIGEST_SCOPE_SESSION {
			t.Errorf("%s entry %d: scope=%v, want DIGEST_SCOPE_SESSION", sessionUUID, i, e.GetScope())
		}
		if e.GetVariantTag() == identityv1.DigestVariantTag_DIGEST_VARIANT_TAG_UNSPECIFIED {
			t.Errorf("%s entry %d: variant_tag unspecified — §7 requires RAW|BASE64|URLENC|HEX", sessionUUID, i)
		}
		if e.GetExpiry() == nil {
			t.Errorf("%s entry %d: expiry is nil — §7 requires an absolute expiry (teardown-flush invariant)", sessionUUID, i)
		}
	}
}

// assertFrozenEntryShapeForCell is the scope/variant-parameterized companion to
// assertFrozenEntryShape: it asserts every loaded entry carries the FULL frozen doc
// 14 §7 wire shape — key_id, algo (HMAC-SHA-256 + truncation length), digest,
// cred_class (ISSUED{service_id} | FORBIDDEN), expiry — AND that the scope +
// variant_tag are EXACTLY the parameterized cell values, unchanged by the
// controller. Where assertFrozenEntryShape pins scope to DIGEST_SCOPE_SESSION (the
// default-shape core tests), this one verifies the controller is OPAQUE to the
// scope (SESSION vs FLEET) and the encoding (RAW|BASE64|URLENC|HEX): a controller
// that rewrote either, or that special-cased a FLEET/HEX entry off the routing
// path, would surface as a mismatch here. It is fixture-fidelity + opacity
// verification; the controller still routes entries opaquely.
func assertFrozenEntryShapeForCell(t *testing.T, cellName, sessionUUID string, entries []*identityv1.DigestEntry, wantKeyID string, wantScope identityv1.DigestScope, wantVariant identityv1.DigestVariantTag) {
	t.Helper()
	if len(entries) == 0 {
		t.Fatalf("%s: %s: no entries to check shape against", cellName, sessionUUID)
	}
	for i, e := range entries {
		if e.GetKeyId() != wantKeyID {
			t.Errorf("%s: %s entry %d: key_id=%q, want %q", cellName, sessionUUID, i, e.GetKeyId(), wantKeyID)
		}
		// algo: present, HMAC-SHA-256 family, non-zero truncation length.
		algo := e.GetAlgo()
		if algo == nil {
			t.Errorf("%s: %s entry %d: algo is nil — frozen §7 requires algo (HMAC-SHA-256 + truncation length)", cellName, sessionUUID, i)
		} else {
			if algo.GetFamily() != identityv1.DigestAlgo_FAMILY_HMAC_SHA256 {
				t.Errorf("%s: %s entry %d: algo family=%v, want FAMILY_HMAC_SHA256", cellName, sessionUUID, i, algo.GetFamily())
			}
			if algo.GetTruncationLenBytes() == 0 {
				t.Errorf("%s: %s entry %d: algo truncation_len_bytes=0, want a non-zero truncation length", cellName, sessionUUID, i)
			}
		}
		// digest bytes present (synthetic, non-empty).
		if len(e.GetDigest()) == 0 {
			t.Errorf("%s: %s entry %d: digest is empty — §7 requires the truncated digest bytes", cellName, sessionUUID, i)
		}
		// cred_class: present and exactly one oneof arm set.
		cc := e.GetCredClass()
		if cc == nil {
			t.Errorf("%s: %s entry %d: cred_class is nil — frozen §7 requires ISSUED{service_id} | FORBIDDEN", cellName, sessionUUID, i)
		} else {
			issued := cc.GetIssued()
			forbidden := cc.GetForbidden()
			switch {
			case issued != nil && forbidden == nil:
				if issued.GetServiceId() == "" {
					t.Errorf("%s: %s entry %d: ISSUED cred_class with empty service_id — §7 ISSUED carries a service_id", cellName, sessionUUID, i)
				}
			case forbidden != nil && issued == nil:
				// FORBIDDEN carries no payload — valid (the D73 canary).
			default:
				t.Errorf("%s: %s entry %d: cred_class oneof not exactly one arm (issued=%v forbidden=%v)", cellName, sessionUUID, i, issued, forbidden)
			}
		}
		// scope + variant_tag are EXACTLY the parameterized cell values — the
		// opacity proof: the controller never rewrote either off the routing path.
		if e.GetScope() != wantScope {
			t.Errorf("%s: %s entry %d: scope=%v, want %v — controller is not opaque to scope", cellName, sessionUUID, i, e.GetScope(), wantScope)
		}
		if e.GetVariantTag() != wantVariant {
			t.Errorf("%s: %s entry %d: variant_tag=%v, want %v — controller is not opaque to encoding", cellName, sessionUUID, i, e.GetVariantTag(), wantVariant)
		}
		if e.GetExpiry() == nil {
			t.Errorf("%s: %s entry %d: expiry is nil — §7 requires an absolute expiry (teardown-flush invariant)", cellName, sessionUUID, i)
		}
	}
}

// assertCredClassSpansBothArms asserts the loaded entry set across the live
// sessions exercises BOTH cred_class oneof arms — at least one ISSUED{service_id}
// AND at least one FORBIDDEN — so the routing/continuity test exercises the full
// §7 oneof, not just one branch. (The synthLiveSessions fixture carries a
// *-canary token, which synthCredClassFor classifies FORBIDDEN, alongside ISSUED
// service creds.)
func assertCredClassSpansBothArms(t *testing.T, h *hostConsumer, sessions []synthLiveSession, keyID string) {
	t.Helper()
	sawIssued, sawForbidden := false, false
	for _, s := range sessions {
		for _, e := range h.entriesUnder(s.uuid, keyID) {
			cc := e.GetCredClass()
			if cc.GetIssued() != nil {
				sawIssued = true
			}
			if cc.GetForbidden() != nil {
				sawForbidden = true
			}
		}
	}
	if !sawIssued {
		t.Errorf("loaded entries never carry an ISSUED cred_class — fixture should span both §7 oneof arms")
	}
	if !sawForbidden {
		t.Errorf("loaded entries never carry a FORBIDDEN cred_class — fixture should span both §7 oneof arms (the canary)")
	}
}
