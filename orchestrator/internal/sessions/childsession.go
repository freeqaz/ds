package sessions

// This file is the ORCHESTRATOR-SIDE CreateChildSession fan-out leg (doc 15 §5.3,
// D18): the create-sequence point where the D18 wrapper calls back to spawn one
// subagent/worktree session per child VM, and each child receives a STRICTLY-
// NARROWER scoped token DERIVED OFFLINE from the parent's token (doc 19 §4, D100)
// — ZERO mint RPCs as the fan-out tree widens (the "killer fit", doc 19 §1/§4).
//
// WHY ITS OWN FILE (the re-scope, taskdb 01KTYSS8R1V2CTCP6ZXXCTT6ZY). CreateChild-
// Session is a RESERVED M0 RPC implemented at M3 (doc 15 §5.3: "carries parent
// link, policy posture, identity lineage, worktree inheritance"). This is the
// minimal honest in-process leg of that point, carved into its OWN sessions file
// so it never collides with the §4.1 step-5 mint-assembly caller (createstep5.go /
// mintrequest.go) — one writer per shared path.
//
// CROSS-TREE NOTE (binding, the mintrequest.go precedent). identity/mint is a
// SEPARATE Go module and the ONLY legal cross-tree import is proto/gen/go
// (CI-enforced). The actual offline derivation — BuildChildAttenuation over
// identity × service × scope × TTL + the role-template seam, then the substrate
// append — lives in identity/mint (attenuation_template.go / sessiontoken.go) and
// runs MINT-SIDE. So this leg does NOT import the mint module: it assembles the
// per-child NARROWING as DATA (ChildSessionDerivation, the in-package projection
// of the doc 19 §4 grant-model dimensions a child hop narrows along) and hands
// that data across the seam to a ChildTokenDeriver — the mint library satisfies
// the deriver natively, a test fake satisfies it identically, and the claim values
// cross the seam as DATA, never as the mint module's type (proto/gen/go-carriable).
//
// WHAT THIS LEG GUARANTEES (the acceptance, doc 19 §4):
//   - ZERO mint RPCs: a child token is DERIVED from the parent's, never minted —
//     the deriver is an OFFLINE attenuation, not a mint call (asserted by the
//     fake's zero-mint counter in the test).
//   - MONOTONIC NARROWING: services ⊆ parent scope, TTL ≤ parent, child session_uuid
//     appended as the next parent_session hop. WIDENING is REJECTED — the substrate
//     (mint-side) fails any over-ask closed; this leg never tries to author a
//     widening, and a deriver that returns one is surfaced as an error, not swallowed.
//   - IDENTITY LINEAGE: the child's session_uuid becomes the chain's next
//     parent_session hop; the launching user is INHERITED unchanged (root attribution
//     never widens or forks, doc 04 §5). Children receive their token through the
//     SAME doc 15 §4.1 step-8 entrypoint slot as any session (no new choreography).

import (
	"context"
	"fmt"
	"time"
)

// ChildSessionDerivation is the per-child NARROWING the fan-out leg assembles for
// one subagent VM (doc 19 §4): the typed DATA — identity × service × scope × TTL +
// role_ref + task_ref — that the offline derivation narrows the parent token along.
// It is the in-package projection of exactly the dimensions the mint library's
// child-attenuation builder consumes; it crosses the seam as DATA, never the mint
// module's type. There is NO Datalog/caveat string to author here (D52) — every
// field maps to one grant-model dimension and can only ever SHRINK the parent.
type ChildSessionDerivation struct {
	// ChildSessionUUID is the child VM's session (the IDENTITY axis): it becomes the
	// child token's session scope and the chain's next parent_session hop (doc 19
	// §4/§9). REQUIRED — a fan-out hop without a child identity is not a child session.
	ChildSessionUUID string
	// Services is the explicit per-child service narrowing (the SERVICE/SCOPE axis):
	// the mint-side derivation intersects it with the parent scope and the role
	// default, so it can only SHRINK the effective set. Nil = no explicit narrowing
	// on this axis (the parent scope, possibly clamped by the role default, governs).
	Services []string
	// TTL is the explicit per-child lifetime (the TTL axis); the child horizon is
	// clamped to never exceed the parent expiry or the role MaxTTL. Zero = inherit
	// the parent horizon (subject to the role clamp).
	TTL time.Duration
	// TaskRef is the child's task reference (doc 19 §4): the recorded prompt/plan the
	// subagent runs (doc 04 §3). The "for which task" axis of the LOG-5 lineage join.
	TaskRef string
	// RoleRef keys the doc 19 §11 role-template seam: the recorded role the child runs
	// under ("" or `default@<vN>` = the de-risking default, which narrows nothing,
	// roles/SCHEMA.md rule 4). The mint-side resolver folds the role's default
	// narrowing in; this leg only carries the ref, never resolves it (doc 19 §11).
	RoleRef string
}

// DerivedChildToken is the OFFLINE-derived child token (the deriver's output),
// carried as DATA back to the fan-out leg. It carries NO token bytes across this
// in-package boundary beyond the opaque presented value the child VM needs at its
// step-8 entrypoint — the lineage fields are FINGERPRINT-ONLY (doc 16 §9 / doc 19
// §9). It mirrors the mint module's SessionTokenBundle shape field-for-field on the
// dimensions the orchestrator records, without importing that type.
type DerivedChildToken struct {
	// Token is the opaque presented credential the child VM receives through the
	// step-8 entrypoint slot (doc 19 §5). Never logged (fingerprint-only, §9); the
	// fan-out leg passes it straight to the entrypoint material and records only its
	// lineage.
	Token []byte
	// SessionUUID echoes the child's session scope (== ChildSessionDerivation.ChildSessionUUID).
	SessionUUID string
	// Expiry is the child horizon (≤ parent expiry — the monotonic-narrowing TTL).
	Expiry time.Time
	// AttenuationDepth is the parent's depth + 1 (doc 19 §4): how deep in the fan-out
	// tree this child sits. depth ≥ 1 for any child (the base token is depth 0).
	AttenuationDepth int
	// BlockFingerprints is the chain of per-block fingerprints (the doc 19 §9 lineage),
	// base→leaf — FINGERPRINTS ONLY, never the per-block bytes or the token. len ==
	// AttenuationDepth+1 for a well-formed chain.
	BlockFingerprints []string
	// ParentSessions is the chain of parent_session hops root→leaf (doc 19 §4/§9): the
	// identity lineage the LOG-5 join walks. One entry per re-rooting hop.
	ParentSessions []string
}

// ChildTokenDeriver is the OFFLINE child-token derivation seam (doc 19 §4): it
// takes the parent's presented token + the per-child narrowing DATA and returns
// the derived child token + its lineage — with ZERO mint RPCs. The mint library
// satisfies it natively (DeriveChildSession over BuildChildAttenuation + the
// substrate append), a test fake satisfies it identically. The derivation is PURE
// w.r.t. the mint: a malformed/over-asking narrowing is rejected (the substrate
// fails a widening closed), never minted around — the deriver returns an error.
//
// parentToken is the parent's opaque presented value; d is the per-child narrowing.
// The deriver reads the parent's EFFECTIVE scope from the token's own claims (so
// the child scope is provably ⊆ the parent's blocks, not a caller-asserted value)
// and folds in the role-template default keyed by d.RoleRef. NO network, NO mint.
type ChildTokenDeriver interface {
	DeriveChildToken(ctx context.Context, parentToken []byte, d ChildSessionDerivation) (DerivedChildToken, error)
}

// CreateChildSessionRequest is the input to the fan-out leg (doc 15 §5.3): the
// parent session whose token is being attenuated, the parent's opaque presented
// token, and the per-child narrowings — one ChildSessionDerivation per subagent VM
// the wrapper is spawning. The leg derives one strictly-narrower child token per
// entry, all from the single parent token, with zero mint RPCs.
type CreateChildSessionRequest struct {
	// ParentSessionUUID is the session whose token the children attenuate from. It is
	// the immediate parent_session each child appends as its next hop (doc 19 §4).
	ParentSessionUUID string
	// ParentToken is the parent's opaque presented credential (the base token, or an
	// already-attenuated token deeper in the tree — fan-out composes, doc 19 §4). The
	// leg never logs it (fingerprint-only); it hands it to the deriver only.
	ParentToken []byte
	// Children is the per-subagent narrowings, one per child VM (doc 15 §5.3 "the D18
	// wrapper launching subagent/workflow calls in their own VMs"). Each yields one
	// strictly-narrower child token.
	Children []ChildSessionDerivation
}

// CreateChildSessionResult is the fan-out leg's output: one derived child token per
// requested child, in request order. Each token rides the SAME doc 15 §4.1 step-8
// entrypoint slot the child VM's create choreography already uses (doc 19 §4: "the
// child VM receives its token through the same step-8 entrypoint slot as any
// session" — no new choreography step).
type CreateChildSessionResult struct {
	// Children is the derived child tokens, request-order aligned with the request's
	// Children. Each carries its opaque token (for the step-8 entrypoint slot) and its
	// fingerprint-only lineage (for the LOG-5 audit join).
	Children []DerivedChildToken
}

// CreateChildSession is the minimal honest in-process fan-out leg (doc 15 §5.3,
// D18): for each requested child it DERIVES one strictly-narrower scoped token from
// the parent's token via the offline ChildTokenDeriver seam — ZERO mint RPCs —
// appending the child's session_uuid as the chain's next parent_session hop and
// recording the child's fingerprint-only lineage for LOG-5 (doc 19 §9).
//
// It is the orchestrator-side wiring ONLY: the actual narrowing/append is the mint
// library's (across the proto seam, carried as DATA); this leg assembles the
// per-child narrowing, drives the deriver, and threads the results to the step-8
// entrypoint slot. A child whose derivation FAILS (the deriver rejected a widening,
// or the parent token was unverifiable) is surfaced as an error naming the child —
// never swallowed into a partially-attenuated tree, and never round-tripped to the
// mint (that would forfeit the killer fit, doc 19 §4). Validates fail-closed: a
// missing parent token or a child with no session_uuid is an error before any
// derivation runs.
func CreateChildSession(ctx context.Context, deriver ChildTokenDeriver, req CreateChildSessionRequest) (CreateChildSessionResult, error) {
	if deriver == nil {
		return CreateChildSessionResult{}, fmt.Errorf("createchildsession: no child-token deriver configured")
	}
	if len(req.ParentToken) == 0 {
		return CreateChildSessionResult{}, fmt.Errorf("createchildsession: parent session %q has no token to attenuate", req.ParentSessionUUID)
	}

	out := CreateChildSessionResult{Children: make([]DerivedChildToken, 0, len(req.Children))}
	for i, d := range req.Children {
		if d.ChildSessionUUID == "" {
			return CreateChildSessionResult{}, fmt.Errorf("createchildsession: child %d (parent %q) has no session_uuid", i, req.ParentSessionUUID)
		}
		child, err := deriver.DeriveChildToken(ctx, req.ParentToken, d)
		if err != nil {
			// A rejected widening / unverifiable parent fails the WHOLE fan-out closed,
			// naming the child — never a partial tree, never a mint round-trip fallback.
			return CreateChildSessionResult{}, fmt.Errorf("createchildsession: derive child %q (parent %q): %w", d.ChildSessionUUID, req.ParentSessionUUID, err)
		}
		out.Children = append(out.Children, child)
	}
	return out, nil
}
