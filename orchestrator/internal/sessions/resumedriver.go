// SPDX-License-Identifier: Apache-2.0

// Production wiring of the resume-authority policy_breach (BIC) arm into the
// suspend/park/resume driver (doc 15 §3 note 3 + §4.3; doc 16 §8.2). parkresume.go
// already CONSULTS AuthorizeResume (resumeauthority.go) before traversing the §3
// SUSPENDED─►RESUMING / PARKED re-place edges, handing it the injected
// ParkResumeSeams.Approvals reader — but the seam is left to the CALLER to fill.
// When it is left nil the policy_breach arm denies fail-closed (the gate cannot
// prove an approval landed), which is the safe-but-PLACEHOLDER posture: a real
// landed rung-2 human approval would still be refused because nothing reads the
// policy_log. This file supplies the production wiring so the BIC arm consults the
// REAL grant-approval presence — a live PolicyKindAskGrant lookup — rather than that
// placeholder.
//
// THE WIRING (consume the frozen seams, declare nothing new). The production
// ApprovalPresence is the existing LiveGrantApprovalPresence (approvalpresence.go):
// "has a CURRENTLY-VALID (un-expired) PolicyKindAskGrant row landed for this
// session?", read through the narrow liveGrantReader slice of the store (just
// store.LiveGrants — *store.Memory and *store.Postgres both satisfy it natively, the
// store package stays FROZEN). This file does no more than build that reader and
// thread it into ParkResumeSeams.Approvals, so a production assembly hands the driver
// the store and gets the policy_breach arm wired to real policy_log state — the same
// shape main.go / controlplane wiring assembles by hand behind DS_ORCH_LIVE, made a
// reusable, OFFLINE-TESTABLE builder in the package that owns the seam.
//
// FAIL-CLOSED / FAITHFUL-TO-THE-GATE. The wiring changes only WHICH reader the
// policy_breach arm consults, never the gate's verdict rules: a missing or expired
// approval is still a denial, a read fault is still a fail-closed denial surfaced via
// ErrResumeApprovalReadFailed, and the user/scheduler arms are untouched (they admit
// on authority match alone). A nil reader is itself fail-closed — the production
// presence reports a read fault on every call rather than a false "no approval"
// (approvalpresence.go), so even a mis-wired build denies a policy_breach resume
// rather than silently allowing it.
//
// ADDITIVE / NEW FILE ONLY. This consumes the frozen ParkResumeSeams bundle, the
// frozen AuthorizeResume gate, the frozen LiveGrantApprovalPresence reader, and the
// frozen store.LiveGrants read. It adds no §3 state/edge/reason, no store method, and
// edits no other sessions file.

package sessions

import "time"

// WithLiveGrantApprovals returns a COPY of seams whose Approvals reader is the
// PRODUCTION LiveGrantApprovalPresence over the supplied liveGrantReader (the
// existing store.LiveGrants read; *store.Memory and *store.Postgres both satisfy it)
// and clock. This is the production wiring of the resume-authority policy_breach
// (BIC) arm: with it in place AuthorizeResume's landed-approval check reads REAL
// policy_log state for the session rather than the nil placeholder (which denies
// every policy_breach resume fail-closed regardless of a landed approval).
//
// A nil clock defaults to time.Now (NewLiveGrantApprovalPresence's contract), so a
// production wiring need only hand the store. The reader is REQUIRED for the BIC arm
// to function; a nil reader is still SAFE — the production presence reports a
// fail-closed read fault on every call rather than a false "no approval", so a
// policy_breach resume denies (it never silently allows), while the user/scheduler
// arms — which never consult Approvals — are unaffected.
//
// It leaves every OTHER seam exactly as supplied (Store/Suspender/Resumer/
// Snapshotter/Placer/HostAllocator/Minter), so a caller composes the host/re-place
// seams as usual and layers the production approval read on top with one call. Any
// Approvals already set on the input is OVERWRITTEN by the production reader — the
// point of the builder is to install the real presence, not to defer to a
// caller-supplied one.
func WithLiveGrantApprovals(seams ParkResumeSeams, reader liveGrantReader, now func() time.Time) ParkResumeSeams {
	seams.Approvals = NewLiveGrantApprovalPresence(reader, now)
	return seams
}

// NewParkResumeDriverWithLiveApprovals constructs a ParkResumeDriver with the
// production resume-authority policy_breach (BIC) arm wired: it installs the
// LiveGrantApprovalPresence over the supplied liveGrantReader into seams.Approvals
// (via WithLiveGrantApprovals) and then builds the driver through the standard
// NewParkResumeDriver, so all of that constructor's contracts hold (a nil Store is a
// construction error; a nil now defaults to time.Now; the host/re-place seams are
// validated lazily at the operation that needs them).
//
// The driverNow clock drives the driver's park/resume TIMING records; the
// approvalNow clock gates the approval-presence TTL liveness (the "un-expired as of
// now" check store.LiveGrants applies). They are taken separately so a test can pin
// the approval-liveness instant independently of the record-timing clock; a
// production wiring typically passes the SAME clock (or nil for time.Now) to both.
// A nil reader still constructs — the BIC arm then denies fail-closed at resume time
// (the production presence reports a read fault), never a silent allow.
func NewParkResumeDriverWithLiveApprovals(seams ParkResumeSeams, reader liveGrantReader, driverNow, approvalNow func() time.Time) (*ParkResumeDriver, error) {
	return NewParkResumeDriver(WithLiveGrantApprovals(seams, reader, approvalNow), driverNow)
}

// WithLiveGrantApprovalsAndRank is WithLiveGrantApprovals with the doc 16 §8.2
// SELF-APPROVAL GUARD engaged: it returns a COPY of seams whose Approvals reader is
// the production LiveGrantApprovalPresence over the supplied liveGrantReader AND the
// production ApproverRankResolver (NewStoreApproverRankResolver over rankStore), so a
// live PolicyKindAskGrant counts as a landed approval ONLY when its Actor (the
// approver) is a rung-2 human (Principal.MayApprove) DISTINCT from the session's
// requestor / launching_user. This closes the gap where a launching user — or a
// prompt-injected agent acting as that launching principal — approves its own
// policy_breach (BIC) park (approvalpresence.go §8.2 guard).
//
// The reader is the EXISTING store.LiveGrants read; rankStore is the EXISTING
// GetPrincipal + GetSessionLaunchingPrincipal reads (both *store.Memory and
// *store.Postgres satisfy the narrow principalRankStore slice natively — the store
// package stays FROZEN, no method added). In production the SAME backing store
// satisfies both, so a caller hands the store twice.
//
// ADDITIVE / FAIL-CLOSED. This is a purely additive sibling of WithLiveGrantApprovals;
// the un-guarded builder is kept for back-compat. A nil rankStore has nothing to back
// the guard with, so it FALLS BACK to the un-guarded production presence — the prior
// contract (any live grant counts) is BEHAVIOR-PRESERVING, and that presence is itself
// fail-closed on a missing/expired approval (and on a nil reader, which reports a read
// fault). A nil clock defaults to time.Now. Any Approvals already set on the input is
// OVERWRITTEN by the guarded reader — the point of the builder is to install the real
// guarded presence, not to defer to a caller-supplied one. Every OTHER seam is left
// exactly as supplied.
func WithLiveGrantApprovalsAndRank(seams ParkResumeSeams, reader liveGrantReader, rankStore principalRankStore, now func() time.Time) ParkResumeSeams {
	if rankStore == nil {
		// No principal-rank store to back the §8.2 guard: fall back to the un-guarded
		// production presence. This is behavior-preserving (the prior contract — any
		// live grant counts) and still fail-closed on a missing/expired approval; the
		// guard TIGHTENS the read, and there is nothing to tighten with absent a resolver.
		seams.Approvals = NewLiveGrantApprovalPresence(reader, now)
		return seams
	}
	seams.Approvals = NewLiveGrantApprovalPresenceWithRank(reader, NewStoreApproverRankResolver(rankStore), now)
	return seams
}

// NewParkResumeDriverWithGuardedApprovals is NewParkResumeDriverWithLiveApprovals with
// the doc 16 §8.2 self-approval guard engaged: it installs the guarded
// LiveGrantApprovalPresence (via WithLiveGrantApprovalsAndRank — the live-grant read
// tightened by the ApproverRankResolver over rankStore) into seams.Approvals and then
// builds the driver through the standard NewParkResumeDriver, so all of that
// constructor's contracts hold (a nil Store is a construction error; a nil now defaults
// to time.Now; the host / re-place seams are validated lazily at the operation that
// needs them).
//
// The driverNow clock drives the driver's park/resume TIMING records; the approvalNow
// clock gates the approval-presence TTL liveness. They are taken separately so a test
// can pin the approval-liveness instant independently of the record-timing clock; a
// production wiring typically passes the SAME clock (or nil for time.Now) to both.
//
// ADDITIVE / FAIL-CLOSED. The un-guarded NewParkResumeDriverWithLiveApprovals is kept
// for back-compat. A nil rankStore falls back to the un-guarded presence
// (behavior-preserving, still fail-closed); a nil reader still constructs and the BIC
// arm then denies fail-closed at resume time (the production presence reports a read
// fault), never a silent allow.
func NewParkResumeDriverWithGuardedApprovals(seams ParkResumeSeams, reader liveGrantReader, rankStore principalRankStore, driverNow, approvalNow func() time.Time) (*ParkResumeDriver, error) {
	return NewParkResumeDriver(WithLiveGrantApprovalsAndRank(seams, reader, rankStore, approvalNow), driverNow)
}
