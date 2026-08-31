// SPDX-License-Identifier: Apache-2.0

package identityrows

import (
	"fmt"
	"sort"
	"strings"
)

// identityrows models the doc 16 §13 identity (c) rows not already implemented by
// credswap/secretegress/appinstall (doc.go states the claims, their anchors, and
// the row split). Each row is a deterministic check over SYNTHETIC fixtures
// (D50) — Go-literal inputs built by the test, never a live mint/validate/swap or
// any VM/host/KVM run. The shape mirrors the orchctl sibling: a typed fixture + a
// typed violation taxonomy + a pure Check* function exercised with a CONFORMING
// control and one fixture per NAMED violation class.

// ── Single-sourced guardrail tags (doc.go REGISTRATION; guardrail-map.yaml) ──
//
// The ten doc 16 §13 identity (c)-row tags this package carries, in doc.go
// REGISTRATION order. Tags is the SINGLE SOURCE for the row names: the repo-root
// guardrail-map.yaml's identityrows glob row and this slice must name the SAME
// rows, and TestTagsStable pins the slice so a silent drift fails HERE rather than
// against a differently-named map row (the orchctl honest-map-row discipline — a
// map row names a real, single-sourced tag value, never a placeholder string).
const (
	// TagMintBeforeAttach — ROW 1 mint-before-attach + fail-closed digest-write (§6.1).
	TagMintBeforeAttach = "identity-mint-before-attach"
	// TagPerSessionCAIsolation — ROW 2 per-session CA isolation + D82 hierarchy separation (§4).
	TagPerSessionCAIsolation = "identity-per-session-ca-isolation"
	// TagIssuedCredRoutingAsymmetry — ROW 3 issued-cred routing asymmetry / double-fire (§11.1, doc 12 OQ2).
	TagIssuedCredRoutingAsymmetry = "identity-issued-cred-routing-asymmetry"
	// TagFleetRevocationClock — ROW 4 fleet revocation clock inside the POL-4 bar (§6.2).
	TagFleetRevocationClock = "identity-fleet-revocation-clock"
	// TagValidationFailure403 — ROW 5 validation failure → structured 403 + stale-cert (§4/§5.4).
	TagValidationFailure403 = "identity-validation-failure-structured-403"
	// TagSocketHoldPaths — ROW 6 socket-hold paths + ask-grant atomicity (§8.2, D78).
	TagSocketHoldPaths = "identity-socket-hold-paths"
	// TagAttendednessFlip — ROW 7 attendedness flip driven only by the distributed signal (§8.1, D78).
	TagAttendednessFlip = "identity-attendedness-flip"
	// TagGitHTTPSPin — ROW 8 git-HTTPS pin guards the §5.3 SSH bypass.
	TagGitHTTPSPin = "identity-git-https-pin"
	// TagLog5Join — ROW 9 LOG-5 join + fingerprint-only across all identity events (§11.1, §9).
	TagLog5Join = "identity-log5-join"
	// TagParkResumeTiers — ROW 10 park/resume at the D46 tiers (§5.4).
	TagParkResumeTiers = "identity-park-resume-tiers"
)

// Tags is the ordered set of single-sourced guardrail tags this package owns, for
// the guardrail-map.yaml identityrows row to name the SAME rows (doc.go REGISTRATION).
var Tags = []string{
	TagMintBeforeAttach,
	TagPerSessionCAIsolation,
	TagIssuedCredRoutingAsymmetry,
	TagFleetRevocationClock,
	TagValidationFailure403,
	TagSocketHoldPaths,
	TagAttendednessFlip,
	TagGitHTTPSPin,
	TagLog5Join,
	TagParkResumeTiers,
}

// ── Shared violation type ───────────────────────────────────────────────────

// ViolationClass names a single failure mode one of the ten rows enumerates, so
// every violation reports WHICH rule it tripped (the "fails NAMED" bar). The
// constants are grouped per row below.
type ViolationClass string

// Violation is a single guardrail breach: which rule, which subject (the session /
// CA / domain / event the check ran against), and a human-readable reason citing
// the governing anchor.
type Violation struct {
	Class   ViolationClass
	Subject string
	Reason  string
}

func (v Violation) String() string {
	return fmt.Sprintf("[%s] %s: %s", v.Class, v.Subject, v.Reason)
}

// sortViolations orders a slice by (class, subject) so failure messages and
// class-set comparisons are stable across runs.
func sortViolations(vs []Violation) {
	sort.Slice(vs, func(i, j int) bool {
		if vs[i].Class != vs[j].Class {
			return vs[i].Class < vs[j].Class
		}
		return vs[i].Subject < vs[j].Subject
	})
}

// ────────────────────────────────────────────────────────────────────────────
// ROW 1 — mint-before-attach + fail-closed digest-write (doc 16 §13; §6.1 mint
//         sub-sequence; round2/08 test 6).
//
// THE CLAIM (§6.1): within the orchestrator-owned master choreography
// (identity mint → CA mint → grant issuance → cred mint → digest computation →
// digest write to the boundary host → ack → session marked ROUTABLE) a freshly
// minted session's digests are MATCHABLE before its FIRST egress byte
// (round2/08 test 6). The session is marked routable ONLY after the digest write
// is ACKed. *Fail-closed:* digest-write failure FAILS or STALLS session create —
// never degrades open. So: a session must not be routable before its digests are
// written+acked, and a digest-write failure must not let the session become
// routable.
// ────────────────────────────────────────────────────────────────────────────

const (
	// ViolationRoutableBeforeDigestsMatchable — the session was marked ROUTABLE
	// (first egress byte possible) before its digests were written+acked, so a byte
	// could egress unscanned (round2/08 test 6 fails).
	ViolationRoutableBeforeDigestsMatchable ViolationClass = "mint-routable-before-digests-matchable"
	// ViolationDigestWriteFailureDegradedOpen — a digest-write failure did NOT fail
	// or stall create: the session became routable anyway (the §6.1 fail-closed
	// invariant degraded OPEN).
	ViolationDigestWriteFailureDegradedOpen ViolationClass = "mint-digest-write-failure-degraded-open"
)

// MintSequence is a synthetic fixture for one session's mint sub-sequence: did the
// digest write to the boundary host SUCCEED and get ACKed, and was the session
// then marked ROUTABLE (the §6.1 readiness gate).
type MintSequence struct {
	Session string
	// DigestsWritten records whether the digest write to the boundary host succeeded.
	DigestsWritten bool
	// DigestAck records whether the host agent ACKed the write (D109; §6.1). The
	// session may be marked routable only after this ack.
	DigestAck bool
	// MarkedRoutable records whether the session was actually marked routable (first
	// egress byte then becomes possible).
	MarkedRoutable bool
}

// digestsMatchable reports whether the session's digests are matchable on the
// boundary host: written AND acked. Until both hold, a first egress byte would be
// unscanned.
func (m MintSequence) digestsMatchable() bool { return m.DigestsWritten && m.DigestAck }

// CheckMintBeforeAttach asserts the §6.1 mint-before-attach + fail-closed
// digest-write claim for one fixture. An empty result means the row holds: the
// session was marked routable only after its digests were matchable, and a
// digest-write failure stalled create rather than degrading open.
func CheckMintBeforeAttach(m MintSequence) []Violation {
	var vs []Violation
	if m.MarkedRoutable && !m.digestsMatchable() {
		// Distinguish the two named failure modes: a digest-write FAILURE that
		// degraded open vs a sequencing race that marked routable before the ack.
		if !m.DigestsWritten {
			vs = append(vs, Violation{
				Class:   ViolationDigestWriteFailureDegradedOpen,
				Subject: m.Session,
				Reason: "the digest write to the boundary host FAILED yet the session was marked " +
					"ROUTABLE; §6.1 makes digest-write failure fail-or-stall session create — it must " +
					"never degrade OPEN (a first egress byte would be unscanned; round2/08 test 6, D73)",
			})
		} else {
			vs = append(vs, Violation{
				Class:   ViolationRoutableBeforeDigestsMatchable,
				Subject: m.Session,
				Reason: "the session was marked ROUTABLE before its digests were ACKed on the " +
					"boundary host; a freshly minted session's digests must be MATCHABLE before its " +
					"first egress byte — routable lags the digest-write ack (§6.1, round2/08 test 6, D109)",
			})
		}
	}
	sortViolations(vs)
	return vs
}

// ────────────────────────────────────────────────────────────────────────────
// ROW 2 — per-session CA isolation + D82 hierarchy separation (doc 16 §13; §4
//         interception-CA mint; D82 two root hierarchies, D17 per-session CA).
//
// THE CLAIM (§4): per-session CA material is session-lifecycle data — session A's
// CA is USELESS against session B (a leaf minted under A's interception CA never
// validates against B's). AND (D82, new) the two ROOT hierarchies are separate —
// workload-identity and interception — so an interception-root signature never
// validates as a workload identity (compromise of one root never yields the
// other's signing capability). A leaf that chains to the EXPECTED per-session root
// AND whose presented purpose matches the issuing hierarchy validates; a
// cross-session chain or a cross-hierarchy presentation does NOT.
// ────────────────────────────────────────────────────────────────────────────

const (
	// ViolationCrossSessionCAValidated — a leaf minted under session A's interception
	// CA validated against session B; per-session CA material must be useless across
	// sessions (§4, D17).
	ViolationCrossSessionCAValidated ViolationClass = "ca-cross-session-validated"
	// ViolationCrossHierarchyValidated — an interception-root signature validated as a
	// WORKLOAD identity (or vice versa); D82 keeps the two root hierarchies separate so
	// neither root's compromise yields the other's signing capability.
	ViolationCrossHierarchyValidated ViolationClass = "ca-cross-hierarchy-validated"
	// ViolationSameSessionSameHierarchyRejected — a leaf that chains to the EXPECTED
	// per-session root AND presents its OWN hierarchy's purpose was rejected; the
	// isolation rule must not over-reject the legitimate same-session same-hierarchy
	// case (the inverse regression that would break every session).
	ViolationSameSessionSameHierarchyRejected ViolationClass = "ca-same-session-same-hierarchy-rejected"
)

// Hierarchy is one of the D82 two separate root hierarchies (§4).
type Hierarchy string

const (
	// HierarchyWorkload — root hierarchy 1: workload identity (the SPIFFE-compatible
	// session cert, MintWorkloadIdentity).
	HierarchyWorkload Hierarchy = "workload"
	// HierarchyInterception — root hierarchy 2: the per-session interception CA (D17,
	// MintInterceptionCA); compromise here never yields workload-identity signing (D82).
	HierarchyInterception Hierarchy = "interception"
)

// CAValidation is a synthetic fixture for one certificate presentation: the leaf's
// issuing session + hierarchy, the session + hierarchy it is being VALIDATED
// against / presented AS, and the observed verdict.
type CAValidation struct {
	Subject string
	// IssuedForSession is the session whose CA minted the leaf.
	IssuedForSession string
	// IssuedUnderHierarchy is the root hierarchy the leaf was minted under.
	IssuedUnderHierarchy Hierarchy
	// ValidatedAgainstSession is the session the leaf is being validated against.
	ValidatedAgainstSession string
	// PresentedAsHierarchy is the purpose/hierarchy the leaf is being presented for
	// (a workload-identity presentation vs an interception-CA chain).
	PresentedAsHierarchy Hierarchy
	// Validated records whether the verifier ACCEPTED the presentation.
	Validated bool
}

// shouldValidate is the reference verdict: a leaf validates IFF it is checked
// against its OWN issuing session AND presented under its OWN issuing hierarchy.
func (c CAValidation) shouldValidate() bool {
	return c.IssuedForSession == c.ValidatedAgainstSession &&
		c.IssuedUnderHierarchy == c.PresentedAsHierarchy
}

// CheckPerSessionCAIsolation asserts the §4 per-session isolation + D82 hierarchy
// separation for one presentation fixture. An empty result means the row holds: a
// cross-session chain is rejected, a cross-hierarchy presentation is rejected, and
// the legitimate same-session same-hierarchy case is accepted.
func CheckPerSessionCAIsolation(c CAValidation) []Violation {
	var vs []Violation
	switch {
	case c.Validated && c.IssuedForSession != c.ValidatedAgainstSession:
		vs = append(vs, Violation{
			Class:   ViolationCrossSessionCAValidated,
			Subject: c.Subject,
			Reason: fmt.Sprintf("a leaf minted under session %q's CA VALIDATED against session %q; "+
				"per-session CA material is session-lifecycle data — session A's CA is useless against "+
				"session B (doc 16 §4, D17)", c.IssuedForSession, c.ValidatedAgainstSession),
		})
	case c.Validated && c.IssuedUnderHierarchy != c.PresentedAsHierarchy:
		vs = append(vs, Violation{
			Class:   ViolationCrossHierarchyValidated,
			Subject: c.Subject,
			Reason: fmt.Sprintf("a signature minted under the %q root hierarchy VALIDATED as %q; D82 "+
				"keeps the workload-identity and interception roots SEPARATE so neither root's "+
				"compromise yields the other's signing capability (doc 16 §4, D82)",
				c.IssuedUnderHierarchy, c.PresentedAsHierarchy),
		})
	case !c.Validated && c.shouldValidate():
		vs = append(vs, Violation{
			Class:   ViolationSameSessionSameHierarchyRejected,
			Subject: c.Subject,
			Reason: fmt.Sprintf("a leaf chaining to its OWN session %q root and presented under its "+
				"OWN %q hierarchy was REJECTED; the isolation rule must not over-reject the legitimate "+
				"same-session same-hierarchy case (doc 16 §4)", c.IssuedForSession, c.IssuedUnderHierarchy),
		})
	}
	sortViolations(vs)
	return vs
}

// ────────────────────────────────────────────────────────────────────────────
// ROW 3 — issued-cred routing asymmetry / double-fire (doc 16 §13; §11.1 step 7
//         + wrong-destination block semantics; doc 12 OQ2 filter ordering).
//
// THE CLAIM (§11.1): the ISSUED{service_id} digest is destination-scoped by its
// grant. On egress to the INTENDED service the swap injects the real credential
// EXACTLY ONCE and the SecretMatcher never flags the proxy-injected credential
// (the swap/scan filter-ordering interlock, doc 12 OQ2 — the injected credential
// is never scan-visible / fires exactly once). The SAME credential (raw + every
// pushed variant_tag) appearing on egress to ANY OTHER destination fires
// keyed-issued-to-wrong-destination, default BLOCK+LOG. So: intended-destination
// egress → swapped, NOT flagged; other-destination egress → block+log.
// ────────────────────────────────────────────────────────────────────────────

const (
	// ViolationInjectedCredFlagged — on the INTENDED-service egress the scan flagged
	// the proxy-injected credential; the filter-ordering interlock (doc 12 OQ2) makes
	// the injected credential scan-INVISIBLE so it fires exactly once, never self-flags.
	ViolationInjectedCredFlagged ViolationClass = "issued-cred-injected-self-flagged"
	// ViolationIntendedNotSwapped — on the intended-service egress the credential was
	// NOT swapped (the agent's placeholder egressed unswapped); the intended egress
	// must swap exactly once.
	ViolationIntendedNotSwapped ViolationClass = "issued-cred-intended-not-swapped"
	// ViolationWrongDestinationNotBlocked — the SAME issued credential appeared on
	// egress to a DIFFERENT destination and was NOT block+logged; a digest is
	// destination-scoped by its grant — elsewhere → block+log.
	ViolationWrongDestinationNotBlocked ViolationClass = "issued-cred-wrong-destination-not-blocked"
)

// EgressDisposition is the observed disposition of one egress carrying an issued
// credential.
type EgressDisposition string

const (
	// DispSwappedNotFlagged — the swap injected the real credential and the scan did
	// NOT flag it (the correct intended-destination outcome).
	DispSwappedNotFlagged EgressDisposition = "swapped-not-flagged"
	// DispSwappedThenFlagged — the swap injected the credential AND the scan then
	// flagged it (the double-fire self-flag the interlock forbids on intended egress).
	DispSwappedThenFlagged EgressDisposition = "swapped-then-flagged"
	// DispPlaceholderUnswapped — no swap happened; the agent's placeholder egressed.
	DispPlaceholderUnswapped EgressDisposition = "placeholder-unswapped"
	// DispBlockLogged — the egress was blocked and logged (the correct
	// wrong-destination outcome).
	DispBlockLogged EgressDisposition = "block-logged"
	// DispLeakedThrough — the credential egressed to the destination with no block.
	DispLeakedThrough EgressDisposition = "leaked-through"
)

// IssuedEgress is a synthetic fixture for one egress carrying an issued credential:
// whether the destination is the grant's INTENDED service, and the observed
// disposition (across raw + variant_tag — the variant is modeled as a label only,
// since the asymmetry is destination-scoped, not encoding-scoped).
type IssuedEgress struct {
	Subject string
	// IntendedDestination is true iff the egress destination is the GitHub host the
	// grant's ISSUED{service_id} names (the only place the digest is expected).
	IntendedDestination bool
	// Disposition is what the swap+scan pipeline actually did.
	Disposition EgressDisposition
}

// CheckIssuedCredRoutingAsymmetry asserts the destination-scoped double-fire claim
// for one egress fixture. An empty result means the row holds: intended-service
// egress swapped exactly once and was not self-flagged; a wrong-destination egress
// was block+logged.
func CheckIssuedCredRoutingAsymmetry(e IssuedEgress) []Violation {
	var vs []Violation
	if e.IntendedDestination {
		switch e.Disposition {
		case DispSwappedNotFlagged:
			// conforming: swapped exactly once, never self-flagged.
		case DispSwappedThenFlagged:
			vs = append(vs, Violation{
				Class:   ViolationInjectedCredFlagged,
				Subject: e.Subject,
				Reason: "on the INTENDED-service egress the scan flagged the proxy-injected " +
					"credential; the swap/scan filter-ordering interlock (doc 12 OQ2) makes the " +
					"injected credential scan-INVISIBLE — it fires exactly once and never self-flags " +
					"(doc 16 §11.1 step 7, §10)",
			})
		default:
			vs = append(vs, Violation{
				Class:   ViolationIntendedNotSwapped,
				Subject: e.Subject,
				Reason: fmt.Sprintf("on the intended-service egress the credential was not swapped "+
					"(disposition %q); the intended-destination egress must swap exactly once "+
					"(doc 16 §11.1 steps 5/7, D83)", e.Disposition),
			})
		}
		sortViolations(vs)
		return vs
	}
	// Wrong destination: the same issued credential anywhere else must block+log.
	if e.Disposition != DispBlockLogged {
		vs = append(vs, Violation{
			Class:   ViolationWrongDestinationNotBlocked,
			Subject: e.Subject,
			Reason: fmt.Sprintf("the same issued credential appeared on egress to a NON-intended "+
				"destination with disposition %q, not block+log; an ISSUED{service_id} digest is "+
				"destination-scoped by its grant — the same credential (raw + every variant_tag) "+
				"elsewhere fires keyed-issued-to-wrong-destination, default block+log (doc 16 §11.1 "+
				"wrong-destination semantics; §7 rung table, D73)", e.Disposition),
		})
	}
	sortViolations(vs)
	return vs
}

// ────────────────────────────────────────────────────────────────────────────
// ROW 4 — fleet revocation clock (doc 16 §13; §6.2 two cadences; POL-4 bar;
//         sweep-plus-flush — D72/D68).
//
// THE CLAIM (§6.2): a fleet-scope FORBIDDEN digest registration/revocation is a
// policy artifact under the policy_log seq, covered by the prepare/commit barrier
// + revocation sweep, inheriting the POL-4 seconds-scale bar — revocation latency
// = the POL-4 push-to-enforced clock INCLUDING sweep-plus-flush. And: Identity
// invents NO third cadence and the matcher needs NO proxy build/restart for any
// rule/digest change (the digest plane is data, not code). So: a registered
// forbidden digest must be enforced fleet-wide within the bar AND with the sweep
// completed, and no proxy restart may be required.
// ────────────────────────────────────────────────────────────────────────────

const (
	// ViolationRevocationOutsidePOL4Bar — a forbidden-digest change took longer than
	// the POL-4 seconds-scale bar to become fleet-enforced.
	ViolationRevocationOutsidePOL4Bar ViolationClass = "fleet-revocation-outside-pol4-bar"
	// ViolationRevocationEnforcedWithoutSweep — the digest was reported enforced before
	// the revocation sweep-plus-flush completed; the clock INCLUDES the sweep.
	ViolationRevocationEnforcedWithoutSweep ViolationClass = "fleet-revocation-enforced-without-sweep"
	// ViolationDigestChangeRequiredProxyRestart — a rule/digest change required a proxy
	// build/restart; the digest plane is DATA — no restart may be needed.
	ViolationDigestChangeRequiredProxyRestart ViolationClass = "fleet-digest-change-required-proxy-restart"
)

// DefaultPOL4BarSeconds is the documented seconds-scale POL-4 revocation bar the
// fleet-revocation clock inherits (§6.2; doc 13 POL-4). A guard test pins this so a
// silent constant drift fails HERE rather than judging against a looser bar than
// the doc promises (the orchctl DefaultCanaryWindowDays / goldenfreshness
// DefaultRotationWindow anchor-guard discipline). It is a fixed strawman ceiling,
// not a re-decision of the (d)-rig-measured number.
const DefaultPOL4BarSeconds = 10

// DigestRevocation is a synthetic fixture for one fleet-scope forbidden-digest
// registration/revocation and its observed propagation.
type DigestRevocation struct {
	Subject string
	// PropagationSeconds is how long the change took to become fleet-enforced.
	PropagationSeconds int
	// BarSeconds is the POL-4 bar the change is judged against (DefaultPOL4BarSeconds).
	BarSeconds int
	// SweepCompleted records whether the revocation sweep-plus-flush completed before
	// the change was reported enforced (the clock includes the sweep).
	SweepCompleted bool
	// Enforced records whether the digest was reported fleet-enforced.
	Enforced bool
	// RequiredProxyRestart records whether a proxy build/restart was needed for the
	// rule/digest change (it must not be — the digest plane is data).
	RequiredProxyRestart bool
}

// CheckFleetRevocationClock asserts the §6.2 fleet revocation clock for one fixture.
// An empty result means the row holds: the change was enforced fleet-wide within
// the POL-4 bar with the sweep-plus-flush completed, and no proxy restart was
// required.
func CheckFleetRevocationClock(r DigestRevocation) []Violation {
	var vs []Violation
	if r.RequiredProxyRestart {
		vs = append(vs, Violation{
			Class:   ViolationDigestChangeRequiredProxyRestart,
			Subject: r.Subject,
			Reason: "a rule/digest change required a proxy build/restart; the digest plane is DATA " +
				"distributed under the policy_log seq — no proxy rebuild/restart may be needed for any " +
				"rule or digest change (doc 16 §6.2, §13, D72)",
		})
	}
	if r.Enforced {
		if r.PropagationSeconds > r.BarSeconds {
			vs = append(vs, Violation{
				Class:   ViolationRevocationOutsidePOL4Bar,
				Subject: r.Subject,
				Reason: fmt.Sprintf("the forbidden-digest change took %ds to become fleet-enforced, "+
					"outside the POL-4 seconds-scale bar of %ds; fleet revocation inherits the POL-4 "+
					"push-to-enforced clock (doc 16 §6.2; doc 13 POL-4)", r.PropagationSeconds, r.BarSeconds),
			})
		}
		if !r.SweepCompleted {
			vs = append(vs, Violation{
				Class:   ViolationRevocationEnforcedWithoutSweep,
				Subject: r.Subject,
				Reason: "the digest was reported fleet-enforced before the revocation sweep-plus-flush " +
					"completed; the revocation-latency clock INCLUDES sweep-plus-flush — derived state " +
					"(live grants / matcher entries) must be evicted before enforcement is claimed " +
					"(doc 16 §6.2, §13, D72/D68)",
			})
		}
	}
	sortViolations(vs)
	return vs
}

// ────────────────────────────────────────────────────────────────────────────
// ROW 5 — validation failure → structured 403 + stale-cert (doc 16 §13; §4
//         Validate seam; §5.4 revocation; §11.1 step 3).
//
// THE CLAIM (§4/§5.4/§11.1 step 3): a Validate DENY surfaces as the IN-BAND
// structured 403 (D77 block+log) carrying a machine-readable reason; the minimal
// CA ships NO CRL/OCSP, so a revoked/killed/suspended session's still-valid cert
// is caught IMMEDIATELY by the session-LIVENESS check, not by revocation (the
// stale-cert row). Kill-mid-flight triggers the same digest flush as teardown
// (§5.4). So: a DENY must carry a machine-readable reason; a revoked session must
// DENY on liveness even with a fresh signature; and a kill-mid-flight must flush
// the session's digests.
// ────────────────────────────────────────────────────────────────────────────

const (
	// ViolationDenyWithoutMachineReason — a DENY verdict carried no machine-readable
	// reason; §4 makes DENY{machine_readable_reason} the structured-403 contract.
	ViolationDenyWithoutMachineReason ViolationClass = "validation-deny-without-machine-reason"
	// ViolationStaleCertValidated — a revoked/killed/suspended session's still-valid
	// cert was ALLOWed; the session-liveness check must fail it IMMEDIATELY (§5.4 — no
	// CRL/OCSP, liveness is the revocation mechanism).
	ViolationStaleCertValidated ViolationClass = "validation-stale-cert-validated"
	// ViolationKillMidFlightDigestsNotFlushed — a kill-mid-flight did NOT flush the
	// session's digests; kill triggers the same digest flush as teardown (§5.4).
	ViolationKillMidFlightDigestsNotFlushed ViolationClass = "validation-kill-mid-flight-digests-not-flushed"
)

// Verdict is the §4 Validate verdict (ALLOW | DENY).
type Verdict string

const (
	VerdictAllow Verdict = "ALLOW"
	VerdictDeny  Verdict = "DENY"
)

// SessionLiveness is the §5.4 liveness state of a session as the Validate seam sees
// it. A revoked/killed/suspended session is NOT live; its cert must fail Validate.
type SessionLiveness string

const (
	LivenessLive      SessionLiveness = "live"
	LivenessRevoked   SessionLiveness = "revoked"
	LivenessKilled    SessionLiveness = "killed"
	LivenessSuspended SessionLiveness = "suspended"
)

// live reports whether the session is still live (the only state whose cert may
// validate).
func (l SessionLiveness) live() bool { return l == LivenessLive }

// ValidationOutcome is a synthetic fixture for one Validate call + its aftermath:
// the session liveness, whether the presented cert signature/freshness was
// otherwise valid, the observed verdict + machine-reason, and — for a kill — whether
// the session digests were flushed.
type ValidationOutcome struct {
	Subject string
	// Liveness is the session's liveness state at Validate time.
	Liveness SessionLiveness
	// SignatureFresh records whether the cert's signature+freshness alone are valid
	// (a stolen-but-unexpired cert is SignatureFresh=true but not Live).
	SignatureFresh bool
	// Verdict is the observed Validate verdict.
	Verdict Verdict
	// MachineReason is the DENY's machine-readable reason (must be non-empty for a DENY).
	MachineReason string
	// KillMidFlight records whether this outcome models a kill-mid-flight event.
	KillMidFlight bool
	// DigestsFlushed records whether the session's digests were flushed (only meaningful
	// for a kill-mid-flight).
	DigestsFlushed bool
}

// CheckValidationFailure403 asserts the §4/§5.4 validation-failure claim for one
// outcome fixture. An empty result means the row holds: a DENY carries a
// machine-readable reason, a non-live session's cert is DENYed on liveness even
// with a fresh signature, and a kill-mid-flight flushes the session's digests.
func CheckValidationFailure403(o ValidationOutcome) []Violation {
	var vs []Violation
	if o.Verdict == VerdictDeny && o.MachineReason == "" {
		vs = append(vs, Violation{
			Class:   ViolationDenyWithoutMachineReason,
			Subject: o.Subject,
			Reason: "a DENY verdict carried no machine-readable reason; §4 freezes the Validate DENY " +
				"shape as DENY{machine_readable_reason}, surfaced as the in-band structured 403 " +
				"(D77 block+log) so the failure is auditable and the agent self-heals (doc 16 §4, §11.1 step 3)",
		})
	}
	if o.Verdict == VerdictAllow && !o.Liveness.live() {
		vs = append(vs, Violation{
			Class:   ViolationStaleCertValidated,
			Subject: o.Subject,
			Reason: fmt.Sprintf("a %q session's cert was ALLOWed (signature_fresh=%t); the minimal CA "+
				"ships no CRL/OCSP, so a stolen-but-unexpired cert must be caught IMMEDIATELY by the "+
				"session-LIVENESS check — a non-live session must DENY (doc 16 §5.4, §11.1 step 3)",
				o.Liveness, o.SignatureFresh),
		})
	}
	if o.KillMidFlight && !o.DigestsFlushed {
		vs = append(vs, Violation{
			Class:   ViolationKillMidFlightDigestsNotFlushed,
			Subject: o.Subject,
			Reason: "a kill-mid-flight did not flush the session's digests; kill-mid-flight triggers " +
				"the SAME digest flush as teardown so a killed session leaves no matchable digests " +
				"behind (doc 16 §5.4)",
		})
	}
	sortViolations(vs)
	return vs
}

// ────────────────────────────────────────────────────────────────────────────
// ROW 6 — socket-hold paths + ask-grant atomicity (doc 16 §13; §8.2 socket-hold
//         connection + parking; D77 socket-hold; D78 detach; doc 13 §7).
//
// THE CLAIM (§8.2): an attended unknown-domain ask gets the TLS-1 30–60 s
// socket-hold via the ask-user seam — approval IN the window proceeds (and the
// first post-approval retry succeeds, the ask-grant atomicity join); a TIMEOUT
// closes the hold (deny). A detach-mid-hold runs the IN-FLIGHT hold to its timeout
// (the D78 detach default: holds already in flight run to their 30–60 s timeout;
// only NEW asks downgrade) — and a NEW ask post-detach blocks IMMEDIATELY. So:
// approve-in-window → proceed; timeout → closed-then-retry-succeeds; detach a hold
// in flight → runs to timeout (not torn down early); new ask after detach → block.
// ────────────────────────────────────────────────────────────────────────────

const (
	// ViolationApprovedInWindowNotProceeded — an approval that arrived inside the hold
	// window did NOT proceed (or its first post-approval retry did not succeed); an
	// in-window approval proceeds (the ask-grant atomicity join).
	ViolationApprovedInWindowNotProceeded ViolationClass = "socket-hold-approved-in-window-not-proceeded"
	// ViolationTimeoutNotClosed — the hold window elapsed with no answer but the hold
	// did not CLOSE (deny); a timeout must close the hold, never time out into allow.
	ViolationTimeoutNotClosed ViolationClass = "socket-hold-timeout-not-closed"
	// ViolationDetachTornDownEarly — a hold ALREADY IN FLIGHT when attendedness dropped
	// was torn down EARLY rather than running to its timeout; the D78 detach default
	// runs in-flight holds to their 30–60 s timeout.
	ViolationDetachTornDownEarly ViolationClass = "socket-hold-detach-torn-down-early"
	// ViolationNewAskPostDetachNotBlocked — a NEW ask raised after detach did not
	// block+log immediately; only in-flight holds ride to timeout — new asks downgrade.
	ViolationNewAskPostDetachNotBlocked ViolationClass = "socket-hold-new-ask-post-detach-not-blocked"
)

// HoldPhase names which socket-hold path a fixture exercises.
type HoldPhase string

const (
	// PhaseApprovedInWindow — an approval arrived inside the hold window.
	PhaseApprovedInWindow HoldPhase = "approved-in-window"
	// PhaseTimeout — the hold window elapsed with no answer.
	PhaseTimeout HoldPhase = "timeout"
	// PhaseDetachInFlight — attendedness dropped while a hold was already in flight.
	PhaseDetachInFlight HoldPhase = "detach-in-flight"
	// PhaseNewAskPostDetach — a new ask raised after detach (unattended).
	PhaseNewAskPostDetach HoldPhase = "new-ask-post-detach"
)

// HoldOutcome names the observed disposition of a socket-hold fixture.
type HoldOutcome string

const (
	HoldProceeded          HoldOutcome = "proceeded"            // approval honored, flow allowed
	HoldRetrySucceeded     HoldOutcome = "retry-succeeded"      // first post-approval retry succeeded
	HoldClosed             HoldOutcome = "closed"               // hold closed (deny) on timeout
	HoldRanToTimeout       HoldOutcome = "ran-to-timeout"       // in-flight hold ran its full window
	HoldTornDownEarly      HoldOutcome = "torn-down-early"      // hold cut short before its timeout
	HoldBlockedImmediately HoldOutcome = "blocked-immediately"  // new ask downgraded to block+log
	HoldTimedOutIntoAllow  HoldOutcome = "timed-out-into-allow" // FORBIDDEN: timeout became allow
)

// SocketHold is a synthetic fixture for one socket-hold path and its observed
// outcome.
type SocketHold struct {
	Subject string
	Phase   HoldPhase
	Outcome HoldOutcome
}

// CheckSocketHoldPaths asserts the §8.2 socket-hold + ask-grant atomicity claim for
// one fixture. An empty result means the row holds for that path.
func CheckSocketHoldPaths(h SocketHold) []Violation {
	var vs []Violation
	switch h.Phase {
	case PhaseApprovedInWindow:
		if h.Outcome != HoldProceeded && h.Outcome != HoldRetrySucceeded {
			vs = append(vs, Violation{
				Class:   ViolationApprovedInWindowNotProceeded,
				Subject: h.Subject,
				Reason: fmt.Sprintf("an approval that arrived inside the socket-hold window did not "+
					"proceed (outcome %q); an in-window approval proceeds and the first post-approval "+
					"retry succeeds — the ask-grant atomicity join (doc 16 §8.2; doc 13 §7)", h.Outcome),
			})
		}
	case PhaseTimeout:
		if h.Outcome != HoldClosed {
			vs = append(vs, Violation{
				Class:   ViolationTimeoutNotClosed,
				Subject: h.Subject,
				Reason: fmt.Sprintf("the hold window elapsed with no answer but the hold did not CLOSE "+
					"(outcome %q); a timeout closes the hold (deny) — a genuine ask never times out into "+
					"allow (doc 16 §8.2; D77)", h.Outcome),
			})
		}
	case PhaseDetachInFlight:
		if h.Outcome != HoldRanToTimeout {
			vs = append(vs, Violation{
				Class:   ViolationDetachTornDownEarly,
				Subject: h.Subject,
				Reason: fmt.Sprintf("a hold already IN FLIGHT when attendedness dropped did not run to "+
					"its timeout (outcome %q); the D78 detach default runs in-flight holds to their "+
					"30–60 s timeout — only NEW asks downgrade (doc 16 §8.1/§8.2, D78)", h.Outcome),
			})
		}
	case PhaseNewAskPostDetach:
		if h.Outcome != HoldBlockedImmediately {
			vs = append(vs, Violation{
				Class:   ViolationNewAskPostDetachNotBlocked,
				Subject: h.Subject,
				Reason: fmt.Sprintf("a NEW ask raised after detach did not block+log immediately "+
					"(outcome %q); only in-flight holds ride to timeout — a new ask while unattended "+
					"downgrades to immediate block+log (doc 16 §8.1/§8.2, D78)", h.Outcome),
			})
		}
	}
	sortViolations(vs)
	return vs
}

// ────────────────────────────────────────────────────────────────────────────
// ROW 7 — attendedness flip (doc 16 §13; §8.1 attendedness semantics; D78).
//
// THE CLAIM (§8.1): the SAME unknown-domain ask socket-HOLDS when ATTENDED and
// block+LOGS when UNATTENDED, driven ONLY by the distributed attendedness signal
// (a POL-1 value the orchestrator computes + pushes). Attended = a human holds the
// ONE writer seat AND produced input within the last T minutes; spectators /
// read-only viewers NEVER count as attended, and a spectate attach NEVER flips the
// attended bit. So: attended → hold; unattended → block+log; and a spectate-only
// attach must leave the bit UNATTENDED.
// ────────────────────────────────────────────────────────────────────────────

const (
	// ViolationAttendedDidNotHold — an ATTENDED session's unknown-domain ask did NOT
	// socket-hold (it block+logged or leaked); attended → hold.
	ViolationAttendedDidNotHold ViolationClass = "attendedness-attended-did-not-hold"
	// ViolationUnattendedDidNotBlock — an UNATTENDED session's unknown-domain ask did
	// NOT block+log (it held or leaked); unattended → block+log.
	ViolationUnattendedDidNotBlock ViolationClass = "attendedness-unattended-did-not-block"
	// ViolationSpectateFlippedAttended — a spectate-only (read-only viewer) attach
	// flipped the attended bit to ATTENDED; spectators never count as attended, and a
	// spectate attach never flips the bit.
	ViolationSpectateFlippedAttended ViolationClass = "attendedness-spectate-flipped-attended"
)

// AskDisposition is the observed disposition of an unknown-domain ask.
type AskDisposition string

const (
	AskHeld     AskDisposition = "socket-held"  // attended: TLS-1 socket-hold
	AskBlockLog AskDisposition = "block-logged" // unattended: immediate block+log
	AskLeaked   AskDisposition = "leaked"       // neither — a leak (always wrong)
)

// Attendedness is a synthetic fixture for one unknown-domain ask: whether a human
// holds the writer seat with fresh input (writerAttendedFresh), whether a
// spectate-only viewer is attached, the resulting attended BIT, and the observed
// ask disposition.
type Attendedness struct {
	Subject string
	// WriterAttendedFresh is true iff a human holds the one writer seat AND produced
	// input within the last T minutes (the D78 definition of attended).
	WriterAttendedFresh bool
	// SpectateAttached is true iff a read-only viewer is attached (never counts as
	// attended).
	SpectateAttached bool
	// AttendedBit is the attendedness bit the distributed signal actually carried.
	AttendedBit bool
	// Disposition is the observed disposition of the unknown-domain ask.
	Disposition AskDisposition
}

// CheckAttendednessFlip asserts the §8.1 attendedness-flip claim for one fixture.
// An empty result means the row holds: the attended bit reflects ONLY a fresh
// writer (spectate never flips it), and the ask holds when attended / block+logs
// when unattended per the bit.
func CheckAttendednessFlip(a Attendedness) []Violation {
	var vs []Violation
	// The bit must reflect ONLY a fresh writer; a spectate attach must not flip it.
	if a.AttendedBit && !a.WriterAttendedFresh {
		vs = append(vs, Violation{
			Class:   ViolationSpectateFlippedAttended,
			Subject: a.Subject,
			Reason: fmt.Sprintf("the attended bit is SET with no fresh writer (spectate_attached=%t); "+
				"attended = a human holds the ONE writer seat AND produced input within T minutes — "+
				"spectators / read-only viewers never count, and a spectate attach never flips the bit "+
				"(doc 16 §8.1, D78)", a.SpectateAttached),
		})
	}
	// The ask disposition must follow the bit: attended → hold; unattended → block+log.
	if a.AttendedBit {
		if a.Disposition != AskHeld {
			vs = append(vs, Violation{
				Class:   ViolationAttendedDidNotHold,
				Subject: a.Subject,
				Reason: fmt.Sprintf("an ATTENDED session's unknown-domain ask did not socket-hold "+
					"(disposition %q); attended → the TLS-1 socket-hold via the ask-user seam, the VM "+
					"keeps running (doc 16 §8.1/§8.2, D78)", a.Disposition),
			})
		}
	} else {
		if a.Disposition != AskBlockLog {
			vs = append(vs, Violation{
				Class:   ViolationUnattendedDidNotBlock,
				Subject: a.Subject,
				Reason: fmt.Sprintf("an UNATTENDED session's unknown-domain ask did not block+log "+
					"(disposition %q); unattended → immediate block+log, the same ask flips by the "+
					"distributed signal alone (doc 16 §8.1, D78)", a.Disposition),
			})
		}
	}
	sortViolations(vs)
	return vs
}

// ────────────────────────────────────────────────────────────────────────────
// ROW 8 — git-HTTPS pin (doc 16 §13; §5.3 SSH seam / HTTPS pin; §11.1 step 5).
//
// THE CLAIM (§5.3): the v0 golden image pins git remotes to HTTPS (insteadOf
// rewrite + credential helper). SSH-git is an explicit, TESTED non-goal — an
// accidental SSH path would silently bypass BOTH the swap and scanning planes, so
// git-over-SSH from the golden image FAILS CLOSED and remotes RESOLVE to HTTPS. So:
// a configured remote must resolve to an https:// scheme, and an SSH git attempt
// must fail closed (not silently succeed past the boundary).
// ────────────────────────────────────────────────────────────────────────────

const (
	// ViolationRemoteNotHTTPS — a configured git remote resolved to a non-HTTPS scheme
	// (ssh/git/git+ssh); the golden image pins remotes to https:// (§5.3).
	ViolationRemoteNotHTTPS ViolationClass = "git-remote-not-https"
	// ViolationSSHDidNotFailClosed — a git-over-SSH attempt did NOT fail closed (it
	// silently succeeded past the boundary, bypassing the swap+scan planes); SSH-git is
	// a tested non-goal.
	ViolationSSHDidNotFailClosed ViolationClass = "git-ssh-did-not-fail-closed"
)

// GitRemote is a synthetic fixture for one git remote configuration / attempt: the
// scheme the remote RESOLVED to, whether an SSH attempt was made, and — if so —
// whether it failed closed.
type GitRemote struct {
	Subject string
	// ResolvedScheme is the scheme the remote resolved to after the insteadOf rewrite
	// (e.g. "https", "ssh", "git").
	ResolvedScheme string
	// SSHAttempted records whether a git-over-SSH attempt was made (e.g. an accidental
	// ssh:// remote or a scp-style git@host: remote).
	SSHAttempted bool
	// SSHFailedClosed records whether the SSH attempt failed closed (only meaningful
	// when SSHAttempted).
	SSHFailedClosed bool
}

// CheckGitHTTPSPin asserts the §5.3 git-HTTPS pin claim for one fixture. An empty
// result means the row holds: the remote resolves to HTTPS and any SSH attempt
// failed closed.
func CheckGitHTTPSPin(g GitRemote) []Violation {
	var vs []Violation
	if !strings.EqualFold(g.ResolvedScheme, "https") {
		vs = append(vs, Violation{
			Class:   ViolationRemoteNotHTTPS,
			Subject: g.Subject,
			Reason: fmt.Sprintf("a git remote resolved to scheme %q, not https; the v0 golden image "+
				"pins git remotes to HTTPS (insteadOf rewrite + credential helper) so no flow silently "+
				"escapes the swap+scan seam (doc 16 §5.3, §11.1 step 5; doc 09 POL-2)", g.ResolvedScheme),
		})
	}
	if g.SSHAttempted && !g.SSHFailedClosed {
		vs = append(vs, Violation{
			Class:   ViolationSSHDidNotFailClosed,
			Subject: g.Subject,
			Reason: "a git-over-SSH attempt did NOT fail closed; SSH-git is an explicit, tested " +
				"non-goal — an accidental SSH path would silently bypass BOTH the swap and scanning " +
				"planes, so it must fail closed, never be a tolerated bypass (doc 16 §5.3, §11.1 step 5)",
		})
	}
	sortViolations(vs)
	return vs
}

// ────────────────────────────────────────────────────────────────────────────
// ROW 9 — LOG-5 join + fingerprint-only (doc 16 §13; §11.1 step 6; §9 LOG-1 row;
//         D73 fingerprint-only invariant).
//
// THE CLAIM (§11.1 step 6 / §9): "which session used the GitHub key, when, for
// what request" is ANSWERABLE for a test push — the CredentialUseEvent carries
// {session, service, credential fingerprint} and the SessionRef join key threads
// every identity-plane event. And: fingerprint-only is asserted across ALL
// identity events — the credential PLAINTEXT never appears in any event (D73
// invariant). So: an event must carry the SessionRef join key + the who/when/what
// fields AND must carry a fingerprint, NEVER the plaintext credential.
// ────────────────────────────────────────────────────────────────────────────

const (
	// ViolationLog5JoinUnanswerable — an event lacked a field the LOG-5 join needs
	// (SessionRef / service / request / timestamp), so "which session used the key,
	// when, for what" is not answerable.
	ViolationLog5JoinUnanswerable ViolationClass = "log5-join-unanswerable"
	// ViolationCredentialPlaintextInEvent — an identity event carried the credential
	// PLAINTEXT (not the fingerprint); fingerprint-only is invariant across all
	// identity events (D73).
	ViolationCredentialPlaintextInEvent ViolationClass = "log5-credential-plaintext-in-event"
	// ViolationFingerprintMissing — an event that should attribute a credential use
	// carried NO fingerprint at all, so the use is unattributable.
	ViolationFingerprintMissing ViolationClass = "log5-fingerprint-missing"
)

// IdentityEvent is a synthetic fixture for one identity-plane LOG-1 event: the
// LOG-5 join fields plus the credential representation it carries.
type IdentityEvent struct {
	Subject string
	// SessionRef is the join key threading the event to its session (§9). Empty =
	// missing.
	SessionRef string
	// Service is the service the credential was used for (e.g. "github"). Empty =
	// missing.
	Service string
	// Request describes the "for what request" dimension (e.g. "git-push refs/...").
	// Empty = missing.
	Request string
	// TimestampUnix is the "when" dimension; 0 = missing.
	TimestampUnix int64
	// CredentialFingerprint is the fingerprint-only representation (D73). For an event
	// that attributes a credential use this MUST be present.
	CredentialFingerprint string
	// CredentialPlaintext is set ONLY by a violation fixture modeling the regression
	// where an event wrongly carries the plaintext credential; it must always be empty.
	CredentialPlaintext string
	// AttributesCredentialUse marks an event that attributes a credential use (so it
	// must carry a fingerprint). A non-credential event (e.g. CAMinted) does not.
	AttributesCredentialUse bool
}

// CheckLog5Join asserts the §11.1/§9 LOG-5-join + fingerprint-only claim for one
// event fixture. An empty result means the row holds: the join fields are present,
// no plaintext credential appears, and a credential-attributing event carries a
// fingerprint.
func CheckLog5Join(e IdentityEvent) []Violation {
	var vs []Violation
	// The LOG-5 join must answer who (session) / when / for what (service + request).
	var missing []string
	if e.SessionRef == "" {
		missing = append(missing, "session_ref")
	}
	if e.Service == "" {
		missing = append(missing, "service")
	}
	if e.Request == "" {
		missing = append(missing, "request")
	}
	if e.TimestampUnix == 0 {
		missing = append(missing, "timestamp")
	}
	if len(missing) > 0 {
		vs = append(vs, Violation{
			Class:   ViolationLog5JoinUnanswerable,
			Subject: e.Subject,
			Reason: fmt.Sprintf("the event is missing LOG-5 join field(s) %v; \"which session used "+
				"the key, when, for what request\" must be answerable for a test push via the SessionRef "+
				"join key (doc 16 §11.1 step 6, §9)", missing),
		})
	}
	// Fingerprint-only is invariant across ALL identity events.
	if e.CredentialPlaintext != "" {
		vs = append(vs, Violation{
			Class:   ViolationCredentialPlaintextInEvent,
			Subject: e.Subject,
			Reason: "an identity event carried the credential PLAINTEXT; fingerprint-only is invariant " +
				"across all identity events — the credential itself never appears in any LOG-1 event " +
				"(doc 16 §11.1 step 6, §9; D73)",
		})
	}
	if e.AttributesCredentialUse && e.CredentialFingerprint == "" {
		vs = append(vs, Violation{
			Class:   ViolationFingerprintMissing,
			Subject: e.Subject,
			Reason: "an event attributing a credential use carried NO fingerprint; the CredentialUseEvent " +
				"carries {session, service, credential fingerprint} so the use is attributable — a missing " +
				"fingerprint makes the use unattributable (doc 16 §11.1 step 6, §9; D73)",
		})
	}
	sortViolations(vs)
	return vs
}

// ────────────────────────────────────────────────────────────────────────────
// ROW 10 — park/resume at the D46 tiers (doc 16 §13; §5.4 park/resume; D46 tiers).
//
// THE CLAIM (§5.4): at the D46 tiers — 60 s / 5 min / 15 min — grants AND digests
// SURVIVE snapshot+park, re-validate against session liveness + TTLs on resume, and
// EXPIRED creds RE-MINT. So on resume: a still-valid grant/digest must SURVIVE (be
// re-checked, not dropped); liveness must be re-checked (a session revoked while
// parked must not silently resume live); and a credential whose TTL EXPIRED during
// the park must be RE-MINTED, never resumed as-is.
// ────────────────────────────────────────────────────────────────────────────

const (
	// ViolationParkGrantsDigestsLost — grants/digests did NOT survive the park (they
	// were dropped); §5.4 says they survive snapshot+park and re-validate on resume.
	ViolationParkGrantsDigestsLost ViolationClass = "park-grants-digests-lost"
	// ViolationParkLivenessNotRechecked — liveness was NOT re-checked on resume, so a
	// session revoked/killed while parked resumed as live (a stale resume).
	ViolationParkLivenessNotRechecked ViolationClass = "park-liveness-not-rechecked"
	// ViolationParkExpiredCredNotReminted — a credential whose TTL EXPIRED during the
	// park was resumed as-is rather than RE-MINTED; expired creds re-mint (§5.4, D46).
	ViolationParkExpiredCredNotReminted ViolationClass = "park-expired-cred-not-reminted"
)

// DefaultParkTierSeconds is the documented D46 park tier ladder — 60 s / 5 min /
// 15 min — the park/resume row exercises (§5.4, §13). A guard test pins it so a
// silent drift fails HERE rather than judging against tiers the doc does not
// promise (the anchor-guard discipline).
var DefaultParkTierSeconds = []int{60, 300, 900}

// ResumeState is the §5.4 liveness verdict produced by the resume re-check.
type ResumeState string

const (
	// ResumeLive — the resume re-check found the session still live.
	ResumeLive ResumeState = "live"
	// ResumeRevoked — the resume re-check found the session revoked/killed while parked.
	ResumeRevoked ResumeState = "revoked-while-parked"
	// ResumeNotChecked — the resume did NOT re-check liveness (a violation marker).
	ResumeNotChecked ResumeState = "not-checked"
)

// ParkResume is a synthetic fixture for one park/resume cycle at a D46 tier: the
// tier (seconds), whether grants+digests survived, whether liveness was re-checked
// (and to what verdict), and whether a credential whose TTL expired during the park
// was re-minted.
type ParkResume struct {
	Subject string
	// TierSeconds is the D46 park tier this cycle ran at (one of DefaultParkTierSeconds).
	TierSeconds int
	// GrantsDigestsSurvived records whether grants AND digests survived the park.
	GrantsDigestsSurvived bool
	// Resume is the liveness re-check verdict on resume (ResumeNotChecked = the
	// re-check was skipped).
	Resume ResumeState
	// CredExpiredDuringPark records whether any session credential's TTL expired during
	// the park (it must then re-mint, not resume as-is).
	CredExpiredDuringPark bool
	// ExpiredCredReminted records whether the expired credential was re-minted on
	// resume (only meaningful when CredExpiredDuringPark).
	ExpiredCredReminted bool
}

// CheckParkResumeTiers asserts the §5.4 park/resume claim for one cycle fixture. An
// empty result means the row holds: grants+digests survived the park, liveness was
// re-checked on resume, and any cred expired during the park was re-minted.
func CheckParkResumeTiers(p ParkResume) []Violation {
	var vs []Violation
	if !p.GrantsDigestsSurvived {
		vs = append(vs, Violation{
			Class:   ViolationParkGrantsDigestsLost,
			Subject: p.Subject,
			Reason: fmt.Sprintf("grants/digests did NOT survive the %ds park; §5.4 says grants and "+
				"digests survive snapshot+park and re-validate against session liveness + TTLs on resume "+
				"(D46 tiers)", p.TierSeconds),
		})
	}
	if p.Resume == ResumeNotChecked {
		vs = append(vs, Violation{
			Class:   ViolationParkLivenessNotRechecked,
			Subject: p.Subject,
			Reason: fmt.Sprintf("liveness was NOT re-checked on resume from the %ds park; resume must "+
				"re-validate against session liveness — a session revoked/killed while parked must not "+
				"silently resume live (doc 16 §5.4, D46)", p.TierSeconds),
		})
	}
	if p.CredExpiredDuringPark && !p.ExpiredCredReminted {
		vs = append(vs, Violation{
			Class:   ViolationParkExpiredCredNotReminted,
			Subject: p.Subject,
			Reason: fmt.Sprintf("a credential whose TTL EXPIRED during the %ds park was resumed as-is, "+
				"not re-minted; expired creds re-mint on resume (doc 16 §5.4, D46)", p.TierSeconds),
		})
	}
	sortViolations(vs)
	return vs
}
