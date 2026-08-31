// SPDX-License-Identifier: Apache-2.0

package hostredeployconverge

import (
	"errors"
	"fmt"
	"os"
	"sort"
)

// convergence.go — the PURE, offline-evaluable verdict core for the
// re-key-on-host-redeploy conformance claim (doc 16 §6.3). It models one live
// re-key as an Observation (the live digests that existed under the OLD key, the
// new-key digest set the freshly redeployed host loaded + acked, and the
// per-host-per-epoch key ids + the ordering of the new-host-ack vs the
// old-host-revoke), and evaluates whether that re-key honored mint-before-attach:
//
//   - EVERY live digest is re-pushed under the new key (no digest dropped) — the
//     §6.3 "re-pushes every live digest under the new key" clause;
//   - the new-key set is ACKED before the old key is revoked (no fail-open gap) —
//     the mint-before-attach ordering RunHostRedeploy enforces by loading + acking
//     the new host EMPTY→FULL before revoking the old host;
//   - the new key is genuinely a NEW epoch (per-host per-epoch keys), never a
//     reuse of the retiring host's key.
//
// The verdict logic is the same shape quic-canary/pol2reachability use: a pure
// Evaluate the OFFLINE half asserts against synthetic observations and the LIVE
// half cross-checks its real-world observation against — so both halves agree on
// the spec and can never drift.

// ── Digest identity ──────────────────────────────────────────────────────────

// Digest is the minimal identity of one secret-digest-feed entry as this harness
// reasons about re-key continuity: which live session it belongs to and a stable
// per-secret id. It deliberately carries NO plaintext and NO HMAC value (D50 /
// doc 14 §7: plaintext never crosses; this harness reasons about PRESENCE and
// KEY-ID continuity, not digest bytes). The KeyID a digest was stamped under is
// tracked on the Observation's sets, not here, so the SAME secret can be compared
// across the old-key and new-key sets by SecretID.
type Digest struct {
	// SessionID is the live session this digest protects (SESSION-scope; doc 16
	// §6.2). A re-key must re-push the digests of every live session.
	SessionID string
	// SecretID is the stable per-secret identity used to match a live old-key
	// digest to its new-key re-push. Two entries with the same SecretID are "the
	// same secret under a different key".
	SecretID string
}

// String renders a digest as session/secret for deterministic, readable sorting
// and error messages.
func (d Digest) String() string { return d.SessionID + "/" + d.SecretID }

// ── Observation ───────────────────────────────────────────────────────────────

// Observation is one live (or synthetic) re-key, as the harness reasons about it.
// The live half fills this in from a REAL host redeploy; the offline half
// synthesizes it to assert the verdict logic. It is exactly the information
// RunHostRedeploy's choreography produces: the old-key digest set the retiring
// host was loaded with at the original mint-before-attach publish, the new-key
// digest set the freshly redeployed host loaded + acked, the per-epoch key ids,
// and whether the new-host ack was OBSERVED to commit before the old host was
// revoked.
type Observation struct {
	// OldKeyID / NewKeyID are the per-host per-epoch HMAC key ids (doc 16 §6.3).
	// They must differ — re-key mints a NEW epoch; reusing the retiring host's key
	// is not a re-key.
	OldKeyID string
	NewKeyID string

	// LiveOldKeyDigests is the set of digests that existed under the OLD key for
	// the still-live sessions at the moment the redeploy began — the population the
	// re-key MUST carry forward in full. (Digests for sessions that ended before
	// the redeploy are not live and are out of scope.)
	LiveOldKeyDigests []Digest

	// NewKeyDigests is the set the freshly redeployed host loaded and the host
	// agent ACKED under the new key (doc 16 §6.1/§6.6, D109 ack-er). For a
	// no-gap re-key this must cover every entry in LiveOldKeyDigests (matched by
	// SessionID+SecretID).
	NewKeyDigests []Digest

	// NewHostAckedBeforeOldRevoked records the ORDERING the live re-key was observed
	// to take: true iff the new host's full new-key set was acked BEFORE the old
	// host's old-key digests were revoked. This is the mint-before-attach ordering
	// RunHostRedeploy enforces (load+ack new EMPTY→FULL, THEN revoke old). false is
	// a fail-open window — the old key gone before the new set committed.
	NewHostAckedBeforeOldRevoked bool

	// StaleKeyedSecretIDs flags specific new-host entries (by session+secret) that
	// the live driver observed loaded under the OLD key id instead of NewKeyID — the
	// §6.3 stale-key fault. Normally empty (a clean re-key stamps the whole set under
	// the new epoch). Evaluate surfaces each as an ErrStaleKeyOnNewSet violation.
	StaleKeyedSecretIDs []digestKey
}

// StaleKey returns the (session, secret) identity used to flag a stale-keyed
// new-host entry in Observation.StaleKeyedSecretIDs. It is the only constructor
// for the unexported digestKey, so callers (the live driver and the offline
// half) can populate StaleKeyedSecretIDs without the harness exporting the key
// type.
func StaleKey(sessionID, secretID string) digestKey {
	return digestKey{session: sessionID, secret: secretID}
}

// ── Named verdict failure modes ────────────────────────────────────────────────
//
// Each names ONE way a live re-key can violate the doc 16 §6.3 claim. A violation
// surfaces the SPECIFIC sentinel (loud, actionable) so a live failure tells the
// operator exactly which property of mint-before-attach the re-key broke. Tests
// assert the specific error via errors.Is.

var (
	// ErrDigestDropped fires when a digest that was live under the OLD key has NO
	// re-push under the new key — the §6.3 "re-pushes EVERY live digest" clause is
	// violated. The dropped digest's live secret is now absent from the keyed
	// plane: a fail-open gap (the boundary would no longer detect that secret's
	// egress), exactly what re-key-on-host-redeploy exists to prevent.
	ErrDigestDropped = errors.New("hostredeployconverge: a live old-key digest was NOT re-pushed under the new key — the re-key dropped a live digest, opening a fail-open gap in the keyed plane (doc 16 §6.3 're-pushes every live digest under the new key')")

	// ErrAttachBeforeMint fires when the old key was revoked BEFORE the new-key set
	// was acked (NewHostAckedBeforeOldRevoked=false) — mint-before-attach inverted.
	// There is a window where the old-key digests are gone and the new-key set has
	// not committed, so a live secret has NO digest on either host: a fail-open
	// gap the §6.3 ordering forbids.
	ErrAttachBeforeMint = errors.New("hostredeployconverge: the old key was revoked BEFORE the new-key digest set was acked — mint-before-attach was VIOLATED, leaving a window with no digest coverage for a live secret (doc 16 §6.3 / §6.1; RunHostRedeploy loads+acks the new host EMPTY→FULL before revoking the old)")

	// ErrKeyNotRotated fires when the new-key id equals the old-key id — the
	// re-key reused the retiring host's epoch key instead of minting a new per-host
	// per-epoch key. A non-rotation is not a re-key (doc 16 §6.3 'per-host
	// per-epoch keys').
	ErrKeyNotRotated = errors.New("hostredeployconverge: the new-key id equals the old-key id — the re-key did NOT rotate to a new per-host per-epoch key (doc 16 §6.3 'per-host per-epoch keys; re-key on host redeploy')")

	// ErrStaleKeyOnNewSet fires when a new-key digest was stamped under the OLD key
	// id — the freshly redeployed host loaded a digest under a stale key, so even a
	// "present" entry would not match under the new epoch. Distinct from a drop:
	// the entry exists but under the wrong key.
	ErrStaleKeyOnNewSet = errors.New("hostredeployconverge: a digest on the new host carries the OLD key id — the re-key loaded a stale-keyed digest, which does not converge under the new epoch (doc 16 §6.3 per-host per-epoch keys)")

	// ErrLiveDriverNotWired fires from the env-gated live half until an operator
	// wires the real host-redeploy driver — so DS_HOST_REDEPLOY_LIVE=1 fails LOUDLY
	// rather than reporting a false green over an unimplemented driver. There is no
	// live KVM/host/boundary in-wave (D50); this is a DEFERRED MANUAL step.
	ErrLiveDriverNotWired = errors.New("hostredeployconverge: live host-redeploy driver not wired — DS_HOST_REDEPLOY_LIVE=1 requires a real KVM boundary host + a real redeploy the wave sandbox lacks; this is a DEFERRED MANUAL step (doc 16 §6.3, D26/D51 re-key-on-host-redeploy conformance)")
)

// ── Verdict ────────────────────────────────────────────────────────────────────

// Verdict is the outcome of evaluating one re-key Observation against the §6.3
// claim. Converged=true iff the re-key honored mint-before-attach with no dropped
// digest and a genuine epoch rotation.
type Verdict struct {
	// Converged reports whether the re-key satisfied the §6.3 claim in full.
	Converged bool
	// Violations is every named way the re-key broke the claim (empty iff
	// Converged). Each is one of the exported Err* sentinels wrapped with the
	// offending detail, never an anonymous error, so the operator gets an
	// actionable cause. Ordered deterministically for stable assertions/reports.
	Violations []error
	// CarriedForward is the count of live old-key digests confirmed re-pushed under
	// the new key (the convergence size), carried for the report.
	CarriedForward int
	// LiveCount is the count of live old-key digests the re-key had to carry.
	LiveCount int
}

// digestKey is the (session, secret) identity a live old-key digest is matched to
// its new-key re-push by.
type digestKey struct {
	session string
	secret  string
}

func keyOf(d Digest) digestKey { return digestKey{d.SessionID, d.SecretID} }

// Evaluate is the PURE verdict core: given one re-key Observation, it decides
// whether the live re-key honored the doc 16 §6.3 claim. It is the function the
// OFFLINE half asserts against synthetic observations and the LIVE half
// cross-checks its real observation against, so both halves prove the SAME claim.
//
// It checks, in order:
//
//  1. epoch rotation — NewKeyID must differ from OldKeyID;
//  2. no stale key on the new set — every new-key digest carries NewKeyID;
//  3. completeness — every live old-key digest has a matching new-key re-push;
//  4. ordering — the new-key set was acked before the old key was revoked.
//
// A violation never short-circuits the others: an operator should see EVERY way a
// re-key broke, not just the first. The empty observation (no live digests) is a
// vacuous convergence ONLY when the key genuinely rotated and the ordering held —
// an empty live set still must not revoke-before-ack.
func Evaluate(obs Observation) Verdict {
	v := Verdict{LiveCount: len(obs.LiveOldKeyDigests)}

	// (1) epoch rotation.
	if obs.NewKeyID == obs.OldKeyID {
		v.Violations = append(v.Violations,
			fmt.Errorf("%w: old=%q new=%q", ErrKeyNotRotated, obs.OldKeyID, obs.NewKeyID))
	}

	// Index the new-key set by (session, secret). A new digest stamped under the
	// OLD key id is a stale-key load — recorded as its own violation and NOT
	// counted as a valid re-push.
	newByKey := make(map[digestKey]Digest, len(obs.NewKeyDigests))
	for _, d := range obs.NewKeyDigests {
		newByKey[keyOf(d)] = d
	}

	// (3) completeness — every live old-key digest must be re-pushed under the new
	// key. Deterministic order over the live set.
	live := append([]Digest(nil), obs.LiveOldKeyDigests...)
	sort.Slice(live, func(i, j int) bool { return live[i].String() < live[j].String() })
	for _, d := range live {
		if _, ok := newByKey[keyOf(d)]; !ok {
			v.Violations = append(v.Violations,
				fmt.Errorf("%w: %s", ErrDigestDropped, d))
			continue
		}
		v.CarriedForward++
	}

	// (2) no stale key on the new set — every entry the new host loaded must carry
	// the NEW key id. Checked over the new set in deterministic order. A stale-keyed
	// entry that ALSO matched a live digest still counts as carried-forward above
	// (the secret is present), but the stale key id is its own §6.3 violation.
	staleNew := append([]Digest(nil), obs.NewKeyDigests...)
	sort.Slice(staleNew, func(i, j int) bool { return staleNew[i].String() < staleNew[j].String() })
	// We cannot read a per-digest key id off Digest (it carries none by design); the
	// new set is, by construction of the Observation, stamped under NewKeyID, EXCEPT
	// where the live driver explicitly recorded a stale entry via StaleKeyedSecretIDs.
	for _, d := range staleNew {
		if obs.staleKeyed(d) {
			v.Violations = append(v.Violations,
				fmt.Errorf("%w: %s carries old key %q", ErrStaleKeyOnNewSet, d, obs.OldKeyID))
		}
	}

	// (4) ordering — mint-before-attach: ack the new set BEFORE revoking the old.
	if !obs.NewHostAckedBeforeOldRevoked {
		v.Violations = append(v.Violations, ErrAttachBeforeMint)
	}

	v.Converged = len(v.Violations) == 0
	return v
}

// StaleKeyedSecretIDs lets the live driver flag specific new-host entries that
// were observed loaded under the OLD key id (the §6.3 stale-key fault). It is
// session/secret-scoped: an entry whose (SessionID, SecretID) is named here is
// treated as stale-keyed by Evaluate. The offline half uses it to assert the
// ErrStaleKeyOnNewSet path; a real re-key normally leaves it empty.
//
// It hangs off Observation rather than Digest so Digest stays a pure (no-key,
// no-plaintext) identity — the harness reasons about key-id continuity at the SET
// level, matching how RunHostRedeploy stamps a whole set under one epoch key.
func (o Observation) staleKeyed(d Digest) bool {
	for _, k := range o.StaleKeyedSecretIDs {
		if k == keyOf(d) {
			return true
		}
	}
	return false
}

// ── Live driver entry point ─────────────────────────────────────────────────────

// LiveEnvVar is the single switch for the live half. UNSET (or any value other
// than "1") keeps the live half disabled — LiveEnabled() returns false and the
// live runner SKIPs naming this var, so the default `go test ./...` is offline
// and deterministic. CI never sets it. Set to "1" to opt into the live run
// (which fails LOUDLY until the real host-redeploy driver is wired).
const LiveEnvVar = "DS_HOST_REDEPLOY_LIVE"

// HostEnvVar points the live run at the KVM boundary host to redeploy (the
// freshly-redeployed host's reachable endpoint). It only resolves WHERE the live
// half would drive a redeploy — it does not by itself enable the live half;
// LiveEnvVar still governs.
const HostEnvVar = "DS_HOST_REDEPLOY_HOST"

// LiveEnabled reports whether the operator opted into the live half via
// LiveEnvVar=1. The default (unset) is false — CI is offline and deterministic.
func LiveEnabled() bool { return os.Getenv(LiveEnvVar) == "1" }

// LiveHost returns the live host endpoint (HostEnvVar override, empty default).
// It does not enable the live half.
func LiveHost() string { return os.Getenv(HostEnvVar) }

// RunLive is the env-gated live driver entry point. It drives a REAL host
// redeploy on a real KVM boundary host (LiveHost()) — observing the freshly
// redeployed host load + ack the new-key digest set for every live session before
// the retiring host's old-key digests are revoked — and returns the observed
// re-key as an Observation for Evaluate to verdict.
//
// Until an operator wires the real driver it returns ErrLiveDriverNotWired so
// DS_HOST_REDEPLOY_LIVE=1 never reports a false green. There is NO live
// KVM/host/boundary in-wave (D50): the live half is a DEFERRED MANUAL step; the
// offline half (convergence_test.go) is the in-wave proof. The verdict logic
// (Evaluate) is unchanged when the real driver lands — the operator replaces only
// this body.
func RunLive() (Observation, error) {
	if !LiveEnabled() {
		// Caller must gate on LiveEnabled(); returning the sentinel here keeps a
		// misuse from silently producing an empty (vacuously-converging) run.
		return Observation{}, fmt.Errorf("%w: live half not enabled (%s != 1)", ErrLiveDriverNotWired, LiveEnvVar)
	}
	return Observation{}, ErrLiveDriverNotWired
}
