package controlplane

// identityseams.go supplies the §4.1 create-coordinator seams that are NOT
// hypervisor.v1 driver verbs — the Identity-owned (D22/D82) mint + digest +
// revocation seams and the boundary/host-agent-owned CA-injection + boot seams
// (doc 15 §4.1 steps 5–8; the seam shapes the host-agent create path INVOKES live
// in internal/hypervisor/libvirt/seams.go). They cross trees the orchestrator may
// not import directly (the only legal cross-tree import is proto/gen/go), so each
// production adapter holds a NARROW client seam this package declares — fronting the
// Identity mint service / the host-agent's inject+boot verbs — and the wiring site
// (main.go) supplies the gRPC-backed implementation, while tests supply the
// generated fakes + synthetic responders (D50: no live VM/host-agent/podman).
//
// WHY NARROW SEAMS, NOT THE GENERATED CLIENTS DIRECTLY. The workload-identity mint
// claims shape is owned by identity/mint (carried across the seam as DATA — the
// orchestrator never imports that module). The CA-inject + boot verbs are
// host-agent-local (the libvirt driver runs them host-side). So these seams are
// declared as the orchestrator's view of those operations, satisfied in production
// by thin adapters main.go builds over the real services and in tests by recording
// fakes — exactly the constructible-component discipline the create coordinator and
// reconciler already use. They COMPILE against the production wiring and are
// EXERCISED via fakes; main.go constructs the real backends, tests never require one.

import (
	"context"
	"fmt"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/sessions"
)

// MintClient is the orchestrator's view of the Identity mint service (D22/D82),
// fronting the per-session workload-identity + interception-CA mint (doc 15 §4.1
// step 5). It carries the assembled claims as DATA (sessions.MintWorkloadIdentityClaims)
// and the pinned role_ref, returning the minted identity + CA references. In
// production main.go adapts the identity.v1 mint gRPC client onto it; in tests a fake
// returns synthetic refs. MintIdentity is a SEPARATE service by design (D22) — this
// seam fronts it, the orchestrator never embeds the mint mechanics (doc 16 owns them).
type MintClient interface {
	// Mint mints the per-session workload identity + interception CA for the claims
	// and role_ref, returning their references. A fault is surfaced so the §4.1 step-5
	// rollback (identity/CA revocation) can compensate.
	Mint(ctx context.Context, claims sessions.MintWorkloadIdentityClaims, roleRef string) (identityRef, caRef string, err error)
}

// MintReply is the TYPED result the MintClient seam carries OUT of the mint
// (additive over MintClient.Mint's bare identityRef/caRef tuple): it adds the
// mint/CA EXPIRY the bare seam dropped. The per-session credential is short-lived
// by design (D22 — "short-lived per-session cert/token"; D82 — the interception CA
// is session-lifecycle material that "dies at teardown"), and the create coordinator
// must record that expiry for the routable-window + teardown bookkeeping: per doc 16
// §5.4 park/resume, grants and digests survive snapshot+park but re-validate against
// session liveness + TTLs on resume, and EXPIRED CREDS RE-MINT — a decision the record
// can only make if the minted credential's expiry was carried this far rather than
// dropped at the seam. Expiry is the wall-clock instant the minted credential / CA
// stops being valid; the ZERO value (Expiry.IsZero()) means the mint surfaced NO
// expiry (not-set), which the consumer treats as "no TTL bookkeeping for this mint"
// — never as "expires at the epoch".
type MintReply struct {
	// IdentityRef is the minted per-session workload identity reference (the same
	// opaque ref MintClient.Mint returns first).
	IdentityRef string
	// CARef is the per-session interception-CA reference (D82, separate root; the
	// same opaque ref MintClient.Mint returns second).
	CARef string
	// Expiry is the wall-clock instant the minted credential / interception CA stops
	// being valid (the mint-response token TTL / CA expiry, D22/D82). The zero value
	// means the mint surfaced no expiry (absent / not-set) — handled gracefully by the
	// routable/teardown bookkeeping as "no TTL to track", per doc 16 §5.4.
	Expiry time.Time
}

// MintExpiryClient is the OPTIONAL, STANDALONE extension a mint seam may also satisfy
// to surface the mint/CA expiry the bare MintClient.Mint tuple drops. It is additive by
// construction and DELIBERATELY does NOT embed MintClient: MintClient stays the required
// seam (every implementation satisfies it), and an implementation that also knows the
// mint-response expiry — e.g. the production adapter reading
// identity.v1 MintInterceptionCAResponse.expiry_unix_seconds — ALSO satisfies this
// single-method extension, so the expiry can be carried forward for the §4.1 step-5/§5.6
// routable + teardown bookkeeping WITHOUT a breaking change to MintClient (no existing
// implementer is forced to grow a method). Keeping it un-embedded also lets the minter
// adapter (whose own Mint is the sessions.Minter shape, not the MintClient shape) expose
// MintWithExpiry without a method-signature collision. mintReply type-asserts the bare
// MintClient to this extension and falls back to Mint when it is absent (Expiry then
// stays zero — the not-set case, handled gracefully per doc 16 §5.4).
type MintExpiryClient interface {
	// MintWithExpiry mints the per-session identity + interception CA exactly as the
	// bare Mint does, but returns the TYPED MintReply carrying the mint/CA expiry (token
	// TTL / CA expiry) the bare seam dropped. A zero MintReply.Expiry means the mint
	// surfaced no expiry (not-set). Faults are surfaced identically to Mint.
	MintWithExpiry(ctx context.Context, claims sessions.MintWorkloadIdentityClaims, roleRef string) (MintReply, error)
}

// mintReply drives the MintReply out of a MintClient, preferring the optional
// MintExpiryClient extension (which carries the mint/CA expiry, D22/D82) and falling
// back to the bare MintClient.Mint (expiry then zero — the not-set case, doc 16 §5.4).
// It is the single place the expiry is lifted off the seam, so both the minter adapter
// and the consumer wiring (sessioncreate threads MintResult.Expiry onto st.mintExpiry,
// the §5.6 record PERSISTS it as the MintExpiry column — migration 0010, now landed)
// read the expiry through one typed path.
func mintReply(ctx context.Context, c MintClient, claims sessions.MintWorkloadIdentityClaims, roleRef string) (MintReply, error) {
	if ec, ok := c.(MintExpiryClient); ok {
		return ec.MintWithExpiry(ctx, claims, roleRef)
	}
	identityRef, caRef, err := c.Mint(ctx, claims, roleRef)
	if err != nil {
		return MintReply{}, err
	}
	// The bare seam carries no expiry — Expiry stays zero (not-set), handled
	// gracefully downstream as "no TTL bookkeeping for this mint" (doc 16 §5.4).
	return MintReply{IdentityRef: identityRef, CARef: caRef}, nil
}

// RevokeClient is the orchestrator's view of the Identity revocation signal
// (D22/D82; the §4.1 step-5/6 rollback): on a create failure at step 5+ the
// coordinator signals identity/CA revocation. It is idempotent (revoking an
// already-revoked identity is a no-op). main.go adapts the identity revocation face;
// tests supply a recording fake.
type RevokeClient interface {
	// Revoke signals revocation of the session's minted identity + CA. Idempotent.
	Revoke(ctx context.Context, sessionUUID, identityRef, caRef string) error
}

// DigestClient is the orchestrator's view of the Identity digest feed (D73; doc 15
// §4.1 step 6): Identity computes the session-scoped digests in the D39 trust zone
// and writes them to the placed host; the host acks on behalf of its fan-out. The
// session is NOT routable until the ack lands (mint-before-attach, enforced by the
// §4.1 step-9 gate). main.go adapts the identity digest-feed face; tests supply a fake.
type DigestClient interface {
	// WriteAndAck writes the session-scoped digests to hostID (keyed on the minted CA
	// ref) and reports the digest ref + whether the host acked.
	WriteAndAck(ctx context.Context, sessionUUID, hostID, caRef string) (digestRef string, acked bool, err error)
}

// InjectClient is the boundary/host-agent-owned CA-injection verb (D17/D29; doc 15
// §4.1 step 7, the libvirt CAInjector seam): it injects the per-session interception
// CA into the cloned overlay's trust store BEFORE boot, FAIL-CLOSED (injection failure
// fails the create). main.go adapts the host-agent inject verb; tests supply a fake.
type InjectClient interface {
	// InjectCA injects caRef into the session's overlay trust store before boot. A
	// fault means the CA is not provably in the trust store — the create must abort
	// before boot (the create coordinator rolls back from step 7).
	InjectCA(ctx context.Context, sessionUUID, overlayPath, caRef string) error
}

// BootClient is the host-agent-owned boot verb (D38; doc 15 §4.1 step 8, the libvirt
// Booter seam): it launches the VM per the frozen entrypoint contract (token via the
// D22 shim, HTTP(S)_PROXY + CA env, exec/supervise spec, event socket up). The
// orchestrator stays runtime-ignorant — it drives the verb and records nothing
// runtime-specific. main.go adapts the host-agent boot verb; tests supply a fake.
type BootClient interface {
	// Boot launches the session's domain per the entrypoint config. A fault rolls the
	// create back from step 8 (destroy the domain, dispose the overlay, unwind step 4).
	Boot(ctx context.Context, sessionUUID, entrypointConfigRef string) error
}

// ---------------------------------------------------------------------------
// Adapters: each wraps the narrow client seam above onto the matching
// sessions.* create-coordinator seam (sessioncreate.go). They are constructed by
// NewControlPlane from the ProductionSeams bundle (wiring.go).
// ---------------------------------------------------------------------------

// minter satisfies sessions.Minter (§4.1 step 5) — and is the WIRED production adapter
// the create coordinator actually calls (constructed as minter{c: d.Mint} at wiring.go's
// ProductionSeams assembly and minter{c: mintC} in redrive.go's host re-create). It lifts
// the mint/CA expiry off the seam via mintReply (D22/D82) so the typed MintReply.Expiry is
// carried onto the sessions.MintResult the coordinator records, for the routable-window +
// teardown bookkeeping (doc 16 §5.4 park/resume: expired creds re-mint).
//
// CONSUMER PATH CLOSED. sessions.MintResult (the value sessions.Minter.Mint returns, owned
// by sessions/sessioncreate.go) now carries an Expiry field (orch29 added it); the create
// coordinator lands it on st.mintExpiry and fires the optional onMintExpiry gate when set
// (sessioncreate.go). So Mint below carries reply.Expiry through onto MintResult.Expiry,
// closing the live mint/CA TTL path end-to-end — a session whose minted credential expires
// is now tracked for teardown / re-mint. The carry is ADDITIVE: a bare MintClient (no
// MintExpiryClient extension) leaves reply.Expiry the zero value, so MintResult.Expiry is
// the not-set zero time and the coordinator schedules no teardown — identical to before.
// MintWithExpiry below remains the standalone expiry-aware accessor (MintExpiryClient).
type minter struct{ c MintClient }

func (m minter) Mint(ctx context.Context, claims sessions.MintWorkloadIdentityClaims, roleRef string) (sessions.MintResult, error) {
	reply, err := mintReply(ctx, m.c, claims, roleRef)
	if err != nil {
		return sessions.MintResult{}, fmt.Errorf("controlplane: mint identity/CA: %w", err)
	}
	return sessions.MintResult{IdentityRef: reply.IdentityRef, CARef: reply.CARef, Expiry: reply.Expiry}, nil
}

// MintWithExpiry runs the §4.1 step-5 mint and returns the TYPED MintReply carrying the
// mint/CA expiry (D22/D82) the bare sessions.MintResult tuple would drop. The create
// coordinator's consumer path already lands the expiry via Mint above (onto
// MintResult.Expiry → st.mintExpiry → the PERSISTED §5.6 MintExpiry column, migration
// 0010), so the §5.6 record now carries the durable routable-window / teardown horizon
// (doc 16 §5.4). This standalone accessor remains the expiry-aware face (MintExpiryClient)
// for callers that want the typed reply directly, so the minter adapter is itself
// expiry-aware — composable without a breaking interface change.
func (m minter) MintWithExpiry(ctx context.Context, claims sessions.MintWorkloadIdentityClaims, roleRef string) (MintReply, error) {
	reply, err := mintReply(ctx, m.c, claims, roleRef)
	if err != nil {
		return MintReply{}, fmt.Errorf("controlplane: mint identity/CA: %w", err)
	}
	return reply, nil
}

// digestWriter satisfies sessions.DigestWriter (§4.1 step 6).
type digestWriter struct{ c DigestClient }

func (d digestWriter) WriteAndAck(ctx context.Context, sessionUUID, hostID, caRef string) (sessions.DigestResult, error) {
	digestRef, acked, err := d.c.WriteAndAck(ctx, sessionUUID, hostID, caRef)
	if err != nil {
		return sessions.DigestResult{}, fmt.Errorf("controlplane: digest write+ack on %s: %w", hostID, err)
	}
	return sessions.DigestResult{DigestRef: digestRef, Acked: acked}, nil
}

// injector satisfies sessions.Injector (§4.1 step 7).
type injector struct{ c InjectClient }

func (i injector) InjectCA(ctx context.Context, sessionUUID, overlayPath, caRef string) error {
	if err := i.c.InjectCA(ctx, sessionUUID, overlayPath, caRef); err != nil {
		return fmt.Errorf("controlplane: CA inject for %s: %w", sessionUUID, err)
	}
	return nil
}

// booter satisfies sessions.Booter (§4.1 step 8).
type booter struct{ c BootClient }

func (b booter) Boot(ctx context.Context, sessionUUID, entrypointConfigRef string) error {
	if err := b.c.Boot(ctx, sessionUUID, entrypointConfigRef); err != nil {
		return fmt.Errorf("controlplane: boot for %s: %w", sessionUUID, err)
	}
	return nil
}

// identityRevoker satisfies sessions.IdentityRevoker (the §4.1 step-5/6 rollback).
type identityRevoker struct{ c RevokeClient }

func (r identityRevoker) Revoke(ctx context.Context, sessionUUID, identityRef, caRef string) error {
	if err := r.c.Revoke(ctx, sessionUUID, identityRef, caRef); err != nil {
		return fmt.Errorf("controlplane: revoke identity/CA for %s: %w", sessionUUID, err)
	}
	return nil
}

// Compile-time proof the adapters satisfy the §4.1 coordinator seams. minter is also
// an expiry-aware MintClient (MintExpiryClient) — the additive surface that carries the
// mint/CA expiry forward (D22/D82; doc 16 §5.4) without a breaking interface change.
var (
	_ sessions.Minter          = minter{}
	_ sessions.DigestWriter    = digestWriter{}
	_ sessions.Injector        = injector{}
	_ sessions.Booter          = booter{}
	_ sessions.IdentityRevoker = identityRevoker{}
	_ MintExpiryClient         = minter{}
)
