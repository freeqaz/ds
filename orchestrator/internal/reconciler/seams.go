package reconciler

// seams.go — the reconciler-side host-targeting seam for the §3 rule-a orphan
// quarantine (doc 15 §4.2). It gives the reporting host_id — which reconcileHost
// already holds (the heartbeat that surfaced the orphan carries it, §4.2) — a way
// to ride onto the context the Driver.Suspend verb receives, so the production
// driver can target the ONE host that observed the orphan instead of BROADCASTING
// the idempotent Suspend across every registered host's driver. At the ~500-host
// virtual-metal density the D37 v0 density model sizes for, that fleet-wide fan-out
// is a real cost (every host driver pinged to quarantine one orphan); the per-host
// HypervisorDriver contract (D35: one driver per virtual-metal host) keyed on the
// host/index binding (D66) is the mechanism that collapses it to the single host.
//
// WHY A RECONCILER-LOCAL CONTEXT HINT (not controlplane.WithQuarantineHostHint).
// The production driver (controlplane.registryDriver) is the wired reconciler.Driver,
// and controlplane.WithQuarantineHostHint already exists there as the context-carried
// targeting knob runVerb honors. But controlplane IMPORTS reconciler (the wiring tree
// assembles the constructible reconciler), so reconciler CANNOT import controlplane —
// that is an import cycle (controlplane → reconciler → controlplane). The context key
// controlplane keys its hint under is unexported there, so the reconciler also cannot
// forge it. The reconciler therefore owns its OWN host-hint context seam HERE (the
// REAL caller of the host-targeting mechanism: quarantineOrphan stamps it, conflict.go),
// and the wiring bridges it onto the driver's routing.
//
// THE ONE-LINE PRODUCTION BRIDGE (a DELIBERATE, DOCUMENTED seam reopen, gated). The
// reconciler stamps the reporting host onto the Suspend context via WithQuarantineHostHint
// below; a host-targeting Driver reads it via QuarantineHostHint and routes to that one
// host. The recording-driver fake in conflict_test.go does exactly that, proving the
// per-host fan-out collapse. For the PRODUCTION registryDriver to honor it, its runVerb
// must read THIS package's QuarantineHostHint (one added clause, or a one-line
// controlplane.WithQuarantineHostHint(ctx, reconciler.QuarantineHostHint(ctx)) re-stamp at
// the registryDriver boundary). That clause lives in controlplane/seams.go — OUTSIDE this
// unit's owned files — so it is called out as a deliberate frozen-seam reopen of the
// reconciler↔driver host-targeting contract for the controlplane unit to land. Absent that
// clause the routing is UNCHANGED and fully backwards-compatible (registryDriver still
// resolves a recorded host, else broadcasts) — the hint is purely additive: present, the
// fast path targets; absent (or unread), the existing behavior holds. The frozen
// reconciler.Driver Suspend/Destroy signatures and the frozen hypervisor.v1 request
// messages are UNTOUCHED — the host rides the context only.

import "context"

// quarantineHostHintKeyType is the unexported context-key type the reconciler carries
// the OPTIONAL reporting-host hint under. Unexported + typed so no other package can
// collide with or forge the key: the value is set only by WithQuarantineHostHint and
// read only by QuarantineHostHint.
type quarantineHostHintKeyType struct{}

var quarantineHostHintKey quarantineHostHintKeyType

// WithQuarantineHostHint returns a child context carrying hostID as the OPTIONAL target
// host for the next orphan-quarantine Suspend (and any host-targeted teardown) the
// reconciler drives through its Driver. It is the reconciler-side host-targeting knob
// (D35 per-host driver contract, D66 host/index binding): reconcileHost holds the
// reporting host_id from the heartbeat that surfaced the orphan (doc 15 §4.2) and stamps
// it here so a host-targeting Driver routes the idempotent verb to that ONE host's driver
// instead of fanning out across the fleet at the ~500-host density the D37 v0 density model
// sizes for. An EMPTY hostID is treated as "no hint" — the context is returned UNCHANGED so
// quarantineOrphan can stamp the reporting host unconditionally and keep the absent-hint
// (record-resolve / broadcast) behavior when it has no host to name. The frozen
// reconciler.Driver verbs and the frozen hypervisor.v1 request messages are untouched: the
// hint rides the context only, purely additive and backwards-compatible.
func WithQuarantineHostHint(ctx context.Context, hostID string) context.Context {
	if hostID == "" {
		return ctx
	}
	return context.WithValue(ctx, quarantineHostHintKey, hostID)
}

// QuarantineHostHint reads the OPTIONAL reporting-host hint a caller (the reconciler's
// quarantineOrphan) attached via WithQuarantineHostHint, reporting "" + false when absent
// (a Driver then runs its record-resolve / broadcast routing unchanged). It is EXPORTED so
// the production driver (controlplane.registryDriver, in the importing tree) can honor the
// hint without this package importing it — the one documented bridge clause that turns the
// fast path on in production (see the file header: the deliberate seam reopen). The value is
// always the string set by WithQuarantineHostHint, so the type assertion cannot pick up a
// foreign value (the key is unexported).
func QuarantineHostHint(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}
	hostID, ok := ctx.Value(quarantineHostHintKey).(string)
	if !ok || hostID == "" {
		return "", false
	}
	return hostID, true
}
