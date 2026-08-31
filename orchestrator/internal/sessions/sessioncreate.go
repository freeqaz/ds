package sessions

// sessioncreate.go is the FULL doc 15 §4.1 canonical ten-step session-create
// CHOREOGRAPHY — the control-plane coordinator that PROMOTES the in-process spine
// (createspine.go's RunCreateSpine, which orders the steps-1–2 + step-5 cluster)
// into the complete master order the SessionService.CreateSession RPC runs (doc 15
// §5.3: "runs §4.1; two-key structural refusal (D56)"). Where createspine.go proves
// the steps-1–2 + step-5 stages thread the right DATA in the right order, THIS file
// drives ALL TEN steps with their structural gates and the compensating rollback,
// wired to the frozen hypervisor/hostagent seams (proto/gen/go
// dreamserpent.hypervisor.v1 / .hostagent.v1) consumed as DATA across narrow,
// package-owned interfaces.
//
// WHAT THIS IS (and is NOT):
//   - IS: a CONSTRUCTIBLE coordinator (SessionCreator) with the store + the
//     per-step seams INJECTED — unit-tested against synthetic fixtures + the
//     generated fakes, exactly the createstep5 / childsession discipline. It owns
//     the FROZEN precedence (`1 ≺ 2 ≺ 3 ≺ {6,7,8}; 5 ≺ 6; 5 ≺ 7-injection;
//     7 ≺ 8; {3,6} ≺ 9 ≺ 10`), the structural gates (D56 two-key, D72 freshness,
//     D73 digest ack, D17/D29 fail-closed CA injection, the routable gate), and the
//     COMPENSATING rollback (drive the §4.2 destroy path from whatever step failed;
//     create is retryable by session UUID; a failed step-4 index is BURNED, never
//     recycled; every rollback satisfies the doc 06 (b) clean-teardown checklist).
//   - IS NOT: the CreateSession RPC handler or any main.go wiring (FENCED — the
//     handler + wiring is a separate task; this is the constructible component the
//     handler will call). It carries NO live VM/host-agent/podman — the host
//     mechanics live host-side; here we DRIVE the verbs (CloneFromImage, the digest
//     write/ack, the CA injection, boot, attach) and RECORD the bindings, against
//     synthetic fixtures + the generated fakes (D50). The actual VM/NFT/overlay
//     work is the host agent's; verb boundaries inside it are FREE (doc 15 §4.1).
//
// THE TEN STEPS (doc 15 §4.1), each a method on SessionCreator's Create:
//   (1) TWO-KEY structural refusal (D56) — CheckTwoKeyActivation (twokey.go): both
//       control-plane enrollment AND a checked-in env spec, or a fail-closed refusal
//       (ErrTwoKeyRefused) BEFORE any record exists.
//   (2) SESSION RECORD created (store) — CreateSession mints the desired-state row
//       (UUID + PENDING), env-config + image refs attached. The record exists from
//       here; every later step rolls back THROUGH it.
//   (3) POLICY-FRESH PLACEMENT (D72) — the package-owned Placer seam picks a host
//       whose applied_seq is within the staleness budget (the §7 filter chain lives
//       in the scheduler; this coordinator consumes it BY INTERFACE so it never
//       imports internal/scheduler — see the Placer doc). State → CREATING.
//   (4) HOST ALLOCATION + VM DEFINE — the HostAllocator seam drives CloneFromImage
//       on the placed host: the host agent allocates the never-recycled index,
//       derives dstap-<idx> + the guest IP, and returns the
//       (host_session_index, tap, guest_ip, overlay_path) binding. The binding is
//       RECORDED via AppendIndexEpoch — which BURNS the index the moment it lands,
//       so a failure at step 4+ never recycles it (the burn is in the store).
//   (5) IDENTITY + INTERCEPTION-CA MINT (D82) — AssembleStep5MintRequest
//       (createstep5.go) over the SAME launching_user resolver the spine threads:
//       the mint claims carry the gate-sourced launching_user + the pinned role_ref.
//       The Minter seam consumes those claims and returns the identity/CA refs.
//   (6) DIGEST WRITE + ACK GATE (D73) — the DigestWriter writes the session-scoped
//       digests to the placed host and the host acks; NOT routable until the ack
//       lands. Recorded as DigestRef + DigestAcked on the record. (5 ≺ 6.)
//   (7) OVERLAY CLONE + FAIL-CLOSED CA INJECTION (D17/D29) — the Injector injects
//       the per-session interception CA into the overlay's trust store BEFORE boot;
//       an injection FAILURE fails the create (5 ≺ 7-injection).
//   (8) BOOT + ENTRYPOINT (D38) — the Booter launches per the frozen entrypoint
//       contract (token via the D22 shim, HTTP(S)_PROXY + CA env, exec/supervise
//       spec, event socket up). (7 ≺ 8.)
//   (9) ROUTABLE GATE (structural) — digest ack (step 6) AND re-checked policy
//       freshness (step 3) both hold; only now can the first egress byte exist.
//       State → READY. ({3,6} ≺ 9.)
//  (10) ATTACH (D79) — the AttachIssuer issues the attach handle (endpoints + auth
//       material + role); WatchSession fan-out live; attendedness begins. State →
//       ATTACHED. (9 ≺ 10.)
//
// CROSS-TREE / SAME-TREE DISCIPLINE (binding, the createspine.go reason). The host
// agent / hypervisor mechanics live in OTHER trees; the only legal cross-tree import
// is proto/gen/go. So the coordinator consumes the host-side verbs through narrow,
// package-owned seams that carry the proto request/response MESSAGES as DATA (the
// generated fakes satisfy them natively, a test fake satisfies them identically) —
// it never imports a host-agent or scheduler package. The Placer seam in particular
// is package-owned so the coordinator never imports internal/scheduler (which would
// cycle: scheduler reads the §3 transition table from THIS package).

import (
	"context"
	"errors"
	"expvar"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"sync"
	"time"

	hypervisorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hypervisor/v1"
	runtimev1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/runtime/v1"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// step9FreshnessDegradeTotal is the §4.1 step-9 D72 freshness-degrade COUNTER: it
// increments once each time the routable gate's LIVE freshness probe is UNAVAILABLE
// (ErrFreshnessUnknown) and the gate DEGRADES to the recorded re-check alone (the
// pre-probe behavior). recheckFreshness already emits a WARN on that branch, but a
// WARN line is not AGGREGATABLE — an operator cannot graph or alert on the degrade
// RATE from logs alone. This counter rides alongside the WARN so the rate of
// unprobeable hosts admitted via the recorded re-check is queryable in production
// (the residual-D72-window admission rate). It is a stdlib expvar.Int (the established
// stdlib metric seam — no new dependency, exported on the standard /debug/vars
// handler the orchestrator's metrics surface mounts), registered once at package init
// under a stable name so it is observable fleet-wide; tests read its .Value() through
// the step9FreshnessDegradeCount helper to assert the degrade branch incremented. It is
// the FLEET TOTAL — the companion step9FreshnessDegradeByHost map below splits the same
// degrade events by host_id so the total stays the unbroken pre-existing observable.
var step9FreshnessDegradeTotal = expvar.NewInt("orchestrator_sessions_step9_freshness_degrade_total")

// step9FreshnessDegradeByHost is the §4.1 step-9 D72 freshness-degrade counter SPLIT BY
// HOST (D72): an expvar.Map keyed by the placed host_id, each key an expvar.Int that
// increments on the SAME ErrFreshnessUnknown degrade branch as the flat total above.
// The flat total answers "how often does the fleet degrade?"; this map answers WHICH
// hosts degrade — a single host falling behind (one hot key) reads very differently from
// a systemic live-freshness outage (many keys climbing together), and the operator can
// only tell them apart with the per-host split. It is the same stdlib expvar seam (no
// new dependency, exported on the standard /debug/vars surface), registered once under a
// stable name; the per-key Int rides next to (never instead of) the flat total, so the
// pre-existing total observable is unbroken. Tests read a host's key through the
// step9FreshnessDegradeHostCount helper to assert the placed host's key advanced.
//
// CARDINALITY GUARD (D72). An expvar.Map keyed by an unbounded id is an operational
// cardinality risk: /debug/vars renders EVERY key, so a churny fleet (hosts cycling
// in/out) or a buggy caller (a placement loop minting fresh host_ids) could grow this
// map without bound, bloating the /debug/vars payload an operator (or a scraper) pulls.
// We bound the DISTINCT-key count with an LRU eviction policy (see degradeHostGuard):
// the map holds at most the effective cap of per-host keys (defaultMaxDegradeHostKeys,
// or the DS_ORCH_DEGRADE_HOST_CAP operator knob — resolveDegradeHostCap) — the most-
// recently-degraded hosts (the ACTIVE set, where the per-host signal is operationally
// useful). When a new host would push past the cap, the LEAST-recently-degraded host's
// key is EVICTED and its accumulated count is FOLDED into a single reserved overflow
// bucket (degradeOverflowKey, the "__other__" key, which itself never counts toward the
// cap). So the per-host signal stays EXACT for the active set, the map size is bounded at
// the effective cap + 1 keys (the active set plus the overflow bucket), and no degrade is
// ever lost — every increment lands in either a per-host key or the overflow bucket, and
// the flat fleet total (step9FreshnessDegradeTotal) counts every degrade unconditionally,
// untouched by the guard. Eviction never collides with the overflow key (it is reserved
// and never a host_id; if a host were literally named "__other__" it would still merge
// correctly — its count is additive). See the orchestrator README /debug/vars runbook
// note for how an operator reads this map (the overflow bucket signals more distinct
// degrading hosts than the cap — a fleet-wide churn or outage signal in its own right).
var step9FreshnessDegradeByHost = expvar.NewMap("orchestrator_sessions_step9_freshness_degrade_by_host")

// defaultMaxDegradeHostKeys is the DEFAULT LRU cap on the number of DISTINCT per-host
// keys the step9FreshnessDegradeByHost map retains (the ACTIVE set), used when the
// DS_ORCH_DEGRADE_HOST_CAP operator knob (degradeHostCapEnv) is unset or malformed. It
// is chosen generously — far above any realistic single-rack active host fleet — so
// that in normal operation every degrading host keeps its own exact key, and the cap
// only ever bites under pathological churn/cardinality growth (the operational footgun
// this guard exists to contain). Past the cap, the least-recently-degraded host's key
// is evicted and folded into degradeOverflowKey. The effective cap is resolved ONCE at
// package init by resolveDegradeHostCap (the env is read exactly once — never on the
// per-degrade hot path); the map's bounded size is therefore the effective cap + 1 (the
// active set plus the overflow bucket).
const defaultMaxDegradeHostKeys = 1024

// degradeHostCapEnv is the operator knob (D72) that retunes the step9FreshnessDegradeByHost
// LRU active-set cap WITHOUT a recompile: set DS_ORCH_DEGRADE_HOST_CAP to a positive
// integer to raise or lower the distinct-per-host-key bound. It is read EXACTLY ONCE at
// package init (resolveDegradeHostCap, wired into the step9DegradeGuard construction
// below) — never on the per-degrade path, so tuning the bound carries no hot-path
// getenv cost. An unset, empty, non-integer, or non-positive value falls back to
// defaultMaxDegradeHostKeys (1024), so a malformed knob can never configure the map into
// an unbounded — or a zero — state. The resolved cap is clamped to >=1 by
// newDegradeHostGuard as a second floor. See the orchestrator README /debug/vars runbook
// note for how an operator reads the resulting map and chooses a cap.
const degradeHostCapEnv = "DS_ORCH_DEGRADE_HOST_CAP"

// resolveDegradeHostCap reads the DS_ORCH_DEGRADE_HOST_CAP operator knob ONCE and returns
// the effective LRU active-set cap for the per-host degrade map (D72). The env is read a
// single time (at package init, where the step9DegradeGuard is constructed); it is NEVER
// consulted on the per-degrade path. The fallback policy is fail-safe: an unset or empty
// value silently takes the default (1024); a NON-empty but malformed value (non-integer,
// or an integer <=0 that would clamp the map toward unboundedness or zero) falls back to
// the default and is logged ONCE at construction so the misconfiguration is visible
// without breaking startup. A valid positive value is returned verbatim (and is further
// floored at >=1 by newDegradeHostGuard, a defensive second clamp).
func resolveDegradeHostCap() int {
	raw, set := os.LookupEnv(degradeHostCapEnv)
	if !set || raw == "" {
		return defaultMaxDegradeHostKeys
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		slog.Default().Warn("sessions: invalid DS_ORCH_DEGRADE_HOST_CAP — falling back to the default per-host degrade-map cap (D72)",
			slog.String("env", degradeHostCapEnv),
			slog.String("value", raw),
			slog.Int("default", defaultMaxDegradeHostKeys))
		return defaultMaxDegradeHostKeys
	}
	return n
}

// degradeOverflowKey is the reserved overflow-bucket key on the per-host degrade map:
// when an LRU eviction drops a host past the cap, that host's accumulated degrade count
// is FOLDED into this single bucket so no degrade is lost and the per-host map stays
// bounded. It is deliberately a sentinel that cannot collide with a real host_id usage
// (the "__other__" convention); it does NOT count toward the active-set cap. An operator
// reading /debug/vars treats a climbing "__other__" as "more distinct hosts degraded
// than the active-set cap retains" — itself a churn/breadth signal (see the README).
const degradeOverflowKey = "__other__"

// degradeHostGuard is the cardinality guard / LRU eviction policy that bounds the
// DISTINCT-key count of the step9FreshnessDegradeByHost expvar.Map. It records, per live
// per-host key, the monotonic "tick" of that host's most recent degrade (its recency)
// so that, when a new host would push the live-key count past the effective cap (g.max,
// resolved once from defaultMaxDegradeHostKeys or the DS_ORCH_DEGRADE_HOST_CAP knob), the
// guard can evict the LEAST-recently-degraded host: it deletes that host's key from the
// expvar.Map and folds the host's accumulated count into degradeOverflowKey. The guard
// is a process-global singleton (the map is process-global), so it carries its own mutex
// — Create is otherwise concurrency-safe (it holds no shared mutable state), and the
// per-host increment is the one shared write that needs serializing against the cap
// bookkeeping. The recency map holds ONLY the bounded active set (≤ g.max entries), so
// the guard's own memory is bounded too.
type degradeHostGuard struct {
	mu       sync.Mutex
	m        *expvar.Map
	max      int
	tick     uint64            // monotonic recency clock; the next degrade gets tick+1
	lastSeen map[string]uint64 // live per-host key → recency tick of its last degrade
}

// step9DegradeGuard is the process-global cardinality guard over the per-host degrade
// map. It is constructed once at package init alongside the map it bounds; the step-9
// degrade branch records through it (recordDegradeByHost) so every per-host increment
// passes the cap/eviction policy.
var step9DegradeGuard = newDegradeHostGuard(step9FreshnessDegradeByHost, resolveDegradeHostCap())

// step9DegradeHostCap is the startup SELF-REPORT of the RESOLVED step-9 per-host
// degrade-map LRU cap (D72): the effective distinct-per-host-key bound the
// step9DegradeGuard actually enforces (step9DegradeGuard.max — already resolved from
// defaultMaxDegradeHostKeys or the DS_ORCH_DEGRADE_HOST_CAP knob and floored at >=1 by
// newDegradeHostGuard). orch26 made the cap an env knob (resolveDegradeHostCap); this
// publishes the RESOLVED value once at package init so an operator reading /debug/vars
// can CONFIRM the effective cap (default 1024 / the env value / a clamp) rather than
// GUESSING whether the DS_ORCH_DEGRADE_HOST_CAP env was applied or fell back. It is the
// same stdlib expvar seam the degrade counters use (no new dependency, exported on the
// standard /debug/vars surface), registered once under a stable name; it is a static
// configuration readout (set at init, never touched on the per-degrade path), so it
// never moves after startup. publishDegradeHostCap is the one publish point so the same
// logic is exercised under test against a fresh expvar.Int (the established
// fresh-var-per-test discipline) without re-registering this global. Tests read it
// through step9DegradeHostCapReported.
var step9DegradeHostCap = publishDegradeHostCap(
	expvar.NewInt("orchestrator_sessions_step9_degrade_host_cap"), step9DegradeGuard.max)

// publishDegradeHostCap sets the self-report expvar.Int to the resolved/clamped cap and
// returns it, so the package-init publish and the unit tests share ONE publish path. The
// returned *expvar.Int is the same value passed in (set in place); the helper exists so a
// test can drive it with a fresh expvar.NewInt (avoiding a re-registration of the global
// stable name) and assert the published value tracks the resolved cap.
func publishDegradeHostCap(v *expvar.Int, cap int) *expvar.Int {
	v.Set(int64(cap))
	return v
}

// step9DegradeHostCapReported reads the published RESOLVED step-9 degrade-host cap
// self-report (D72). It exists so tests assert the operator-visible cap through the same
// expvar seam production exposes, keeping the metric the single observation point.
func step9DegradeHostCapReported() int64 { return step9DegradeHostCap.Value() }

// step9StalenessBudget is the startup SELF-REPORT of the RESOLVED §4.1 step-9 D72
// STALENESS BUDGET (the re-check window): the effective applied_seq freshness window the
// routable gate's step-9 re-check actually enforces — how far behind its placement seq a
// host's CURRENT (or recorded) applied_seq may fall before recheckFreshness fail-closes as
// ErrPolicyStale. The budget is INSTANCE-scoped (passed to NewSessionCreator by the wiring
// — SessionCreator.stalenessBudget) and RESOLVED at construction: a negative input is
// clamped to 0 (the strictest budget — an exact applied_seq match is required). orch26 made
// the degrade-host cap an env knob with a self-report (orch27, step9DegradeHostCap); this is
// the SAME self-report pattern for the step-9 staleness budget, which is likewise resolved
// at construction but was not operator-visible: an operator reading /debug/vars could
// confirm the degrade-host cap but had to GUESS whether the effective re-check window was
// the wired value or a clamp. Publishing it lets the operator CONFIRM the booted window.
//
// It is the same stdlib expvar seam the degrade counters/cap use (no new dependency,
// exported on the standard /debug/vars surface the orchestrator's admin mount serves),
// REGISTERED ONCE under a stable name at package init — never via expvar.NewInt inside the
// constructor, which would panic on the second NewSessionCreator (the constructor runs many
// times under test, and once per wiring in production). NewSessionCreator instead SETS this
// already-registered var to its resolved budget through publishStep9StalenessBudget, so the
// var reflects the budget of the constructed coordinator (one control plane per process —
// the last/only constructor wins). It is a static configuration readout (set at
// construction, never touched on the per-recheck path), so it never moves after startup.
// Tests read it through step9StalenessBudgetReported and drive the publish helper against a
// fresh expvar.Int (the established fresh-var-per-test discipline) so the publish logic is
// exercised across resolved inputs without re-registering this global stable name.
var step9StalenessBudget = expvar.NewInt("orchestrator_sessions_step9_staleness_budget")

// publishStep9StalenessBudget sets the staleness-budget self-report expvar.Int to the
// RESOLVED step-9 re-check window and returns it, so the construction-time publish (in
// NewSessionCreator) and the unit tests share ONE publish path. The returned *expvar.Int is
// the same value passed in (set in place); the helper exists so a test can drive it with a
// fresh expvar.NewInt (avoiding a re-registration of the global stable name) and assert the
// published value tracks the resolved budget (D72).
func publishStep9StalenessBudget(v *expvar.Int, budget int64) *expvar.Int {
	v.Set(budget)
	return v
}

// step9StalenessBudgetReported reads the published RESOLVED §4.1 step-9 staleness-budget
// self-report (D72). It exists so tests assert the operator-visible re-check window through
// the same expvar seam production exposes, keeping the metric the single observation point.
func step9StalenessBudgetReported() int64 { return step9StalenessBudget.Value() }

// newDegradeHostGuard builds the LRU cardinality guard over an expvar.Map with the given
// distinct-key cap. A non-positive cap is clamped to 1 (the map always holds at least the
// single most-recent host plus the overflow bucket) so the guard can never be configured
// into an unbounded state.
func newDegradeHostGuard(m *expvar.Map, max int) *degradeHostGuard {
	if max < 1 {
		max = 1
	}
	return &degradeHostGuard{m: m, max: max, lastSeen: make(map[string]uint64, max)}
}

// recordDegradeByHost increments the per-host degrade key for hostID under the LRU
// cardinality guard (D72). The increment is exact for any host in the bounded ACTIVE set:
//
//   - if hostID is already a live key (or is the reserved overflow key itself), its key
//     is bumped by 1 and its recency is refreshed (a fresh degrade makes it most-recent);
//   - if hostID is a NEW host and the live-key count is below the cap, it is admitted as a
//     new exact key (recency = now);
//   - if hostID is a NEW host and the live set is FULL, the LEAST-recently-degraded host
//     is EVICTED first (its key deleted, its accumulated count folded into the overflow
//     bucket so no degrade is lost), THEN hostID is admitted as a fresh exact key.
//
// The map size is therefore bounded at max+1 keys (the active set plus the overflow
// bucket). The flat fleet total (step9FreshnessDegradeTotal) is NOT touched here — the
// caller bumps it unconditionally — so the guard never perturbs the unbroken total.
func (g *degradeHostGuard) recordDegradeByHost(hostID string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	// The overflow bucket is its own ever-present key — folding into it (or a host literally
	// named "__other__") is additive and does not consume an active-set slot. Bump and return.
	if hostID == degradeOverflowKey {
		g.m.Add(degradeOverflowKey, 1)
		return
	}

	g.tick++
	if _, live := g.lastSeen[hostID]; live {
		// Already an exact key — bump and refresh recency.
		g.m.Add(hostID, 1)
		g.lastSeen[hostID] = g.tick
		return
	}

	// A new host. If the active set is full, evict the least-recently-degraded host first,
	// folding its accumulated count into the overflow bucket so the signal is not lost.
	if len(g.lastSeen) >= g.max {
		g.evictLRULocked()
	}
	g.m.Add(hostID, 1)
	g.lastSeen[hostID] = g.tick
}

// evictLRULocked removes the least-recently-degraded host's key from the map and folds its
// accumulated count into the overflow bucket. The caller holds g.mu and has ensured the
// active set is non-empty. Folding reads the evicted key's current value before deleting it
// so no degrade is lost (the overflow bucket gains exactly what the per-host key held).
func (g *degradeHostGuard) evictLRULocked() {
	var victim string
	var victimTick uint64
	first := true
	for host, t := range g.lastSeen {
		if first || t < victimTick {
			victim, victimTick, first = host, t, false
		}
	}
	if first {
		return // active set empty — nothing to evict (defensive; the caller guards on len)
	}
	// Fold the victim's accumulated count into the overflow bucket, then drop its key.
	var carried int64
	if v, ok := g.m.Get(victim).(*expvar.Int); ok {
		carried = v.Value()
	}
	if carried > 0 {
		g.m.Add(degradeOverflowKey, carried)
	}
	g.m.Delete(victim)
	delete(g.lastSeen, victim)
}

// step9FreshnessDegradeCount reads the current §4.1 step-9 freshness-degrade FLEET-TOTAL
// counter value. It exists so tests can assert the degrade branch incremented the counter
// via the same seam production exposes (the expvar var), rather than reaching into expvar
// directly — keeping the metric seam the single observation point.
func step9FreshnessDegradeCount() int64 { return step9FreshnessDegradeTotal.Value() }

// step9FreshnessDegradeHostCount reads the current §4.1 step-9 freshness-degrade counter
// value for a SINGLE host_id key of the per-host map (0 when that host has never
// degraded — the key is absent). It exists so tests can assert the degrade branch
// incremented the placed host's key (and that two distinct hosts produce two distinct
// keys) through the same expvar.Map seam production exposes, keeping the metric the
// single observation point.
func step9FreshnessDegradeHostCount(hostID string) int64 {
	v := step9FreshnessDegradeByHost.Get(hostID)
	if iv, ok := v.(*expvar.Int); ok {
		return iv.Value()
	}
	return 0
}

// CreateStep names a step of the §4.1 ten-step sequence. It is the FAILURE-SITE
// label the coordinator stamps onto a CreateError so the rollback (and the audit
// event) can compensate from the EXACT step that failed (doc 15 §4.1's step-specific
// rollback notes key on this). The integer values are the §4.1 step numbers; they
// are NOT a wire contract — they are the in-package failure-site vocabulary.
type CreateStep int

const (
	// StepNone is the zero value — no step reached (a pre-flight misconfiguration).
	StepNone CreateStep = 0
	// StepTwoKey is §4.1 step 1: the D56 two-key structural refusal.
	StepTwoKey CreateStep = 1
	// StepRecord is §4.1 step 2: the session record creation.
	StepRecord CreateStep = 2
	// StepPlacement is §4.1 step 3: policy-fresh placement (D72).
	StepPlacement CreateStep = 3
	// StepHostAlloc is §4.1 step 4: host allocation + VM define (the index binding).
	StepHostAlloc CreateStep = 4
	// StepMint is §4.1 step 5: identity + interception-CA mint (D82).
	StepMint CreateStep = 5
	// StepDigest is §4.1 step 6: session-scoped digest write + ack gate (D73).
	StepDigest CreateStep = 6
	// StepInject is §4.1 step 7: overlay clone + fail-closed CA injection (D17/D29).
	StepInject CreateStep = 7
	// StepBoot is §4.1 step 8: boot + entrypoint (D38).
	StepBoot CreateStep = 8
	// StepRoutable is §4.1 step 9: the routable gate (digest ack AND freshness).
	StepRoutable CreateStep = 9
	// StepAttach is §4.1 step 10: attach (D79).
	StepAttach CreateStep = 10
)

// String renders the §4.1 step label for audit/error text.
func (s CreateStep) String() string {
	switch s {
	case StepTwoKey:
		return "1-two-key"
	case StepRecord:
		return "2-record"
	case StepPlacement:
		return "3-placement"
	case StepHostAlloc:
		return "4-host-alloc"
	case StepMint:
		return "5-mint"
	case StepDigest:
		return "6-digest"
	case StepInject:
		return "7-inject"
	case StepBoot:
		return "8-boot"
	case StepRoutable:
		return "9-routable"
	case StepAttach:
		return "10-attach"
	default:
		return "0-none"
	}
}

// CreateError is the coordinator's failure shape: the §4.1 step that failed, the
// underlying error, and whether the COMPENSATING rollback (the §4.2 destroy path
// driven from that step) completed cleanly. A create is RETRYABLE by session UUID
// (every host verb is idempotent on it, doc 15 §4.1), so a CreateError names the
// session so a retry can re-drive it. RolledBack==false with a non-nil RollbackErr
// means the compensation ITSELF failed — the reconciler's orphan-reaping (§3) is the
// backstop, and the create driver surfaces that honestly rather than claiming a
// clean teardown.
type CreateError struct {
	// SessionUUID is the session the create was for (the retry key, doc 15 §4.1).
	SessionUUID string
	// Step is the §4.1 step that failed — the rollback compensates FROM here.
	Step CreateStep
	// Err is the underlying failure (a refusal, a seam fault, a gate violation).
	Err error
	// RolledBack is true when the compensating rollback from Step completed cleanly
	// (every clean-teardown assertion satisfied). False when no rollback was needed
	// (a step-1 refusal: nothing host-side exists) OR the rollback itself faulted.
	RolledBack bool
	// RollbackErr is the rollback's own error when the compensation faulted (nil on a
	// clean rollback or when no rollback was needed). Surfaced so a half-torn-down
	// session is attributable to the reconciler's orphan-reaping backstop, never
	// silently claimed clean.
	RollbackErr error
}

func (e *CreateError) Error() string {
	base := fmt.Sprintf("sessions: create session %s failed at step %s: %v", e.SessionUUID, e.Step, e.Err)
	if e.RollbackErr != nil {
		return base + fmt.Sprintf(" (ROLLBACK ALSO FAILED: %v)", e.RollbackErr)
	}
	return base
}

// Unwrap exposes the underlying error so callers classify the failure with
// errors.Is (ErrTwoKeyRefused, ErrLaunchRefused, ErrRoleRefRefused, the gate
// sentinels, store sentinels) without parsing the step label.
func (e *CreateError) Unwrap() error { return e.Err }

// ErrPolicyStale is the §4.1 step-3 / step-9 structural refusal (D72): a host whose
// heartbeat applied_seq is outside the staleness budget is UNSCHEDULABLE (placement,
// step 3) and a session on a host that has since gone stale is NOT routable (the
// step-9 re-check). It is a fail-closed gate, distinct from a placement fault (no
// host available) — a stale host is a refusal the create driver surfaces, never a
// silently-degraded READY.
var ErrPolicyStale = errors.New("sessions: host policy stale (applied_seq outside the D72 staleness budget — not freshness-routable)")

// ErrDigestNotAcked is the §4.1 step-6 / step-9 structural refusal (D73): the
// session-scoped digests were written but the host has NOT acked, so the session is
// NOT routable. mint-before-attach is enforced by THIS gate, not by convention —
// the create driver never reaches READY on an un-acked session.
var ErrDigestNotAcked = errors.New("sessions: session digests not acked (D73 — not routable until the host acks)")

// ErrCAInjection is the §4.1 step-7 fail-closed refusal (D17/D29): the per-session
// interception CA could not be injected into the overlay's trust store BEFORE boot.
// Injection failure FAILS the create (it is the security-load-bearing gate that
// makes the egress boundary trustworthy); the create driver rolls back from step 7.
var ErrCAInjection = errors.New("sessions: CA injection into overlay failed (D17/D29 fail-closed — injection must precede boot)")

// ErrSessionFinalized is the §4.1 step-2 retry-vs-resurrection refusal (D66): a
// same-store create retry by session UUID landed on a record the previous attempt
// already FINALIZED (DESTROYED — the sole terminal §3 state, store.SessionState.
// IsTerminal). CreateSession is idempotent on the UUID, so the retry's
// CreatePreBindingSession returns that finalized row VERBATIM rather than minting a
// fresh one — and the very next step (placement → UpdateSession(State=CREATING))
// would silently RESURRECT it, because the store validates state VOCABULARY, not
// §3 TRANSITIONS (repository.go / memory.go). The create coordinator refuses
// fail-closed here so a finalized, retained (D66) row is never re-opened in place:
// a retry of a finalized session must mint a FRESH session UUID (the continuity key
// moves; re-opening a terminal record is forbidden without an explicit transition,
// which the create path does not own). A still-live in-flight record (PENDING /
// CREATING / any non-terminal state) is returned idempotently as before — that is a
// legitimate retry resuming an unfinished create, not a resurrection.
var ErrSessionFinalized = errors.New("sessions: session record already finalized DESTROYED (D66 — a retry cannot resurrect a terminal record; mint a fresh session UUID)")

// Placement is the §4.1 step-3 result: the host the scheduler placed the session
// on, plus the applied_seq it placed AGAINST (the D72 freshness the step-9 re-check
// re-validates). It is the DATA the Placer seam returns — the coordinator records
// the applied_seq and re-checks it at step 9, never re-running placement.
type Placement struct {
	// HostID is the host the scheduler placed the session on (the §7 filter chain's
	// winner — image-cache locality, floors-fit, freshness). Required.
	HostID string
	// AppliedSeq is the host's heartbeat applied_seq AT placement (D72): the policy
	// version the host had applied. Recorded on the record (PolicyAppliedSeq) and
	// re-checked at step 9 against the host's CURRENT applied_seq.
	AppliedSeq int64
}

// Placer is the §4.1 step-3 POLICY-FRESH PLACEMENT seam (D72), OWNED BY THIS
// PACKAGE so the coordinator never imports internal/scheduler (which reads the §3
// transition table from THIS package — a production import sessions→scheduler would
// cycle; the scheduler satisfies this seam from its side, the same data-across-the-
// seam discipline createspine.go uses for the launch gate). It picks a host whose
// applied_seq is within the D72 staleness budget (the §7 filter chain) and returns
// the Placement, or ErrPolicyStale when no fresh host is placeable.
//
// Place is idempotent w.r.t. the create's retry-by-UUID: a retry MAY land on the
// same or a new host (placement is free to re-pick), but the recorded applied_seq is
// always the host's value at the time of the call (the step-9 re-check reads CURRENT
// freshness, so a host that went stale after placement is caught there).
//
// CurrentFreshness is the §4.1 step-9 LIVE re-check probe (D72), ADDED additively so
// the routable gate re-validates against the host's CURRENT applied_seq, not just the
// recorded one. recheckFreshness alone re-reads the recorded PolicyAppliedSeq, which
// catches a host the reconciler has since MARKED stale (it would have written the
// record) but NOT a host that fell behind in the placement→step-9 window with no
// record write — the residual D72 window this probe closes. It returns the placed
// host's CURRENT applied_seq (the live heartbeat value). It returns ErrFreshnessUnknown
// when the live probe is UNAVAILABLE (the Placer has no live-freshness seam wired); the
// coordinator then DEGRADES to the recorded re-check (the pre-probe behavior), so a
// wiring that does not supply a live probe is unchanged. Adding this method does NOT
// change Place; scheduler.Adapter implements it additively (no constructor change), so a
// wiring that constructs the adapter stays compiling.
type Placer interface {
	Place(ctx context.Context, sessionUUID string, req PlacementRequest) (Placement, error)
	CurrentFreshness(ctx context.Context, hostID string) (int64, error)
}

// ErrFreshnessUnknown is the §4.1 step-9 LIVE-probe "unavailable" sentinel: the Placer
// has no live-freshness seam wired, so the placed host's CURRENT applied_seq cannot be
// read. It is NOT itself a staleness verdict — at the routable gate the coordinator
// treats it as "no live signal" and DEGRADES to the recorded re-check (the pre-probe
// behavior), so an adapter that does not (yet) carry the live-freshness seam behaves
// exactly as before the probe existed (backwards compatible). A live probe that IS
// wired but finds the host has fallen behind returns a real CURRENT seq, which the
// recheck fail-closes as ErrPolicyStale — the window-closing path. (A wired probe that
// finds the host absent from the live feed also surfaces as ErrFreshnessUnknown, with a
// host-named cause, so a fleet without that host's current report degrades rather than
// hard-failing a create the recorded re-check still vouches for.)
var ErrFreshnessUnknown = errors.New("sessions: host current freshness unknown (no live freshness probe available for the placed host — D72 live re-check unavailable, degrades to the recorded re-check)")

// PlacementRequest is the §4.1 step-3 input: the image the session needs (image-cache
// locality is a §7 filter), the resource floors (floors-fit math, D37), and the
// env-config ref (placement constraints may key on it). The coordinator assembles it
// from the CreateRequest; the scheduler's filter chain reads it.
type PlacementRequest struct {
	// ImageID is the resolved content-addressed image (the §7 image-cache-locality
	// filter prefers a host that already holds it warm).
	ImageID string
	// EnvConfigRef is the env-config reference (placement constraints may key on it).
	EnvConfigRef string
	// Floors is the resource floors the host must fit (D37 floors-fit math). Opaque
	// here — the scheduler reads the proto floors; the coordinator carries them as DATA.
	Floors *hypervisorv1.ResourceFloors
	// RequiredBaselineVersion is the host-baseline artifact version this session must
	// land on (doc 14 §11; the §7 filter-2 host-baseline-compatibility constraint, D72
	// freshness's structural sibling). The >=6.12 host-kernel baseline floor is pinned
	// on the session; the scheduler's frozen filter chain honors it as a hard predicate
	// so a session pinned to a new kernel floor never lands on an old host (kernel-floor
	// changes force host-image re-rolls). EMPTY = no baseline constraint (any reporting
	// host is compatible on this axis — the pre-pinning posture). Opaque carrier DATA:
	// the coordinator threads it from the create request, the scheduler's filter chain
	// reads it (filter 2), the placer adapter never interprets it.
	RequiredBaselineVersion string
}

// HostAllocation is the §4.1 step-4 result: the never-recycled host binding the host
// agent allocated and the overlay path it cloned. It mirrors the frozen
// CloneFromImageResponse (§5.1) field-for-field on the dimensions the record joins
// (the binding the §5.6 SessionRef quartet carries) — carried as DATA so the
// coordinator records it without re-deriving the host-side values.
type HostAllocation struct {
	// HostSessionIndex is the host-local never-recycled index (the §5.6 monotonic
	// counter's value). BURNED the moment it is recorded (AppendIndexEpoch); a
	// failure at step 4+ never recycles it.
	HostSessionIndex uint64
	// TapName is dstap-<idx> (≤15 chars IFNAMSIZ, D66) the host derived.
	TapName string
	// GuestIP is the family-agnostic guest IP bytes (D75) the host derived.
	GuestIP []byte
	// GuestIPFamily tags the bytes (v4/v6).
	GuestIPFamily store.IPFamily
	// OverlayPath is the per-session qcow2 overlay the host cloned (the step-7
	// injection target + the delta/durability unit, D29).
	OverlayPath string
}

// HostAllocator is the §4.1 step-4 HOST ALLOCATION + VM DEFINE seam: it drives the
// host agent's CloneFromImage on the PLACED host (allocate the never-recycled index,
// derive dstap-<idx> + the guest IP, invoke the Boundary tap-create primitive,
// instantiate the per-session NFT objects, clone the overlay) and returns the
// binding. The host-agent gRPC client (hypervisor.v1.HypervisorDriverService) and
// the generated fake both satisfy it natively; a test fake satisfies it identically.
// The coordinator carries the request/response as the frozen proto MESSAGES (DATA),
// never a host-agent package handle.
type HostAllocator interface {
	AllocateAndDefine(ctx context.Context, hostID string, spec *hypervisorv1.VmSpec) (HostAllocation, error)
}

// Minter is the §4.1 step-5 IDENTITY + INTERCEPTION-CA MINT seam (D82): it consumes
// the assembled mint claims (AssembleStep5MintRequest's output — the gate-sourced
// launching_user + the pinned role_ref) and returns the minted identity + CA refs.
// MintIdentity is a SEPARATE service by design (D22); this seam fronts it. The
// claims cross as DATA (MintWorkloadIdentityClaims); the mint mechanics live in doc
// 16. A mint fault is surfaced so the §4.1 step-5 rollback note (signal identity/CA
// revocation) can compensate.
type Minter interface {
	Mint(ctx context.Context, claims MintWorkloadIdentityClaims, roleRef string) (MintResult, error)
}

// MintResult is the §4.1 step-5 output: the identity ref + the interception-CA ref
// (the per-session CA under the separate root hierarchy, D82) the create records and
// the step-7 injection consumes (CARef → the overlay's trust store).
type MintResult struct {
	// IdentityRef is the minted per-session workload identity reference (opaque here;
	// doc 16 owns the mechanics). Recorded on the §5.6 record (Session.IdentityRef).
	IdentityRef string
	// CARef is the per-session interception-CA reference (D82, separate root). The
	// step-7 injection injects THIS CA into the overlay; recorded as Session.CARef.
	CARef string
	// Expiry is the wall-clock instant the minted credential / interception CA stops
	// being valid (D22/D82) — the mint/CA TTL the Minter seam surfaces OUT of the mint.
	// orch24 added it to the controlplane MintReply (the MintClient seam result) and
	// orch28 wired the PRODUCER leg (liveMint.MintWithExpiry populates it from the proto
	// expiry_unix_seconds); THIS field is the CONSUMER landing point on the sessions.Minter
	// seam result so the create coordinator can carry it forward (the routable window +
	// the teardown/re-mint bookkeeping, doc 16 §5.4: an expired credential re-mints on
	// resume; the routable gate). It is ADDITIVE: the ZERO value (Expiry.IsZero()) means
	// the mint surfaced NO expiry (a bare MintClient with no MintExpiryClient extension,
	// or a proto that omitted the TTL) — the not-set case the coordinator treats as "no
	// TTL to track" (no teardown scheduled), so a Minter that never sets it behaves
	// exactly as before this field existed.
	Expiry time.Time
}

// DigestResult is the §4.1 step-6 output: the digest reference written and whether
// the host ACKED (D73). The session is NOT routable until Acked is true — the step-9
// gate re-validates it. A write with no ack is a valid intermediate (the record
// carries DigestRef with DigestAcked=false); the create driver gates READY on the ack.
type DigestResult struct {
	// DigestRef is the session-scoped digest reference Identity wrote to the placed
	// host (recorded as Session.DigestRef).
	DigestRef string
	// Acked is the host's ack on behalf of the host-side fan-out (D73 OQ1 proposed
	// default). Routability (step 9) gates on this being true.
	Acked bool
}

// DigestWriter is the §4.1 step-6 SESSION-SCOPED DIGEST WRITE + ACK seam (D73):
// Identity computes the digests in the D39 trust zone and writes them to the placed
// host; the host acks on behalf of the host-side fan-out. The session cannot become
// routable until the ack lands (mint-before-attach, enforced by step 9). The seam
// returns the DigestResult; a write fault is surfaced so the §4.1 step-6 rollback
// (flush written digests, signal identity/CA revocation) can compensate.
type DigestWriter interface {
	WriteAndAck(ctx context.Context, sessionUUID, hostID, caRef string) (DigestResult, error)
}

// Injector is the §4.1 step-7 OVERLAY CLONE + FAIL-CLOSED CA INJECTION seam
// (D17/D29): it injects the per-session interception CA (caRef) into the cloned
// overlay's trust store BEFORE boot. Injection FAILURE fails the create (the create
// driver rolls back from step 7) — this is the security-load-bearing gate that makes
// the egress boundary trustworthy, so it is fail-closed by construction. (5 ≺ 7's
// injection: the CA must be minted, step 5, before it is injected.)
type Injector interface {
	InjectCA(ctx context.Context, sessionUUID, overlayPath, caRef string) error
}

// Booter is the §4.1 step-8 BOOT + ENTRYPOINT seam (D38): it launches the VM per the
// frozen entrypoint contract (session token via the D22 shim, HTTP(S)_PROXY + CA
// env, exec/supervise spec, local event socket up). (7 ≺ 8: the CA must be injected,
// step 7, before boot.) The orchestrator stays runtime-ignorant — it drives the verb
// and records nothing runtime-specific (doc 15 §1: "an image plus an entrypoint
// config"). A boot fault is surfaced so the §4.1 step-8 rollback (destroy the domain,
// dispose the overlay, unwind step 4) can compensate.
type Booter interface {
	Boot(ctx context.Context, sessionUUID, entrypointConfigRef string) error
}

// AttachIssuer is the §4.1 step-10 ATTACH seam (D79): it issues the attach handle
// (endpoint candidates + auth material + role) for a session that has reached READY
// (step 9), bringing WatchSession fan-out live and starting attendedness computation
// (D78). It is the ONLY step that runs after READY; the coordinator records the
// AttachState and flips the record to ATTACHED.
type AttachIssuer interface {
	IssueAttach(ctx context.Context, sessionUUID, hostID string, role store.AttachRole) (AttachIssued, error)
}

// AttachIssued is the §4.1 step-10 output: the seat role the handle was issued for
// (recorded as Session.AttachState — D61 one-writer/N-reader). The handle bytes
// themselves are out of scope here (doc 16 / doc 15 §5.4 own the AttachHandle shape);
// the coordinator records the seat class the create issued.
type AttachIssued struct {
	// Role is the seat class the attach handle was issued for (WRITER at create — the
	// launching attach takes the one writer seat, D61). Recorded as Session.AttachState.
	Role store.AttachRole
}

// HostDestroyer is the COMPENSATING ROLLBACK seam (the §4.2 destroy path driven from
// whatever create step failed): it drives the host agent's Destroy verb (libvirt
// domain destroy → flush_session(legs=all) + NFT-6 order → overlay disposal), which
// is idempotent on session_uuid (doc 15 §4.1/§4.2). The coordinator calls it on a
// failure at step 4+ (anything host-side exists); the destroy satisfies the doc 06
// (b) clean-teardown checklist (no orphaned VM, no leaked NFTables rules/allow-set
// entries, no dangling CoW overlay, no stranded proxy session). The host-agent gRPC
// client and the generated fake both satisfy it; a test fake satisfies it identically.
type HostDestroyer interface {
	Destroy(ctx context.Context, hostID, sessionUUID string) error
}

// IdentityRevoker is the §4.1 step-5/6 rollback seam (D22/D82): on a failure at
// step 5–6 (or any later step, since the identity/CA exist from step 5 onward) the
// coordinator signals identity/CA revocation to Identity (the §4.2 step-5 teardown
// assertion: "no leftover minted identity") and flushes any written digests. It is
// idempotent (revoking an already-revoked identity is a no-op); a revoke fault is
// recorded on the CreateError's RollbackErr (the reconciler is the backstop).
type IdentityRevoker interface {
	Revoke(ctx context.Context, sessionUUID, identityRef, caRef string) error
}

// MintExpirySink is the §4.1 step-5 minted-credential EXPIRY teardown/re-mint sink
// (D22/D82, doc 16 §5.4): when a session whose minted credential / interception CA
// carries a NON-ZERO expiry reaches its routable (READY) horizon, the coordinator
// hands the sink the session UUID + the expiry instant so the routable-window /
// teardown-re-mint bookkeeping can register the TTL (an expired credential re-mints
// on resume; the routable gate, doc 16 §5.4). It is the REAL action wired behind the
// in-package onMintExpiry seam point the coordinator previously stubbed as a no-op.
//
// IDEMPOTENCY (the load-bearing contract): the coordinator fires OnMintExpiry ONLY
// after the session is DURABLY READY — past the create rollback window. A create that
// rolls back AFTER step 5 (mint done) but before/at the READY transition NEVER reaches
// the fire point, so a minted-then-destroyed session does NOT register a spurious
// teardown/re-mint (the §4.2 step-5 rollback already revoked the identity/CA — there
// is nothing left to expire). The sink itself SHOULD also be idempotent on its own
// (registering the same session twice is a no-op) so a redrive that re-reaches READY
// cannot double-register, but the coordinator's once-per-create fire makes the common
// path single-shot by construction. A nil sink defaults to the safe no-op
// (nopMintExpirySink) — a wiring that does not (yet) supply a teardown scheduler is
// unchanged (backwards compatible).
type MintExpirySink interface {
	// OnMintExpiry registers the minted-credential expiry horizon for a session that
	// has reached READY. expiry is the wall-clock instant the credential / CA stops
	// being valid (always non-zero when the coordinator calls — the zero/not-set case
	// never reaches here). It MUST NOT block the create path (the create has already
	// committed READY); a slow or fault-prone scheduler is the sink's own concern.
	OnMintExpiry(sessionUUID string, expiry time.Time)
}

// nopMintExpirySink is the safe default sink: it tracks no TTL and schedules no
// teardown. It is installed when CreateSeams.OnMintExpiry is nil so a wiring that does
// not supply a teardown scheduler carries the expiry on the create-local state without
// an external registration (no behavior change — backwards compatible).
type nopMintExpirySink struct{}

func (nopMintExpirySink) OnMintExpiry(string, time.Time) {}

// CreateSeams bundles the per-step seams the coordinator drives. They are injected at
// construction (NewSessionCreator) — the constructible-component discipline — so the
// coordinator is unit-tested against synthetic fixtures + the generated fakes and is
// never wired into main.go here (FENCED). A nil REQUIRED seam is a construction-time
// misconfiguration; the rollback seams (HostDestroyer, IdentityRevoker) MAY be nil
// only when the coordinator is used for a create that cannot reach the host-side
// steps (test-narrowing) — a production wiring supplies them.
type CreateSeams struct {
	// TwoKey backs §4.1 step 1 (D56). Required.
	TwoKey TwoKeyChecker
	// Store backs §4.1 step 2 (CreateSession) and every record mutation (UpdateSession,
	// AppendIndexEpoch). It is the SINGLE backing store the spine's coherence
	// assertion requires (the gate linker, the launching_user resolver, and the pin
	// writer all hit it). Required.
	Store SessionRecordStore
	// Gate backs the §4.1 step-1 launch authorization (doc 16 §11.2), consulted via
	// RunCreateSpine before the step-5 mint assembly. Required (the spine refuses a
	// nil gate).
	Gate launchGate
	// RoleResolver backs §4.1 steps 1–2 (role resolve + pin). Required.
	RoleResolver RoleResolver
	// MintResolver backs the §4.1 step-5 launching_user resolution (the SAME store as
	// Store — coherence). Required.
	MintResolver launchingUserResolver
	// PinWriter persists the steps-1–2 role pin (migration 0009). MAY be nil (the
	// in-package pin still rides; the pre-unfreeze no-persist posture). Production
	// supplies the SAME store as Store.
	PinWriter rolePinWriter
	// Placer backs §4.1 step 3 (D72 policy-fresh placement). Required.
	Placer Placer
	// HostAllocator backs §4.1 step 4 (host allocation + VM define). Required.
	HostAllocator HostAllocator
	// Minter backs §4.1 step 5 (identity + interception-CA mint, D82). Required.
	Minter Minter
	// DigestWriter backs §4.1 step 6 (digest write + ack, D73). Required.
	DigestWriter DigestWriter
	// Injector backs §4.1 step 7 (fail-closed CA injection, D17/D29). Required.
	Injector Injector
	// Booter backs §4.1 step 8 (boot + entrypoint, D38). Required.
	Booter Booter
	// AttachIssuer backs §4.1 step 10 (attach, D79). Required.
	AttachIssuer AttachIssuer
	// HostDestroyer drives the compensating §4.2 destroy on a host-side rollback.
	// Required when the coordinator can reach step 4+ (production); a nil destroyer
	// makes a step-4+ rollback unable to tear down host-side state — surfaced on the
	// CreateError's RollbackErr.
	HostDestroyer HostDestroyer
	// IdentityRevoker drives the §4.1 step-5/6 identity/CA revocation on rollback.
	// Required when the coordinator can reach step 5+ (production); a nil revoker
	// surfaces on RollbackErr the same way.
	IdentityRevoker IdentityRevoker
	// OnMintExpiry is the OPTIONAL §4.1 step-5 minted-credential EXPIRY teardown/re-mint
	// sink (D22/D82, doc 16 §5.4): when a session whose minted credential carries a
	// non-zero expiry reaches READY, the coordinator hands it the session UUID + the
	// expiry horizon (the routable-window / teardown-re-mint registration). It is
	// ADDITIVE and DEFAULTS to the safe no-op (nopMintExpirySink) when nil — a wiring
	// that does not (yet) supply a teardown scheduler is unchanged (no external
	// registration; the expiry still rides the create-local state). It is fired ONLY
	// for a DURABLY-READY session (past the rollback window), so a minted-then-rolled-
	// back session never registers a spurious teardown (the idempotency contract).
	OnMintExpiry MintExpirySink
	// DigestPublisher is the OPTIONAL §6.1 DIGEST-PUBLISH seam (mint-before-attach,
	// D73/D84, doc 16 §6.1): the coordinator threads it into the spine's
	// CreateSpineRequest.DigestPublisher so RunCreateSpine drives the digest push
	// BETWEEN the step-5 cred-mint and mark-routable and gates routability on the host
	// ack (digestpublish.go's runCreateDigestPublish). It is FLAG-GATED by
	// DS_ORCH_DIGEST_PUBLISH_WIRE and DEFAULTS to nil (the wave default): when the flag
	// is OFF the spine SKIPS the step and this field is UNUSED — the create path is
	// byte-for-byte the pre-wire behavior (D50). When the flag is ARMED, a nil publisher
	// fails the create CLOSED (ErrDigestPublisherUnwired) and a publish/transport error
	// or an uncommitted ack fails it closed too (ErrDigestNotRoutable) — the session is
	// never marked routable when its digests did not land. The production adapter
	// (DigestFeedPublisher, digestpublish.go) speaks the frozen
	// identityv1.DigestFeedServiceClient via proto/gen/go (D80); a test fake satisfies it
	// (D50). It is NOT a required seam (NewSessionCreator does not refuse a nil one) — a
	// disarmed or test-narrowed coordinator carries it nil and the gate stays skipped.
	DigestPublisher digestPublisher
}

// TwoKeyChecker is the §4.1 step-1 seam (D56): it runs the two-key activation check
// (CheckTwoKeyActivation, twokey.go) and returns the resolved keys or a fail-closed
// refusal. It is package-owned so the coordinator drives step 1 through one seam the
// test fakes and the production wiring (over EnrollmentResolver + envConfigReader)
// both satisfy.
type TwoKeyChecker interface {
	Check(ctx context.Context, req TwoKeyRequest) (TwoKeyResult, error)
}

// SessionRecordStore is the §4.1 step-2 + record-mutation seam the coordinator needs:
// CreateSession (step 2), UpdateSession (the policy-posture / digest-ack / gated
// state flips), AppendIndexEpoch (step 4's binding — which BURNS the index), and
// GetSession (the step-9 routable re-check reads the recorded freshness + ack). It is
// a NARROW interface this package owns — not the full store.Repository — so the
// coordinator depends only on the four methods it uses; both *store.Memory and
// *store.Postgres satisfy it identically (these are existing exported methods — the
// store package stays frozen). The same value is the spine's coherence store.
type SessionRecordStore interface {
	CreateSession(ctx context.Context, s store.Session) (store.Session, error)
	GetSession(ctx context.Context, sessionUUID string) (store.Session, error)
	UpdateSession(ctx context.Context, sessionUUID string, u store.SessionUpdate) (store.Session, error)
	AppendIndexEpoch(ctx context.Context, sessionUUID string, e store.IndexEpoch) (store.Session, error)
}

// SessionCreator is the constructible §4.1 ten-step create coordinator. It is built
// once with the store + the per-step seams injected (NewSessionCreator) and drives
// Create per session. It is concurrency-safe by construction (it holds no mutable
// per-create state — every Create threads its own state through locals), so one
// coordinator serves the CreateSession RPC's replicas.
type SessionCreator struct {
	seams  CreateSeams
	logger *slog.Logger
	// stalenessBudget is the D72 applied_seq freshness window the step-9 re-check
	// uses: the session is routable only if the host's CURRENT applied_seq has not
	// fallen more than this many versions behind what the session expects. Placement
	// (step 3) owns its own budget (the Placer's filter); this is the re-check budget.
	stalenessBudget int64
	// clock is the timestamp seam (nil → time.Now); overridable for deterministic
	// record timestamps under test (the SetClock test-only setter installs it).
	clock func() time.Time
	// onMintExpiry is the §4.1 step-5 minted-credential EXPIRY teardown/re-mint sink
	// (D22/D82, doc 16 §5.4): when a session whose minted credential / CA carries a
	// NON-ZERO expiry reaches its routable (READY) horizon, the coordinator hands it
	// (with the session UUID) the expiry so the routable-window / teardown-re-mint
	// bookkeeping can register the TTL (the future §5.6 record column lands the same
	// value; until then this is the in-package seam point). It is wired from
	// CreateSeams.OnMintExpiry at construction and DEFAULTS to the safe no-op
	// (nopMintExpirySink) when unset — a wiring that does not (yet) supply a teardown
	// scheduler simply carries the expiry on the create-local state without an external
	// registration (no behavior change). It is non-nil after NewSessionCreator (the
	// no-op fills the unset case) so the Create fire path never nil-checks; tests may
	// install a func directly (same-package field access, like clock) to observe it.
	//
	// IDEMPOTENCY: the coordinator fires it ONLY once the session is DURABLY READY (past
	// the create rollback window), so a create that rolls back AFTER step 5 (mint done,
	// session destroyed) NEVER fires it — no spurious teardown/re-mint for a session that
	// no longer exists. A ZERO/absent expiry never reaches it (mintExpiry.IsZero() → no
	// TTL to track, no spurious teardown).
	onMintExpiry func(sessionUUID string, expiry time.Time)
}

// NewSessionCreator builds the coordinator. It refuses a wiring missing a REQUIRED
// seam (fail-closed at construction, never at the first create) so a half-wired
// coordinator can never half-run a create. The rollback seams (HostDestroyer,
// IdentityRevoker) are NOT required here — a test-narrowed coordinator that cannot
// reach the host-side steps may omit them — but a production wiring supplies them
// (a nil rollback seam surfaces on the CreateError's RollbackErr if a host-side
// rollback is needed). stalenessBudget is the D72 step-9 re-check window (≤0 means an
// exact match is required — the strictest budget); the RESOLVED value is self-reported
// once here as the step9StalenessBudget expvar so an operator can confirm the effective
// window on /debug/vars (D72). logger nil → slog.Default.
func NewSessionCreator(seams CreateSeams, stalenessBudget int64, logger *slog.Logger) (*SessionCreator, error) {
	if logger == nil {
		logger = slog.Default()
	}
	missing := make([]string, 0, 12)
	if seams.TwoKey == nil {
		missing = append(missing, "TwoKey")
	}
	if seams.Store == nil {
		missing = append(missing, "Store")
	}
	if seams.Gate == nil {
		missing = append(missing, "Gate")
	}
	if seams.RoleResolver == nil {
		missing = append(missing, "RoleResolver")
	}
	if seams.MintResolver == nil {
		missing = append(missing, "MintResolver")
	}
	if seams.Placer == nil {
		missing = append(missing, "Placer")
	}
	if seams.HostAllocator == nil {
		missing = append(missing, "HostAllocator")
	}
	if seams.Minter == nil {
		missing = append(missing, "Minter")
	}
	if seams.DigestWriter == nil {
		missing = append(missing, "DigestWriter")
	}
	if seams.Injector == nil {
		missing = append(missing, "Injector")
	}
	if seams.Booter == nil {
		missing = append(missing, "Booter")
	}
	if seams.AttachIssuer == nil {
		missing = append(missing, "AttachIssuer")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("sessions: NewSessionCreator: missing required seams: %v", missing)
	}
	if stalenessBudget < 0 {
		stalenessBudget = 0
	}
	// Self-report the RESOLVED step-9 staleness budget (the re-check window) once at
	// construction so an operator reading /debug/vars can CONFIRM the effective window
	// rather than guessing whether the wired value or the clamp applied (D72). Stdlib
	// expvar, set on the package-registered var (never re-registered per construction).
	publishStep9StalenessBudget(step9StalenessBudget, stalenessBudget)
	// Wire the minted-credential expiry sink from the (optional) seam, defaulting to the
	// safe no-op so the Create fire path never nil-checks and an unwired coordinator is
	// backwards-compatible (no external teardown registration). The interface is adapted
	// to the in-package func field so a directly-installed test func and an injected
	// MintExpirySink are one seam.
	sink := seams.OnMintExpiry
	if sink == nil {
		sink = nopMintExpirySink{}
	}
	return &SessionCreator{
		seams:           seams,
		logger:          logger,
		stalenessBudget: stalenessBudget,
		onMintExpiry:    sink.OnMintExpiry,
	}, nil
}

// ResolvedStalenessBudget returns the RESOLVED §4.1 step-9 D72 staleness budget (the
// re-check window) THIS coordinator enforces: the already-clamped value sealed into the
// instance at NewSessionCreator (a negative input is clamped to 0 — the strictest budget,
// an exact applied_seq match). It is a pure, additive read of the unexported
// stalenessBudget field — no new field, no behavior change, no record mutation, no §3
// state touched — so a caller (notably the controlplane staleness pin) can observe THIS
// instance's enforced window directly off cp.Creator, instead of scraping the SET-last-
// wins process-global orchestrator_sessions_step9_staleness_budget expvar (which is a
// per-process self-report, not a per-instance observation point, and is racy under any
// test that builds a second coordinator in a background goroutine overlapping the read).
// The published expvar remains the operator-visible self-report; this is the in-package
// instance-scoped read for tests/callers that need the budget of one specific coordinator.
func (c *SessionCreator) ResolvedStalenessBudget() int64 { return c.stalenessBudget }

// CreateRequest is the input to the ten-step create. It carries the session UUID
// (the retry key + the join key for every step), the resolved auth (the launch gate
// input; nil = an unauthenticated launch the gate refuses fail-closed), the requested
// role_ref (resolved + pinned at steps 1–2), the env-config + image refs (steps 2/3),
// the resource floors (step 3 floors-fit + step 4 VmSpec), the repo to activate
// (step 1 two-key), and the entrypoint config ref (step 8). It is assembled from the
// CreateSessionRequest by the (fenced) RPC handler; here it is the DATA the
// coordinator drives.
type CreateRequest struct {
	// SessionUUID is the session being created (minted by the caller; the retry key,
	// doc 15 §4.1 "create is retryable by session UUID"). Required.
	SessionUUID string
	// RepoID is the repo the session activates against (the §4.1 step-1 two-key
	// enrollment key). Required (an empty repo is a two-key refusal).
	RepoID string
	// EnvConfigRef is the checked-in env spec reference (the §4.1 step-1 second key +
	// the step-2 record's EnvConfigRef + a step-3 placement constraint). Required.
	EnvConfigRef string
	// ImageID is the resolved content-addressed image (the step-2 record's ImageID +
	// the step-3 image-cache-locality filter + the step-4 VmSpec.image_id). Required.
	ImageID string
	// Auth is the resolved IdP auth (doc 16 §11.2), carried as DATA. NIL is the
	// unauthenticated launch the gate REFUSES fail-closed (no role, no mint).
	Auth *LaunchInput
	// RoleRef is the requested role (doc 18 §6; empty = the recorded default).
	// Resolved + pinned at steps 1–2.
	RoleRef string
	// Floors is the resource floors (D37) the step-3 placement fits and the step-4
	// VmSpec carries. Opaque proto DATA; nil = the host's defaults.
	Floors *hypervisorv1.ResourceFloors
	// RequiredBaselineVersion is the host-baseline artifact version this session is
	// pinned to (doc 14 §11): the >=6.12 host-kernel baseline floor that step-3
	// placement must honor (the §7 filter-2 host-baseline-compatibility constraint), so
	// a session pinned to a new kernel floor never lands on an old host. It is sourced
	// upstream from the resolved env-spec / baseline-pin (the same upstream resolution
	// that produces the floors), carried here as DATA and threaded into the step-3
	// PlacementRequest. EMPTY = no baseline constraint (any reporting host is compatible
	// on this axis — the pre-pinning posture, unchanged behavior).
	RequiredBaselineVersion string
	// EntrypointConfigRef is the D38 entrypoint config the step-8 boot launches per
	// (opaque — the orchestrator stays runtime-ignorant). Required.
	EntrypointConfigRef string
	// AttachRole is the seat class the step-10 attach issues (default WRITER — the
	// launching attach takes the one writer seat, D61). RoleNone defaults to WRITER.
	AttachRole store.AttachRole
	// Posture is the OPTIONAL orchestrator-resolved per-session permission posture
	// (runtimev1.PermissionPosture, doc 13 §2), carried as resolved DATA into the step-4
	// VmSpec (VmSpec.posture) so it reaches the gap-1 EntrypointConfig producer's
	// ProduceInput.Posture. The orchestrator stays runtime-IGNORANT about HOW it was
	// resolved (the POL-1 resolution happens at the RPC boundary, sessionservice.go). The
	// zero value = PERMISSION_POSTURE_UNSPECIFIED = "the orchestrator supplied none" makes
	// the producer fall back to the daemon-pinned EntrypointFacts.Posture (the M0 default-deny
	// LOCKED pin); a CONCRETE value WINS over that fallback. Absent (the frozen no-posture
	// create path), it is the zero value, so the step-4 VmSpec is byte-identical to today.
	Posture runtimev1.PermissionPosture
}

// createState threads the per-create progress through the ten steps so a failure at
// any step knows exactly what host-side state exists to compensate (the rollback's
// from-each-step matrix keys on these). It is a Create-local value (never shared), so
// the coordinator is concurrency-safe.
type createState struct {
	placement   Placement
	hostBound   bool   // step 4 recorded the index binding (the index is BURNED)
	hostID      string // the placed host (for the destroy/attach verbs)
	identityRef string // step 5 minted (rollback signals revocation)
	caRef       string // step 5 minted
	// mintExpiry is the step-5 minted credential / CA EXPIRY (D22/D82, doc 16 §5.4): the
	// wall-clock instant the minted token / interception CA stops being valid, threaded
	// out of MintResult.Expiry. It is the CONSUMER landing of the expiry orch24 added to
	// the controlplane MintReply seam and orch28's producer leg populates. The coordinator
	// carries it on the create-local session state for the ROUTABLE WINDOW + the
	// teardown/re-mint bookkeeping (an expired credential re-mints on resume; the routable
	// gate, doc 16 §5.4). It is ADDITIVE coordinator state — NOT a frozen §5.6 store-record
	// column yet (the future record column is a §4.1/§4.2 seam follow-up; see the step-5
	// note in Create). The ZERO value (mintExpiry.IsZero()) is the not-set case: no TTL to
	// track, so NO teardown is scheduled (a zero expiry never triggers a spurious
	// immediate teardown).
	mintExpiry  time.Time // step 5 minted credential/CA expiry (zero = no TTL to track)
	digestRef   string    // step 6 wrote (rollback flushes)
	overlayPath string    // step 4 cloned (rollback disposes)
	booted      bool      // step 8 launched the domain
	// mintExpiryFired guards the post-READY onMintExpiry fire so the teardown/re-mint
	// sink is registered AT MOST ONCE per create (idempotent fire by construction). It
	// flips true only after the session is durably READY and the sink ran — a rollback
	// before READY leaves it false (the sink never fired for the destroyed session).
	mintExpiryFired bool // post-READY expiry sink fired (once-only guard)
}

// Create runs the doc 15 §4.1 canonical ten-step sequence for one session, honoring
// the frozen precedence (`1 ≺ 2 ≺ 3 ≺ {6,7,8}; 5 ≺ 6; 5 ≺ 7-injection; 7 ≺ 8;
// {3,6} ≺ 9 ≺ 10`) and the structural gates (D56/D72/D73/D17/D29). On a failure at
// any step it drives the COMPENSATING rollback (the §4.2 destroy path from that step)
// and returns a *CreateError naming the step, the underlying error, and whether the
// rollback completed cleanly. Create is RETRYABLE by session UUID — every host verb
// is idempotent on it, and a step-4 index, once recorded, is BURNED (the store burns
// it on AppendIndexEpoch), never recycled on retry.
//
// The sequence runs the steps-1–2 + step-5 cluster THROUGH the existing in-process
// spine (RunCreateSpine) so the launch-gate-before-mint ordering + the single-store
// coherence assertion + the role pin persistence are reused verbatim (one master
// order, doc 15 §4.1) — Create wraps that cluster with the host-side steps 3–4, 6–10
// this unit promotes.
func (c *SessionCreator) Create(ctx context.Context, req CreateRequest) (store.Session, error) {
	if req.SessionUUID == "" {
		return store.Session{}, &CreateError{Step: StepNone, Err: errors.New("empty session UUID")}
	}
	st := &createState{}

	// (1) TWO-KEY structural refusal (D56) — BEFORE any record exists. A refusal here
	// needs NO rollback (nothing host-side, no record): nothing to compensate.
	if _, err := c.seams.TwoKey.Check(ctx, TwoKeyRequest{RepoID: req.RepoID, EnvConfigRef: req.EnvConfigRef}); err != nil {
		return store.Session{}, &CreateError{SessionUUID: req.SessionUUID, Step: StepTwoKey, Err: err, RolledBack: false}
	}

	// (2) SESSION RECORD created (store). The desired-state row (PENDING) with the
	// env-config + image refs attached. No host binding yet — the (index, tap, ip)
	// binding lands at step 4. CreatePreBindingSession (sessioncreate_queries.go)
	// writes it under the per-session UNBOUND sentinel host so the step-2 burn cannot
	// collide with another unbound record (the §4.1 step-2-vs-step-4 ordering, D66);
	// step 4's AppendIndexEpoch advances Ref off the sentinel onto the real host. A
	// failure here finalizes nothing host-side; the record either was not written or
	// is finalized with an audit event (the §4.1 1–3 note).
	rec, err := store.CreatePreBindingSession(ctx, c.seams.Store, store.Session{
		Ref:          store.SessionRef{SessionUUID: req.SessionUUID},
		EnvConfigRef: req.EnvConfigRef,
		ImageID:      req.ImageID,
		State:        store.SessionPending,
	})
	if err != nil {
		return store.Session{}, &CreateError{SessionUUID: req.SessionUUID, Step: StepRecord, Err: err, RolledBack: c.finalizeRecordOnly(ctx, req.SessionUUID)}
	}
	// RETRY-VS-RESURRECTION GUARD (D66). The WHERE decision: the guard lives HERE, in
	// the create coordinator at step 2, because CreateSession is idempotent on the
	// session UUID (memory.go / postgres.go return the EXISTING row verbatim) and the
	// store cannot be the guard — it validates state VOCABULARY, not §3 TRANSITIONS, by
	// design (a real DESTROYED→CREATING re-open is a legal store write the migration/
	// re-placement paths use). So a same-store retry by UUID after a step-1..3 failure
	// gets back the row the previous attempt FINALIZED (DESTROYED), and the very next
	// step (placement → UpdateSession(State=CREATING)) would silently RESURRECT that
	// terminal, retained (D66) record. The create coordinator is the one actor that
	// knows "this is a fresh create, not an explicit re-open", so it refuses
	// fail-closed: a retry of a finalized session must mint a FRESH session UUID (the
	// continuity key moves; re-opening a terminal record is forbidden on the create
	// path). A still-live in-flight record (any non-terminal state) is the legitimate
	// idempotent-retry case and proceeds. Nothing host-side exists on a finalized row
	// (it was already torn down), so the refusal needs no rollback.
	if rec.State.IsTerminal() {
		return store.Session{}, &CreateError{SessionUUID: req.SessionUUID, Step: StepRecord, Err: ErrSessionFinalized, RolledBack: false}
	}

	// (1–2 + 5 CLUSTER) — run the in-process spine: authorize launch (doc 16 §11.2)
	// BEFORE the mint, resolve + PIN role_ref, then assemble the step-5 mint claims.
	// The spine's single-store coherence assertion proves the gate linker, the
	// launching_user resolver, and the pin writer share one store. A spine failure is
	// attributed to its step: a launch/role refusal is step 1–2 (StepTwoKey covers the
	// gate-as-launch-refusal precedence position; the role refusal is its own step but
	// the spine fuses 1–2), surfaced before any host-side work. Note: the spine runs
	// AFTER the record exists (step 2) so the gate's session→principal link lands on a
	// real row, exactly as the frozen precedence requires (1 ≺ 2, then the gate at 1's
	// authorization runs against the step-2 row).
	spine, err := RunCreateSpine(ctx, c.seams.Gate, c.seams.RoleResolver, c.seams.MintResolver, c.seams.PinWriter, CreateSpineRequest{
		SessionUUID: req.SessionUUID,
		Auth:        req.Auth,
		RoleRef:     req.RoleRef,
		// DIGEST-PUBLISH (doc 16 §6.1, D73/D84) — thread the coordinator's optional
		// digest-publish seam into the spine so RunCreateSpine drives the mint-before-attach
		// push BETWEEN cred-mint and mark-routable and gates routability on the host ack.
		// FLAG-GATED (DS_ORCH_DIGEST_PUBLISH_WIRE): OFF (default) the spine SKIPS the step and
		// this is unused (byte-identical, D50); ARMED, a nil publisher / a publish error / an
		// uncommitted ack fails the create CLOSED here (surfaced below at the spine-error site),
		// so the session is never marked routable when its digests did not land.
		DigestPublisher: c.seams.DigestPublisher,
	}, c.logger)
	if err != nil {
		// A launch/role refusal (or the coherence assertion / a store fault) — the
		// record exists but nothing host-side does. Compensate by finalizing the record
		// with an audit event (the §4.1 1–3 rollback note). Classify the failure step:
		// a role refusal is the role stage (steps 1–2); an ARMED digest-publish
		// fail-closed (nil publisher / publish error / uncommitted ack — the §6.1
		// mint-before-attach gate the spine runs after the mint assembly) is attributed to
		// the DIGEST step so a caller (and the CreateSession RPC's mapCreateError) sees the
		// mint-before-attach gate as the failure site, not a two-key refusal; everything
		// else (launch refusal, coherence, store fault) is the launch/two-key position.
		step := StepTwoKey
		switch {
		case ErrIsDigestNotRoutable(err):
			step = StepDigest // the §6.1 digest-publish routable gate (D73/D84)
		case ErrIsRoleRefused(err):
			step = StepRecord // the steps-1–2 role stage sits at the record boundary
		}
		return store.Session{}, &CreateError{SessionUUID: req.SessionUUID, Step: step, Err: err, RolledBack: c.finalizeRecordOnly(ctx, req.SessionUUID)}
	}

	// (3) POLICY-FRESH PLACEMENT (D72). The scheduler picks a host within the
	// staleness budget; ErrPolicyStale when none is placeable. State → CREATING. A
	// failure here still has no host-side state — finalize the record (the §4.1 1–3
	// note: nothing host-side exists).
	placement, err := c.seams.Placer.Place(ctx, req.SessionUUID, PlacementRequest{
		ImageID:                 req.ImageID,
		EnvConfigRef:            req.EnvConfigRef,
		Floors:                  req.Floors,
		RequiredBaselineVersion: req.RequiredBaselineVersion,
	})
	if err != nil {
		return store.Session{}, &CreateError{SessionUUID: req.SessionUUID, Step: StepPlacement, Err: err, RolledBack: c.finalizeRecordOnly(ctx, req.SessionUUID)}
	}
	st.placement = placement
	st.hostID = placement.HostID
	creating := store.SessionCreating
	appliedSeq := placement.AppliedSeq
	if _, err := c.seams.Store.UpdateSession(ctx, req.SessionUUID, store.SessionUpdate{
		State:            &creating,
		PolicyAppliedSeq: &appliedSeq,
	}); err != nil {
		return store.Session{}, &CreateError{SessionUUID: req.SessionUUID, Step: StepPlacement, Err: err, RolledBack: c.finalizeRecordOnly(ctx, req.SessionUUID)}
	}

	// (4) HOST ALLOCATION + VM DEFINE. CloneFromImage on the placed host: allocate the
	// never-recycled index, derive dstap-<idx> + the guest IP, clone the overlay. The
	// binding is RECORDED via AppendIndexEpoch — which BURNS the index. A failure
	// AFTER the binding is recorded leaves the index burned (never recycled); the
	// rollback runs flush_session(legs=all) + NFT-6 for the partial allocation (the
	// §4.1 step-4 note) via the host destroyer.
	spec := &hypervisorv1.VmSpec{
		SessionUuid:         req.SessionUUID,
		ImageId:             req.ImageID,
		Floors:              req.Floors,
		EntrypointConfigRef: req.EntrypointConfigRef,
		// Carry the orchestrator-resolved per-session posture (additive VmSpec.posture) so
		// CloneFromImage threads it into the libvirt create path's CreateRequest.Posture ->
		// gap-1 ProduceInput.Posture. UNSPECIFIED (the no-posture create) is the zero value,
		// keeping this VmSpec byte-identical to the pre-change path (M0 default-deny fallback).
		Posture: req.Posture,
	}
	alloc, err := c.seams.HostAllocator.AllocateAndDefine(ctx, placement.HostID, spec)
	if err != nil {
		// The host agent faulted before (or during) the binding. Nothing was recorded
		// here, but the host MAY hold a partial allocation — drive the compensating
		// destroy (flush_session + NFT-6) from step 4. The index is whatever the host
		// allocated; if it never reached our record it is the host's to burn on its
		// monotonic counter (never recycled there either, §5.6).
		return store.Session{}, c.rollback(ctx, req.SessionUUID, StepHostAlloc, err, st)
	}
	st.overlayPath = alloc.OverlayPath
	// Record the binding — this BURNS the index (AppendIndexEpoch). From here the
	// index is never recycled, even if a later step fails.
	if _, err := c.seams.Store.AppendIndexEpoch(ctx, req.SessionUUID, store.IndexEpoch{
		HostID:           placement.HostID,
		HostSessionIndex: alloc.HostSessionIndex,
		TapName:          alloc.TapName,
		GuestIP:          alloc.GuestIP,
		GuestIPFamily:    alloc.GuestIPFamily,
		// PERSIST the per-session CoW overlay path (D29) on the durable epoch so the
		// §4.2 teardown can dispose the REAL overlay after a control-plane restart —
		// the in-process st.overlayPath above does not survive a restart, so a destroy
		// that resolves host-side state from the record (destroyRequestFromRecord) must
		// read the overlay from here, not pass OverlayPath="" and leak the overlay.
		OverlayPath: alloc.OverlayPath,
	}); err != nil {
		// The binding could not be recorded (e.g. the index was already burned — a
		// retry that re-allocated a recycled index, which the store REFUSES, ErrInvalid).
		// Compensate the host-side allocation.
		return store.Session{}, c.rollback(ctx, req.SessionUUID, StepHostAlloc, err, st)
	}
	st.hostBound = true

	// (5) IDENTITY + INTERCEPTION-CA MINT (D82). The spine already ASSEMBLED the
	// claims (gate-sourced launching_user + pinned role_ref); the Minter consumes them
	// and returns the identity + CA refs. A mint fault rolls back from step 5 (signal
	// identity/CA revocation — but nothing minted yet, so the revoke is a no-op; the
	// host-side step-4 state still unwinds).
	mint, err := c.seams.Minter.Mint(ctx, spine.MintClaims.Claims, spine.MintClaims.RoleRef)
	if err != nil {
		return store.Session{}, c.rollback(ctx, req.SessionUUID, StepMint, err, st)
	}
	st.identityRef = mint.IdentityRef
	st.caRef = mint.CARef
	// CONSUMER LEG (D22/D82, doc 16 §5.4). Thread the minted credential / CA EXPIRY the
	// Minter seam surfaced (MintResult.Expiry — orch24 added it to the controlplane
	// MintReply seam, orch28's producer leg populates it from the proto) onto the
	// create-local session state, so a session whose minted credential expires is tracked
	// for the ROUTABLE WINDOW + the teardown/re-mint (an expired credential re-mints on
	// resume; the routable gate, doc 16 §5.4). A ZERO/absent expiry (mint.Expiry.IsZero(),
	// the not-set case a bare MintClient or a TTL-less proto produces) is carried as the
	// zero value and registers NO teardown — no spurious teardown for a session with no
	// minted-credential TTL.
	//
	// IDEMPOTENCY vs ROLLBACK (D22/D82, doc 16 §5.4). The expiry is CARRIED on the state
	// here at step 5, but the teardown/re-mint sink (onMintExpiry) is FIRED only AFTER
	// the session is DURABLY READY (the step-9 routable transition below), past the
	// create rollback window. So a create that rolls back AFTER step 5 (mint done) — the
	// digest/inject/boot/routable/attach faults that drive c.rollback — destroys the
	// session WITHOUT ever firing the sink: no spurious teardown/re-mint for a session
	// that no longer exists (the §4.2 step-5 rollback already revoked the identity/CA).
	st.mintExpiry = mint.Expiry
	// DURABLE §5.6 RECORD HORIZON (§4.1/§4.2, doc 16 §5.4). The minted-credential expiry
	// is now PERSISTED to the §5.6 session record (the MintExpiry column, migration 0010)
	// alongside IdentityRef/CARef — the store-seam unfreeze closed this leg. So the durable
	// routable-window / teardown horizon survives an orchestrator restart: the §4.2
	// teardown/resume re-mint path reads the PERSISTED horizon (GetSession(...).MintExpiry)
	// rather than reconstructing it from create-local state, and an expired credential
	// re-mints on resume (doc 16 §5.4). The in-package st.mintExpiry + the onMintExpiry
	// sink remain the IN-FLIGHT routable-window/teardown seam point (fired once, post-READY);
	// the record column is the DURABLE backing the sink and the resume path read. A ZERO
	// mint.Expiry (the not-set case) persists as the NULL not-set posture — no spurious
	// epoch horizon, no teardown scheduled.
	if _, err := c.seams.Store.UpdateSession(ctx, req.SessionUUID, store.SessionUpdate{
		IdentityRef: &mint.IdentityRef,
		CARef:       &mint.CARef,
		MintExpiry:  &mint.Expiry,
	}); err != nil {
		return store.Session{}, c.rollback(ctx, req.SessionUUID, StepMint, err, st)
	}

	// (6) SESSION-SCOPED DIGEST WRITE + ACK GATE (D73). Identity writes the digests to
	// the placed host; the host acks. NOT routable until the ack lands (the step-9
	// gate re-validates). 5 ≺ 6: the mint (step 5) ran first, so the CA ref the digest
	// write keys on exists. A write fault rolls back from step 6 (flush digests +
	// identity/CA revocation).
	digest, err := c.seams.DigestWriter.WriteAndAck(ctx, req.SessionUUID, placement.HostID, mint.CARef)
	if err != nil {
		return store.Session{}, c.rollback(ctx, req.SessionUUID, StepDigest, err, st)
	}
	st.digestRef = digest.DigestRef
	if _, err := c.seams.Store.UpdateSession(ctx, req.SessionUUID, store.SessionUpdate{
		DigestRef:   &digest.DigestRef,
		DigestAcked: &digest.Acked,
	}); err != nil {
		return store.Session{}, c.rollback(ctx, req.SessionUUID, StepDigest, err, st)
	}

	// (7) OVERLAY CLONE + FAIL-CLOSED CA INJECTION (D17/D29). Inject the per-session CA
	// into the overlay's trust store BEFORE boot. 5 ≺ 7-injection: the CA was minted at
	// step 5. Injection FAILURE fails the create — roll back from step 7 (destroy the
	// domain, dispose the overlay, unwind step 4 + revoke identity/CA).
	if err := c.seams.Injector.InjectCA(ctx, req.SessionUUID, alloc.OverlayPath, mint.CARef); err != nil {
		return store.Session{}, c.rollback(ctx, req.SessionUUID, StepInject, fmt.Errorf("%w: %v", ErrCAInjection, err), st)
	}

	// (8) BOOT + ENTRYPOINT (D38). 7 ≺ 8: the CA was injected at step 7. A boot fault
	// rolls back from step 8 (destroy the domain, dispose the overlay, unwind step 4).
	if err := c.seams.Booter.Boot(ctx, req.SessionUUID, req.EntrypointConfigRef); err != nil {
		return store.Session{}, c.rollback(ctx, req.SessionUUID, StepBoot, err, st)
	}
	st.booted = true

	// (9) ROUTABLE GATE (structural): digest ack (step 6) AND re-checked policy
	// freshness (step 3) both hold; only now can the first egress byte exist. State →
	// READY. {3,6} ≺ 9. The re-check reads the CURRENT record (the digest ack we just
	// wrote) and re-validates the placement freshness against the staleness budget — a
	// host that went stale after placement is caught HERE (ErrPolicyStale), not waved
	// through to READY.
	if !digest.Acked {
		// The digest was written but never acked — NOT routable (D73). Roll back from
		// step 9 (the create cannot reach READY).
		return store.Session{}, c.rollback(ctx, req.SessionUUID, StepRoutable, ErrDigestNotAcked, st)
	}
	if err := c.recheckFreshness(ctx, req.SessionUUID, placement); err != nil {
		return store.Session{}, c.rollback(ctx, req.SessionUUID, StepRoutable, err, st)
	}
	ready := store.SessionReady
	if _, err := c.seams.Store.UpdateSession(ctx, req.SessionUUID, store.SessionUpdate{
		State:   &ready,
		ReadyAt: store.SetTime(c.now()),
	}); err != nil {
		return store.Session{}, c.rollback(ctx, req.SessionUUID, StepRoutable, err, st)
	}

	// (10) ATTACH (D79). 9 ≺ 10: the session is READY. Issue the attach handle (the
	// launching attach takes the one WRITER seat, D61); state → ATTACHED. A failure
	// here leaves a READY session — the rollback from step 10 still drives the full
	// teardown (the create did not complete; the reconciler would otherwise re-drive,
	// but a create-time attach failure compensates here).
	role := req.AttachRole
	if role == store.RoleNone {
		role = store.RoleWriter
	}
	attach, err := c.seams.AttachIssuer.IssueAttach(ctx, req.SessionUUID, placement.HostID, role)
	if err != nil {
		return store.Session{}, c.rollback(ctx, req.SessionUUID, StepAttach, err, st)
	}
	attached := store.SessionAttached
	final, err := c.seams.Store.UpdateSession(ctx, req.SessionUUID, store.SessionUpdate{
		State:       &attached,
		AttachState: &attach.Role,
		WriterRole:  &attach.Role,
		AttachedAt:  store.SetTime(c.now()),
	})
	if err != nil {
		return store.Session{}, c.rollback(ctx, req.SessionUUID, StepAttach, err, st)
	}
	// MINTED-CREDENTIAL EXPIRY TEARDOWN/RE-MINT SINK (D22/D82, doc 16 §5.4). The create
	// has now COMPLETED — the session is durably READY (step 9) and ATTACHED (step 10),
	// past EVERY create rollback point — so the routable-window / teardown-re-mint
	// bookkeeping can safely register the minted-credential TTL the Minter surfaced
	// (st.mintExpiry, threaded at step 5). Firing HERE (the post-commit horizon, not at
	// step 5) is the IDEMPOTENCY contract: a create that rolled back AFTER step 5 (the
	// digest/inject/boot/routable/attach faults that drive c.rollback) destroyed the
	// session WITHOUT reaching this point, so NO spurious teardown is registered for a
	// session that no longer exists (the §4.2 step-5 rollback already revoked the
	// identity/CA). Only a NON-ZERO expiry registers a TTL (the zero case is the no-track
	// path); the once-only state guard makes the fire single-shot per create. An unset
	// wiring fires the safe no-op sink — backwards compatible.
	c.fireMintExpiry(req.SessionUUID, st)
	return final, nil
}

// recheckFreshness is the §4.1 step-9 D72 re-check: it re-validates that the placed
// host's freshness still holds within the staleness budget before the session is
// routable. It fail-closes on TWO independent staleness signals:
//
//   - the RECORDED applied_seq (re-read from the session record): this catches a host
//     the reconciler has since MARKED stale — the reconciler writes the record, so a
//     regressed recorded seq is the "marked-stale" signal; and
//   - the host's CURRENT applied_seq (the LIVE probe, Placer.CurrentFreshness): this
//     catches a host that fell behind in the placement→step-9 window with NO record
//     write — the residual D72 window the recorded-only re-check misses (a host that
//     silently lags but was never re-marked on the record). The live value is read
//     from the host's current heartbeat through the Placer seam.
//
// Either signal exceeding the staleness budget is ErrPolicyStale (the host is NOT
// routable). A live probe that cannot establish the host's current freshness
// (ErrFreshnessUnknown — no live-freshness seam wired, or the placed host absent from
// the live feed) is NOT itself a staleness verdict: there is no live signal to judge,
// so the gate DEGRADES to the recorded re-check (a) alone — the pre-probe behavior —
// and the create proceeds on the recorded freshness that (a) just vouched for. This is
// the backwards-compatible degrade the inline (b) branch, the ErrFreshnessUnknown
// sentinel doc, the README residual-windows block, and the TestCreate degrade test all
// pin: an unprobeable host is NOT refused here, it falls back to the recorded re-check
// (D72). The degrade is emitted as a log/metric (see the (b) branch) so an unprobeable
// host admitted via the recorded re-check is observable in production, never silent.
// Only a live probe that DOES answer with a current seq beyond the budget fail-closes
// as ErrPolicyStale. drift = placement.AppliedSeq - value; a positive drift beyond the
// budget means the host fell behind.
func (c *SessionCreator) recheckFreshness(ctx context.Context, sessionUUID string, placement Placement) error {
	// (a) RECORDED re-check — the reconciler-marked-stale signal.
	cur, err := c.seams.Store.GetSession(ctx, sessionUUID)
	if err != nil {
		return err
	}
	if drift := placement.AppliedSeq - cur.PolicyAppliedSeq; drift > c.stalenessBudget {
		return fmt.Errorf("%w: host %s recorded applied_seq %d is %d behind placement seq %d (budget %d)",
			ErrPolicyStale, placement.HostID, cur.PolicyAppliedSeq, drift, placement.AppliedSeq, c.stalenessBudget)
	}

	// (b) LIVE re-check — the placement→step-9 fell-behind signal the record misses.
	// Re-poll the host's CURRENT applied_seq through the Placer seam and re-validate it
	// against the placement, closing the residual D72 window. ErrFreshnessUnknown means
	// the live probe is UNAVAILABLE (the Placer has no live-freshness seam wired) — the
	// gate then DEGRADES to the recorded re-check (a) alone, which is exactly the
	// pre-probe behavior, so a wiring that does not (yet) supply a live probe is
	// unchanged (backwards compatible). A live probe that DOES answer with a fell-behind
	// current seq is the new fail-closed catch; any other probe error surfaces.
	curSeq, err := c.seams.Placer.CurrentFreshness(ctx, placement.HostID)
	if err != nil {
		if errors.Is(err, ErrFreshnessUnknown) {
			// Live probe unavailable — degrade to the recorded re-check, which already
			// passed above. No live window-closing is possible, but the gate is not
			// newly stricter than before the probe existed. EMIT the degrade (D72): an
			// unprobeable host admitted via the recorded re-check alone is a residual-
			// window admission an operator must be able to see, so it is never silent —
			// the log AND the COUNTER make the degrade observable in production (the
			// recorded re-check still vouched for this host; this records that the LIVE
			// catch did not run for it). The COUNTER is the aggregatable companion to the
			// WARN: a single line is not graphable/alertable, but the per-degrade
			// increment makes the degrade RATE queryable (the residual-D72-window
			// admission rate) on the standard expvar surface. We bump BOTH the flat
			// fleet total (the unbroken pre-existing observable) AND the per-host key
			// (placement.HostID) of the by-host map, so an operator can see WHICH host
			// degraded — one hot key is a single host falling behind, many keys climbing
			// together is a systemic live-freshness outage (D72).
			// The per-host bump rides the cardinality guard (recordDegradeByHost): the
			// map is bounded to the most-recently-degraded active set, with overflow
			// folded into the "__other__" bucket so a churny/buggy fleet cannot grow
			// /debug/vars without bound (D72). The flat total above counts every degrade
			// unconditionally; the guard never perturbs the unbroken total observable.
			step9FreshnessDegradeTotal.Add(1)
			step9DegradeGuard.recordDegradeByHost(placement.HostID)
			c.logger.Warn("sessions: step-9 freshness live probe unavailable — degrading to the recorded re-check (D72)",
				slog.String("session", sessionUUID),
				slog.String("host", placement.HostID),
				slog.Int64("recorded_applied_seq", placement.AppliedSeq),
				slog.Any("cause", err))
			return nil
		}
		return err
	}
	if drift := placement.AppliedSeq - curSeq; drift > c.stalenessBudget {
		return fmt.Errorf("%w: host %s CURRENT applied_seq %d is %d behind placement seq %d (budget %d — fell behind after placement)",
			ErrPolicyStale, placement.HostID, curSeq, drift, placement.AppliedSeq, c.stalenessBudget)
	}
	return nil
}

// finalizeRecordOnly is the §4.1 1–3 rollback (a failure at steps 1–3 where nothing
// host-side exists): finalize the session record with the teardown timestamps and a
// DESTROYED state — the record is RETAINED (D66), never deleted, but is moved out of
// the create path so a retry by UUID is not blocked by a half-created row. It returns
// true when the finalize completed cleanly (the rollback satisfied), false on a
// finalize fault (recorded on the CreateError; the reconciler is the backstop). A
// step-2 CreateSession that never wrote the row has nothing to finalize — GetSession
// would miss — so a finalize miss is treated as clean (nothing to roll back).
func (c *SessionCreator) finalizeRecordOnly(ctx context.Context, sessionUUID string) bool {
	destroyed := store.SessionDestroyed
	if _, err := c.seams.Store.UpdateSession(ctx, sessionUUID, store.SessionUpdate{
		State:       &destroyed,
		DestroyedAt: store.SetTime(c.now()),
	}); err != nil {
		// A missing record (the step-2 write never landed) is a clean no-op rollback —
		// there is nothing host-side and no row to finalize.
		if errors.Is(err, store.ErrNotFound) {
			return true
		}
		c.logger.Warn("sessions: create rollback: finalize record failed",
			slog.String("session", sessionUUID), slog.Any("err", err))
		return false
	}
	return true
}

// rollback drives the COMPENSATING §4.2 destroy path from the step that failed (doc
// 15 §4.1's step-specific rollback notes). It is the from-each-step matrix's engine:
//
//   - step 4 (host alloc): flush_session(legs=all) + NFT-6 for the partial allocation
//     via the HostDestroyer; the burned index is NOT recycled (the store burned it on
//     AppendIndexEpoch — or, if the binding never recorded, the host's monotonic
//     counter burned it). No identity/CA yet.
//   - steps 5–6 (mint / digest): signal identity/CA revocation (IdentityRevoker) +
//     flush any written digests (folded into the host destroy), THEN unwind the
//     host-side step-4 state.
//   - steps 7–8 (inject / boot): destroy the domain + dispose the overlay (HostDestroyer)
//     THEN unwind step 4 + revoke identity/CA.
//   - steps 9–10 (routable / attach): the full teardown — the session reached boot,
//     so destroy the domain, dispose the overlay, revoke identity/CA, flush digests.
//
// Every path satisfies the doc 06 (b) clean-teardown checklist (no orphaned VM, no
// leaked NFTables rules/allow-set entries, no dangling CoW overlay, no stranded proxy
// session, no leftover minted identity) — the HostDestroyer's Destroy verb carries
// the NFT-6 order and overlay disposal; the IdentityRevoker carries the identity/CA
// revocation. The record is finalized DESTROYED + retained (D66). Create is RETRYABLE
// by UUID: a clean rollback leaves no host-side state, and the burned index is never
// recycled. Returns a *CreateError stamping the step, the underlying error, and
// whether the compensation completed cleanly.
func (c *SessionCreator) rollback(ctx context.Context, sessionUUID string, step CreateStep, cause error, st *createState) error {
	ce := &CreateError{SessionUUID: sessionUUID, Step: step, Err: cause}
	var rbErrs []error

	// (a) IDENTITY/CA REVOCATION — when an identity/CA was minted (step 5+). The §4.2
	// step-5 teardown assertion: "no leftover minted identity". Idempotent; a nil
	// revoker on a wiring that reached step 5 is itself a rollback gap, surfaced.
	if st.identityRef != "" || st.caRef != "" {
		if c.seams.IdentityRevoker == nil {
			rbErrs = append(rbErrs, errors.New("no IdentityRevoker wired (cannot revoke minted identity/CA — reconciler backstop)"))
		} else if err := c.seams.IdentityRevoker.Revoke(ctx, sessionUUID, st.identityRef, st.caRef); err != nil {
			rbErrs = append(rbErrs, fmt.Errorf("identity/CA revoke: %w", err))
		}
	}

	// (b) HOST-SIDE DESTROY — when anything host-side exists (step 4+: the binding was
	// recorded, the overlay cloned, and/or the domain booted). The Destroy verb is the
	// §4.2 ordering (domain destroy → flush_session(legs=all) + NFT-6 → overlay
	// disposal), idempotent on session_uuid — it satisfies the clean-teardown checklist
	// whether the domain booted (step 8) or only the overlay was cloned (step 4). We
	// drive it from step 4 onward (the host has SOMETHING to tear down from the
	// allocation onward).
	if step >= StepHostAlloc && st.hostID != "" {
		if c.seams.HostDestroyer == nil {
			rbErrs = append(rbErrs, errors.New("no HostDestroyer wired (cannot flush host-side allocation — reconciler backstop)"))
		} else if err := c.seams.HostDestroyer.Destroy(ctx, st.hostID, sessionUUID); err != nil {
			rbErrs = append(rbErrs, fmt.Errorf("host destroy: %w", err))
		}
	}

	// (c) FINALIZE the record DESTROYED + retained (D66). Even a host-side rollback
	// finalizes the record so the create path is clear and the row is the audit trail.
	// A missing record is a clean no-op (nothing to finalize).
	if !c.finalizeRecordOnly(ctx, sessionUUID) {
		rbErrs = append(rbErrs, errors.New("finalize record failed"))
	}

	if len(rbErrs) > 0 {
		ce.RolledBack = false
		ce.RollbackErr = errors.Join(rbErrs...)
		c.logger.Error("sessions: create rollback did not complete cleanly",
			slog.String("session", sessionUUID), slog.String("step", step.String()), slog.Any("rollback_err", ce.RollbackErr))
		return ce
	}
	ce.RolledBack = true
	c.logger.Info("sessions: create rolled back cleanly (clean-teardown checklist satisfied)",
		slog.String("session", sessionUUID), slog.String("step", step.String()), slog.Any("cause", cause))
	return ce
}

// now is the coordinator's clock seam (overridable in tests via the unexported
// clock field; nil → time.Now). It stamps the record timestamps deterministically
// under test.
func (c *SessionCreator) now() time.Time {
	if c.clock != nil {
		return c.clock()
	}
	return time.Now()
}

// fireMintExpiry hands the minted-credential expiry horizon to the teardown/re-mint
// sink (onMintExpiry, D22/D82, doc 16 §5.4) for a session whose create has COMPLETED
// (durably READY + ATTACHED — past every rollback point). It is the single fire point;
// the Create flow calls it ONCE, only after the final ATTACHED transition lands, so a
// minted-then-rolled-back session (a post-step-5 rollback that destroyed the session)
// NEVER reaches it — no spurious teardown for a session that no longer exists.
//
// It is a no-op in two cases that need NO teardown: a ZERO/absent expiry
// (st.mintExpiry.IsZero() — the not-set case a bare MintClient or a TTL-less proto
// produces, so there is no TTL to track), and an already-fired state (st.mintExpiryFired
// — the once-only guard, so even if the fire point were reached twice the sink runs at
// most once per create). The onMintExpiry func is always non-nil after NewSessionCreator
// (the safe no-op fills the unset case), so no nil-check is needed.
func (c *SessionCreator) fireMintExpiry(sessionUUID string, st *createState) {
	if st.mintExpiry.IsZero() || st.mintExpiryFired {
		return
	}
	st.mintExpiryFired = true
	c.onMintExpiry(sessionUUID, st.mintExpiry)
}
