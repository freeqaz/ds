// Package createtiming decomposes every session create into the D81 §8 segments
// and records their trends — INSTRUMENT FIRST, GATE LATER. It is constructible
// and PURE over synthetic segment fixtures (D50): no live VM / host-agent /
// podman / KVM, NOT wired into main.go, NO proto edit, NO Repository-interface
// method, NO shared-store-file edit.
//
// The §8 segment decomposition (doc 15 §8, §11 (b) row) — every create is timed
// per segment so a venue problem and a stack regression stay distinguishable:
//
//   - placement decision (the §4.1 step-3 scheduler placement)
//   - overlay clone (step 7 CloneFromImage qcow2 overlay)
//   - tap/NFT programming (step 4 tap-create + per-session NFT objects)
//   - identity/CA/digest sequence (steps 5–6 mint + digest write/ack)
//   - boot-to-entrypoint (step 8 boot + frozen entrypoint contract)
//   - policy-ready (step 9 routable freshness gate)
//   - routable (step 9 first-egress-byte gate)
//   - attach handshake (step 10 attach handle issue)
//
// Client RTT is measured SEPARATELY and EXCLUDED from any trigger evaluation
// (doc 15 §8 first bullet): RTT is the network venue between client and control
// plane, NOT the create stack — folding it into the create budget would conflate
// a venue problem with a stack regression. ServerSpan() (the trigger-eligible
// total) sums only the eight stack segments; RTT is carried on the record for
// observability but is never in the trigger-evaluation sum. This separation is
// the load-bearing invariant the suite pins (TriggerSpan excludes RTT).
//
// INSTRUMENT-FIRST-GATE-LATER fence (D81, doc 15 §8 second bullet / §11 (b)):
// there is NO CI gate, NO release-blocker, and NO D32 rented-metal trigger
// before M2. doc 06 (b)'s "regression here is a release blocker" ARMS only when
// the product budget is set from dogfood data at the warm-image milestone (M2);
// until then this package asserts the decomposition EXISTS and records trends.
// This package therefore exposes NO Pass/Fail/Gate verdict and NO threshold
// comparison that could block a release; it offers only EXISTENCE assertion
// (MissingSegments) and trend recording (Recorder / Trend). The non-binding
// banded strawmen (p95 ≤ 30 s base-image at M0/M1; ≤ 10 s warm-image from M2)
// are planning aids, never assertions, and are not encoded as a gate here.
//
// The D30 re-evaluation seam (Cloud Hypervisor at M3) stays live because the
// §5.1 driver contract carries no QEMU/libvirt-specific fields; this package
// names segments by their §8 role, not by substrate, so a faster-boot substrate
// is a driver swap, not a timing-contract event.
//
// Governing decisions: D81 (create→attach budget, instrument first / gate
// later), D50 (synthetic fixtures only), D32 (rented-metal fallback trigger,
// deferred to M2), D30 (hypervisor re-evaluation seam). Primary sources:
// docs/15-orchestrator-design.md §8 (the segment decomposition + RTT exclusion +
// no-gate-now fence), §11 (b) ((b)-row measurement-from-M0 / gate-from-M2),
// §4.1 (the ten-step create the segments map onto).
package createtiming
