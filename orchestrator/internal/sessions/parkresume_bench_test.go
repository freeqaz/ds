// SPDX-License-Identifier: Apache-2.0

package sessions

import (
	"context"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// Bench the SYNCHRONOUS resume-boundary re-mint against the doc 16 §8.2 / doc 15 §4.3
// resume-commit budget.
//
// THE PATH BEING MEASURED. ParkResumeDriver.Resume (parkresume.go) inserts a SYNCHRONOUS
// d.seams.Minter.Mint call BEFORE the host Resume verb on the in-place resume path when
// the PERSISTED MintExpiry horizon has already PASSED (doc 16 §5.4 — an expired credential
// re-mints on resume; a still-future/zero horizon resumes with NO Minter call). That
// inserted re-mint adds latency on the resume boundary, and doc 16 §8.2 + doc 15 §4.3
// track a socket-hold / resume-commit window budget against which it must fit:
//
//   - doc 16 §8.2: notification ≤ 5 s + human decision ≤ 40 s + approval→enforced through
//     the D72 two-phase barrier ≤ 5 s (the doc 15 §4.3 target — doc 15 owns that number);
//     10 s is the OUTER CEILING the window budget tolerates.
//   - doc 15 §4.3: the resume-commit / approval→enforced segment target is ≤ 5 s.
//
// The re-mint sits inside that approval→enforced resume-commit segment, so the budget this
// bench asserts against is the ≤ 5 s commit segment (with the 10 s outer ceiling as the
// hard backstop). This added latency is currently UNMEASURED on a live rig (no live runs
// this wave, D50/D81 — instrument-first, the live gate stays OFF by default).
//
// WHAT THIS FILE SHIPS.
//   - BenchmarkParkResume_Resume_RemintBoundary drives ParkResumeDriver.Resume against an
//     expired-horizon SUSPENDED session through the SAME pr-prefixed synthetic seams the
//     parkresume tests use (NO live claude / cia / podman, D50). It reports two ARMS so the
//     re-mint delta is isolated: WITH the re-mint (an expired horizon → the Minter is hit)
//     vs WITHOUT (a future horizon → no Minter call), each emitting p50/p99 via
//     b.ReportMetric.
//   - The Minter's per-Mint cost is PARAMETERIZABLE (benchRemintMinter.cost). Off the live
//     rig the cost is ZERO, so the offline bench is cheap and the file passes `go test`.
//     Behind DS_ORCH_LIVE=1 the live-rig assertion variant
//     (TestParkResumeRemintBudget_Live) drives the same path with a REALISTIC mint cost and
//     FAILS if the re-mint delta pushes the resume-commit past the §8.2/§4.3 budget; off the
//     live rig it SKIPs cleanly.
//
// It builds on the pr-prefixed synthetic seams in parkresume_test.go / the Expiry-bearing
// minter pattern in parkresume_mintexpiry_test.go (same package). Only the cost-bearing
// minter + the per-op timing harness are new here.

// --- the parameterizable-cost minter (the only new seam this bench needs) ---

// benchRemintMinter is an Expiry-bearing Minter whose Mint imposes a CONFIGURABLE wall-clock
// cost — the knob that lets the live arm model a realistic mint round-trip while the offline
// bench runs at zero cost. It surfaces a fresh (future) MintResult.Expiry so the re-mint
// advances the horizon exactly as the live path does (parkresume.go Resume horizon branch).
type benchRemintMinter struct {
	expiry time.Time     // the fresh horizon the re-mint persists
	cost   time.Duration // synthetic per-Mint latency (0 = free, the offline default)
	calls  int
}

func (m *benchRemintMinter) Mint(_ context.Context, _ MintWorkloadIdentityClaims, _ string) (MintResult, error) {
	m.calls++
	if m.cost > 0 {
		time.Sleep(m.cost)
	}
	return MintResult{IdentityRef: "id-remint", CARef: "ca-remint", Expiry: m.expiry}, nil
}

// benchResumeFixture re-seeds a fresh SUSPENDED(user) session whose persisted MintExpiry is
// EXPIRED (when expired) or FUTURE (when not), wires a driver over it, and returns the driver
// + the cost-bearing minter so a bench/assertion can drive Resume and inspect minter.calls.
// Each call is independent (a fresh in-memory store), so the per-op loop never reuses a
// record that already advanced to WORKING (Resume is idempotent on a resumed session — a
// reused record would short-circuit and measure nothing).
//
// The driver clock is the same pinned instant the parkresume tests use (mustDriver /
// fixedNow), so the EXPIRED horizon is deterministically before now and the FUTURE horizon
// deterministically after it — the re-mint branch is taken iff expired, with no wall-clock
// flakiness in the decision.
func benchResumeFixture(tb testing.TB, expired bool, mintCost time.Duration) (*ParkResumeDriver, *benchRemintMinter) {
	tb.Helper()
	repo := store.NewMemory()
	ctx := context.Background()
	if _, err := repo.CreateSession(ctx, store.Session{
		Ref:     store.SessionRef{SessionUUID: "s1", HostID: "host-a", HostSessionIndex: 1, TapName: "dstap-1"},
		ImageID: "img-1",
		State:   store.SessionWorking,
		RolePin: store.RolePin{Name: "default", Version: "v1", ContentHash: "h"},
	}); err != nil {
		tb.Fatalf("seed CreateSession: %v", err)
	}
	suspended := store.SessionSuspended
	reason := store.SuspendReasonUser
	if _, err := repo.UpdateSession(ctx, "s1", store.SessionUpdate{State: &suspended, SuspendReason: &reason}); err != nil {
		tb.Fatalf("seed advance to SUSPENDED: %v", err)
	}
	// Persist the horizon: an hour BEFORE the pinned clock (expired → re-mint) or an hour
	// AFTER it (future → no Minter call).
	horizon := fixedNow.Add(time.Hour)
	if expired {
		horizon = fixedNow.Add(-time.Hour)
	}
	if _, err := repo.UpdateSession(ctx, "s1", store.SessionUpdate{MintExpiry: &horizon}); err != nil {
		tb.Fatalf("seed MintExpiry: %v", err)
	}

	minter := &benchRemintMinter{expiry: fixedNow.Add(time.Hour), cost: mintCost}
	d, err := NewParkResumeDriver(ParkResumeSeams{
		Store:   repo,
		Resumer: &prResumer{},
		Minter:  minter,
	}, func() time.Time { return fixedNow })
	if err != nil {
		tb.Fatalf("NewParkResumeDriver: %v", err)
	}
	return d, minter
}

// BenchmarkParkResume_Resume_RemintBoundary measures end-to-end ParkResumeDriver.Resume
// latency on the in-place resume path, in two ARMS so the synchronous-re-mint delta is
// isolated:
//
//	with_remint    — an EXPIRED horizon: the Minter IS called before the host Resume verb.
//	without_remint — a FUTURE horizon: no Minter call (the baseline resume cost).
//
// Each arm reseeds a fresh expired/future SUSPENDED session per op (so Resume always
// traverses SUSPENDED→RESUMING→WORKING, never short-circuits an already-resumed record),
// records the per-op Resume latency, and emits p50/p99 (ns) via b.ReportMetric alongside the
// default ns/op. The DELTA between the arms' p50/p99 IS the synchronous re-mint cost on the
// resume boundary. Offline the Minter cost is ZERO, so this reports the harness/store/
// state-machine overhead of the re-mint branch, not a live mint round-trip; the live-gated
// TestParkResumeRemintBudget_Live below supplies a realistic cost and asserts the budget.
//
// Run: `go test ./internal/sessions/ -run '^$' -bench BenchmarkParkResume_Resume_RemintBoundary`.
func BenchmarkParkResume_Resume_RemintBoundary(b *testing.B) {
	for _, arm := range []struct {
		name    string
		expired bool
	}{
		{"with_remint", true},
		{"without_remint", false},
	} {
		b.Run(arm.name, func(b *testing.B) {
			ctx := context.Background()
			lat := make([]time.Duration, 0, b.N)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				// Reseed OUTSIDE the timed segment so we measure Resume, not the seed.
				d, minter := benchResumeFixture(b, arm.expired, 0)
				b.StartTimer()

				start := time.Now()
				rec, err := d.Resume(ctx, "s1", ResumeAuthorityUser)
				elapsed := time.Since(start)

				b.StopTimer()
				if err != nil {
					b.Fatalf("Resume: %v", err)
				}
				if rec.State != store.SessionWorking {
					b.Fatalf("Resume landed at %s, want WORKING", rec.State)
				}
				// Sanity-pin the arm: the expired arm MUST hit the Minter, the future arm
				// MUST NOT — so the two arms genuinely isolate the re-mint branch.
				wantMint := 0
				if arm.expired {
					wantMint = 1
				}
				if minter.calls != wantMint {
					b.Fatalf("arm %q: Minter called %d times, want %d", arm.name, minter.calls, wantMint)
				}
				lat = append(lat, elapsed)
				b.StartTimer()
			}
			b.StopTimer()
			p50, p99 := percentile(lat, 0.50), percentile(lat, 0.99)
			b.ReportMetric(float64(p50.Nanoseconds()), "p50-ns/op")
			b.ReportMetric(float64(p99.Nanoseconds()), "p99-ns/op")
		})
	}
}

// resumeCommitBudget / resumeCommitOuterCeiling are the doc 15 §4.3 / doc 16 §8.2 numbers the
// live assertion variant gates against: the approval→enforced resume-commit SEGMENT target
// (≤ 5 s) and the OUTER CEILING the §8.2 window budget tolerates (10 s). The re-mint sits
// inside the resume-commit segment, so the segment target is the budget the live re-mint
// delta must fit under; the outer ceiling is the hard backstop.
const (
	resumeCommitBudget       = 5 * time.Second
	resumeCommitOuterCeiling = 10 * time.Second
)

// liveRemintCost is the REALISTIC synthetic mint round-trip the live assertion variant
// imposes so the budget check measures a plausible re-mint, not the zero-cost offline path.
// It is a strawman (doc 15 §3 latency strawmen are rig-tuned, free) standing in for a real
// MintIdentity + interception-CA mint until (d)-rig data arms it; well under the ≤ 5 s
// resume-commit segment so a healthy re-mint passes and only a pathological one trips the
// gate. Override on the live rig with DS_ORCH_REMINT_COST_MS to feed a measured cost.
const liveRemintCost = 250 * time.Millisecond

// TestParkResumeRemintBudget_Live is the DEFERRED MANUAL live-rig assertion variant. Behind
// DS_ORCH_LIVE=1 it drives the SAME expired-horizon Resume path with a REALISTIC mint cost
// (liveRemintCost, or DS_ORCH_REMINT_COST_MS if set) and FAILS if the re-mint delta — the
// expired-arm resume latency minus the future-arm (no-re-mint) baseline — pushes the
// resume-commit past the doc 15 §4.3 / doc 16 §8.2 budget (≤ 5 s segment, 10 s outer
// ceiling). Off the live rig (DS_ORCH_LIVE unset) it SKIPs cleanly — no live runs this wave
// (D50/D81; the instrument-first live gate stays OFF by default). The measurement here uses
// the SYNTHETIC cost-bearing minter (still no live claude/cia/podman) so the gate is a
// budget-fit ASSERTION harness, ready to retarget at a real Minter on the rig.
func TestParkResumeRemintBudget_Live(t *testing.T) {
	if os.Getenv("DS_ORCH_LIVE") != "1" {
		t.Skip("DS_ORCH_LIVE!=1: live-rig resume-commit budget assertion is a deferred manual step (no live runs this wave, D50/D81)")
	}

	mintCost := liveRemintCost
	if v := os.Getenv("DS_ORCH_REMINT_COST_MS"); v != "" {
		d, err := time.ParseDuration(v + "ms")
		if err != nil {
			t.Fatalf("DS_ORCH_REMINT_COST_MS=%q: %v", v, err)
		}
		mintCost = d
	}

	const iters = 32
	ctx := context.Background()

	measure := func(expired bool, cost time.Duration) (p50, p99 time.Duration) {
		lat := make([]time.Duration, 0, iters)
		for i := 0; i < iters; i++ {
			d, minter := benchResumeFixture(t, expired, cost)
			start := time.Now()
			rec, err := d.Resume(ctx, "s1", ResumeAuthorityUser)
			elapsed := time.Since(start)
			if err != nil {
				t.Fatalf("Resume (expired=%v): %v", expired, err)
			}
			if rec.State != store.SessionWorking {
				t.Fatalf("Resume landed at %s, want WORKING", rec.State)
			}
			wantMint := 0
			if expired {
				wantMint = 1
			}
			if minter.calls != wantMint {
				t.Fatalf("expired=%v: Minter called %d times, want %d", expired, minter.calls, wantMint)
			}
			lat = append(lat, elapsed)
		}
		return percentile(lat, 0.50), percentile(lat, 0.99)
	}

	// WITHOUT the re-mint (future horizon, no Minter call): the baseline resume cost.
	baseP50, baseP99 := measure(false, 0)
	// WITH the re-mint (expired horizon, realistic mint cost): the synchronous re-mint path.
	remintP50, remintP99 := measure(true, mintCost)

	deltaP50 := remintP50 - baseP50
	deltaP99 := remintP99 - baseP99
	t.Logf("resume-commit (live): baseline p50=%v p99=%v | with re-mint p50=%v p99=%v | re-mint delta p50=%v p99=%v (budget segment=%v, outer ceiling=%v, mint cost=%v)",
		baseP50, baseP99, remintP50, remintP99, deltaP50, deltaP99, resumeCommitBudget, resumeCommitOuterCeiling, mintCost)

	// The synchronous re-mint must fit inside the approval→enforced resume-commit SEGMENT
	// (doc 15 §4.3 ≤ 5 s) — assert on the full p99 resume-with-re-mint latency, not just the
	// delta, since the whole resume-commit must beat the segment target.
	if remintP99 > resumeCommitBudget {
		t.Fatalf("expired-horizon resume p99=%v EXCEEDS the doc 15 §4.3 / doc 16 §8.2 resume-commit segment budget %v (re-mint delta p99=%v, mint cost=%v)",
			remintP99, resumeCommitBudget, deltaP99, mintCost)
	}
	// And never past the 10 s outer ceiling (the hard backstop the §8.2 window tolerates).
	if remintP99 > resumeCommitOuterCeiling {
		t.Fatalf("expired-horizon resume p99=%v EXCEEDS the doc 16 §8.2 outer ceiling %v", remintP99, resumeCommitOuterCeiling)
	}
}

// percentile returns the q-quantile (0..1) of ds using nearest-rank on a sorted copy. An
// empty slice returns 0. It is the tiny order-statistic the bench/assertion report from a
// per-op latency sample (stdlib-only; no dependency on a metrics lib).
func percentile(ds []time.Duration, q float64) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	cp := make([]time.Duration, len(ds))
	copy(cp, ds)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	if q <= 0 {
		return cp[0]
	}
	if q >= 1 {
		return cp[len(cp)-1]
	}
	// Nearest-rank: rank = ceil(q*N), 1-indexed → idx = rank-1.
	rank := int(q*float64(len(cp)) + 0.999999)
	if rank < 1 {
		rank = 1
	}
	if rank > len(cp) {
		rank = len(cp)
	}
	return cp[rank-1]
}
