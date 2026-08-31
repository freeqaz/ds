// SPDX-License-Identifier: Apache-2.0

package sessions

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// Bench the COLD-RESUME re-mint SPINE — ParkResumeDriver.ResumeFromPark, the PARKED→
// CREATING@host' re-place (parkresume.go) — against the doc 16 §8.2 / doc 15 §4.3
// resume-commit budget, isolating the re-place spine cost the in-place wave-1 resume does
// NOT pay.
//
// THE TWO ARMS BEING COMPARED.
//   - IN-PLACE (wave-1) arm — ParkResumeDriver.Resume on an EXPIRED-horizon SUSPENDED
//     session whose VM is still resident. It re-mints (doc 16 §5.4 — an expired credential
//     re-mints on resume) and drives the host Resume verb, but does NO re-place: no Placer,
//     no HostAllocator, no index-epoch append. This is the SAME re-mint boundary the
//     companion parkresume_bench_test.go measures; it is the BASELINE here.
//   - RE-PLACE (cold-resume) arm — ParkResumeDriver.ResumeFromPark on a PARKED session. The
//     §3 PARKED→CREATING@host' edge: it ALWAYS re-mints (the re-place re-mint is
//     unconditional, doc 16 §5.4), re-places through the scheduler (Placer), allocates a NEW
//     index/tap on the target (HostAllocator), appends the new index epoch (AppendIndexEpoch
//     — closes the prior epoch, burns the new index), and advances PARKED→CREATING@host'.
//     The DELTA between this arm and the in-place arm IS the cold-resume re-place spine cost
//     (re-place + host-allocate + index-epoch append + the wider record advance) layered on
//     top of the SHARED re-mint — the price a PARKED session pays over a still-resident one.
//
// WHY THE COMPARISON IS APT. Both arms cross the SAME synchronous re-mint on the resume
// boundary; the in-place arm stops there, the re-place arm additionally runs the full
// scheduler re-place spine. Subtracting the in-place arm from the re-place arm therefore
// isolates the re-place machinery, not the re-mint, so a regression in the cold-resume spine
// (a slow Placer / allocator / epoch append) shows up as a growing delta independent of mint
// cost. This added latency is currently UNMEASURED on a live rig (no live runs this wave,
// D50/D81 — instrument-first, the live gate stays OFF by default).
//
// THE BUDGET. The cold resume's re-mint + re-place sits inside the doc 15 §4.3
// approval→enforced resume-commit SEGMENT (≤ 5 s; resumeCommitBudget, shared from
// parkresume_bench_test.go), under the doc 16 §8.2 outer ceiling (10 s;
// resumeCommitOuterCeiling). The live assertion arm gates the re-place arm's p99 against that
// segment.
//
// WHAT THIS FILE SHIPS (both arms run under a plain `go test -bench .`).
//   - BenchmarkColdResume_ReplaceSpine drives BOTH arms — in_place_remint
//     (ParkResumeDriver.Resume) and re_place_remint (ParkResumeDriver.ResumeFromPark) —
//     through the SAME pr-prefixed synthetic seams the parkresume tests use (NO live claude /
//     cia / podman, D50). Each arm reports p50/p99 via b.ReportMetric; the delta is the
//     re-place spine cost. The Minter is the shared parameterizable-cost benchRemintMinter
//     (cost 0 offline).
//   - TestColdResumeReplaceBudget_Live is the DS_ORCH_LIVE-gated assertion arm: it drives the
//     re-place arm with a realistic mint cost and FAILS if the cold-resume p99 (or its delta
//     over the in-place baseline) busts the §8.2/§4.3 budget. Off the live rig it SKIPs
//     cleanly.
//
// It REUSES, never re-declares: benchRemintMinter + benchResumeFixture +
// resumeCommitBudget/resumeCommitOuterCeiling/liveRemintCost + percentile from
// parkresume_bench_test.go; fixedNow from parkresume_mintexpiry_test.go; prPlacer / prAlloc /
// prResumer / prApprovals / seedSession from parkresume_test.go (same package). Only the
// re-place fixture + the two-arm spine harness are new here. No exported hook is added to
// parkresume.go — the existing synthetic seams construct the full re-place spine.

// coldReplaceFixture seeds a fresh PARKED(none) session, wires a driver with the FULL
// re-place spine seams (Placer / HostAllocator / Minter / a landed-approval reader), and
// returns the driver + the cost-bearing minter so a bench/assertion can drive ResumeFromPark
// and inspect minter.calls. Each call is independent (a fresh in-memory store), so the per-op
// loop never reuses a record that already advanced to CREATING (ResumeFromPark is idempotent
// on an already-re-placing record — a reused record would short-circuit and measure nothing).
//
// The driver clock is the same pinned instant the parkresume tests use (fixedNow), and the
// minter surfaces a fresh future Expiry (fixedNow+1h) so the re-place re-mint advances the
// durable horizon exactly as the live path does. The re-place re-mint is UNCONDITIONAL (it
// does not consult the horizon, unlike the in-place Resume), so no MintExpiry is seeded.
func coldReplaceFixture(tb testing.TB, mintCost time.Duration) (*ParkResumeDriver, *benchRemintMinter) {
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
	// Advance to PARKED (the cold-resume origin). PARKED carries no suspend reason — the park
	// cleared it — so the parkReason is supplied to ResumeFromPark by the caller (user here).
	parked := store.SessionParked
	if _, err := repo.UpdateSession(ctx, "s1", store.SessionUpdate{State: &parked}); err != nil {
		tb.Fatalf("seed advance to PARKED: %v", err)
	}

	minter := &benchRemintMinter{expiry: fixedNow.Add(time.Hour), cost: mintCost}
	d, err := NewParkResumeDriver(ParkResumeSeams{
		Store:         repo,
		Placer:        &prPlacer{hostID: "host-b", appliedSeq: 99},
		HostAllocator: &prAlloc{idx: 7, tap: "dstap-7"},
		Minter:        minter,
		Approvals:     prApprovals{landed: true},
	}, func() time.Time { return fixedNow })
	if err != nil {
		tb.Fatalf("NewParkResumeDriver: %v", err)
	}
	return d, minter
}

// BenchmarkColdResume_ReplaceSpine measures end-to-end resume latency in two ARMS so the
// cold-resume re-place spine cost is isolated from the shared re-mint:
//
//	in_place_remint — ParkResumeDriver.Resume on an EXPIRED-horizon SUSPENDED session: the
//	                  re-mint boundary ONLY (no re-place). The baseline (the wave-1 path).
//	re_place_remint — ParkResumeDriver.ResumeFromPark on a PARKED session: the re-mint PLUS
//	                  the full PARKED→CREATING@host' re-place spine (Placer + HostAllocator +
//	                  AppendIndexEpoch + the wider record advance).
//
// Each arm reseeds a fresh session per op (so Resume/ResumeFromPark always traverses its
// edges and never short-circuits an already-advanced record), records the per-op latency, and
// emits p50/p99 (ns) via b.ReportMetric alongside the default ns/op. The DELTA between
// re_place_remint and in_place_remint IS the cold-resume re-place spine cost. Offline the
// Minter cost is ZERO, so this reports the harness/store/state-machine overhead of the
// re-place spine, not a live mint/scheduler round-trip; the live-gated
// TestColdResumeReplaceBudget_Live below supplies a realistic cost and asserts the budget.
//
// Run: `go test ./internal/sessions/ -run '^$' -bench BenchmarkColdResume_ReplaceSpine`.
func BenchmarkColdResume_ReplaceSpine(b *testing.B) {
	ctx := context.Background()

	// in_place_remint — the wave-1 in-place Resume re-mint boundary (no re-place). Reuses the
	// expired-horizon SUSPENDED fixture from parkresume_bench_test.go (benchResumeFixture).
	b.Run("in_place_remint", func(b *testing.B) {
		lat := make([]time.Duration, 0, b.N)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			b.StopTimer()
			d, minter := benchResumeFixture(b, true /* expired → re-mint */, 0)
			b.StartTimer()

			start := time.Now()
			rec, err := d.Resume(ctx, "s1", ResumeAuthorityUser)
			elapsed := time.Since(start)

			b.StopTimer()
			if err != nil {
				b.Fatalf("in-place Resume: %v", err)
			}
			if rec.State != store.SessionWorking {
				b.Fatalf("in-place Resume landed at %s, want WORKING", rec.State)
			}
			if minter.calls != 1 {
				b.Fatalf("in-place arm: Minter called %d times, want 1 (expired horizon re-mints)", minter.calls)
			}
			lat = append(lat, elapsed)
			b.StartTimer()
		}
		b.StopTimer()
		b.ReportMetric(float64(percentile(lat, 0.50).Nanoseconds()), "p50-ns/op")
		b.ReportMetric(float64(percentile(lat, 0.99).Nanoseconds()), "p99-ns/op")
	})

	// re_place_remint — the cold-resume ResumeFromPark re-place spine (re-mint + re-place +
	// host-allocate + index-epoch append + advance to CREATING@host').
	b.Run("re_place_remint", func(b *testing.B) {
		lat := make([]time.Duration, 0, b.N)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			b.StopTimer()
			d, minter := coldReplaceFixture(b, 0)
			b.StartTimer()

			start := time.Now()
			rec, err := d.ResumeFromPark(ctx, "s1", ResumeAuthorityUser, attachReasonUser)
			elapsed := time.Since(start)

			b.StopTimer()
			if err != nil {
				b.Fatalf("cold-resume ResumeFromPark: %v", err)
			}
			if rec.State != store.SessionCreating {
				b.Fatalf("cold-resume ResumeFromPark landed at %s, want CREATING@host'", rec.State)
			}
			// The re-place spine MUST have run: a new binding on the target + a kept prior
			// epoch + an unconditional re-mint. Pin them so the arm genuinely measures the
			// full spine, not a short-circuit.
			if rec.Ref.HostID != "host-b" || rec.Ref.HostSessionIndex != 7 || rec.Ref.TapName != "dstap-7" {
				b.Fatalf("cold-resume did not rebind to the re-place target: %+v", rec.Ref)
			}
			if len(rec.IndexHistory) != 2 {
				b.Fatalf("cold-resume should keep the prior epoch + open the new one, got %d epochs", len(rec.IndexHistory))
			}
			if minter.calls != 1 {
				b.Fatalf("re-place arm: Minter called %d times, want 1 (re-place re-mints unconditionally)", minter.calls)
			}
			lat = append(lat, elapsed)
			b.StartTimer()
		}
		b.StopTimer()
		b.ReportMetric(float64(percentile(lat, 0.50).Nanoseconds()), "p50-ns/op")
		b.ReportMetric(float64(percentile(lat, 0.99).Nanoseconds()), "p99-ns/op")
	})
}

// TestColdResumeReplaceBudget_Live is the DEFERRED MANUAL live-rig assertion arm for the
// cold-resume re-place spine. Behind DS_ORCH_LIVE=1 it drives the SAME two arms with a
// REALISTIC mint cost (liveRemintCost, or DS_ORCH_REMINT_COST_MS if set — both shared from
// parkresume_bench_test.go) and FAILS if the cold-resume (re-place) p99 busts the doc 15 §4.3
// resume-commit SEGMENT (≤ 5 s) or the doc 16 §8.2 outer ceiling (10 s). It also LOGS the
// re-place spine delta over the in-place baseline so a regression in the cold-resume
// machinery is visible. Off the live rig (DS_ORCH_LIVE unset) it SKIPs cleanly — no live runs
// this wave (D50/D81; the instrument-first live gate stays OFF by default). The measurement
// uses the SYNTHETIC cost-bearing minter + synthetic re-place seams (still no live
// claude/cia/podman), so the gate is a budget-fit ASSERTION harness ready to retarget at a
// real Minter/Placer on the rig.
func TestColdResumeReplaceBudget_Live(t *testing.T) {
	if os.Getenv("DS_ORCH_LIVE") != "1" {
		t.Skip("DS_ORCH_LIVE!=1: live-rig cold-resume re-place budget assertion is a deferred manual step (no live runs this wave, D50/D81)")
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

	// inPlace measures the wave-1 in-place Resume re-mint boundary (the baseline).
	inPlace := func(cost time.Duration) (p50, p99 time.Duration) {
		lat := make([]time.Duration, 0, iters)
		for i := 0; i < iters; i++ {
			d, minter := benchResumeFixture(t, true /* expired → re-mint */, cost)
			start := time.Now()
			rec, err := d.Resume(ctx, "s1", ResumeAuthorityUser)
			elapsed := time.Since(start)
			if err != nil {
				t.Fatalf("in-place Resume: %v", err)
			}
			if rec.State != store.SessionWorking {
				t.Fatalf("in-place Resume landed at %s, want WORKING", rec.State)
			}
			if minter.calls != 1 {
				t.Fatalf("in-place arm: Minter called %d times, want 1", minter.calls)
			}
			lat = append(lat, elapsed)
		}
		return percentile(lat, 0.50), percentile(lat, 0.99)
	}

	// rePlace measures the cold-resume ResumeFromPark re-place spine.
	rePlace := func(cost time.Duration) (p50, p99 time.Duration) {
		lat := make([]time.Duration, 0, iters)
		for i := 0; i < iters; i++ {
			d, minter := coldReplaceFixture(t, cost)
			start := time.Now()
			rec, err := d.ResumeFromPark(ctx, "s1", ResumeAuthorityUser, attachReasonUser)
			elapsed := time.Since(start)
			if err != nil {
				t.Fatalf("cold-resume ResumeFromPark: %v", err)
			}
			if rec.State != store.SessionCreating {
				t.Fatalf("cold-resume ResumeFromPark landed at %s, want CREATING@host'", rec.State)
			}
			if minter.calls != 1 {
				t.Fatalf("re-place arm: Minter called %d times, want 1", minter.calls)
			}
			lat = append(lat, elapsed)
		}
		return percentile(lat, 0.50), percentile(lat, 0.99)
	}

	baseP50, baseP99 := inPlace(mintCost)
	coldP50, coldP99 := rePlace(mintCost)

	deltaP50 := coldP50 - baseP50
	deltaP99 := coldP99 - baseP99
	t.Logf("cold-resume re-place (live): in-place baseline p50=%v p99=%v | re-place p50=%v p99=%v | re-place-spine delta p50=%v p99=%v (budget segment=%v, outer ceiling=%v, mint cost=%v)",
		baseP50, baseP99, coldP50, coldP99, deltaP50, deltaP99, resumeCommitBudget, resumeCommitOuterCeiling, mintCost)

	// The cold resume (re-mint + re-place spine) must fit inside the approval→enforced
	// resume-commit SEGMENT (doc 15 §4.3 ≤ 5 s) — assert on the full p99 cold-resume latency,
	// since the whole resume-commit must beat the segment target.
	if coldP99 > resumeCommitBudget {
		t.Fatalf("cold-resume re-place p99=%v EXCEEDS the doc 15 §4.3 / doc 16 §8.2 resume-commit segment budget %v (re-place-spine delta p99=%v, mint cost=%v)",
			coldP99, resumeCommitBudget, deltaP99, mintCost)
	}
	// And never past the 10 s outer ceiling (the hard backstop the §8.2 window tolerates).
	if coldP99 > resumeCommitOuterCeiling {
		t.Fatalf("cold-resume re-place p99=%v EXCEEDS the doc 16 §8.2 outer ceiling %v", coldP99, resumeCommitOuterCeiling)
	}
}
