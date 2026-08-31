package boundary

// Load rows (LOAD-*): the Stage-5 (d) rig scenarios. Each is guarded with
// testing.Short() per CONVENTIONS, asserts a budget constant, and runs RED
// against the stub.

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// planRef: doc 09 doc 06 (d); §5; Stage 5. [load]
func TestLoad_ConcurrentVMs_ProxyP99WithinBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("load: scheduled (d) rig")
	}
	h := newHarness(t)
	ctx := context.Background()
	const N = 64

	sessions := make([]Session, N)
	for i := range sessions {
		s := h.newSession(t)
		sessions[i] = s
		h.setUpstreamA(t, "api.anthropic.com", 5*time.Minute, rotatedAddrA)
		h.resolveOK(t, s.Ref, "api.anthropic.com")
	}

	lat := make([]time.Duration, N)
	var wg sync.WaitGroup
	errs := make([]error, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			start := time.Now()
			_, err := h.b.VM(sessions[i].Ref).HTTP(ctx, HTTPRequest{
				Method: "GET", Host: "api.anthropic.com", Path: "/v1/models",
				Headers: map[string]string{"Authorization": "Bearer " + string(sessions[i].ShortLivedCred)},
			})
			lat[i] = time.Since(start)
			errs[i] = err
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("session[%d] inspected HTTPS failed under fan-out: %v", i, err)
		}
	}
	sortDurations(lat)
	if p99 := percentile(lat, 99); p99 > ProxyP99Budget {
		t.Fatalf("proxy p99 = %v exceeds budget %v under %d-VM fan-out", p99, ProxyP99Budget, N)
	}
}

// planRef: doc 09 POL-4 Done-when; doc 06 (d). [load]
func TestLoad_PolicyPushFanout_EnforcedWithinSeconds(t *testing.T) {
	if testing.Short() {
		t.Skip("load: scheduled (d) rig")
	}
	h := newHarness(t)
	ctx := context.Background()
	const hosts = 32
	const formerlyAllowed = "github.com"

	sessions := make([]Session, hosts)
	for i := range sessions {
		s := h.newSession(t)
		sessions[i] = s
		h.setUpstreamA(t, formerlyAllowed, 5*time.Minute, rotatedAddrA)
		h.resolveOK(t, s.Ref, formerlyAllowed)
	}

	// Push a block for the previously-allowed domain across the fleet.
	start := time.Now()
	ver, err := h.b.Policy().Push(ctx, PolicySnapshot{Layers: []PolicyLayer{{
		Name: "system", Allow: BaselineDomains, Block: []string{formerlyAllowed},
	}}})
	if err != nil {
		t.Fatalf("Policy.Push: %v", err)
	}

	// Measure time until EVERY host denies it.
	for i, s := range sessions {
		deadline := time.Now().Add(PolicyPushBudget)
		denied := false
		for time.Now().Before(deadline) {
			resp, err := h.b.VM(s.Ref).ResolveDNS(ctx, DNSQuery{Name: formerlyAllowed, Type: DNSTypeA})
			if err != nil {
				t.Fatalf("ResolveDNS[%d]: %v", i, err)
			}
			if resp.Rcode != RcodeNoError || len(resp.Answers) == 0 {
				denied = true
				break
			}
		}
		if !denied {
			t.Fatalf("host %d did not enforce the pushed block within %v", i, PolicyPushBudget)
		}
		// Both services on a host share the version.
		if active, err := h.b.Policy().Active(ctx); err != nil || active != ver {
			t.Fatalf("host %d active policy = %q, want pushed %q (both services share the version)", i, active, ver)
		}
	}
	if elapsed := time.Since(start); elapsed > PolicyPushBudget {
		t.Fatalf("push-to-enforced fleet latency = %v exceeds budget %v", elapsed, PolicyPushBudget)
	}
}

// planRef: doc 09 doc 06 (d); doc 03 §6; Stage 5. [load]
func TestLoad_PackageStampede_CacheEffective(t *testing.T) {
	if testing.Short() {
		t.Skip("load: scheduled (d) rig")
	}
	h := newHarness(t)
	ctx := context.Background()
	const M = 48
	const name = "registry.npmjs.org"

	sessions := make([]Session, M)
	for i := range sessions {
		s := h.newSession(t)
		sessions[i] = s
		h.setUpstreamA(t, name, 5*time.Minute, rotatedAddrA)
	}

	lat := make([]time.Duration, M)
	errs := make([]error, M)
	var wg sync.WaitGroup
	for i := 0; i < M; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Goroutine-safe resolve: failures surface via errs on the test
			// goroutine, never t.Fatalf from here.
			if _, err := h.tryResolve(sessions[i].Ref, name); err != nil {
				errs[i] = err
				return
			}
			start := time.Now()
			_, err := h.b.VM(sessions[i].Ref).HTTP(ctx, HTTPRequest{
				Method: "GET", Host: name, Path: "/lodash/-/lodash-4.17.21.tgz",
			})
			lat[i] = time.Since(start)
			errs[i] = err
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("stampede session[%d] failed: %v", i, err)
		}
	}
	// Cache/pre-bake absorbs the stampede: the single registry proxy stays
	// within the p99 budget despite M simultaneous pulls.
	sortDurations(lat)
	if p99 := percentile(lat, 99); p99 > ProxyP99Budget {
		t.Fatalf("registry proxy p99 = %v exceeds budget %v under %d-session stampede (cache not effective)", p99, ProxyP99Budget, M)
	}
}

// planRef: doc 09 DNS-1 Done-when; doc 06 (d). [load]
func TestLoad_DNSResolutionP99_WarmBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("load: scheduled (d) rig")
	}
	h := newHarness(t)
	const N = 100
	const name = "api.anthropic.com"

	sessions := make([]Session, N)
	for i := range sessions {
		s := h.newSession(t)
		sessions[i] = s
		h.setUpstreamA(t, name, 5*time.Minute, rotatedAddrA)
		// Warm the cache.
		h.resolveOK(t, s.Ref, name)
	}

	lat := make([]time.Duration, N)
	errs := make([]error, N)
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Goroutine-safe resolve: failures surface via errs on the test
			// goroutine, never t.Fatalf from here.
			start := time.Now()
			_, err := h.tryResolve(sessions[i].Ref, name)
			lat[i] = time.Since(start)
			errs[i] = err
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("session[%d] warm resolve failed under fan-out: %v", i, err)
		}
	}
	sortDurations(lat)
	if p99 := percentile(lat, 99); p99 > DNSWarmP99Budget {
		t.Fatalf("warm DNS p99 added latency = %v exceeds budget %v (on every first-connection critical path)", p99, DNSWarmP99Budget)
	}
}

// planRef: doc 09 NFT-3; Stage 5 (d) rig. [load]
func TestLoad_AllowSetChurn_UnderFanout(t *testing.T) {
	if testing.Short() {
		t.Skip("load: scheduled (d) rig")
	}
	h := newHarness(t)
	ctx := context.Background()
	const sessions = 24
	const cycles = 20

	// Per-session domain names: concurrent upstream programming must never
	// collide on a shared key (no cross-talk between sessions).
	names := make([]string, sessions)
	allow := append([]string{}, BaselineDomains...)
	for i := range names {
		names[i] = fmt.Sprintf("s%d.churn.example", i)
		allow = append(allow, names[i])
	}
	if _, err := h.b.Policy().Load(ctx, PolicySnapshot{Layers: []PolicyLayer{{
		Name: "system", Allow: allow,
	}}}); err != nil {
		t.Fatalf("Policy.Load: %v", err)
	}

	sess := make([]Session, sessions)
	for i := range sess {
		sess[i] = h.newSession(t)
	}
	// Each session gets its own distinct admitted address.
	addrFor := func(i int) netip.Addr { return netip.AddrFrom4([4]byte{203, 0, 113, byte(100 + i)}) }

	errs := make(chan error, sessions)
	checkErrs := func() {
		for {
			select {
			case err := <-errs:
				t.Fatalf("allow-set churn invariant violated: %v", err)
			default:
				return
			}
		}
	}

	for c := 0; c < cycles; c++ {
		// Phase 1 (concurrent fan-out): program upstream, resolve, verify
		// admission and cross-session containment. Failures are reported to
		// the test goroutine — never t.Fatalf from a spawned goroutine.
		var wg sync.WaitGroup
		for i := 0; i < sessions; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				s := sess[i]
				addr := addrFor(i)
				if err := h.trySetUpstreamA(names[i], TTLClampMin, addr); err != nil {
					errs <- err
					return
				}
				addrs, err := h.tryResolve(s.Ref, names[i])
				if err != nil {
					errs <- err
					return
				}
				if len(addrs) != 1 || addrs[0] != addr {
					errs <- fmt.Errorf("session %d: resolve churn returned wrong address %v, want [%v]", i, addrs, addr)
					return
				}
				set, err := h.tryAllowSet(s.Ref)
				if err != nil {
					errs <- err
					return
				}
				// Valid new flow must be admitted immediately.
				if !allowSetContains(set, addr) {
					errs <- fmt.Errorf("session %d: valid new flow %v not admitted under churn", i, addr)
					return
				}
				// No cross-session leakage: another session's address must
				// not appear in this session's set.
				other := addrFor((i + 1) % sessions)
				if other != addr && allowSetContains(set, other) {
					errs <- fmt.Errorf("session %d: cross-session allow-set leakage of %v", i, other)
					return
				}
			}(i)
		}
		wg.Wait()
		checkErrs()

		// Single coordinator drives expiry ONCE per cycle (the shared fake
		// clock is never advanced concurrently from racing goroutines).
		h.clock.Advance(TTLClampMin + AllowSetGraceMax + time.Second)

		// Phase 2 (concurrent fan-out): every session's expired entry reaped.
		var wg2 sync.WaitGroup
		for i := 0; i < sessions; i++ {
			wg2.Add(1)
			go func(i int) {
				defer wg2.Done()
				set, err := h.tryAllowSet(sess[i].Ref)
				if err != nil {
					errs <- err
					return
				}
				if allowSetContains(set, addrFor(i)) {
					errs <- fmt.Errorf("session %d: expired entry %v not reaped under churn", i, addrFor(i))
				}
			}(i)
		}
		wg2.Wait()
		checkErrs()
	}
}
