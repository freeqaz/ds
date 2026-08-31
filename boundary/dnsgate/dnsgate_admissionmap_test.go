package dnsgate

// DNS-2b — the host-local per-session (domain → admitted IPs, expiry) map the
// TLS proxy reads. These are CONTRACT tests for the AdmissionStore seam: they
// run against the NewAdmissionStore surface here (RED against the stub) and
// later against the real store, per the doc 06 §2.5 run-twice rule.

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"
)

// planRef: doc 09 §4 DNS-2b (written in the same insert-then-answer transaction as DNS-2)
func TestAdmissionMap_WrittenAtomicallyWithAllowSet(t *testing.T) {
	clock := newFakeClock()
	store := NewAdmissionStore(clock.Now)
	if store == nil {
		t.Fatal("NewAdmissionStore returned nil")
	}
	ctx := context.Background()
	addr := mkAddr("140.82.114.3")

	t.Run("one Admit produces both views", func(t *testing.T) {
		start := clock.Now()
		tx := AdmissionTx{
			Session:  sess1,
			Domain:   "github.com",
			Addrs:    []netip.Addr{addr},
			Timeout:  120 * time.Second,
			Decision: allowDec("baseline/github"),
		}
		if err := store.Admit(ctx, tx); err != nil {
			t.Fatalf("Admit: %v", err)
		}
		ok, err := store.ContainsAddr(ctx, sess1, addr)
		if err != nil {
			t.Fatalf("ContainsAddr: %v", err)
		}
		if !ok {
			t.Error("ContainsAddr = false after Admit — allow-set half missing")
		}
		adm, hit, err := store.Lookup(ctx, sess1, "github.com", addr)
		if err != nil {
			t.Fatalf("Lookup: %v", err)
		}
		if !hit {
			t.Fatal("Lookup missed after Admit — map half missing")
		}
		wantExp := start.Add(120 * time.Second)
		if !adm.ExpiresAt.Equal(wantExp) {
			t.Errorf("Admission.ExpiresAt = %v, want now+120s = %v", adm.ExpiresAt, wantExp)
		}
		if adm.Domain != "github.com" {
			t.Errorf("Admission.Domain = %q, want github.com", adm.Domain)
		}
	})

	t.Run("mid-transaction failure leaves no half-written state", func(t *testing.T) {
		// Fault injection through the seam: a context cancelled mid-Admit.
		// (The real-store run additionally injects a failure of the map half
		// via its own test hooks; the observable contract is identical:
		// after a failed Admit, NEITHER view shows the entry.)
		addr2 := mkAddr("140.82.114.4")
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		admitErr := store.Admit(cancelled, AdmissionTx{
			Session: sess1,
			Domain:  "half.example",
			Addrs:   []netip.Addr{addr2},
			Timeout: 120 * time.Second,
		})
		// The seam contract is unconditional: an Admit handed an already-
		// cancelled context MUST fail. A store that ignores cancellation and
		// commits the transaction anyway would dodge the injected failure and
		// leave the no-half-written-state guarantee untested.
		if admitErr == nil {
			t.Fatal("Admit succeeded with an already-cancelled context — injected failure ignored, transaction committed")
		}
		ok, err := store.ContainsAddr(ctx, sess1, addr2)
		if err != nil {
			t.Fatalf("ContainsAddr: %v", err)
		}
		_, hit, err := store.Lookup(ctx, sess1, "half.example", addr2)
		if err != nil {
			t.Fatalf("Lookup: %v", err)
		}
		// Unconditional: after the failed Admit, NEITHER view shows the entry.
		if ok || hit {
			t.Errorf("half-written state after failed Admit: ContainsAddr=%v Lookup=%v — transaction not atomic", ok, hit)
		}
	})
}

// planRef: doc 09 §4 DNS-2b (entries expire in lockstep with NFT-3 set timeouts)
func TestAdmissionMap_ExpiryLockstepWithSetTimeout(t *testing.T) {
	clock := newFakeClock()
	store := NewAdmissionStore(clock.Now)
	ctx := context.Background()
	addr := mkAddr("93.184.216.34")

	if err := store.Admit(ctx, AdmissionTx{
		Session: sess1, Domain: "lockstep.example",
		Addrs: []netip.Addr{addr}, Timeout: 90 * time.Second,
		Decision: allowDec("org/lockstep"),
	}); err != nil {
		t.Fatalf("Admit: %v", err)
	}

	probe := func() (setHit, mapHit bool) {
		t.Helper()
		ok, err := store.ContainsAddr(ctx, sess1, addr)
		if err != nil {
			t.Fatalf("ContainsAddr: %v", err)
		}
		_, hit, err := store.Lookup(ctx, sess1, "lockstep.example", addr)
		if err != nil {
			t.Fatalf("Lookup: %v", err)
		}
		return ok, hit
	}

	clock.Advance(89 * time.Second)
	if setHit, mapHit := probe(); !setHit || !mapHit {
		t.Errorf("+89s: ContainsAddr=%v Lookup=%v, want both live", setHit, mapHit)
	}

	clock.Advance(1 * time.Second) // +90s — the boundary instant
	if setHit, mapHit := probe(); setHit != mapHit {
		t.Errorf("+90s: views disagree at the transition instant: ContainsAddr=%v Lookup=%v", setHit, mapHit)
	}

	clock.Advance(1 * time.Second) // +91s
	if setHit, mapHit := probe(); setHit || mapHit {
		t.Errorf("+91s: ContainsAddr=%v Lookup=%v, want both expired", setHit, mapHit)
	}
}

// planRef: doc 09 §4 DNS-2b Done-when (expired mapping refuses while another domain keeps the IP alive) — the CDN shared-IP hole, doc 03 OQ1
func TestAdmissionMap_ExpiredDomainMisses_WhileSharedIPAliveForOtherDomain(t *testing.T) {
	clock := newFakeClock()
	store := NewAdmissionStore(clock.Now)
	ctx := context.Background()
	shared := mkAddr("151.101.0.1")

	if err := store.Admit(ctx, AdmissionTx{
		Session: sess1, Domain: "a.example", Addrs: []netip.Addr{shared},
		Timeout: 60 * time.Second, Decision: allowDec("org/a"),
	}); err != nil {
		t.Fatalf("Admit a.example: %v", err)
	}
	if err := store.Admit(ctx, AdmissionTx{
		Session: sess1, Domain: "b.example", Addrs: []netip.Addr{shared},
		Timeout: 600 * time.Second, Decision: allowDec("org/b"),
	}); err != nil {
		t.Fatalf("Admit b.example: %v", err)
	}

	clock.Advance(120 * time.Second) // a expired, b alive

	ok, err := store.ContainsAddr(ctx, sess1, shared)
	if err != nil {
		t.Fatalf("ContainsAddr: %v", err)
	}
	if !ok {
		t.Error("ContainsAddr(151.101.0.1) = false — b.example should keep the shared IP alive in the set")
	}
	if _, hit, err := store.Lookup(ctx, sess1, "b.example", shared); err != nil || !hit {
		t.Errorf("Lookup(b.example) hit=%v err=%v, want live hit", hit, err)
	}
	// The read ds-tlsproxy uses for its TLS-1 refusal: per-domain, not per-IP.
	if _, hit, err := store.Lookup(ctx, sess1, "a.example", shared); err != nil {
		t.Fatalf("Lookup(a.example): %v", err)
	} else if hit {
		t.Error("Lookup(a.example, 151.101.0.1) hit after expiry — an IP alive for domain B must not vouch for expired domain A")
	}
}

// planRef: doc 09 §4 DNS-2b (host-local PER-SESSION store) + doc 06 §3(c) session isolation
func TestAdmissionMap_CrossSessionLookupAlwaysMisses(t *testing.T) {
	clock := newFakeClock()
	store := NewAdmissionStore(clock.Now)
	ctx := context.Background()
	addr := mkAddr("140.82.114.3")

	if err := store.Admit(ctx, AdmissionTx{
		Session: sess1, Domain: "github.com", Addrs: []netip.Addr{addr},
		Timeout: 300 * time.Second, Decision: allowDec("baseline/github"),
	}); err != nil {
		t.Fatalf("Admit under s1: %v", err)
	}
	s2Addr := mkAddr("198.51.7.9")
	if err := store.Admit(ctx, AdmissionTx{
		Session: sess2, Domain: "own.s2.example", Addrs: []netip.Addr{s2Addr},
		Timeout: 300 * time.Second, Decision: allowDec("org/s2"),
	}); err != nil {
		t.Fatalf("Admit under s2: %v", err)
	}

	// Identical domain and IP, wrong session: both views must miss.
	if ok, err := store.ContainsAddr(ctx, sess2, addr); err != nil {
		t.Fatalf("ContainsAddr s2: %v", err)
	} else if ok {
		t.Error("ContainsAddr under s2 = true for s1's admission — allow-set leaked across sessions")
	}
	if _, hit, err := store.Lookup(ctx, sess2, "github.com", addr); err != nil {
		t.Fatalf("Lookup s2: %v", err)
	} else if hit {
		t.Error("Lookup under s2 hit for s1's admission — admission map leaked across sessions")
	}

	// Both hit under the originating session.
	if ok, err := store.ContainsAddr(ctx, sess1, addr); err != nil || !ok {
		t.Errorf("ContainsAddr under s1 = %v err=%v, want hit", ok, err)
	}
	if _, hit, err := store.Lookup(ctx, sess1, "github.com", addr); err != nil || !hit {
		t.Errorf("Lookup under s1 hit=%v err=%v, want hit", hit, err)
	}

	// FlushSession(s1) leaves s2's own entries untouched.
	if err := store.FlushSession(ctx, sess1); err != nil {
		t.Fatalf("FlushSession(s1): %v", err)
	}
	if _, hit, err := store.Lookup(ctx, sess1, "github.com", addr); err != nil {
		t.Fatalf("Lookup s1 after flush: %v", err)
	} else if hit {
		t.Error("s1 entry survived FlushSession(s1)")
	}
	if _, hit, err := store.Lookup(ctx, sess2, "own.s2.example", s2Addr); err != nil || !hit {
		t.Errorf("s2's own entry gone after FlushSession(s1): hit=%v err=%v", hit, err)
	}
}

// planRef: doc 09 §4 DNS-2b (flushed at session teardown, NFT-6) + doc 06 §3(b) clean-teardown row
func TestAdmissionMap_FlushedAtSessionTeardown_NoResidue(t *testing.T) {
	clock := newFakeClock()
	store := NewAdmissionStore(clock.Now)
	ctx := context.Background()

	domains := []string{"a.example", "b.example", "c.example"}
	addrFor := func(i, loop int) netip.Addr {
		return mkAddr(fmt.Sprintf("93.184.%d.%d", 100+loop, 10+i))
	}

	// create→admit→flush looped 10 times for the SAME SessionRef: a recycled
	// session ID must inherit nothing.
	for loop := 0; loop < 10; loop++ {
		for i, d := range domains {
			if err := store.Admit(ctx, AdmissionTx{
				Session: sess1, Domain: d, Addrs: []netip.Addr{addrFor(i, loop)},
				Timeout:  600 * time.Second, // unexpired at flush time
				Decision: allowDec("org/" + d),
			}); err != nil {
				t.Fatalf("loop %d: Admit(%s): %v", loop, d, err)
			}
		}
		if err := store.FlushSession(ctx, sess1); err != nil {
			t.Fatalf("loop %d: FlushSession: %v", loop, err)
		}
		// After each flush every Lookup and ContainsAddr for s1 misses,
		// including the still-unexpired entries — no leaked allow-set entries.
		for i, d := range domains {
			a := addrFor(i, loop)
			if _, hit, err := store.Lookup(ctx, sess1, d, a); err != nil {
				t.Fatalf("loop %d: Lookup(%s): %v", loop, d, err)
			} else if hit {
				t.Errorf("loop %d: Lookup(%s, %s) hit after teardown flush — admission residue", loop, d, a)
			}
			if ok, err := store.ContainsAddr(ctx, sess1, a); err != nil {
				t.Fatalf("loop %d: ContainsAddr(%s): %v", loop, a, err)
			} else if ok {
				t.Errorf("loop %d: ContainsAddr(%s) hit after teardown flush — leaked allow-set entry", loop, a)
			}
		}
	}
	// The loop must end exactly as it started: every addr from every loop
	// absent (the (b) suite's byte-identical/no-growth assertion expressed
	// through this seam; the real-store run adds a ruleset-dump comparison).
	for loop := 0; loop < 10; loop++ {
		for i := range domains {
			a := addrFor(i, loop)
			ok, err := store.ContainsAddr(ctx, sess1, a)
			if err != nil {
				t.Fatalf("final sweep: ContainsAddr(%s): %v", a, err)
			}
			if ok {
				t.Errorf("residual allow-set entry %s survived all flushes", a)
			}
		}
	}
}
