// SPDX-License-Identifier: Apache-2.0

package e2e

// teardown_nft6_test.go is the (b) clean-teardown / NFT-6 loop assertion at the
// e2e tier (doc 06 §3b; NFT-6, doc 09 §3): a create→destroy loop run N times
// leaves the host's modeled NFT ruleset BYTE-IDENTICAL to bootstrap — no leaked
// NFTables rules / allow-set entries, no orphaned VM, no dangling CoW overlay.
//
// REUSING THE HOSTDESTROY CONFORMANCE (the task constraint). The canonical model
// of this loop lives in orchestrator/internal/hostagent/destroy_test.go, driven
// against its RecordingBackend through the real libvirt + host-agent §4.2
// teardown ordering. That model is INTERNAL to the orchestrator module (a
// package-internal test fake), so it cannot be imported across the module
// boundary into this standalone e2e module. Rather than fork the production
// teardown, this file reuses the SAME conformance SHAPE — the same per-session
// NFT objects (the per-session interface rule, the empty allow4_<session> /
// allow6_<session> named sets, the DNS-2b admission-map entry, the ct-mark
// accounting key), instantiated on create and flushed in the frozen NFT-6 order
// on destroy, serialized to a STABLE string so the N-loop byte-identity can be
// asserted. The seam-level loop in internal/hostagent is the authority on the
// PRODUCTION teardown ordering; this is the e2e-tier statement that the
// clean-teardown invariant holds end-to-end (and it is driven against the fake,
// NOT the ds-nft cgo bridge — DS_NFTGATE_LIVE stays disabled, the live-metal
// binding is a separately-tracked follow-up).
//
// This is a MODEL fake (D50): it records the create-side instantiation and the
// teardown flush and never touches the kernel — flush_session itself is DONE in
// ds-nft and invoked through a seam in production; here the modeled deletion in
// the frozen order stands in for it so the byte-identity invariant is testable
// offline, in CI, with no nested virt.

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// nftObjects is the per-session NFT state one create instantiates (mirrors the
// internal/hostagent RecordingBackend's model so the e2e statement and the
// seam-level conformance describe the same objects).
type nftObjects struct {
	tapName   string
	allow4Set string // allow4_<session> named set (starts EMPTY, doc 15 §4.1 step 4)
	allow6Set string // allow6_<session> named set (dormant Phase B, D75)
	dns2bMap  string // the DNS-2b admission-map entry key for the session
	ctMark    uint64 // the ct-mark accounting key (the index residue rides it, D76)
	ifaceRule string // the per-session interface rule (iifname dstap-<idx>)
}

// modeledHost is the (b) clean-teardown conformance fake: it models the host's
// NFT ruleset as the set of per-session objects plus the booted domains, the
// qcow2 overlays, and the per-session conntrack flow the teardown flush must
// kill. Bootstrap is the empty host; a clean teardown loop returns to it
// byte-for-byte.
//
// THE nf_conntrack_tcp_loose HOST BASELINE (doc 15 §11, doc 14 §5/§7.x, D68).
// NFT-6's byte-identity done-when is explicitly conditioned on
// `nf_conntrack_tcp_loose=0` from the NFT-1 host-baseline artifact. The reason is
// a kernel subtlety, not a footnote: the kernel default is loose=1, under which a
// flushed flow's mid-stream packets are "picked up" as a FRESH established
// conntrack entry and sail through the established-accept rule — so the
// flush_session conntrack kill (delete-by-ct-mark) is a SILENT NO-OP and the
// session's flow residue survives teardown (docs/sessions/round2/03). With
// loose=0 a flushed flow has no entry, its packets classify INVALID, and the kill
// is real. modeledHost therefore carries the host baseline as a field and the
// teardown flush kills the conntrack flow ONLY when loose=0 — so the byte-identity
// loop tests the done-when WITH its stated precondition, and a loose=1 host
// (baseline violated) is observably NOT byte-identical (the negative control).
type modeledHost struct {
	nft      map[string]nftObjects
	domains  map[string]string // session → domainUUID
	overlays map[string]string // session → overlayPath
	ctFlows  map[string]uint64 // session → live conntrack flow, keyed by its per-session ct mark (D44/D76)
	flushes  int               // count of flush_session(legs=all) invocations

	// tcpLooseZero models the `nf_conntrack_tcp_loose=0` host baseline (doc 15 §11).
	// true = the required baseline (the flush kill is effective); false = the kernel
	// default loose=1 (the flush kill is a silent no-op — the revocation/teardown
	// flow residue survives). The N-loop byte-identity done-when REQUIRES this true.
	tcpLooseZero bool
}

// newModeledHost builds a host AT THE REQUIRED NFT-6 baseline
// (`nf_conntrack_tcp_loose=0`, doc 15 §11): the create→destroy loop's conntrack
// flush is effective. newModeledHostLoose models the baseline-violated kernel
// default (loose=1) for the negative control.
func newModeledHost() *modeledHost { return newHostWithBaseline(true) }

// newModeledHostLoose builds a host with the NFT-6 baseline VIOLATED
// (`nf_conntrack_tcp_loose=1`, the kernel default): the teardown conntrack flush
// is a silent no-op (docs/sessions/round2/03), so a flow leaks across teardown.
func newModeledHostLoose() *modeledHost { return newHostWithBaseline(false) }

func newHostWithBaseline(tcpLooseZero bool) *modeledHost {
	return &modeledHost{
		nft:          map[string]nftObjects{},
		domains:      map[string]string{},
		overlays:     map[string]string{},
		ctFlows:      map[string]uint64{},
		tcpLooseZero: tcpLooseZero,
	}
}

// create instantiates the per-session host-side state for the lifecycle's create
// half: the per-session NFT objects (empty allow sets + DNS-2b map + ct-mark +
// iface rule), the booted domain, and the qcow2 overlay. hostSessionIndex is the
// never-recycled monotonic index the ct-mark residue rides (D76); a fresh index
// per iteration is the real host's burn-on-allocate posture (D66).
func (h *modeledHost) create(sessionUUID string, hostSessionIndex uint64) {
	tap := fmt.Sprintf("dstap-%d", hostSessionIndex)
	h.nft[sessionUUID] = nftObjects{
		tapName:   tap,
		allow4Set: "allow4_" + sessionUUID,
		allow6Set: "allow6_" + sessionUUID,
		dns2bMap:  "dns2b_" + sessionUUID,
		ctMark:    0xD0000000 | (hostSessionIndex & 0x3FFF),
		ifaceRule: "iifname " + tap + " accept",
	}
	h.domains[sessionUUID] = "domain-" + sessionUUID
	h.overlays[sessionUUID] = "/var/lib/ds/overlays/" + sessionUUID + ".qcow2"
	// A live session carries at least one established conntrack flow, stamped with
	// its per-session ct mark (D44/D76). This is the residue the §4.2 flush_session
	// kill must clear; whether the kill is effective depends on the host baseline.
	h.ctFlows[sessionUUID] = h.nft[sessionUUID].ctMark
}

// destroy runs the §4.2 host-local teardown: domain destroy → UNCONDITIONAL
// flush_session(legs=all) in the NFT-6 order (interface rules → named sets +
// DNS-2b map → conntrack by mark) → overlay disposal. The flush is UNCONDITIONAL
// (D68): it is counted on every destroy and converges to a no-op for a session
// with no live objects. Idempotent on session_uuid.
func (h *modeledHost) destroy(sessionUUID string) {
	// step 1: guest VM destroy (idempotent — absent domain is a no-op).
	delete(h.domains, sessionUUID)
	// step 2: UNCONDITIONAL flush_session — the NFT-6 order is the deletion order;
	// the kernel atomicity is ds-nft's. Counted even when there are no live objects.
	h.flushes++
	delete(h.nft, sessionUUID)
	// step 2b: the conntrack-by-mark kill leg of flush_session. The static NFT
	// objects (rules / sets / maps) delete unconditionally, but the conntrack flow
	// kill is effective ONLY at the `nf_conntrack_tcp_loose=0` host baseline
	// (doc 15 §11). At the kernel default loose=1 the kill is a SILENT NO-OP —
	// mid-stream packets re-establish a fresh entry (docs/sessions/round2/03) — so
	// the flow residue SURVIVES teardown and the loop is not byte-identical.
	if h.tcpLooseZero {
		delete(h.ctFlows, sessionUUID)
	}
	// step 3: overlay disposal + durability finalize (idempotent — absent is no-op).
	delete(h.overlays, sessionUUID)
}

// ruleset serializes the modeled host to a STABLE string for the byte-identity
// assertion (NFT-6). Bootstrap (no sessions) is the empty ruleset; a clean
// teardown returns to it byte-for-byte. Domains + overlays are folded in so a
// leak there (an orphaned VM / dangling CoW overlay) also fails the assertion.
func (h *modeledHost) ruleset() string {
	var sb strings.Builder
	sb.WriteString("table ds-sessions {\n")
	for _, k := range sortedKeys(h.nft) {
		o := h.nft[k]
		fmt.Fprintf(&sb, "  session %s {\n", k)
		fmt.Fprintf(&sb, "    rule %s\n", o.ifaceRule)
		fmt.Fprintf(&sb, "    set %s {}\n", o.allow4Set)
		fmt.Fprintf(&sb, "    set %s {}\n", o.allow6Set)
		fmt.Fprintf(&sb, "    map %s\n", o.dns2bMap)
		fmt.Fprintf(&sb, "    ctmark 0x%x\n", o.ctMark)
		sb.WriteString("  }\n")
	}
	sb.WriteString("}\n")
	for _, k := range sortedStrMap(h.domains) {
		fmt.Fprintf(&sb, "domain %s -> %s\n", k, h.domains[k])
	}
	for _, k := range sortedStrMap(h.overlays) {
		fmt.Fprintf(&sb, "overlay %s -> %s\n", k, h.overlays[k])
	}
	// The conntrack flow residue is folded in so a flow the teardown flush failed
	// to kill (the loose=1 silent no-op, doc 15 §11) breaks byte-identity exactly
	// the way a leaked rule / set / overlay does — making the host baseline a
	// load-bearing precondition of the NFT-6 done-when, not a doc-comment.
	for _, k := range sortedU64Map(h.ctFlows) {
		fmt.Fprintf(&sb, "ctflow %s -> 0x%x\n", k, h.ctFlows[k])
	}
	return sb.String()
}

func sortedKeys(m map[string]nftObjects) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedStrMap(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedU64Map(m map[string]uint64) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestTeardown_CreateDestroyLoopByteIdenticalToBootstrap is the (b) clean-teardown
// / NFT-6 done-when at the e2e tier: a create→destroy loop run N times leaves the
// modeled ruleset byte-identical to bootstrap, the flush ran once per destroy
// (unconditional, D68), and nothing leaked.
func TestTeardown_CreateDestroyLoopByteIdenticalToBootstrap(t *testing.T) {
	h := newModeledHost()
	bootstrap := h.ruleset()
	if !strings.Contains(bootstrap, "table ds-sessions {") {
		t.Fatalf("bootstrap ruleset malformed: %q", bootstrap)
	}

	const n = 5
	var index uint64 = 1 // index 0 is the reserved "unallocated" sentinel
	for i := 0; i < n; i++ {
		sess := fmt.Sprintf("sess-%d", i)
		h.create(sess, index)
		index++ // NEVER recycle (D66): a fresh index every iteration
		// Between create and destroy the ruleset MUST differ from bootstrap — a
		// non-vacuous loop proves the objects really were instantiated.
		if mid := h.ruleset(); mid == bootstrap {
			t.Fatalf("iter %d: ruleset unchanged after create — the loop is vacuous", i)
		}
		h.destroy(sess)
	}

	if got := h.ruleset(); got != bootstrap {
		t.Fatalf("NFT-6 leak: ruleset after %d create→destroy loops not byte-identical to bootstrap\n--- bootstrap ---\n%s\n--- got ---\n%s", n, bootstrap, got)
	}
	if len(h.nft) != 0 || len(h.domains) != 0 || len(h.overlays) != 0 {
		t.Fatalf("clean-teardown leak: nft=%d domains=%d overlays=%d", len(h.nft), len(h.domains), len(h.overlays))
	}
	if h.flushes != n {
		t.Fatalf("expected %d unconditional flush_session invocations (one per destroy, D68), got %d", n, h.flushes)
	}
}

// TestTeardown_NegativeControl_LeakBreaksByteIdentity proves the byte-identity
// assertion is NOT vacuous: if a destroy were to LEAK a session's NFT objects (a
// broken teardown), the ruleset would NOT return to bootstrap. We simulate the
// leak by creating without destroying and assert the assertion catches it — so a
// regression that strands host-side state can never slip past the loop test above.
func TestTeardown_NegativeControl_LeakBreaksByteIdentity(t *testing.T) {
	h := newModeledHost()
	bootstrap := h.ruleset()

	h.create("sess-leaked", 1)
	// Deliberately DO NOT destroy — model a teardown that failed to flush.
	if got := h.ruleset(); got == bootstrap {
		t.Fatal("a leaked session left the ruleset byte-identical to bootstrap — the (b) clean-teardown assertion would be vacuous (it cannot detect a leak)")
	}

	// And confirm a proper destroy DOES return to bootstrap (the leak is the only
	// difference) — so the assertion is targeted, not a blanket mismatch.
	h.destroy("sess-leaked")
	if got := h.ruleset(); got != bootstrap {
		t.Fatalf("after destroying the leaked session the ruleset must return to bootstrap\n--- bootstrap ---\n%s\n--- got ---\n%s", bootstrap, got)
	}
}

// TestTeardown_FlushIsUnconditional asserts flush_session runs even for a destroy
// of a session with no live objects (D68 — the unconditional posture): a teardown
// can never leak by being skipped. The flush count increments and the host stays
// at bootstrap.
func TestTeardown_FlushIsUnconditional(t *testing.T) {
	h := newModeledHost()
	bootstrap := h.ruleset()
	h.destroy("sess-orphan-never-created")
	if h.flushes != 1 {
		t.Errorf("flush_session must run unconditionally even with no recorded host-side state (D68); flushes=%d, want 1", h.flushes)
	}
	if got := h.ruleset(); got != bootstrap {
		t.Errorf("an unconditional flush of a non-existent session must converge to bootstrap (no-op), got:\n%s", got)
	}
}

// TestNFT6_RequiresTcpLooseZeroBaseline closes the explicit doc 15 §11 clause that
// the NFT-6 byte-identity done-when "requires nf_conntrack_tcp_loose=0 from the
// host baseline" — the one part of the (b) NFT-6 row the byte-identity loop above
// asserted only in prose. It is a paired positive/negative assertion:
//
//   - AT the baseline (loose=0): the create→destroy N-loop's conntrack flush is
//     effective, the per-session flow is killed, and the ruleset returns
//     byte-identical to bootstrap. (The same done-when the loop above asserts, now
//     with its precondition modeled explicitly rather than assumed.)
//   - WITH the baseline VIOLATED (loose=1, the kernel default): the conntrack kill
//     is a SILENT no-op (docs/sessions/round2/03 — mid-stream packets re-establish
//     a fresh entry), the flow residue SURVIVES teardown, and the ruleset is NOT
//     byte-identical. This is the negative control proving the baseline is
//     load-bearing: without it the NFT-6 "kill" is not a kill and teardown leaks.
func TestNFT6_RequiresTcpLooseZeroBaseline(t *testing.T) {
	const n = 5

	// runLoop drives n create→destroy iterations on a host at the given baseline and
	// returns whether the final ruleset is byte-identical to bootstrap plus any
	// surviving conntrack-flow leak count.
	runLoop := func(h *modeledHost) (byteIdentical bool, ctLeaks int) {
		bootstrap := h.ruleset()
		var index uint64 = 1 // index 0 is the reserved "unallocated" sentinel (D66)
		for i := 0; i < n; i++ {
			sess := fmt.Sprintf("sess-%d", i)
			h.create(sess, index)
			index++ // NEVER recycle (D66)
			// Non-vacuity: a live session must carry a conntrack flow to kill, else the
			// loose=0/loose=1 distinction would be untestable.
			if _, ok := h.ctFlows[sess]; !ok {
				t.Fatalf("iter %d: a created session must carry a live conntrack flow for the flush to kill", i)
			}
			h.destroy(sess)
		}
		return h.ruleset() == bootstrap, len(h.ctFlows)
	}

	t.Run("loose0-baseline-flush-is-effective-byte-identical", func(t *testing.T) {
		h := newModeledHost() // nf_conntrack_tcp_loose=0 — the required NFT-1 baseline
		if !h.tcpLooseZero {
			t.Fatal("newModeledHost must model the required nf_conntrack_tcp_loose=0 baseline")
		}
		identical, leaks := runLoop(h)
		if !identical {
			t.Errorf("at the nf_conntrack_tcp_loose=0 baseline the NFT-6 loop must return byte-identical to bootstrap (the flush kill is effective)")
		}
		if leaks != 0 {
			t.Errorf("at loose=0 the teardown flush must kill every conntrack flow; %d flow(s) leaked", leaks)
		}
	})

	t.Run("loose1-baseline-violated-flush-noop-leaks", func(t *testing.T) {
		h := newModeledHostLoose() // nf_conntrack_tcp_loose=1 — the kernel default, baseline VIOLATED
		if h.tcpLooseZero {
			t.Fatal("newModeledHostLoose must model the baseline-violated nf_conntrack_tcp_loose=1 default")
		}
		identical, leaks := runLoop(h)
		if identical {
			t.Errorf("with nf_conntrack_tcp_loose=1 (baseline VIOLATED) the conntrack flush is a silent no-op (doc 15 §11; docs/sessions/round2/03) — the loop MUST NOT be byte-identical to bootstrap, else the NFT-6 done-when's stated precondition would be vacuous")
		}
		if leaks != n {
			t.Errorf("with loose=1 every session's conntrack flow must survive the no-op flush; want %d leaked flows, got %d", n, leaks)
		}
	})
}
