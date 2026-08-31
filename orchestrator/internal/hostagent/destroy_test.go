package hostagent

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"testing"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/hypervisor/libvirt"
)

// ─────────────────────────────────────────────────────────────────────────────
// RecordingBackend — the (b) clean-teardown conformance fake (doc 06 §3b / NFT-6,
// doc 09 §3). It models the host's NFT ruleset as the set of per-session objects
// the boundary owns — the per-session interface rules, the named
// allow4_<session>/allow6_<session> sets, the DNS-2b admission-map entries, and
// the ct-mark accounting key — plus the booted libvirt domains and the qcow2
// overlays. Create-side INSTANTIATES them (CreateTap + InstantiateSessionNFT +
// CreateOverlay + Boot); the §4.2 teardown FLUSHES them in the NFT-6 order
// (interface rules → named sets + DNS-2b map → conntrack by mark). It serializes
// to a STABLE string so a create→destroy loop run N times can be asserted
// BYTE-IDENTICAL to bootstrap (NFT-6 done-when, doc 09 §3).
//
// This is the fake/RecordingBackend the task constraint requires — NOT the Go↔
// ds-nft cgo staticlib bridge (DS_NFTGATE_LIVE stays disabled; the live-metal
// binding is a separately-tracked follow-up). flush_session itself is DONE in
// ds-nft and invoked through the seam — this fake records the invocation + its
// effect on the modeled ruleset, never re-implementing the kernel semantics.
// ─────────────────────────────────────────────────────────────────────────────

// nftObjects is the per-session NFT state one InstantiateSessionNFT created.
type nftObjects struct {
	tapName   string
	allow4Set string // allow4_<session> named set (starts EMPTY per step 4)
	allow6Set string // allow6_<session> named set (dormant Phase B, D75)
	dns2bMap  string // the DNS-2b admission-map entry key for the session
	ctMark    uint64 // the ct-mark accounting key (the index residue rides it, D76)
	ifaceRule string // the per-session interface rule (iifname dstap-<idx>)
}

// RecordingBackend records every create-side instantiation and teardown flush and
// models the resulting ruleset so the loop-byte-identity assertion holds.
type RecordingBackend struct {
	// nft is the live per-session NFT objects keyed by session_uuid. Bootstrap is
	// the empty map; a clean teardown loop returns to it.
	nft map[string]nftObjects
	// domains / overlays model the booted domains and the qcow2 overlays.
	domains  map[string]string // session → domainUUID
	overlays map[string]string // session → overlayPath
	// flowlog records the final destroy byte-count events emitted (ds-flowlog).
	flowlog []string
	// flushOrder records the NFT-6 phase order observed at the LAST flush so a
	// test can assert interface rules → sets+map → conntrack-by-mark.
	flushOrder []string
	// flushedSessions records every flush_session(legs=all) invocation, in order,
	// so the unconditional-flush assertion can confirm it always ran.
	flushedSessions []string
	// burned records the indices a step-4 rollback burned (never recycled, D66).
	burned []uint64

	// fault injection (per-method, per-call):
	tapErr     error
	nftErr     error
	flushErr   error
	overlayErr error
	disposeErr error
	bootErr    error
	flowErr    error
	domainErr  error
}

func newRecordingBackend() *RecordingBackend {
	return &RecordingBackend{
		nft:      map[string]nftObjects{},
		domains:  map[string]string{},
		overlays: map[string]string{},
	}
}

// ── create-side seams (libvirt.AttachPrimitive / OverlayStore / Booter) ──────

func (b *RecordingBackend) CreateTap(_ context.Context, bind libvirt.Binding) error {
	if b.tapErr != nil {
		return b.tapErr
	}
	return nil
}

func (b *RecordingBackend) InstantiateSessionNFT(_ context.Context, sessionUUID string, bind libvirt.Binding) error {
	if b.nftErr != nil {
		return b.nftErr
	}
	// Instantiate the per-session NFT objects: the session chains + the EMPTY
	// allow{4,6}_<session> sets + the DNS-2b admission map entry + the ct-mark
	// accounting key (step 4). The sets start EMPTY — DNS-admitted destinations
	// land later through the policy path; allow6 stays dormant (Phase B, D75).
	b.nft[sessionUUID] = nftObjects{
		tapName:   bind.TapName,
		allow4Set: "allow4_" + sessionUUID,
		allow6Set: "allow6_" + sessionUUID,
		dns2bMap:  "dns2b_" + sessionUUID,
		// the 14-bit index residue rides the ct mark as a disambiguator (D76).
		ctMark:    0xD0000000 | (bind.HostSessionIndex & 0x3FFF),
		ifaceRule: "iifname " + bind.TapName + " accept",
	}
	return nil
}

func (b *RecordingBackend) CreateOverlay(_ context.Context, sessionUUID, _ string) (string, error) {
	if b.overlayErr != nil {
		return "", b.overlayErr
	}
	p := "/var/lib/ds/overlays/" + sessionUUID + ".qcow2"
	b.overlays[sessionUUID] = p
	return p, nil
}

func (b *RecordingBackend) Boot(_ context.Context, sessionUUID, _, _, _ string, _ uint32) (string, error) {
	if b.bootErr != nil {
		return "", b.bootErr
	}
	dom := "domain-" + sessionUUID
	b.domains[sessionUUID] = dom
	return dom, nil
}

// CA injector + routability gate are happy by default for the create path.
func (b *RecordingBackend) InjectCA(_ context.Context, _, _ string) error { return nil }

func (b *RecordingBackend) DigestAcked(_ context.Context, _ string) (bool, error) { return true, nil }

func (b *RecordingBackend) PolicyFresh(_ context.Context) (bool, error) { return true, nil }

// ── teardown-side seams ──────────────────────────────────────────────────────

// FlushSession is the UNCONDITIONAL flush_session(legs=all) (NFT-6, D68): it
// removes the per-session NFT objects in the frozen NFT-6 order — interface rules
// → named sets + DNS-2b map → conntrack by mark. It records the order observed and
// the invocation so the conformance + unconditional-flush assertions hold. A flush
// of a session with no live objects is a no-op convergence (idempotent), never an
// error — exactly the unconditional posture.
func (b *RecordingBackend) FlushSession(_ context.Context, sessionUUID string, _ libvirt.Binding) error {
	b.flushedSessions = append(b.flushedSessions, sessionUUID)
	if b.flushErr != nil {
		return b.flushErr
	}
	if _, ok := b.nft[sessionUUID]; ok {
		// NFT-6 phase order (interface rules → named sets + DNS-2b map → conntrack
		// by mark). Modeled as the deletion order; the kernel atomicity is ds-nft's.
		b.flushOrder = []string{"interface-rules", "named-sets+dns2b-map", "conntrack-by-mark"}
		delete(b.nft, sessionUUID)
	}
	return nil
}

func (b *RecordingBackend) DisposeOverlay(_ context.Context, overlayPath string) error {
	if b.disposeErr != nil {
		return b.disposeErr
	}
	for s, p := range b.overlays {
		if p == overlayPath {
			delete(b.overlays, s)
		}
	}
	return nil
}

// DestroyDomain (libvirt.DomainDestroyer) — idempotent: an empty/absent domain is
// a no-op (a create that failed before boot has no domain). A domainErr fault
// leaves the domain modeled (the destroy did not take) so the conformance
// assertion can confirm the FLUSH still ran past a step-1 fault.
func (b *RecordingBackend) DestroyDomain(_ context.Context, sessionUUID, domainUUID string) error {
	if b.domainErr != nil {
		return b.domainErr
	}
	delete(b.domains, sessionUUID)
	return nil
}

// FinalizeDurabilityStream (libvirt.DurabilityFinalizer) — a no-op record here;
// the durability stream is modeled as closed when the overlay is disposed.
func (b *RecordingBackend) FinalizeDurabilityStream(_ context.Context, _, _ string) error {
	return nil
}

// EmitDestroyByteCounts (libvirt.FlowByteCounter) — emits the final ds-flowlog
// byte-count event for the session. Read from conntrack-by-mark before the
// conntrack flush; non-fatal to teardown.
func (b *RecordingBackend) EmitDestroyByteCounts(_ context.Context, sessionUUID string, bind libvirt.Binding) error {
	if b.flowErr != nil {
		return b.flowErr
	}
	b.flowlog = append(b.flowlog, fmt.Sprintf("destroy %s ctmark=0x%x bytes=final", sessionUUID, 0xD0000000|(bind.HostSessionIndex&0x3FFF)))
	return nil
}

// ── §4.2 step 4–6 seams (host-agent) ─────────────────────────────────────────

func (b *RecordingBackend) FlushDigests(_ context.Context, _ string) error { return nil }

func (b *RecordingBackend) RevokeIdentity(_ context.Context, _, _, _ string) error { return nil }

func (b *RecordingBackend) ReportDestroyed(_ context.Context, _ string) error { return nil }

func (b *RecordingBackend) BurnIndex(_ context.Context, _ string, idx uint64) error {
	b.burned = append(b.burned, idx)
	return nil
}

// Ruleset serializes the modeled ruleset to a STABLE string for the loop-byte-
// identity assertion (NFT-6). Bootstrap (no sessions) is the empty ruleset; a
// clean teardown returns to it byte-for-byte.
func (b *RecordingBackend) Ruleset() string {
	keys := make([]string, 0, len(b.nft))
	for k := range b.nft {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	sb.WriteString("table ds-sessions {\n")
	for _, k := range keys {
		o := b.nft[k]
		fmt.Fprintf(&sb, "  session %s {\n", k)
		fmt.Fprintf(&sb, "    rule %s\n", o.ifaceRule)
		fmt.Fprintf(&sb, "    set %s {}\n", o.allow4Set)
		fmt.Fprintf(&sb, "    set %s {}\n", o.allow6Set)
		fmt.Fprintf(&sb, "    map %s\n", o.dns2bMap)
		fmt.Fprintf(&sb, "    ctmark 0x%x\n", o.ctMark)
		sb.WriteString("  }\n")
	}
	sb.WriteString("}\n")
	// Domains + overlays are part of the clean-teardown surface (no orphaned VM,
	// no dangling CoW overlay) — fold them in so a leak there also fails the
	// byte-identity assertion.
	doms := make([]string, 0, len(b.domains))
	for k := range b.domains {
		doms = append(doms, k)
	}
	sort.Strings(doms)
	for _, k := range doms {
		fmt.Fprintf(&sb, "domain %s -> %s\n", k, b.domains[k])
	}
	ovs := make([]string, 0, len(b.overlays))
	for k := range b.overlays {
		ovs = append(ovs, k)
	}
	sort.Strings(ovs)
	for _, k := range ovs {
		fmt.Fprintf(&sb, "overlay %s -> %s\n", k, b.overlays[k])
	}
	return sb.String()
}

// ─────────────────────────────────────────────────────────────────────────────
// test wiring
// ─────────────────────────────────────────────────────────────────────────────

// newCreateAgent builds the libvirt create driver over the RecordingBackend.
func newCreateAgent(t *testing.T, b *RecordingBackend, counter *seedCounter) *libvirt.HostAgent {
	t.Helper()
	plan := libvirt.AddressPlan{Subnet: netip.MustParsePrefix("10.42.0.0/16"), HostOffset: 2}
	alloc, err := libvirt.NewAllocator(counter, plan)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	h, err := libvirt.NewHostAgent(alloc, b, b, b, b, b)
	if err != nil {
		t.Fatalf("NewHostAgent: %v", err)
	}
	return h
}

// newDestroyAgent builds the host-agent §4.2 destroy orchestrator over the
// RecordingBackend.
func newDestroyAgent(t *testing.T, b *RecordingBackend) *Destroyer {
	t.Helper()
	libv, err := libvirt.NewDestroyer(b, b, b, b, b)
	if err != nil {
		t.Fatalf("libvirt.NewDestroyer: %v", err)
	}
	d, err := NewDestroyer(DestroyDeps{
		Libvirt:  libv,
		Digests:  b,
		Identity: b,
		Reporter: b,
		Indices:  b,
	})
	if err != nil {
		t.Fatalf("hostagent.NewDestroyer: %v", err)
	}
	return d
}

// seedCounter is a process-local monotonic IndexCounter for the conformance loop —
// it NEVER recycles (the never-recycle invariant, D66): each Next() advances, so a
// create→destroy loop draws a FRESH index every iteration, exactly the real host's
// burn-on-allocate posture.
type seedCounter struct{ next uint64 }

func (c *seedCounter) Next() (uint64, error) {
	idx := c.next
	c.next++
	return idx, nil
}

func goodCreateReq(sessionUUID string) libvirt.CreateRequest {
	return libvirt.CreateRequest{
		SessionUUID:         sessionUUID,
		ImageID:             "img-abc",
		EntrypointConfigRef: "entry-ref",
		CABundleRef:         "ca-ref",
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// (b) clean-teardown / NFT-6: create→destroy loop run N times is byte-identical
// ─────────────────────────────────────────────────────────────────────────────

func TestCreateDestroyLoopByteIdenticalToBootstrap(t *testing.T) {
	b := newRecordingBackend()
	counter := &seedCounter{next: 1} // index 0 is reserved "unallocated"
	creator := newCreateAgent(t, b, counter)
	destroyer := newDestroyAgent(t, b)

	bootstrap := b.Ruleset()
	if !strings.Contains(bootstrap, "table ds-sessions {") {
		t.Fatalf("bootstrap ruleset malformed: %q", bootstrap)
	}

	const n = 5
	for i := 0; i < n; i++ {
		sess := fmt.Sprintf("sess-%d", i)
		res, err := creator.CreateSession(context.Background(), goodCreateReq(sess))
		if err != nil {
			t.Fatalf("iter %d: CreateSession: %v", i, err)
		}
		if !res.Routable {
			t.Fatalf("iter %d: create should be routable", i)
		}
		// Between create and destroy the ruleset MUST differ from bootstrap (a
		// non-vacuous loop: the objects really were instantiated).
		if mid := b.Ruleset(); mid == bootstrap {
			t.Fatalf("iter %d: ruleset unchanged after create — the loop is vacuous", i)
		}

		dres, err := destroyer.Destroy(context.Background(), DestroyRequest{
			SessionUUID: sess,
			HostID:      "host-1",
			Binding:     res.Binding,
			HasBinding:  true,
			DomainUUID:  res.DomainUUID,
			OverlayPath: res.Binding.OverlayPath,
			IdentityRef: "id-" + sess,
			CARef:       "ca-" + sess,
		})
		if err != nil {
			t.Fatalf("iter %d: Destroy: %v", i, err)
		}
		// UNCONDITIONAL flush ran, and every §4.2 step ran.
		if !dres.Libvirt.SessionFlushed {
			t.Fatalf("iter %d: flush_session(legs=all) must run unconditionally (D68)", i)
		}
		if !dres.DigestsFlushed || !dres.IdentityRevoked || !dres.Reported {
			t.Fatalf("iter %d: full §4.2 order incomplete: %+v", i, dres)
		}
	}

	// NFT-6 DONE-WHEN: after N create→destroy loops the ruleset is BYTE-IDENTICAL
	// to bootstrap — no leaked NFTables rules / allow-set entries, no orphaned VM,
	// no dangling CoW overlay.
	if got := b.Ruleset(); got != bootstrap {
		t.Fatalf("NFT-6 leak: ruleset after %d create→destroy loops not byte-identical to bootstrap\n--- bootstrap ---\n%s\n--- got ---\n%s", n, bootstrap, got)
	}
	if len(b.nft) != 0 || len(b.domains) != 0 || len(b.overlays) != 0 {
		t.Fatalf("clean-teardown leak: nft=%d domains=%d overlays=%d", len(b.nft), len(b.domains), len(b.overlays))
	}
	// Unconditional flush: one flush per destroyed session.
	if len(b.flushedSessions) != n {
		t.Fatalf("expected %d unconditional flushes, got %d", n, len(b.flushedSessions))
	}
	// Final byte counts emitted into ds-flowlog (doc 14 §5), one per destroy.
	if len(b.flowlog) != n {
		t.Fatalf("expected %d ds-flowlog destroy byte-count events, got %d", n, len(b.flowlog))
	}
}

func TestDestroyHonorsNFT6Order(t *testing.T) {
	b := newRecordingBackend()
	creator := newCreateAgent(t, b, &seedCounter{next: 1})
	destroyer := newDestroyAgent(t, b)

	res, err := creator.CreateSession(context.Background(), goodCreateReq("sess-x"))
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if _, err := destroyer.Destroy(context.Background(), DestroyRequest{
		SessionUUID: "sess-x", HostID: "host-1", Binding: res.Binding, HasBinding: true,
		DomainUUID: res.DomainUUID, OverlayPath: res.Binding.OverlayPath,
	}); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	want := []string{"interface-rules", "named-sets+dns2b-map", "conntrack-by-mark"}
	if strings.Join(b.flushOrder, ",") != strings.Join(want, ",") {
		t.Errorf("NFT-6 order = %v, want %v (interface rules → named sets + DNS-2b map → conntrack by mark)", b.flushOrder, want)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// UNCONDITIONAL flush_session(legs=all) on destroy
// ─────────────────────────────────────────────────────────────────────────────

func TestDestroyFlushIsUnconditionalEvenWithoutBinding(t *testing.T) {
	b := newRecordingBackend()
	destroyer := newDestroyAgent(t, b)
	// No binding, no domain, no overlay — the unconditional flush MUST still run.
	res, err := destroyer.Destroy(context.Background(), DestroyRequest{
		SessionUUID: "sess-orphan", HostID: "host-1",
	})
	if err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if !res.Libvirt.SessionFlushed {
		t.Error("flush_session(legs=all) must run unconditionally even with no recorded host-side state (D68)")
	}
	if len(b.flushedSessions) != 1 || b.flushedSessions[0] != "sess-orphan" {
		t.Errorf("expected one unconditional flush of sess-orphan, got %v", b.flushedSessions)
	}
	// A binding-less teardown emits NO byte counts (no ct-mark accounting).
	if res.Libvirt.ByteCountsEmitted {
		t.Error("a binding-less teardown has no ct-mark accounting to emit")
	}
}

func TestDestroyFlushRunsEvenWhenDomainDestroyFaults(t *testing.T) {
	// A domain that won't destroy must NOT strand the NFT objects — the
	// unconditional flush runs past the step-1 fault (clean teardown wins).
	b := newRecordingBackend()
	creator := newCreateAgent(t, b, &seedCounter{next: 1})
	res, _ := creator.CreateSession(context.Background(), goodCreateReq("sess-d"))
	b.domainErr = errors.New("libvirt domain destroy: device busy") // step-1 fault
	destroyer := newDestroyAgent(t, b)

	dres, err := destroyer.Destroy(context.Background(), DestroyRequest{
		SessionUUID: "sess-d", HostID: "host-1", Binding: res.Binding, HasBinding: true,
		DomainUUID: res.DomainUUID, OverlayPath: res.Binding.OverlayPath,
	})
	// The step-1 fault is surfaced, but the flush + overlay disposal STILL ran
	// (the order is unconditional — a stranded domain must never strand the NFT
	// objects, the exact "slow rot" the doc 06 (b) clean-teardown row guards).
	if err == nil {
		t.Error("a domain-destroy fault should be surfaced")
	}
	var de *libvirt.DestroyError
	if !errors.As(err, &de) || de.Step != libvirt.DestroyStepDomain {
		t.Errorf("first fault should surface at DestroyStepDomain, got %v", err)
	}
	if !dres.Libvirt.SessionFlushed {
		t.Error("flush_session(legs=all) must run past a step-1 domain-destroy fault (D68, clean teardown wins)")
	}
	if !dres.Libvirt.OverlayDisposed {
		t.Error("overlay disposal must run past a step-1 domain-destroy fault")
	}
	if len(b.nft) != 0 || len(b.overlays) != 0 {
		t.Errorf("a step-1 fault must not strand NFT objects/overlay: nft=%d overlays=%d", len(b.nft), len(b.overlays))
	}
}

func TestDestroyByteCountFaultIsNonFatal(t *testing.T) {
	// A ds-flowlog hiccup must NOT abort the teardown (the missed event is a
	// warning, never a leak): the flush + overlay disposal still run.
	b := newRecordingBackend()
	creator := newCreateAgent(t, b, &seedCounter{next: 1})
	res, _ := creator.CreateSession(context.Background(), goodCreateReq("sess-f"))
	b.flowErr = errors.New("flowlog spool full")
	destroyer := newDestroyAgent(t, b)

	dres, err := destroyer.Destroy(context.Background(), DestroyRequest{
		SessionUUID: "sess-f", HostID: "host-1", Binding: res.Binding, HasBinding: true,
		DomainUUID: res.DomainUUID, OverlayPath: res.Binding.OverlayPath,
	})
	// The first fault is surfaced, but the teardown still flushed + disposed.
	if err == nil {
		t.Error("a byte-count fault should be surfaced as a teardown warning")
	}
	if !dres.Libvirt.SessionFlushed || !dres.Libvirt.OverlayDisposed {
		t.Error("a non-fatal byte-count fault must not abort the flush + overlay disposal (clean teardown wins)")
	}
	if len(b.nft) != 0 || len(b.overlays) != 0 {
		t.Errorf("teardown must complete despite the flowlog fault: nft=%d overlays=%d", len(b.nft), len(b.overlays))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// §4.1 create-rollback compensations
// ─────────────────────────────────────────────────────────────────────────────

// step-4 failure → flush_session + NFT-6 for the partial allocation + BURN the
// consumed index (never recycle, D66).
func TestRollbackStep4FlushesAndBurnsIndex(t *testing.T) {
	b := newRecordingBackend()
	b.nftErr = errors.New("instantiate session nft EBUSY") // fail at step 4
	counter := &seedCounter{next: 7}
	creator := newCreateAgent(t, b, counter)
	destroyer := newDestroyAgent(t, b)

	_, err := creator.CreateSession(context.Background(), goodCreateReq("sess-r4"))
	var ce *libvirt.CreateError
	if !errors.As(err, &ce) || ce.Step != libvirt.StepAllocate {
		t.Fatalf("want StepAllocate CreateError, got %v", err)
	}
	if !ce.HasBinding {
		t.Fatal("step-4 failure must surface the (burned-index) binding for rollback")
	}
	consumedIndex := ce.Binding.HostSessionIndex

	res, err := destroyer.Rollback(context.Background(), "host-1", ce)
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if !res.Libvirt.SessionFlushed {
		t.Error("step-4 rollback must run flush_session(legs=all) for the partial allocation (§4.1)")
	}
	if !res.IndexBurned {
		t.Error("step-4 rollback must BURN the consumed index (never recycle, D66)")
	}
	if len(b.burned) != 1 || b.burned[0] != consumedIndex {
		t.Errorf("burned indices = %v, want [%d]", b.burned, consumedIndex)
	}
	// No identity/CA existed yet (step 5 not reached) — no revocation.
	if res.IdentityRevoked {
		t.Error("step-4 rollback must NOT revoke identity (none minted before step 5)")
	}
	// The next allocation must NOT recycle the consumed index (the counter advanced).
	if counter.next <= consumedIndex {
		t.Errorf("counter must have advanced past the burned index %d (next=%d)", consumedIndex, counter.next)
	}
	// Clean teardown: the NFT objects are flushed.
	if len(b.nft) != 0 {
		t.Errorf("step-4 rollback leaked NFT objects: %d", len(b.nft))
	}
}

// steps 5–6 failure → flush written digests + signal identity/CA revocation (plus
// the host-side flush for the partial allocation).
func TestRollbackStep6FlushesDigestsAndRevokes(t *testing.T) {
	b := newRecordingBackend()
	destroyer := newDestroyAgent(t, b)

	// Drive a real step-6 failure: un-acked digest gate. Build a creator whose gate
	// returns acked=false by wrapping the backend with a not-acked gate.
	plan := libvirt.AddressPlan{Subnet: netip.MustParsePrefix("10.42.0.0/16"), HostOffset: 2}
	alloc, _ := libvirt.NewAllocator(&seedCounter{next: 1}, plan)
	creator, err := libvirt.NewHostAgent(alloc, b, b, b, b, notAckedGate{})
	if err != nil {
		t.Fatalf("NewHostAgent: %v", err)
	}

	_, err = creator.CreateSession(context.Background(), goodCreateReq("sess-r6"))
	var ce *libvirt.CreateError
	if !errors.As(err, &ce) || ce.Step != libvirt.StepDigestAck {
		t.Fatalf("want StepDigestAck CreateError, got %v", err)
	}

	res, err := destroyer.Rollback(context.Background(), "host-1", ce)
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if !res.Libvirt.SessionFlushed {
		t.Error("step-6 rollback must flush the partial host-side allocation")
	}
	if !res.DigestsFlushed {
		t.Error("step-6 rollback must flush written digests (§4.1)")
	}
	if !res.IdentityRevoked {
		t.Error("step-6 rollback must signal identity/CA revocation (§4.1)")
	}
	if len(b.nft) != 0 {
		t.Errorf("step-6 rollback leaked NFT objects: %d", len(b.nft))
	}
}

// steps 7–8 failure → destroy the domain + dispose the overlay (full host-local
// teardown) BEFORE unwinding step 4, then revoke identity/CA.
func TestRollbackStep7DestroysDomainAndDisposesOverlay(t *testing.T) {
	b := newRecordingBackend()
	b.bootErr = errors.New("libvirt domain define failed") // fail at step 8 (boot)
	creator := newCreateAgent(t, b, &seedCounter{next: 1})
	destroyer := newDestroyAgent(t, b)

	_, err := creator.CreateSession(context.Background(), goodCreateReq("sess-r8"))
	var ce *libvirt.CreateError
	if !errors.As(err, &ce) || ce.Step != libvirt.StepBoot {
		t.Fatalf("want StepBoot CreateError, got %v", err)
	}
	if ce.OverlayPath == "" || !ce.HasBinding {
		t.Fatal("step-8 failure must surface overlay + binding for rollback")
	}

	res, err := destroyer.Rollback(context.Background(), "host-1", ce)
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if !res.Libvirt.SessionFlushed {
		t.Error("step-8 rollback must run flush_session for the allocation")
	}
	if !res.Libvirt.OverlayDisposed {
		t.Error("step-8 rollback must dispose the overlay (§4.1)")
	}
	if !res.IdentityRevoked {
		t.Error("step-8 rollback must revoke identity/CA (live from step 5)")
	}
	// Clean teardown: no leaked NFT objects, no dangling overlay.
	if len(b.nft) != 0 || len(b.overlays) != 0 {
		t.Errorf("step-8 rollback leaked: nft=%d overlays=%d", len(b.nft), len(b.overlays))
	}
}

// step 1–3 failure (StepNone, pre-allocation) → nothing host-side exists; the
// rollback is a clean no-op (the record is finalized with an audit event by the
// coordinator).
func TestRollbackStepNoneIsNoHostSideCompensation(t *testing.T) {
	b := newRecordingBackend()
	destroyer := newDestroyAgent(t, b)
	ce := &libvirt.CreateError{Step: libvirt.StepNone, SessionUUID: "sess-r0", HasBinding: false}

	res, err := destroyer.Rollback(context.Background(), "host-1", ce)
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if res.Libvirt.SessionFlushed || res.IndexBurned || res.IdentityRevoked {
		t.Error("a pre-allocation (StepNone) rollback owes NO host-side compensation")
	}
	if len(b.flushedSessions) != 0 {
		t.Errorf("StepNone rollback must not flush (nothing host-side exists), got %v", b.flushedSessions)
	}
}

// A create→rollback loop (step-8 failure each time) is ALSO byte-identical to
// bootstrap — every rollback satisfies the (b) clean-teardown checklist.
func TestCreateRollbackLoopByteIdenticalToBootstrap(t *testing.T) {
	b := newRecordingBackend()
	b.bootErr = errors.New("boot fails every time")
	counter := &seedCounter{next: 1}
	creator := newCreateAgent(t, b, counter)
	destroyer := newDestroyAgent(t, b)
	bootstrap := b.Ruleset()

	const n = 4
	for i := 0; i < n; i++ {
		_, err := creator.CreateSession(context.Background(), goodCreateReq(fmt.Sprintf("sess-rb-%d", i)))
		var ce *libvirt.CreateError
		if !errors.As(err, &ce) {
			t.Fatalf("iter %d: want CreateError, got %v", i, err)
		}
		if _, err := destroyer.Rollback(context.Background(), "host-1", ce); err != nil {
			t.Fatalf("iter %d: Rollback: %v", i, err)
		}
	}
	if got := b.Ruleset(); got != bootstrap {
		t.Fatalf("create→rollback loop leaked: not byte-identical to bootstrap\n--- bootstrap ---\n%s\n--- got ---\n%s", bootstrap, got)
	}
}

func TestNewDestroyerRejectsNilDeps(t *testing.T) {
	b := newRecordingBackend()
	libv, _ := libvirt.NewDestroyer(b, b, b, b, b)
	if _, err := NewDestroyer(DestroyDeps{Libvirt: nil, Digests: b, Identity: b, Reporter: b, Indices: b}); err == nil {
		t.Error("nil libvirt destroyer should be rejected")
	}
	if _, err := NewDestroyer(DestroyDeps{Libvirt: libv, Digests: nil, Identity: b, Reporter: b, Indices: b}); err == nil {
		t.Error("nil digest flusher should be rejected")
	}
	if _, err := NewDestroyer(DestroyDeps{Libvirt: libv, Digests: b, Identity: b, Reporter: b, Indices: nil}); err == nil {
		t.Error("nil index burner should be rejected")
	}
}

// notAckedGate satisfies libvirt.RoutabilityGate with a not-acked digest so the
// create surfaces a step-6 failure.
type notAckedGate struct{}

func (notAckedGate) DigestAcked(context.Context, string) (bool, error) { return false, nil }
func (notAckedGate) PolicyFresh(context.Context) (bool, error)         { return true, nil }
