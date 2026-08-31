package tlsproxy

// TLS-LC — clean session teardown (doc 06 §3(b), NFT-6 lockstep) and
// TLS-LD — load/fan-out budgets and cross-session bleed (doc 06 §3(d)).

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// planRef: doc 06 §3(b) clean-teardown row ("no stranded proxy session");
// doc 09 NFT-6 lockstep + DNS-2b flush. e2e-lifecycle.
func TestLifecycle_SessionTeardown_NoStrandedProxyState(t *testing.T) {
	ctx := context.Background()
	h := newInspectHarness(t)
	up := &recordingUpstream{}
	h.dialer.tlsFn = up.dialTLS
	h.policy.allow("github.com")

	exercise := func(sess SessionRef) {
		t.Helper()
		h.admit(sess, "github.com", time.Hour, ip("140.82.1.1"))
		resp, _, err := h.inspectRequest(sess, "github.com", ap("140.82.1.1:443"),
			newReq(t, http.MethodGet, "https://github.com/live", nil, ""))
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("session %s positive control: status=%v err=%v", sess.ID, resp, err)
		}
	}
	refuseReplay := func(sess SessionRef) {
		t.Helper()
		conn, _ := h.startTransparent(sess, ap("140.82.1.1:443"))
		defer conn.Close()
		// Replaying the old session's parameters — including its (old) CA
		// trust pool — must fail: no admission honored, old CA rejected.
		if _, err := h.sessionTLSClient(conn, sess, "github.com"); err == nil {
			t.Errorf("post-teardown connection for %s must be refused", sess.ID)
		}
	}

	// Live session with tunnels, cached leaf, swap-capable state.
	old := SessionRef{ID: "sess-old"}
	exercise(old)
	if err := h.proxy.TeardownSession(ctx, old); err != nil {
		t.Fatalf("TeardownSession must complete cleanly: %v", err)
	}
	dialsAfterTeardown := h.dialer.dialCount()
	refuseReplay(old)
	if n := h.dialer.dialCount(); n != dialsAfterTeardown {
		t.Errorf("a torn-down session drove %d new upstream dials (stranded state)", n-dialsAfterTeardown)
	}

	// N create→destroy cycles leave the proxy at fresh-boot behavior.
	// TLS-LC.a observable: every cycle must present a fresh-boot-equivalent
	// call pattern to the dependencies — identical per-cycle upstream-dial
	// and leaf-mint counts. Residue from earlier cycles (cached leaves,
	// swap state, stale admissions) shows up as per-cycle growth.
	const cycles = 5
	dialDeltas := make([]int, cycles)
	leafMints := make([]int, cycles)
	for i := 0; i < cycles; i++ {
		s := SessionRef{ID: fmt.Sprintf("sess-cycle-%d", i)}
		before := h.dialer.dialCount()
		exercise(s)
		if err := h.proxy.TeardownSession(ctx, s); err != nil {
			t.Fatalf("cycle %d teardown: %v", i, err)
		}
		dialDeltas[i] = h.dialer.dialCount() - before
		leafMints[i] = h.cas.caFor(s).leafCount()
	}
	for i := 1; i < cycles; i++ {
		if dialDeltas[i] != dialDeltas[0] {
			t.Errorf("cycle %d drove %d upstream dial(s), cycle 0 drove %d: per-cycle proxy state is not fresh-boot-equivalent", i, dialDeltas[i], dialDeltas[0])
		}
		if leafMints[i] != leafMints[0] {
			t.Errorf("cycle %d minted %d leaf cert(s), cycle 0 minted %d: cached-leaf/CA residue across teardown", i, leafMints[i], leafMints[0])
		}
	}
	dialsAfterCycles := h.dialer.dialCount()
	for i := 0; i < cycles; i++ {
		refuseReplay(SessionRef{ID: fmt.Sprintf("sess-cycle-%d", i)})
	}
	if n := h.dialer.dialCount(); n != dialsAfterCycles {
		t.Errorf("cycled sessions still drive upstream dials after teardown (%d leaked)", n-dialsAfterCycles)
	}

	// A fresh session still works — teardown removed state, not capability.
	exercise(SessionRef{ID: "sess-fresh"})
}

// loadP99Budget is the (d)-rig added-latency budget the harness asserts even
// at CI scale; the scheduled rig runs the full fan-out.
const loadP99Budget = 25 * time.Millisecond

// planRef: doc 06 §3(d) proxy throughput + p99 under fan-out; doc 09 Stage 5.
// category: load.
func TestLoad_FanOutP99WithinBudget_NoVerdictBleed(t *testing.T) {
	if testing.Short() {
		t.Skip("load: scheduled (d) rig")
	}
	ctx := context.Background()
	const nSessions, mFlows = 4, 6
	h := newHarness(t)

	domains := make([]string, nSessions)
	sessions := make([]SessionRef, nSessions)
	for i := range domains {
		domains[i] = fmt.Sprintf("domain-%d.example", i)
		sessions[i] = SessionRef{ID: fmt.Sprintf("sess-%d", i)}
	}
	origin := newTLSOrigin(t, "echo", domains...)
	h.dialer.rawFn = origin.dialRaw

	// Per-session distinct policies: session i may reach ONLY domain i.
	h.policy.connectFn = func(sess SessionRef, domain string) (Decision, bool) {
		for i := range sessions {
			if sess == sessions[i] {
				if domain == domains[i] {
					return Decision{Allow: true, Provenance: Provenance{RuleID: "allow:" + domain, PolicyLayer: "session", PolicyVersion: "policy-v1"}}, true
				}
				return Decision{Allow: false, Provenance: Provenance{RuleID: "deny:cross-session", PolicyLayer: "session", PolicyVersion: "policy-v1"}}, true
			}
		}
		return Decision{}, false
	}
	for i := range sessions {
		h.admit(sessions[i], domains[i], time.Hour, ip(fmt.Sprintf("10.0.%d.1", i)))
	}

	type sample struct {
		d   time.Duration
		err error
	}
	results := make(chan sample, nSessions*mFlows)
	var wg sync.WaitGroup
	for i := 0; i < nSessions; i++ {
		for j := 0; j < mFlows; j++ {
			wg.Add(1)
			go func(i, j int) {
				defer wg.Done()
				start := time.Now()
				conn, _ := h.startTransparent(sessions[i], ap(fmt.Sprintf("10.0.%d.1:443", i)))
				defer conn.Close()
				tc := tls.Client(conn, &tls.Config{RootCAs: origin.pool, ServerName: domains[i]})
				if err := tc.Handshake(); err != nil {
					results <- sample{0, fmt.Errorf("sess-%d flow %d handshake: %w", i, j, err)}
					return
				}
				payload := []byte(fmt.Sprintf("probe-%d-%d", i, j))
				if _, err := tc.Write(payload); err != nil {
					results <- sample{0, fmt.Errorf("sess-%d flow %d write: %w", i, j, err)}
					return
				}
				echo := make([]byte, len(payload))
				if _, err := io.ReadFull(tc, echo); err != nil {
					results <- sample{0, fmt.Errorf("sess-%d flow %d read: %w", i, j, err)}
					return
				}
				if !bytes.Equal(echo, payload) {
					results <- sample{0, fmt.Errorf("sess-%d flow %d: payload cross-contaminated: %q", i, j, echo)}
					return
				}
				results <- sample{time.Since(start), nil}
			}(i, j)
		}
	}
	wg.Wait()
	close(results)
	var latencies []time.Duration
	for r := range results {
		if r.err != nil {
			t.Error(r.err)
			continue
		}
		latencies = append(latencies, r.d)
	}
	if len(latencies) == 0 {
		t.Fatal("no flows completed under fan-out")
	}
	sort.Slice(latencies, func(a, b int) bool { return latencies[a] < latencies[b] })
	p99 := latencies[int(float64(len(latencies)-1)*0.99)]
	if p99 > loadP99Budget {
		t.Errorf("p99 added latency %v exceeds the budget %v", p99, loadP99Budget)
	}

	// Zero verdict bleed: every (session, domain) pair gets ITS verdict.
	for i := range sessions {
		for j := range domains {
			dec, err := h.gate.Evaluate(ctx, sessions[i], ClientHello{SNI: domains[j]}, ap(fmt.Sprintf("10.0.%d.1:443", j)))
			if err != nil {
				t.Fatalf("Evaluate(sess-%d, domain-%d): %v", i, j, err)
			}
			if i == j && (dec.Action == ActionRefuse || dec.Action == ActionUnknown) {
				t.Errorf("session %d refused its OWN domain under fan-out (action %v)", i, dec.Action)
			}
			if i != j && dec.Action != ActionRefuse {
				t.Errorf("VERDICT BLEED: session %d admitted session %d's domain (action %v)", i, j, dec.Action)
			}
		}
	}
}

// planRef: doc 06 §3(d) × §9 credential row — the leak-absence invariant must
// hold under race, not just single-flight. category: load. ADVERSARIAL.
func TestLoad_ConcurrentSwaps_NoCrossSessionCredentialBleed(t *testing.T) {
	if testing.Short() {
		t.Skip("load: scheduled (d) rig")
	}
	const kSessions, reqsPer = 4, 5
	h := newInspectHarness(t)
	const host = "api.github.com"
	h.policy.allow(host)
	h.policy.mu.Lock()
	h.policy.swapRules = []ServiceRule{{Service: "github", Hosts: []string{host}, CredLocation: "header:Authorization"}}
	h.policy.mu.Unlock()
	up := &recordingUpstream{handler: func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}}
	h.dialer.tlsFn = up.dialTLS

	sessions := make([]SessionRef, kSessions)
	canaries := make([][]byte, kSessions)
	shorts := make([]Credential, kSessions)
	for i := range sessions {
		sessions[i] = SessionRef{ID: fmt.Sprintf("sess-%d", i)}
		canaries[i] = newCanary(t, 64)
		shorts[i] = h.identity.mint(sessions[i], "github", time.Hour)
		h.secrets.programForSession("github", sessions[i],
			Credential{Value: Secret(canaries[i]), Fingerprint: fmt.Sprintf("fp-long-github-%d", i)})
		h.admit(sessions[i], host, time.Hour, ip("140.82.1.1"))
		h.cas.poolFor(t, sessions[i]) // pre-mint CAs on the test goroutine
	}

	// Pre-build all requests on the test goroutine (aggressive reuse of one
	// upstream + tight interleave to provoke state bleed).
	type job struct {
		i   int
		req *http.Request
	}
	var jobs []job
	for i := 0; i < kSessions; i++ {
		for j := 0; j < reqsPer; j++ {
			jobs = append(jobs, job{i, newReq(t, http.MethodGet,
				fmt.Sprintf("https://%s/sess-%d/op-%d", host, i, j),
				map[string]string{"Authorization": bearer(shorts[i])}, "")})
		}
	}
	errs := make(chan error, len(jobs))
	var wg sync.WaitGroup
	for _, jb := range jobs {
		wg.Add(1)
		go func(jb job) {
			defer wg.Done()
			resp, _, err := h.inspectRequest(sessions[jb.i], host, ap("140.82.1.1:443"), jb.req)
			if err != nil {
				errs <- fmt.Errorf("%s %s: %w", sessions[jb.i].ID, jb.req.URL.Path, err)
				return
			}
			if resp.StatusCode != http.StatusOK {
				errs <- fmt.Errorf("%s %s: status %d", sessions[jb.i].ID, jb.req.URL.Path, resp.StatusCode)
				return
			}
			errs <- nil
		}(jb)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}

	// Every upstream request carries exactly its own session's canary.
	reqs := up.requests()
	if len(reqs) != kSessions*reqsPer {
		t.Errorf("upstream saw %d requests, want %d", len(reqs), kSessions*reqsPer)
	}
	for _, r := range reqs {
		var owner int
		if _, err := fmt.Sscanf(r.Path, "/sess-%d/", &owner); err != nil {
			t.Errorf("unattributable upstream request path %q", r.Path)
			continue
		}
		auth := r.Header.Get("Authorization")
		for k := range sessions {
			has := strings.Contains(auth, string(canaries[k]))
			if k == owner && !has {
				t.Errorf("session %d's upstream request lost its own credential", owner)
			}
			if k != owner && has {
				t.Errorf("CREDENTIAL BLEED: session %d's request carried session %d's long-lived credential", owner, k)
			}
		}
	}

	// Zero canary hits on any VM surface, for every session's canary.
	h.probe.snapshotEnv()
	allEvents := serializeEvents(h.events.all())
	for k := range sessions {
		requireZeroLeaks(t, h.probe, sessions[k], canaries[k])
		requireNoCanary(t, allEvents, canaries[k], fmt.Sprintf("captured events (session %d canary)", k))
	}

	// CredentialUseEvents attribute correctly per session.
	for k := range sessions {
		ev, ok := findEventContaining(h.events.all(), EventCredentialUse, fmt.Sprintf("fp-long-github-%d", k))
		if !ok {
			t.Errorf("missing CredentialUseEvent for session %d", k)
			continue
		}
		if ev.Session != sessions[k] {
			t.Errorf("CredentialUseEvent for session %d's key attributed to %q", k, ev.Session.ID)
		}
	}
}
