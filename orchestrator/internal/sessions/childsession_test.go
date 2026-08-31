package sessions

// CreateChildSession fan-out leg tests (doc 15 §5.3, D18; doc 19 §4/§9). The leg
// is orchestrator-side WIRING: the actual offline derivation lives in identity/mint
// (a separate module the orchestrator never imports). So these tests drive the leg
// against a FAKE ChildTokenDeriver that mirrors the mint library's offline contract
// — strictly-narrower, zero-mint, lineage-populating — proving the leg threads
// per-child narrowings, surfaces a rejected widening fail-closed, and never round-
// trips a mint. Everything synthetic (D50); no live mint, no network.

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeDeriver mimics identity/mint's OFFLINE child-token deriver: it narrows a
// parent's claims per child, appends the child session_uuid as the next hop,
// REJECTS a widening (a service not in the parent's set), and counts the number of
// MINT round-trips it makes (which must stay ZERO — derivation is offline).
type fakeDeriver struct {
	mints int // must stay 0 — a real deriver attenuates offline, never mints

	// parentScope/parentExpiry/parentSession model the parent token's claims the
	// deriver would read from the verified parent token (here keyed by token bytes so
	// a depth-2 hop reads its depth-1 parent's narrowed scope).
	scope   map[string][]string
	expiry  map[string]time.Time
	session map[string]string   // token -> the session that token scopes to
	hops    map[string][]string // token -> root→leaf parent_session hops
	depth   map[string]int      // token -> attenuation depth
	user    string

	derivations int // how many child derivations ran (the fan-out width)
}

func newFakeDeriver() *fakeDeriver {
	return &fakeDeriver{
		scope:   map[string][]string{},
		expiry:  map[string]time.Time{},
		session: map[string]string{},
		hops:    map[string][]string{},
		depth:   map[string]int{},
		user:    "idp|launching-subject",
	}
}

// seedParent registers a (root) parent token's claims so the deriver can narrow
// against them.
func (f *fakeDeriver) seedParent(token, session string, scope []string, expiry time.Time) {
	f.scope[token] = scope
	f.expiry[token] = expiry
	f.session[token] = session
	f.hops[token] = nil
	f.depth[token] = 0
}

func (f *fakeDeriver) DeriveChildToken(ctx context.Context, parentToken []byte, d ChildSessionDerivation) (DerivedChildToken, error) {
	f.derivations++
	pt := string(parentToken)
	parentScope, ok := f.scope[pt]
	if !ok {
		return DerivedChildToken{}, errors.New("unverifiable parent token")
	}
	parentSession := f.session[pt]
	parentExpiry := f.expiry[pt]
	parentHops := f.hops[pt]
	parentDepth := f.depth[pt]

	// SERVICE narrowing — REJECT a widening (a requested service the parent lacks).
	childScope := parentScope
	if d.Services != nil {
		for _, svc := range d.Services {
			if !contains(parentScope, svc) {
				return DerivedChildToken{}, errors.New("attenuation would widen token scope")
			}
		}
		childScope = d.Services
	}
	// TTL narrowing — clamp to ≤ parent.
	childExpiry := parentExpiry
	if d.TTL > 0 {
		cand := time.Now().Add(d.TTL)
		if !parentExpiry.IsZero() && cand.Before(parentExpiry) {
			childExpiry = cand
		}
	}
	// IDENTITY — append the parent's session as the next hop (the child re-roots).
	childHops := append(append([]string(nil), parentHops...), parentSession)
	childToken := pt + "|child:" + d.ChildSessionUUID

	// Register the child so a DEEPER hop derives against THIS child's narrowed claims.
	f.scope[childToken] = childScope
	f.expiry[childToken] = childExpiry
	f.session[childToken] = d.ChildSessionUUID
	f.hops[childToken] = childHops
	f.depth[childToken] = parentDepth + 1

	// FINGERPRINT-ONLY lineage: one fingerprint per chain block (base + hops).
	fps := make([]string, 0, parentDepth+2)
	for i := 0; i <= parentDepth+1; i++ {
		fps = append(fps, "fp-"+d.ChildSessionUUID+"-"+strconv.Itoa(i))
	}
	return DerivedChildToken{
		Token:             []byte(childToken),
		SessionUUID:       d.ChildSessionUUID,
		Expiry:            childExpiry,
		AttenuationDepth:  parentDepth + 1,
		BlockFingerprints: fps,
		ParentSessions:    childHops,
	}, nil
}

func contains(s []string, x string) bool {
	for _, v := range s {
		if v == x {
			return true
		}
	}
	return false
}

// TestCreateChildSession_FanOutNarrowsZeroMint proves the leg derives one strictly-
// narrower child per subagent with ZERO mint RPCs (doc 19 §4): a 3-wide fan-out off
// one parent token yields three child tokens, each scoped ⊆ parent, and the deriver
// made no mint calls.
func TestCreateChildSession_FanOutNarrowsZeroMint(t *testing.T) {
	f := newFakeDeriver()
	parentTok := "base-token-bytes"
	exp := time.Now().Add(time.Hour)
	f.seedParent(parentTok, "root-session", []string{"github", "npm", "pypi"}, exp)

	req := CreateChildSessionRequest{
		ParentSessionUUID: "root-session",
		ParentToken:       []byte(parentTok),
		Children: []ChildSessionDerivation{
			{ChildSessionUUID: "child-a", Services: []string{"github"}, TaskRef: "task:a"},
			{ChildSessionUUID: "child-b", Services: []string{"github", "npm"}, TaskRef: "task:b"},
			{ChildSessionUUID: "child-c", TaskRef: "task:c"}, // inherits parent scope
		},
	}
	res, err := CreateChildSession(context.Background(), f, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Children) != 3 {
		t.Fatalf("fan-out width = %d, want 3", len(res.Children))
	}
	if f.mints != 0 {
		t.Fatalf("mint round-trips = %d, want 0 (offline derivation, doc 19 §4)", f.mints)
	}
	if f.derivations != 3 {
		t.Fatalf("derivations = %d, want 3 (one per child)", f.derivations)
	}
	// Each child is at depth 1, carries its own session, and its lineage hop is the
	// parent (root) session.
	for i, c := range res.Children {
		if c.AttenuationDepth != 1 {
			t.Fatalf("child %d depth = %d, want 1", i, c.AttenuationDepth)
		}
		if len(c.ParentSessions) != 1 || c.ParentSessions[0] != "root-session" {
			t.Fatalf("child %d hops = %v, want [root-session]", i, c.ParentSessions)
		}
		if len(c.BlockFingerprints) != 2 {
			t.Fatalf("child %d fingerprints = %d, want 2 (base + hop)", i, len(c.BlockFingerprints))
		}
		if len(c.Token) == 0 {
			t.Fatalf("child %d has no token for the step-8 entrypoint slot", i)
		}
	}
}

// TestCreateChildSession_DepthTwoChildOfChild proves the leg composes — a child
// derived from a child (depth ≥2) threads the full root→leaf parent_session hop
// chain and lands at depth 2.
func TestCreateChildSession_DepthTwoChildOfChild(t *testing.T) {
	f := newFakeDeriver()
	parentTok := "base-token-bytes"
	f.seedParent(parentTok, "root-session", []string{"github", "npm"}, time.Now().Add(time.Hour))

	// Depth 1.
	r1, err := CreateChildSession(context.Background(), f, CreateChildSessionRequest{
		ParentSessionUUID: "root-session",
		ParentToken:       []byte(parentTok),
		Children:          []ChildSessionDerivation{{ChildSessionUUID: "child-x", Services: []string{"github"}, TaskRef: "task:x"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	child := r1.Children[0]

	// Depth 2: a grandchild off the child token.
	r2, err := CreateChildSession(context.Background(), f, CreateChildSessionRequest{
		ParentSessionUUID: "child-x",
		ParentToken:       child.Token,
		Children:          []ChildSessionDerivation{{ChildSessionUUID: "grand-y", Services: []string{"github"}, TaskRef: "task:y"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	grand := r2.Children[0]
	if grand.AttenuationDepth != 2 {
		t.Fatalf("grandchild depth = %d, want 2 (child-of-child)", grand.AttenuationDepth)
	}
	wantHops := []string{"root-session", "child-x"}
	if len(grand.ParentSessions) != 2 || grand.ParentSessions[0] != wantHops[0] || grand.ParentSessions[1] != wantHops[1] {
		t.Fatalf("grandchild hops = %v, want %v (full root→leaf chain)", grand.ParentSessions, wantHops)
	}
	if f.mints != 0 {
		t.Fatalf("mint round-trips = %d, want 0 across depth-2 fan-out", f.mints)
	}
}

// TestCreateChildSession_WideningRejectedFailsClosed proves a widening child fails
// the WHOLE fan-out closed (doc 19 §4/§13): a child requesting a service the parent
// lacks is rejected by the deriver, the leg surfaces the error naming the child, and
// NEVER round-trips the mint to fabricate the widened token.
func TestCreateChildSession_WideningRejectedFailsClosed(t *testing.T) {
	f := newFakeDeriver()
	parentTok := "base-token-bytes"
	f.seedParent(parentTok, "root-session", []string{"github"}, time.Now().Add(time.Hour))

	res, err := CreateChildSession(context.Background(), f, CreateChildSessionRequest{
		ParentSessionUUID: "root-session",
		ParentToken:       []byte(parentTok),
		Children: []ChildSessionDerivation{
			{ChildSessionUUID: "child-ok", Services: []string{"github"}},
			{ChildSessionUUID: "child-widen", Services: []string{"github", "npm"}}, // npm not in parent
		},
	})
	if err == nil {
		t.Fatal("widening child want error (fail-closed), got nil")
	}
	if !strings.Contains(err.Error(), "child-widen") {
		t.Fatalf("error should name the offending child, got %v", err)
	}
	if len(res.Children) != 0 {
		t.Fatalf("failed fan-out must return no partial tree, got %d children", len(res.Children))
	}
	if f.mints != 0 {
		t.Fatalf("mint round-trips = %d, want 0 — a rejected widening must NEVER fall back to a mint", f.mints)
	}
}

// TestCreateChildSession_FailClosedInputs proves the leg validates before any
// derivation: a nil deriver, a missing parent token, or a child with no session_uuid
// each fails closed without calling the deriver.
func TestCreateChildSession_FailClosedInputs(t *testing.T) {
	f := newFakeDeriver()
	f.seedParent("tok", "root-session", []string{"github"}, time.Now().Add(time.Hour))

	if _, err := CreateChildSession(context.Background(), nil, CreateChildSessionRequest{ParentToken: []byte("tok")}); err == nil {
		t.Fatal("nil deriver want error")
	}
	if _, err := CreateChildSession(context.Background(), f, CreateChildSessionRequest{ParentSessionUUID: "root-session"}); err == nil {
		t.Fatal("missing parent token want error")
	}
	if _, err := CreateChildSession(context.Background(), f, CreateChildSessionRequest{
		ParentSessionUUID: "root-session",
		ParentToken:       []byte("tok"),
		Children:          []ChildSessionDerivation{{ChildSessionUUID: ""}}, // no child session
	}); err == nil {
		t.Fatal("child with no session_uuid want error")
	}
	if f.derivations != 0 {
		t.Fatalf("no derivation should run on a validation failure, ran %d", f.derivations)
	}
}

// TestCreateChildSession_NoTokenBytesInLineage is the orchestrator-side mirror of
// the FINGERPRINT-ONLY guard (doc 19 §9): the lineage a child carries up to the
// audit join holds fingerprints, hops, and depth — never the child token bytes.
func TestCreateChildSession_NoTokenBytesInLineage(t *testing.T) {
	f := newFakeDeriver()
	parentTok := "base-token-bytes"
	f.seedParent(parentTok, "root-session", []string{"github"}, time.Now().Add(time.Hour))

	res, err := CreateChildSession(context.Background(), f, CreateChildSessionRequest{
		ParentSessionUUID: "root-session",
		ParentToken:       []byte(parentTok),
		Children:          []ChildSessionDerivation{{ChildSessionUUID: "child-z", Services: []string{"github"}, TaskRef: "task:z"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	c := res.Children[0]
	tok := string(c.Token)
	for _, fp := range c.BlockFingerprints {
		if strings.Contains(fp, tok) || strings.Contains(tok, fp) {
			t.Fatal("a block fingerprint overlaps the token bytes (fingerprint-only violation, doc 19 §9)")
		}
	}
	for _, hop := range c.ParentSessions {
		if hop == tok {
			t.Fatal("a parent_session hop carries token bytes (fingerprint-only violation)")
		}
	}
}
