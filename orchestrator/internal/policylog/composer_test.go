package policylog

import (
	"context"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// testLayerDecoder decodes an append row's payload as a tiny scriptable layer:
// the payload is "<scope>|<sessionID>|allow=a,b|deny=c". This stands in for the
// ds-contracts POL-1 parse (opaque in this package) so the composer's deny-wins
// fold + sectioning can be asserted without that schema.
type testLayerDecoder struct{ rows map[int64]layerSpec }

type layerSpec struct {
	scope     LayerScope
	sessionID string
	allow     []string
	deny      []string
}

func (d testLayerDecoder) DecodeLayer(row store.PolicyLogRow) (Layer, string, bool) {
	spec, ok := d.rows[row.Seq]
	if !ok {
		return Layer{}, "", false
	}
	return Layer{Scope: spec.scope, Allow: spec.allow, Deny: spec.deny}, spec.sessionID, true
}

// testGrantDecoder yields a grant's rule key from a per-seq script.
type testGrantDecoder struct{ rules map[int64]string }

func (d testGrantDecoder) DecodeGrant(row store.PolicyLogRow) (string, bool) {
	r, ok := d.rules[row.Seq]
	return r, ok
}

// TestDefaultComposer_SharedAndSessionLayers proves the composer folds host-wide
// (empty-session) append layers into the shared material and session-scoped
// layers into per-session sections, with a session inheriting the shared deny set
// (doc 13 §1 rule 2 — a session can never re-admit a baseline/org deny).
func TestDefaultComposer_SharedAndSessionLayers(t *testing.T) {
	rows := []store.PolicyLogRow{
		{Seq: 1, Kind: store.PolicyKindAppend, Actor: "sys"},
		{Seq: 2, Kind: store.PolicyKindAppend, Actor: "org-admin"},
		{Seq: 3, Kind: store.PolicyKindAppend, Actor: "dev"},
	}
	ld := testLayerDecoder{rows: map[int64]layerSpec{
		1: {scope: LayerSystemBaseline, deny: []string{"evil.example"}}, // host-wide
		2: {scope: LayerOrg, allow: []string{"github.com"}},             // host-wide
		3: {scope: LayerRepoSession, sessionID: "sess-1", allow: []string{"evil.example", "pypi.org"}},
	}}
	c := NewDefaultComposer(ld, testGrantDecoder{})

	snap, err := c.ComposeAt(context.Background(), 3, rows, time.Unix(1000, 0))
	if err != nil {
		t.Fatalf("ComposeAt: %v", err)
	}
	if snap.Seq != 3 {
		t.Errorf("Seq = %d, want 3", snap.Seq)
	}
	// One session section (sess-1). The session tried to allow evil.example, which
	// the baseline denies → deny wins, so the section's effective allow is pypi.org.
	if len(snap.Sections) != 1 || snap.Sections[0].SessionID != "sess-1" {
		t.Fatalf("want one section for sess-1, got %+v", snap.Sections)
	}
	// Re-derive what the section SHOULD compose to and assert the snapshot matches.
	wantSession := SessionComposite{
		SessionID: "sess-1",
		Composed: ComposeLayers([]Layer{
			{Scope: LayerSystemBaseline, Deny: []string{"evil.example"}},
			{Scope: LayerOrg, Allow: []string{"github.com"}},
			{Scope: LayerRepoSession, Allow: []string{"evil.example", "pypi.org"}},
		}),
	}
	wantShared := ComposeLayers([]Layer{
		{Scope: LayerSystemBaseline, Deny: []string{"evil.example"}},
		{Scope: LayerOrg, Allow: []string{"github.com"}},
	})
	want := ComposeSnapshot(3, wantShared, []SessionComposite{wantSession})
	if snap.ContentHash != want.ContentHash {
		t.Errorf("content_hash mismatch:\n got  %x\n want %x", snap.ContentHash, want.ContentHash)
	}
	// Sanity: the session must NOT re-admit evil.example.
	for _, a := range wantSession.Composed.Allow {
		if a == "evil.example" {
			t.Fatal("deny-overrides violated: session re-admitted a baseline-denied key")
		}
	}
}

// TestDefaultComposer_LiveGrantFold proves a live ask-grant folds into its
// session section while an EXPIRED grant is dropped (doc 13 §1 rule 8): the
// composer evaluates grant liveness against `now`.
func TestDefaultComposer_LiveGrantFold(t *testing.T) {
	now := time.Unix(2000, 0)
	expired := time.Unix(1000, 0)
	future := time.Unix(3000, 0)
	rows := []store.PolicyLogRow{
		{Seq: 1, Kind: store.PolicyKindAskGrant, Actor: "p-ada", SessionUUID: "sess-1", ExpiresAt: &future},
		{Seq: 2, Kind: store.PolicyKindAskGrant, Actor: "p-ada", SessionUUID: "sess-1", ExpiresAt: &expired},
	}
	gd := testGrantDecoder{rules: map[int64]string{1: "allow github.com", 2: "allow stale.example"}}
	c := NewDefaultComposer(testLayerDecoder{}, gd)

	got, err := c.ComposeAt(context.Background(), 2, rows, now)
	if err != nil {
		t.Fatalf("ComposeAt: %v", err)
	}
	// Only the live grant survives. Re-derive the expected section.
	want := ComposeSnapshot(2, ComposedPolicy{}, []SessionComposite{{
		SessionID: "sess-1",
		Grants:    []LiveGrant{{Rule: "allow github.com", ExpiresUnix: future.Unix()}},
	}})
	if got.ContentHash != want.ContentHash {
		t.Errorf("content_hash mismatch (expired grant not dropped?):\n got  %x\n want %x", got.ContentHash, want.ContentHash)
	}
}

// TestDefaultComposer_UndecodableRowFailsClosed proves an append the decoder does
// not own contributes NOTHING (fail-closed) — it never fabricates an admit.
func TestDefaultComposer_UndecodableRowFailsClosed(t *testing.T) {
	rows := []store.PolicyLogRow{{Seq: 1, Kind: store.PolicyKindAppend, Actor: "x"}}
	c := NewDefaultComposer(testLayerDecoder{rows: map[int64]layerSpec{}}, testGrantDecoder{}) // decodes nothing

	got, err := c.ComposeAt(context.Background(), 1, rows, time.Unix(0, 0))
	if err != nil {
		t.Fatalf("ComposeAt: %v", err)
	}
	// No layers decoded → empty shared, no sections → identical to an empty log.
	empty := ComposeSnapshot(1, ComposedPolicy{}, nil)
	if got.ContentHash != empty.ContentHash {
		t.Errorf("an undecodable append changed the snapshot — fail-closed violated")
	}
}
