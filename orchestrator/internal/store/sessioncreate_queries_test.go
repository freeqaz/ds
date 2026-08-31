package store

import (
	"context"
	"errors"
	"testing"
)

// TestCreatePreBindingSession_NoCrossSessionBurnCollision proves the additive helper
// solves the doc 15 §4.1 step-2-vs-step-4 problem: two pre-binding (unplaced) records
// on ONE store do NOT collide on the burned-index invariant (D66), because each rides
// a per-session unbound sentinel host. Without the helper, both would burn the shared
// ("", 0) sentinel and the second would be ErrInvalid.
func TestCreatePreBindingSession_NoCrossSessionBurnCollision(t *testing.T) {
	ctx := context.Background()
	repo := NewMemory()

	a, err := CreatePreBindingSession(ctx, repo, Session{
		Ref: SessionRef{SessionUUID: "sess-a"}, EnvConfigRef: "env", ImageID: "img",
	})
	if err != nil {
		t.Fatalf("first pre-binding create: %v", err)
	}
	if !IsUnboundHost(a.Ref.HostID) {
		t.Errorf("pre-binding record host %q is not the unbound sentinel", a.Ref.HostID)
	}
	if a.State != SessionPending {
		t.Errorf("pre-binding state = %q, want PENDING default", a.State)
	}

	// A SECOND unbound record on the same store must NOT collide (the bug the helper
	// fixes — a shared ("", 0) burn would make this ErrInvalid).
	b, err := CreatePreBindingSession(ctx, repo, Session{
		Ref: SessionRef{SessionUUID: "sess-b"}, EnvConfigRef: "env2", ImageID: "img2",
	})
	if err != nil {
		t.Fatalf("second pre-binding create collided on the unbound sentinel: %v", err)
	}
	if a.Ref.HostID == b.Ref.HostID {
		t.Error("two pre-binding records must carry DISTINCT unbound sentinels")
	}
}

// TestCreatePreBindingSession_AdvancesOffSentinel proves the step-4 transition: a
// pre-binding record advances off the unbound sentinel onto the real host via
// AppendIndexEpoch (the first real binding), which burns the real (host, index).
func TestCreatePreBindingSession_AdvancesOffSentinel(t *testing.T) {
	ctx := context.Background()
	repo := NewMemory()

	if _, err := CreatePreBindingSession(ctx, repo, Session{Ref: SessionRef{SessionUUID: "sess-c"}}); err != nil {
		t.Fatalf("pre-binding create: %v", err)
	}
	got, err := repo.AppendIndexEpoch(ctx, "sess-c", IndexEpoch{
		HostID: "host-a", HostSessionIndex: 9, TapName: "dstap-9",
		GuestIP: []byte{10, 0, 0, 9}, GuestIPFamily: IPFamilyV4,
	})
	if err != nil {
		t.Fatalf("step-4 AppendIndexEpoch off the sentinel: %v", err)
	}
	if got.Ref.HostID != "host-a" || got.Ref.HostSessionIndex != 9 {
		t.Errorf("Ref not advanced to the real binding: %+v", got.Ref)
	}
	if IsUnboundHost(got.Ref.HostID) {
		t.Error("Ref still on the unbound sentinel after the real binding")
	}
	// The real index is now burned: a fresh session re-allocating (host-a, 9) is refused.
	if _, err := repo.AppendIndexEpoch(ctx, "sess-c", IndexEpoch{HostID: "host-a", HostSessionIndex: 9}); !errors.Is(err, ErrInvalid) {
		t.Errorf("real binding must be burned (ErrInvalid on recycle), got %v", err)
	}
}

// TestIsUnboundHost_Discriminates proves the sentinel discriminator: only the
// unbound:<uuid> form is unbound; a real host id and the empty string are not.
func TestIsUnboundHost_Discriminates(t *testing.T) {
	if !IsUnboundHost(UnboundHostID("sess-x")) {
		t.Error("UnboundHostID output must be recognized as unbound")
	}
	if IsUnboundHost("host-a") {
		t.Error("a real host id must not be unbound")
	}
	if IsUnboundHost("") {
		t.Error("the empty host id is malformed, not the sentinel")
	}
	if IsUnboundHost(unboundHostPrefix) {
		t.Error("the bare prefix with no uuid must not be unbound")
	}
}
