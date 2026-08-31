package store

import (
	"context"
	"errors"
	"testing"

	hostagentv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hostagent/v1"
)

// TestPolicyHead proves the additive policy-head query: an empty log reports head 0 (no
// policy applied yet), and after appends the head is the latest appended seq (the single
// policy version namespace, D36/D72). It is composed from the existing ListPolicy, so it
// can never drift from the rows the host agents replay.
func TestPolicyHead(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()

	// Empty log → head 0 (the "no policy applied yet" baseline the staleness filter
	// treats conservatively).
	head, err := PolicyHead(ctx, m)
	if err != nil {
		t.Fatalf("PolicyHead (empty): %v", err)
	}
	if head != 0 {
		t.Fatalf("empty-log head = %d, want 0", head)
	}

	// Append three rows; the head is the latest seq.
	var lastSeq int64
	for i := 0; i < 3; i++ {
		row, aerr := m.AppendPolicy(ctx, PolicyLogRow{
			Kind:        PolicyKindAppend,
			Actor:       "admin-1",
			ContentHash: "h",
			Payload:     []byte("{}"),
		})
		if aerr != nil {
			t.Fatalf("AppendPolicy[%d]: %v", i, aerr)
		}
		lastSeq = row.Seq
	}

	head, err = PolicyHead(ctx, m)
	if err != nil {
		t.Fatalf("PolicyHead (after appends): %v", err)
	}
	if head != uint64(lastSeq) {
		t.Fatalf("head = %d, want the latest appended seq %d", head, lastSeq)
	}
}

// fakeHostSnapshots is a synthetic HostAppliedSeqSource (D50): a host_id→snapshot map
// resolving SnapshotForHost as the O(1) point read HostAppliedSeq drives. An err field
// lets a test assert HostAppliedSeq surfaces a source fault verbatim.
type fakeHostSnapshots struct {
	byHost map[string]HeartbeatSnapshot
	err    error
}

func (f fakeHostSnapshots) SnapshotForHost(_ context.Context, hostID string) (HeartbeatSnapshot, bool, error) {
	if f.err != nil {
		return HeartbeatSnapshot{}, false, f.err
	}
	snap, ok := f.byHost[hostID]
	return snap, ok, nil
}

// TestHostAppliedSeq proves the additive host-keyed O(1) applied_seq point read (D72):
// a present host reports its current applied_seq + true (the live freshness the §4.1
// step-9 re-check re-validates against); an absent host reports (0, false) so the caller
// degrades to the recorded re-check rather than hard-failing a create; a present host
// with a nil heartbeat reports (0, true) — reporting but no policy applied yet, distinct
// from absent; and a source fault is surfaced verbatim.
func TestHostAppliedSeq(t *testing.T) {
	ctx := context.Background()
	src := fakeHostSnapshots{byHost: map[string]HeartbeatSnapshot{
		"host-fresh": {HostID: "host-fresh", Heartbeat: &hostagentv1.Heartbeat{HostId: "host-fresh", AppliedSeq: 7}},
		"host-zero":  {HostID: "host-zero", Heartbeat: nil}, // reporting, but no policy applied yet
	}}

	// Present host → its current applied_seq + true.
	seq, ok, err := HostAppliedSeq(ctx, src, "host-fresh")
	if err != nil {
		t.Fatalf("HostAppliedSeq(host-fresh): %v", err)
	}
	if !ok || seq != 7 {
		t.Fatalf("HostAppliedSeq(host-fresh) = (%d, %v), want (7, true)", seq, ok)
	}

	// Absent host (vanished from the live feed) → (0, false): the caller degrades to the
	// recorded re-check (the pre-probe, backwards-compatible behavior).
	seq, ok, err = HostAppliedSeq(ctx, src, "host-gone")
	if err != nil {
		t.Fatalf("HostAppliedSeq(host-gone): %v", err)
	}
	if ok || seq != 0 {
		t.Fatalf("HostAppliedSeq(host-gone) = (%d, %v), want (0, false)", seq, ok)
	}

	// Present host with a nil heartbeat → (0, true): reporting but no policy applied yet,
	// the conservative "no policy applied" value, distinct from the absent (false) case.
	seq, ok, err = HostAppliedSeq(ctx, src, "host-zero")
	if err != nil {
		t.Fatalf("HostAppliedSeq(host-zero): %v", err)
	}
	if !ok || seq != 0 {
		t.Fatalf("HostAppliedSeq(host-zero) = (%d, %v), want (0, true)", seq, ok)
	}

	// A source fault is surfaced verbatim (never swallowed into a false).
	wantErr := errors.New("boom")
	if _, _, err := HostAppliedSeq(ctx, fakeHostSnapshots{err: wantErr}, "host-fresh"); !errors.Is(err, wantErr) {
		t.Fatalf("HostAppliedSeq (source fault) err = %v, want %v", err, wantErr)
	}
}
