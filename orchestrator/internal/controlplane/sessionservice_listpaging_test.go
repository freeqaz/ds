package controlplane

// sessionservice_listpaging_test.go drives the ListSessions pagination + launching_user filter
// legs (doc 15 §5.3; the frozen ListSessionsRequest page_size/page_token/launching_user fields).
// It pins, over the in-memory store fake (no live VM/host-agent/podman):
//   - page_size == 0 returns ALL sessions in one shot (BACK-COMPAT — single-call clients are
//     never silently truncated) and an empty next_page_token;
//   - page_size > 0 paginates and a next_page_token round-trip walks every session EXACTLY ONCE
//     across pages (no dup, no skip), in the store's stable newest-first order — exercised both
//     across distinct CreatedAt values and across a CreatedAt tie (the session_uuid tiebreak);
//   - the launching_user filter narrows to the sessions one principal launched (resolver-backed),
//     excluding sessions with no launching principal, and refuses Unavailable when the resolver is
//     unwired (never leaking the unfiltered fleet);
//   - a malformed page_token is InvalidArgument;
//   - pagination composes with the launching_user filter.
// All seams are fakes — the *store.Memory backing store + a resolver wrapped over its
// ResolveLaunchingUserClaim.

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	orchestratorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/orchestrator/v1"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// seedSessionsClock seeds n sessions into a fresh in-memory store at the given created-at,
// uuid prefix and host. host_session_index is unique per session (indices are burned per host).
// It returns the store for further seeding/wiring.
func seedSessionsAt(t *testing.T, st *store.Memory, created time.Time, prefix, host string, n int, idxBase uint64) {
	t.Helper()
	for i := 0; i < n; i++ {
		uuid := prefix + "-" + string(rune('a'+i))
		if _, err := st.CreateSession(context.Background(), store.Session{
			Ref: store.SessionRef{
				SessionUUID:      uuid,
				HostID:           host,
				HostSessionIndex: idxBase + uint64(i),
				TapName:          "tap-" + uuid,
			},
			EnvConfigRef: testEnvRef,
			CreatedAt:    created,
		}); err != nil {
			t.Fatalf("seed %s: %v", uuid, err)
		}
	}
}

// listAllPages walks ListSessions to exhaustion with the given page_size, returning the ordered
// uuids seen and asserting no page exceeds the requested size. A request with the same filters
// (host/launching_user) is repeated per page, carrying the prior page's next_page_token.
func listAllPages(t *testing.T, svc *SessionService, base *orchestratorv1.ListSessionsRequest, pageSize uint32) []string {
	t.Helper()
	var got []string
	token := ""
	for pages := 0; ; pages++ {
		if pages > 1000 {
			t.Fatalf("pagination did not terminate after 1000 pages (cursor not advancing)")
		}
		req := &orchestratorv1.ListSessionsRequest{
			HostId:        base.GetHostId(),
			LaunchingUser: base.GetLaunchingUser(),
			PageSize:      pageSize,
			PageToken:     token,
		}
		resp, err := svc.ListSessions(context.Background(), req)
		if err != nil {
			t.Fatalf("ListSessions(page_size=%d, token=%q): %v", pageSize, token, err)
		}
		if pageSize > 0 && len(resp.GetSessions()) > int(pageSize) {
			t.Fatalf("page returned %d sessions, want <= page_size %d", len(resp.GetSessions()), pageSize)
		}
		for _, s := range resp.GetSessions() {
			got = append(got, s.GetSessionUuid())
		}
		token = resp.GetNextPageToken()
		if token == "" {
			return got
		}
		// A non-final page must be full (we only emit a continuation token when more remain).
		if pageSize > 0 && len(resp.GetSessions()) != int(pageSize) {
			t.Fatalf("non-final page returned %d sessions with a continuation token, want a full page of %d", len(resp.GetSessions()), pageSize)
		}
	}
}

// TestListSessions_PageSizeZeroReturnsAll pins the BACK-COMPAT contract: page_size == 0 (the
// existing single-call clients — serpent / serpent-tui) returns the WHOLE matching set in one
// shot and an EMPTY next_page_token. Pagination is strictly opt-in; an unset page_size must NEVER
// silently truncate.
func TestListSessions_PageSizeZeroReturnsAll(t *testing.T) {
	st := store.NewMemoryClock(func() time.Time { return time.Unix(1_700_000_000, 0).UTC() })
	seedSessionsAt(t, st, time.Unix(1_700_000_900, 0).UTC(), "sess", testHostID, 7, 1)

	svc := newSessionService(nil, nil, nil, testOrg, nil, nil)
	svc.SetListServing(st)

	resp, err := svc.ListSessions(context.Background(), &orchestratorv1.ListSessionsRequest{}) // page_size == 0
	if err != nil {
		t.Fatalf("ListSessions(page_size=0): %v", err)
	}
	if len(resp.GetSessions()) != 7 {
		t.Fatalf("page_size=0 returned %d sessions, want ALL 7 (back-compat single-shot)", len(resp.GetSessions()))
	}
	if resp.GetNextPageToken() != "" {
		t.Fatalf("page_size=0 returned a next_page_token %q, want empty (single-shot)", resp.GetNextPageToken())
	}
}

// TestListSessions_PaginationWalksEverySessionOnce seeds N sessions and walks the whole set via the
// returned next_page_token at a page_size below N, asserting the token round-trip covers EVERY
// session exactly once (no dup, no skip) AND in the same stable newest-first order page_size==0
// returns. It exercises BOTH distinct CreatedAt values and a CreatedAt TIE (the session_uuid
// tiebreak the cursor must respect), since the boundary between two records tied on CreatedAt is
// the cursor's hardest case.
func TestListSessions_PaginationWalksEverySessionOnce(t *testing.T) {
	st := store.NewMemoryClock(func() time.Time { return time.Unix(1_700_000_000, 0).UTC() })
	// Two created-at buckets: 4 newer + 3 older. The 4 newer share ONE created-at (the tiebreak
	// case); the 3 older share another. Across buckets the order is created-at DESC.
	seedSessionsAt(t, st, time.Unix(1_700_000_900, 0).UTC(), "new", testHostID, 4, 1)
	seedSessionsAt(t, st, time.Unix(1_700_000_100, 0).UTC(), "old", testHostID, 3, 100)

	svc := newSessionService(nil, nil, nil, testOrg, nil, nil)
	svc.SetListServing(st)

	// The ground truth: the full single-shot order (page_size == 0).
	full, err := svc.ListSessions(context.Background(), &orchestratorv1.ListSessionsRequest{})
	if err != nil {
		t.Fatalf("ListSessions(full): %v", err)
	}
	var want []string
	for _, s := range full.GetSessions() {
		want = append(want, s.GetSessionUuid())
	}
	if len(want) != 7 {
		t.Fatalf("seeded set = %d, want 7", len(want))
	}

	for _, pageSize := range []uint32{1, 2, 3, 6, 7, 100} {
		got := listAllPages(t, svc, &orchestratorv1.ListSessionsRequest{}, pageSize)
		if len(got) != len(want) {
			t.Fatalf("page_size=%d walked %d sessions, want %d (no skip/dup)", pageSize, len(got), len(want))
		}
		// Exact-order equality: pagination must reproduce the single-shot stable order.
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("page_size=%d order mismatch at %d: got %q want %q (full=%v paged=%v)", pageSize, i, got[i], want[i], want, got)
			}
		}
		// And every uuid appears exactly once.
		seen := map[string]int{}
		for _, u := range got {
			seen[u]++
		}
		for u, c := range seen {
			if c != 1 {
				t.Fatalf("page_size=%d: uuid %q appeared %d times, want exactly 1", pageSize, u, c)
			}
		}
	}
}

// TestListSessions_PaginationSubSecondCreatedAt pins the cursor's FULL-precision contract: a fleet
// routinely creates more than one session per WALL-CLOCK SECOND, so a cluster of sessions can share
// one Unix SECOND while differing in sub-second CreatedAt. Both stores order on the full-precision
// CreatedAt (memory: time.Time.After/Equal; postgres: a microsecond timestamptz), so the page cursor
// MUST compare at the same precision — a second-granularity cursor would treat the cluster as one
// CreatedAt tie, fall through to the uuid tiebreak, disagree with the store's sub-second order, and
// SKIP or DUPLICATE a session at a page boundary inside the cluster. This seeds such a cluster with
// the uuid order DELIBERATELY OPPOSED to the sub-second time order (so a uuid-tiebreak collapse is
// observable) and asserts a small-page walk reproduces the single-shot order exactly, once each.
func TestListSessions_PaginationSubSecondCreatedAt(t *testing.T) {
	st := store.NewMemoryClock(func() time.Time { return time.Unix(1_700_000_000, 0).UTC() })
	ctx := context.Background()

	// 6 sessions sharing ONE Unix second (1_700_000_900) with distinct, strictly-increasing
	// sub-second nanos. The session_uuid order is the REVERSE of the time order: the EARLIEST
	// instant gets the LEXICALLY-LAST uuid. In the store's newest-first order the LATEST instant
	// sorts first; were the cursor to collapse the same-second cluster to its uuid tiebreak it would
	// order them the other way — so any precision collapse shows up as an order/coverage mismatch.
	const base = 1_700_000_900
	for i := 0; i < 6; i++ {
		uuid := "sub-" + string(rune('a'+(5-i))) // i=0 (earliest) → "sub-f"; i=5 (latest) → "sub-a"
		if _, err := st.CreateSession(ctx, store.Session{
			Ref:          store.SessionRef{SessionUUID: uuid, HostID: testHostID, HostSessionIndex: uint64(1 + i), TapName: "tap-" + uuid},
			EnvConfigRef: testEnvRef,
			CreatedAt:    time.Unix(base, int64(i+1)*1_000_000).UTC(), // same second, distinct ms (1ms..6ms)
		}); err != nil {
			t.Fatalf("seed %s: %v", uuid, err)
		}
	}
	// A couple of older, whole-second sessions so the walk crosses the cluster boundary too.
	seedSessionsAt(t, st, time.Unix(1_700_000_100, 0).UTC(), "old", testHostID, 2, 100)

	svc := newSessionService(nil, nil, nil, testOrg, nil, nil)
	svc.SetListServing(st)

	// Ground truth: the full single-shot order.
	full, err := svc.ListSessions(ctx, &orchestratorv1.ListSessionsRequest{})
	if err != nil {
		t.Fatalf("ListSessions(full): %v", err)
	}
	var want []string
	for _, s := range full.GetSessions() {
		want = append(want, s.GetSessionUuid())
	}
	if len(want) != 8 {
		t.Fatalf("seeded set = %d, want 8", len(want))
	}
	// Guard the fixture is doing its job: within the cluster the newest-first order must be the
	// sub-second time order (sub-a latest … sub-f earliest), i.e. NOT lexical uuid order. If this
	// ever reads sorted ascending by uuid the fixture stopped exercising the tiebreak.
	wantCluster := []string{"sub-a", "sub-b", "sub-c", "sub-d", "sub-e", "sub-f"}
	for i := range wantCluster {
		if want[i] != wantCluster[i] {
			t.Fatalf("cluster order = %v, want %v (newest-first by sub-second CreatedAt)", want[:6], wantCluster)
		}
	}

	for _, pageSize := range []uint32{1, 2, 3, 4, 5} {
		got := listAllPages(t, svc, &orchestratorv1.ListSessionsRequest{}, pageSize)
		if len(got) != len(want) {
			t.Fatalf("page_size=%d walked %d sessions, want %d (no skip/dup across same-second cluster)", pageSize, len(got), len(want))
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("page_size=%d sub-second order mismatch at %d: got %q want %q (full=%v paged=%v)", pageSize, i, got[i], want[i], want, got)
			}
		}
	}
}

// TestListSessions_MalformedPageToken pins that a page_token the client did not get from the
// server (not opaque-valid) is InvalidArgument — the client must treat the token as opaque and
// only echo it verbatim.
func TestListSessions_MalformedPageToken(t *testing.T) {
	st := store.NewMemoryClock(func() time.Time { return time.Unix(1_700_000_000, 0).UTC() })
	seedSessionsAt(t, st, time.Unix(1_700_000_900, 0).UTC(), "sess", testHostID, 2, 1)

	svc := newSessionService(nil, nil, nil, testOrg, nil, nil)
	svc.SetListServing(st)

	cases := []struct {
		name  string
		token string
	}{
		{"not-base64", "!!!not base64!!!"},
		{"no-separator", encodeRaw("nocolonhere")},
		{"bad-createdat", encodeRaw("notanint:sess-a")},
		{"empty-uuid", encodeRaw("123:")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := svc.ListSessions(context.Background(), &orchestratorv1.ListSessionsRequest{PageSize: 1, PageToken: c.token})
			if st, _ := status.FromError(err); st.Code() != codes.InvalidArgument {
				t.Fatalf("malformed token %q → code %v, want InvalidArgument; err=%v", c.token, st.Code(), err)
			}
		})
	}
}

// TestListSessions_LaunchingUserFilter pins that the launching_user filter narrows to the sessions
// one principal launched: two principals each launch sessions, plus one session with NO launching
// principal, and a launching_user-scoped list returns ONLY the matching principal's sessions
// (the unlinked session is excluded, never leaked).
func TestListSessions_LaunchingUserFilter(t *testing.T) {
	st := store.NewMemoryClock(func() time.Time { return time.Unix(1_700_000_000, 0).UTC() })
	ctx := context.Background()

	// Two principals in the org.
	for _, p := range []store.Principal{
		{ID: "prin-alice", IdPSubject: "alice@acme", Org: testOrg, Roles: []store.PrincipalRole{store.RoleLauncher}},
		{ID: "prin-bob", IdPSubject: "bob@acme", Org: testOrg, Roles: []store.PrincipalRole{store.RoleLauncher}},
	} {
		if _, err := st.CreatePrincipal(ctx, p); err != nil {
			t.Fatalf("CreatePrincipal %s: %v", p.ID, err)
		}
	}

	// alice launched 2, bob launched 1, plus one unlinked (no launching principal).
	link := []struct{ uuid, principal string }{
		{"sess-alice-1", "prin-alice"},
		{"sess-alice-2", "prin-alice"},
		{"sess-bob-1", "prin-bob"},
		{"sess-orphan", ""},
	}
	idx := uint64(1)
	for _, l := range link {
		if _, err := st.CreateSession(ctx, store.Session{
			Ref:          store.SessionRef{SessionUUID: l.uuid, HostID: testHostID, HostSessionIndex: idx, TapName: "tap-" + l.uuid},
			EnvConfigRef: testEnvRef,
			CreatedAt:    time.Unix(1_700_000_500, 0).UTC(),
		}); err != nil {
			t.Fatalf("seed %s: %v", l.uuid, err)
		}
		idx++
		if l.principal != "" {
			if err := st.SetSessionLaunchingPrincipal(ctx, l.uuid, l.principal); err != nil {
				t.Fatalf("link %s→%s: %v", l.uuid, l.principal, err)
			}
		}
	}

	svc := newSessionService(nil, nil, nil, testOrg, nil, nil)
	svc.SetListServing(st)
	svc.SetLaunchingUserResolver(resolverOver(st))

	// alice's scope.
	resp, err := svc.ListSessions(ctx, &orchestratorv1.ListSessionsRequest{LaunchingUser: "alice@acme"})
	if err != nil {
		t.Fatalf("ListSessions(launching_user=alice@acme): %v", err)
	}
	got := uuidSet(resp)
	if len(got) != 2 || !got["sess-alice-1"] || !got["sess-alice-2"] {
		t.Fatalf("alice scope = %v, want exactly {sess-alice-1, sess-alice-2}", got)
	}
	if got["sess-bob-1"] || got["sess-orphan"] {
		t.Fatalf("alice scope leaked a non-alice session: %v", got)
	}

	// bob's scope.
	resp, err = svc.ListSessions(ctx, &orchestratorv1.ListSessionsRequest{LaunchingUser: "bob@acme"})
	if err != nil {
		t.Fatalf("ListSessions(launching_user=bob@acme): %v", err)
	}
	got = uuidSet(resp)
	if len(got) != 1 || !got["sess-bob-1"] {
		t.Fatalf("bob scope = %v, want exactly {sess-bob-1}", got)
	}

	// Empty launching_user is fleet-wide: ALL four sessions (the resolver is never consulted).
	resp, err = svc.ListSessions(ctx, &orchestratorv1.ListSessionsRequest{})
	if err != nil {
		t.Fatalf("ListSessions(fleet-wide): %v", err)
	}
	if len(uuidSet(resp)) != 4 {
		t.Fatalf("fleet-wide = %v, want all 4", uuidSet(resp))
	}
}

// TestListSessions_LaunchingUserFilter_UnwiredResolver pins that a launching_user-scoped read with
// NO resolver wired refuses Unavailable rather than ignoring the filter and returning the whole
// fleet (which would leak other principals' sessions) — the clean degrade the other unserved read
// legs use. An empty launching_user against the same unwired handler is unaffected (fleet-wide).
func TestListSessions_LaunchingUserFilter_UnwiredResolver(t *testing.T) {
	st := store.NewMemoryClock(func() time.Time { return time.Unix(1_700_000_000, 0).UTC() })
	seedSessionsAt(t, st, time.Unix(1_700_000_900, 0).UTC(), "sess", testHostID, 3, 1)

	svc := newSessionService(nil, nil, nil, testOrg, nil, nil)
	svc.SetListServing(st) // list leg wired, but NO launching-user resolver

	_, err := svc.ListSessions(context.Background(), &orchestratorv1.ListSessionsRequest{LaunchingUser: "alice@acme"})
	if st, _ := status.FromError(err); st.Code() != codes.Unavailable {
		t.Fatalf("launching_user filter w/ unwired resolver → code %v, want Unavailable; err=%v", st.Code(), err)
	}

	// Empty launching_user is still served fleet-wide (resolver never consulted).
	resp, err := svc.ListSessions(context.Background(), &orchestratorv1.ListSessionsRequest{})
	if err != nil {
		t.Fatalf("fleet-wide list w/ unwired resolver: %v", err)
	}
	if len(resp.GetSessions()) != 3 {
		t.Fatalf("fleet-wide w/ unwired resolver = %d sessions, want 3", len(resp.GetSessions()))
	}
}

// TestListSessions_PaginationComposesWithLaunchingUser pins that pagination and the launching_user
// filter compose: a paged walk scoped to one principal covers exactly that principal's sessions,
// once each, and never the other principal's or the unlinked sessions.
func TestListSessions_PaginationComposesWithLaunchingUser(t *testing.T) {
	st := store.NewMemoryClock(func() time.Time { return time.Unix(1_700_000_000, 0).UTC() })
	ctx := context.Background()

	if _, err := st.CreatePrincipal(ctx, store.Principal{ID: "prin-alice", IdPSubject: "alice@acme", Org: testOrg, Roles: []store.PrincipalRole{store.RoleLauncher}}); err != nil {
		t.Fatalf("CreatePrincipal: %v", err)
	}
	if _, err := st.CreatePrincipal(ctx, store.Principal{ID: "prin-bob", IdPSubject: "bob@acme", Org: testOrg, Roles: []store.PrincipalRole{store.RoleLauncher}}); err != nil {
		t.Fatalf("CreatePrincipal: %v", err)
	}

	// 5 alice sessions interleaved (by created-at) with 5 bob + 2 orphan sessions.
	idx := uint64(1)
	var aliceWant []string
	for i := 0; i < 12; i++ {
		uuid := "sess-" + string(rune('a'+i))
		if _, err := st.CreateSession(ctx, store.Session{
			Ref:          store.SessionRef{SessionUUID: uuid, HostID: testHostID, HostSessionIndex: idx, TapName: "tap-" + uuid},
			EnvConfigRef: testEnvRef,
			CreatedAt:    time.Unix(1_700_000_000+int64(i), 0).UTC(), // distinct created-at, ascending
		}); err != nil {
			t.Fatalf("seed %s: %v", uuid, err)
		}
		idx++
		switch i % 3 {
		case 0:
			if err := st.SetSessionLaunchingPrincipal(ctx, uuid, "prin-alice"); err != nil {
				t.Fatalf("link: %v", err)
			}
			aliceWant = append(aliceWant, uuid)
		case 1:
			if err := st.SetSessionLaunchingPrincipal(ctx, uuid, "prin-bob"); err != nil {
				t.Fatalf("link: %v", err)
			}
			// case 2: orphan (no link)
		}
	}

	svc := newSessionService(nil, nil, nil, testOrg, nil, nil)
	svc.SetListServing(st)
	svc.SetLaunchingUserResolver(resolverOver(st))

	base := &orchestratorv1.ListSessionsRequest{LaunchingUser: "alice@acme"}
	for _, pageSize := range []uint32{1, 2, 3, 100} {
		got := listAllPages(t, svc, base, pageSize)
		if len(got) != len(aliceWant) {
			t.Fatalf("page_size=%d alice-scoped walk = %d, want %d", pageSize, len(got), len(aliceWant))
		}
		seen := map[string]bool{}
		for _, u := range got {
			if seen[u] {
				t.Fatalf("page_size=%d: duplicate %q in alice-scoped walk", pageSize, u)
			}
			seen[u] = true
		}
		for _, u := range aliceWant {
			if !seen[u] {
				t.Fatalf("page_size=%d: alice-scoped walk missed %q (got=%v)", pageSize, u, got)
			}
		}
	}
}

// TestSessionPageToken_RoundTrip pins the opaque-cursor codec: encode→decode is lossless and a
// decode of the empty token is the start-from-newest (unset) cursor.
func TestSessionPageToken_RoundTrip(t *testing.T) {
	empty, err := decodeSessionPageToken("")
	if err != nil || empty.set {
		t.Fatalf("decode(\"\") = %+v, err=%v, want the unset start cursor", empty, err)
	}
	in := sessionPageCursor{set: true, createdAt: time.Unix(1_700_000_123, 456_789_000).UnixNano(), uuid: "sess-xyz"}
	round, err := decodeSessionPageToken(encodeSessionPageToken(in))
	if err != nil {
		t.Fatalf("decode(encode(c)): %v", err)
	}
	if round.createdAt != in.createdAt || round.uuid != in.uuid || !round.set {
		t.Fatalf("round-trip cursor = %+v, want %+v", round, in)
	}
}

// resolverOver adapts a *store.Memory's ResolveLaunchingUserClaim into the handler's
// launching-user resolver seam (the SAME resolver shape the production store satisfies).
func resolverOver(st *store.Memory) listLaunchingUserResolverFunc {
	return func(ctx context.Context, sessionUUID string) (string, bool, error) {
		claim, ok, err := st.ResolveLaunchingUserClaim(ctx, sessionUUID)
		if err != nil {
			return "", false, err
		}
		return claim.Subject, ok, nil
	}
}

// encodeRaw base64url-encodes a raw cursor body so a test can craft a token whose ENVELOPE is
// valid base64url but whose BODY is malformed (no separator / bad int / empty uuid) — matching
// the handler's RawURLEncoding so the decode gets a clean envelope but a bad body.
func encodeRaw(body string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(body))
}

// uuidSet collects the response uuids into a set for membership assertions.
func uuidSet(resp *orchestratorv1.ListSessionsResponse) map[string]bool {
	out := map[string]bool{}
	for _, s := range resp.GetSessions() {
		out[s.GetSessionUuid()] = true
	}
	return out
}
