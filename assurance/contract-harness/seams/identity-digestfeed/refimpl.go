// SPDX-License-Identifier: Apache-2.0

package identitydigestfeed

import (
	"context"
	"sort"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
)

// RefImpl is a minimal honest reference implementation of DigestFeedService — the
// "real implementation" side of the dual-run. It implements exactly the doc 16 §6
// secret-digest feed producer→boundary contract (D73/D84) as it lands on the
// Stage-0 wire surface (doc 16 §6.6/§9): the two UNARY verbs DigestPublish and
// DigestRevoke over session-scoped digests.
//
// What it models, honestly:
//
//   - DigestPublish registers a batch of session-scoped digest entries and acks
//     committed once every entry is matchable — the mint-before-attach write
//     (doc 16 §6.1): the session is not routable until the ack returns committed.
//     The ack echoes the producer's batch_id and names the acking host-side
//     consumer (the D35 host agent, D109), so the ack never bakes in a
//     single-consumer assumption (doc 16 §6.5/§6.6). Re-publishing the same batch
//     is idempotent — the digest set is keyed by (session, key_id), so a re-issue
//     converges to the same registered set rather than duplicating it.
//   - DigestRevoke removes named key ids from a session's set and acks committed
//     once they are no longer matchable. Idempotent and honest about a no-op:
//     revoking already-gone (or never-published) key ids still SUCCEEDS committed,
//     exactly like an idempotent teardown flush (doc 16 §5.4 / §6.2).
//
// Honest error paths (doc 16 §6: "honest errors", fail-closed while the keyed
// plane is loaded):
//
//   - a publish/revoke with no session ref, or an empty session uuid, is
//     InvalidArgument — the session scopes the mint-before-attach ordering.
//   - a publish with no entries is InvalidArgument — an empty batch can never
//     satisfy mint-before-attach, so it must not silently ack open.
//   - a publish entry that omits its key id, algo, digest, cred class, or carries
//     the unspecified variant tag is InvalidArgument — the doc 14 §7 frozen entry
//     shape; an under-specified entry must be refused, never registered.
//   - a REVOKE tagged DIGEST_SCOPE_FLEET on this RPC is FailedPrecondition:
//     fleet-scope revocation is a policy artifact under the policy_log seq (D72),
//     delivered through the one-per-host WatchPolicies subscriber, NOT this
//     session-lifecycle seam (doc 16 §6.2; the DigestRevokeRequest.scope "must be
//     DIGEST_SCOPE_SESSION on this path" invariant).
//
// NOT an error (a faithful-to-the-frozen-contract subtlety): a fleet-class
// ENTRY appearing in a DigestPublish batch is the producer STATING the entry's
// class, not requesting session-path delivery (digest_feed.proto
// DigestScope.DIGEST_SCOPE_FLEET; DigestPublishRequest.session is "Omitted/ignored
// for fleet-class entries"). It is accepted and simply not registered on this
// session-lifecycle path — refusing it would drift the reference impl from the
// frozen proto.
//
// PLAINTEXT NEVER CROSSES (doc 14 §7, D73): this is a structural property of the
// wire shape — no field carries a credential plaintext — so the reference impl
// stores only key ids and the digest set membership, never a secret. Synthetic
// fixtures only (D50).
//
// This is the M0 stand-in until the production Identity digest producer (a
// skeleton today) lands. When that lands it replaces RefImpl as the "real" end
// and the conformance suite is unchanged — the suite is the contract, not the
// implementation.
//
// State is held in-memory, keyed by session_uuid → set of registered key ids;
// access is mutex-guarded so the in-process gRPC server is safe under concurrent
// calls.
type RefImpl struct {
	identityv1.UnimplementedDigestFeedServiceServer

	mu sync.Mutex
	// registered maps session_uuid -> set of registered key ids. A key id present
	// in the set is a digest currently matchable for that session.
	registered map[string]map[string]struct{}
}

// NewRefImpl returns a reference DigestFeedService server with an empty store.
func NewRefImpl() *RefImpl {
	return &RefImpl{registered: map[string]map[string]struct{}{}}
}

// DigestPublish registers a session-scoped digest batch and returns the publish
// ack (doc 16 §6.1/§6.6). It validates the doc 14 §7 frozen entry shape on every
// entry, registers the batch idempotently keyed by (session, key_id), and acks
// committed once every entry is matchable — the mint-before-attach write. The ack
// echoes batch_id, names the acking consumer, and carries the session whose
// digests are now matchable. Fail-closed: any structural problem is a refusal, so
// the seam never routes open on an under-specified batch.
func (s *RefImpl) DigestPublish(_ context.Context, req *identityv1.DigestPublishRequest) (*identityv1.DigestPublishResponse, error) {
	uuid := req.GetSession().GetSessionUuid()
	if uuid == "" {
		return nil, status.Error(codes.InvalidArgument, "DigestPublishRequest.session.session_uuid is required (session-scope mint-before-attach)")
	}
	if len(req.GetEntries()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "DigestPublishRequest.entries must be non-empty (an empty batch can never satisfy mint-before-attach)")
	}
	for i, e := range req.GetEntries() {
		if err := validateEntry(i, e); err != nil {
			return nil, err
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	set := s.registered[uuid]
	if set == nil {
		set = map[string]struct{}{}
		s.registered[uuid] = set
	}
	// Idempotent registration: keyed by (session, key_id), a re-publish of the
	// same batch converges to the same set rather than duplicating entries. A
	// fleet-class entry is the producer stating the entry's class, not requesting
	// session-path delivery (digest_feed.proto DigestScope.DIGEST_SCOPE_FLEET), so
	// it is NOT registered on this session-lifecycle path — ignored, never refused.
	for _, e := range req.GetEntries() {
		if e.GetScope() == identityv1.DigestScope_DIGEST_SCOPE_FLEET {
			continue
		}
		set[e.GetKeyId()] = struct{}{}
	}
	return &identityv1.DigestPublishResponse{
		BatchId:    req.GetBatchId(),
		Session:    &identityv1.DigestSessionRef{SessionUuid: uuid},
		ConsumerId: synthConsumerID,
		Committed:  true,
	}, nil
}

// DigestRevoke removes named key ids from a session's digest set and returns the
// revoke ack (doc 16 §6.2 / §5.4). It refuses a fleet-scoped revoke (that rides
// the policy stream, not this seam), and is idempotent: revoking key ids that are
// already gone or were never published still SUCCEEDS committed — the teardown
// flush must be safe to re-drive. The ack carries the session and names the
// acking consumer, symmetric with the publish ack.
func (s *RefImpl) DigestRevoke(_ context.Context, req *identityv1.DigestRevokeRequest) (*identityv1.DigestRevokeResponse, error) {
	uuid := req.GetSession().GetSessionUuid()
	if uuid == "" {
		return nil, status.Error(codes.InvalidArgument, "DigestRevokeRequest.session.session_uuid is required")
	}
	if req.GetScope() == identityv1.DigestScope_DIGEST_SCOPE_FLEET {
		return nil, status.Error(codes.FailedPrecondition, "fleet-scope revocation rides the policy stream (D72), not this seam (doc 16 §6.2)")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if set := s.registered[uuid]; set != nil {
		for _, k := range req.GetKeyIds() {
			delete(set, k)
		}
		if len(set) == 0 {
			delete(s.registered, uuid)
		}
	}
	// Idempotent: a revoke of already-gone key ids (or an unknown session)
	// SUCCEEDS committed — the digests are not matchable, which is the point.
	return &identityv1.DigestRevokeResponse{
		Session:    &identityv1.DigestSessionRef{SessionUuid: uuid},
		ConsumerId: synthConsumerID,
		Committed:  true,
	}, nil
}

// validateEntry enforces the doc 14 §7 frozen entry shape: key id, algo, digest
// bytes, cred class, and a specified variant tag are all required. The entry's
// SCOPE is not validated here: a fleet-class entry is a legitimate class
// statement on publish (it is ignored for session-path delivery in DigestPublish,
// not refused — digest_feed.proto DigestScope.DIGEST_SCOPE_FLEET). A FORBIDDEN
// canary and an ISSUED{service_id} entry are both well-formed; the cred-class
// oneof must be set to one of them.
func validateEntry(i int, e *identityv1.DigestEntry) error {
	if e.GetKeyId() == "" {
		return status.Errorf(codes.InvalidArgument, "DigestPublishRequest.entries[%d].key_id is required", i)
	}
	if e.GetAlgo() == nil || e.GetAlgo().GetFamily() == identityv1.DigestAlgo_FAMILY_UNSPECIFIED {
		return status.Errorf(codes.InvalidArgument, "DigestPublishRequest.entries[%d].algo.family must be specified", i)
	}
	if len(e.GetDigest()) == 0 {
		return status.Errorf(codes.InvalidArgument, "DigestPublishRequest.entries[%d].digest is required (the keyed hash bytes)", i)
	}
	if e.GetCredClass().GetClass() == nil {
		return status.Errorf(codes.InvalidArgument, "DigestPublishRequest.entries[%d].cred_class must be ISSUED{service_id} or FORBIDDEN", i)
	}
	if e.GetVariantTag() == identityv1.DigestVariantTag_DIGEST_VARIANT_TAG_UNSPECIFIED {
		return status.Errorf(codes.InvalidArgument, "DigestPublishRequest.entries[%d].variant_tag must be specified (RAW|BASE64|URLENC|HEX)", i)
	}
	// A DIGEST_SCOPE_FLEET entry appearing on DigestPublish is the producer STATING
	// the entry's class, not requesting session-path delivery (digest_feed.proto
	// DigestScope.DIGEST_SCOPE_FLEET; DigestPublishRequest.session "Omitted/ignored
	// for fleet-class entries"). The frozen contract does NOT make it an error, so a
	// faithful impl must not refuse it — it is simply not registered on this
	// session-lifecycle path (see DigestPublish, which skips fleet-class entries).
	return nil
}

// Registered returns the sorted set of key ids currently registered for a
// session. It is a test affordance on the reference impl — not a contract verb —
// used to assert the matchable digest set after publish/revoke. Synthetic
// fixtures only (D50).
func (s *RefImpl) Registered(uuid string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	set := s.registered[uuid]
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Register registers the reference impl on a grpc.ServiceRegistrar.
func (s *RefImpl) Register(reg grpc.ServiceRegistrar) {
	identityv1.RegisterDigestFeedServiceServer(reg, s)
}
