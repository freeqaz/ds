// SPDX-License-Identifier: Apache-2.0

package identitydigestfeed

import (
	"context"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/dream-serpent/dream-serpent/assurance/contract-harness/dualrun"

	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
	"github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1/identityv1fake"
)

// Synthetic fixtures (D50). Every identifier — session uuid, key id, digest
// bytes, service id, consumer id — is obviously-synthetic. No field on this seam
// carries a credential plaintext (doc 14 §7 "digests, never secrets"); the digest
// bytes here are an obviously-fake constant, never derived from a real secret.
const (
	synthSessionPublish  = "ses-digest-aaaaaaaa-0000-4000-8000-aaaaaaaaaaaa"
	synthSessionRevoke   = "ses-digest-bbbbbbbb-1111-4111-8111-bbbbbbbbbbbb"
	synthSessionForbid   = "ses-digest-cccccccc-2222-4222-8222-cccccccccccc"
	synthSessionVariants = "ses-digest-dddddddd-3333-4333-8333-dddddddddddd"

	synthKeyIDPrimary   = "hmackey-synthetic-epoch01"
	synthKeyIDForbidden = "hmackey-synthetic-forbidden01"

	synthServiceID = "svc-synthetic-registry-target"

	synthConsumerID = "consumer-synthetic-hostagent"

	synthBatchPublish = "batch-synthetic-publish-0001"
	synthBatchForbid  = "batch-synthetic-forbid-0002"
	synthBatchVariant = "batch-synthetic-variant-0003"

	synthTruncationLenBytes = uint32(16)
	synthExpiryUnix         = int64(1_700_000_000)
)

// synthDigestBytes is an obviously-synthetic stand-in for the truncated HMAC
// digest bytes — a fixed non-secret byte run, NOT derived from any real
// credential (D50; doc 14 §7 plaintext-never-crosses is structural here). Each
// variant tag below carries its own obviously-fake digest run.
var (
	synthDigestRaw    = []byte("synthetic-digest-raw-0000000000")
	synthDigestBase64 = []byte("synthetic-digest-b64-0000000000")
	synthDigestURLEnc = []byte("synthetic-digest-url-0000000000")
	synthDigestHex    = []byte("synthetic-digest-hex-0000000000")
)

// Suite is the identity-digestfeed seam's single conformance suite (doc 06 §3a:
// one suite, run against real + fake). Every scenario is stated purely in terms
// of the frozen identity.v1 DigestFeedService contract (the two UNARY verbs
// DigestPublish and DigestRevoke — doc 16 §6.6/§9, doc 14 §7), so the same suite
// is meaningful against any faithful implementation. It drives the digest SHAPE
// (the doc 14 §7 frozen entry: key id / algo / digest / cred class / scope /
// expiry / variant tag), the publish-then-revoke ordering and idempotency
// (mint-before-attach + teardown flush, doc 16 §6.1/§6.2), and the honest error
// paths (under-specified batch, fleet-scope-on-this-seam refusal).
func Suite() dualrun.Suite {
	return dualrun.Suite{
		Seam:      "identity(DigestFeedService)<->boundary",
		Scenarios: scenarios(),
	}
}

func scenarios() []dualrun.Scenario {
	return []dualrun.Scenario{
		{
			Name: "publish/issued-entry-shape-and-committed-ack",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := identityv1.NewDigestFeedServiceClient(conn)
				// An ISSUED{service_id} session-scoped digest: the doc 14 §7 entry
				// shape, registered ahead of first egress (mint-before-attach). The
				// ack must echo batch_id, name the acking consumer, and report
				// committed=true with the session whose digests are now matchable.
				req := &identityv1.DigestPublishRequest{
					Session: sessionRef(synthSessionPublish),
					BatchId: synthBatchPublish,
					Entries: []*identityv1.DigestEntry{
						issuedEntry(synthKeyIDPrimary, synthServiceID, identityv1.DigestVariantTag_DIGEST_VARIANT_TAG_RAW, synthDigestRaw),
					},
				}
				resp, err := cl.DigestPublish(ctx, req)
				if err != nil {
					return errObservation("publish", err), nil
				}
				return publishObservation(resp), nil
			},
		},
		{
			Name: "publish/forbidden-canary-entry-shape",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := identityv1.NewDigestFeedServiceClient(conn)
				// A FORBIDDEN canary (no payload — its presence in the oneof is the
				// signal). The doc 06 (c) "canary never egresses" assurance anchor
				// (D73): the entry is well-formed with cred_class set to FORBIDDEN
				// and must register the same as any other entry.
				req := &identityv1.DigestPublishRequest{
					Session: sessionRef(synthSessionForbid),
					BatchId: synthBatchForbid,
					Entries: []*identityv1.DigestEntry{
						forbiddenEntry(synthKeyIDForbidden, identityv1.DigestVariantTag_DIGEST_VARIANT_TAG_HEX, synthDigestHex),
					},
				}
				resp, err := cl.DigestPublish(ctx, req)
				if err != nil {
					return errObservation("publish", err), nil
				}
				return publishObservation(resp), nil
			},
		},
		{
			Name: "publish/accepts-fleet-class-entry-as-class-statement",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := identityv1.NewDigestFeedServiceClient(conn)
				// A fleet-class entry appearing in a publish batch is the producer
				// STATING the entry's class, not requesting session-path delivery
				// (digest_feed.proto DigestScope.DIGEST_SCOPE_FLEET). The frozen
				// contract does NOT make it an error — the batch is accepted and acks
				// committed; the fleet entry is simply not registered on this
				// session-lifecycle path. This proves the reference impl does not
				// over-refuse a well-formed fleet-class entry (real and fake agree).
				req := &identityv1.DigestPublishRequest{
					Session: sessionRef(synthSessionPublish),
					BatchId: "batch-synthetic-fleet-class",
					Entries: []*identityv1.DigestEntry{
						issuedEntry(synthKeyIDPrimary, synthServiceID, identityv1.DigestVariantTag_DIGEST_VARIANT_TAG_RAW, synthDigestRaw),
						fleetClassEntry(synthKeyIDForbidden, identityv1.DigestVariantTag_DIGEST_VARIANT_TAG_HEX, synthDigestHex),
					},
				}
				resp, err := cl.DigestPublish(ctx, req)
				if err != nil {
					return errObservation("publish", err), nil
				}
				return publishObservation(resp), nil
			},
		},
		{
			Name: "publish/idempotent-on-key-id",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := identityv1.NewDigestFeedServiceClient(conn)
				// Re-publishing the SAME batch is idempotent: the digest set is keyed
				// by (session, key_id), so a re-issue converges to the same set and
				// acks the same way — never a divergent second registration.
				req := &identityv1.DigestPublishRequest{
					Session: sessionRef(synthSessionVariants),
					BatchId: synthBatchVariant,
					Entries: variantEntries(synthKeyIDPrimary),
				}
				first, err := cl.DigestPublish(ctx, req)
				if err != nil {
					return errObservation("publish", err), nil
				}
				second, err := cl.DigestPublish(ctx, req)
				if err != nil {
					return errObservation("publish", err), nil
				}
				obs := publishObservation(second)
				obs.Setf("idempotent_ack", "%t",
					first.GetBatchId() == second.GetBatchId() &&
						first.GetCommitted() == second.GetCommitted() &&
						first.GetSession().GetSessionUuid() == second.GetSession().GetSessionUuid())
				return obs, nil
			},
		},
		{
			Name: "publish-then-revoke/ordering-and-committed",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := identityv1.NewDigestFeedServiceClient(conn)
				// The publish→revoke ordering (doc 16 §6.1 mint-before-attach, §6.2
				// session-scope teardown flush): publish a session's digests, then
				// revoke them by key id on the session scope. Both legs ack committed.
				pub, err := cl.DigestPublish(ctx, &identityv1.DigestPublishRequest{
					Session: sessionRef(synthSessionRevoke),
					BatchId: synthBatchPublish,
					Entries: []*identityv1.DigestEntry{
						issuedEntry(synthKeyIDPrimary, synthServiceID, identityv1.DigestVariantTag_DIGEST_VARIANT_TAG_RAW, synthDigestRaw),
						forbiddenEntry(synthKeyIDForbidden, identityv1.DigestVariantTag_DIGEST_VARIANT_TAG_BASE64, synthDigestBase64),
					},
				})
				if err != nil {
					return errObservation("publish", err), nil
				}
				rev, err := cl.DigestRevoke(ctx, &identityv1.DigestRevokeRequest{
					Session: sessionRef(synthSessionRevoke),
					KeyIds:  []string{synthKeyIDPrimary, synthKeyIDForbidden},
					Scope:   identityv1.DigestScope_DIGEST_SCOPE_SESSION,
				})
				if err != nil {
					return errObservation("revoke", err), nil
				}
				obs := dualrun.NewObservation()
				obs.Set("status", codes.OK.String())
				obs.Setf("publish_committed", "%t", pub.GetCommitted())
				obs.Setf("revoke_committed", "%t", rev.GetCommitted())
				obs.Set("revoke_session", rev.GetSession().GetSessionUuid())
				obs.Setf("revoke_consumer_present", "%t", rev.GetConsumerId() != "")
				return obs, nil
			},
		},
		{
			Name: "revoke/idempotent-on-already-gone-key-id",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := identityv1.NewDigestFeedServiceClient(conn)
				// Revoking a key id that was never published (or already revoked)
				// SUCCEEDS committed — the digests are not matchable, which is the
				// teardown-flush intent. This must NOT error NotFound.
				resp, err := cl.DigestRevoke(ctx, &identityv1.DigestRevokeRequest{
					Session: sessionRef(synthSessionRevoke),
					KeyIds:  []string{"hmackey-synthetic-never-published"},
					Scope:   identityv1.DigestScope_DIGEST_SCOPE_SESSION,
				})
				if err != nil {
					return errObservation("revoke", err), nil
				}
				obs := dualrun.NewObservation()
				obs.Set("status", codes.OK.String())
				obs.Setf("committed", "%t", resp.GetCommitted())
				return obs, nil
			},
		},
		{
			Name: "publish/refuses-empty-batch",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := identityv1.NewDigestFeedServiceClient(conn)
				// An empty batch can never satisfy mint-before-attach, so it must be
				// refused, never silently acked open (fail-closed, doc 16 §6 invariant).
				_, err := cl.DigestPublish(ctx, &identityv1.DigestPublishRequest{
					Session: sessionRef(synthSessionPublish),
					BatchId: "batch-synthetic-empty",
				})
				return errObservation("publish", err), nil
			},
		},
		{
			Name: "publish/refuses-missing-session",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := identityv1.NewDigestFeedServiceClient(conn)
				// The session scopes the mint-before-attach ordering; a publish with
				// no session ref is InvalidArgument.
				_, err := cl.DigestPublish(ctx, &identityv1.DigestPublishRequest{
					BatchId: "batch-synthetic-nosession",
					Entries: []*identityv1.DigestEntry{
						issuedEntry(synthKeyIDPrimary, synthServiceID, identityv1.DigestVariantTag_DIGEST_VARIANT_TAG_RAW, synthDigestRaw),
					},
				})
				return errObservation("publish", err), nil
			},
		},
		{
			Name: "publish/refuses-underspecified-entry",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := identityv1.NewDigestFeedServiceClient(conn)
				// An entry missing its digest bytes violates the doc 14 §7 frozen
				// entry shape and must be refused rather than registered.
				_, err := cl.DigestPublish(ctx, &identityv1.DigestPublishRequest{
					Session: sessionRef(synthSessionPublish),
					BatchId: "batch-synthetic-underspecified",
					Entries: []*identityv1.DigestEntry{
						{
							KeyId:      synthKeyIDPrimary,
							Algo:       hmacAlgo(),
							CredClass:  issuedClass(synthServiceID),
							Scope:      identityv1.DigestScope_DIGEST_SCOPE_SESSION,
							VariantTag: identityv1.DigestVariantTag_DIGEST_VARIANT_TAG_RAW,
							// Digest omitted on purpose.
						},
					},
				})
				return errObservation("publish", err), nil
			},
		},
		{
			Name: "revoke/refuses-fleet-scope-on-this-seam",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := identityv1.NewDigestFeedServiceClient(conn)
				// Fleet-scope revocation is a policy artifact under policy_log (D72),
				// delivered via the WatchPolicies subscriber — NOT this session-
				// lifecycle seam. A fleet-scoped revoke here is FailedPrecondition
				// (doc 16 §6.2; digest_feed.proto file invariants).
				_, err := cl.DigestRevoke(ctx, &identityv1.DigestRevokeRequest{
					Session: sessionRef(synthSessionRevoke),
					KeyIds:  []string{synthKeyIDPrimary},
					Scope:   identityv1.DigestScope_DIGEST_SCOPE_FLEET,
				})
				return errObservation("revoke", err), nil
			},
		},
	}
}

// --- Observation builders ----------------------------------------------------

// errObservation records a verb's gRPC status under a verb-tagged status key so a
// success path and an error path are observed distinctly across real and fake.
func errObservation(verb string, err error) *dualrun.Observation {
	obs := dualrun.NewObservation()
	obs.Set(verb+"_status", status.Code(err).String())
	return obs
}

// publishObservation records the contract-observable shape of a publish ack: the
// echoed batch id, the session whose digests are now matchable, the presence of
// an acking consumer id (the ack-er is named so the message never assumes a
// single consumer — doc 16 §6.5/§6.6), and the committed bit. The consumer id is
// recorded only as PRESENCE, not value: which host-side consumer acks is an
// allocation detail, while "an ack named its consumer" is the contract property.
func publishObservation(resp *identityv1.DigestPublishResponse) *dualrun.Observation {
	obs := dualrun.NewObservation()
	obs.Set("status", codes.OK.String())
	obs.Set("batch_id", resp.GetBatchId())
	obs.Set("session", resp.GetSession().GetSessionUuid())
	obs.Setf("consumer_present", "%t", resp.GetConsumerId() != "")
	obs.Setf("committed", "%t", resp.GetCommitted())
	return obs
}

// --- synthetic fixture constructors (D50) ------------------------------------

func sessionRef(uuid string) *identityv1.DigestSessionRef {
	return &identityv1.DigestSessionRef{SessionUuid: uuid}
}

// hmacAlgo returns the doc 14 §7 keyed-hash family + truncation length. The
// truncation length is carried so the boundary matcher truncates identically
// (doc 16 §6.3); it is NOT the plaintext.
func hmacAlgo() *identityv1.DigestAlgo {
	return &identityv1.DigestAlgo{
		Family:             identityv1.DigestAlgo_FAMILY_HMAC_SHA256,
		TruncationLenBytes: synthTruncationLenBytes,
	}
}

// issuedClass builds the ISSUED{service_id} cred-class oneof: a credential
// Identity minted, tagged with its intended registry service id (doc 16 §5.1).
func issuedClass(serviceID string) *identityv1.DigestCredClass {
	return &identityv1.DigestCredClass{
		Class: &identityv1.DigestCredClass_Issued_{
			Issued: &identityv1.DigestCredClass_Issued{ServiceId: serviceID},
		},
	}
}

// forbiddenClass builds the FORBIDDEN cred-class oneof: a credential Identity
// guards — must never egress in any variant. No payload; its presence in the
// oneof is the signal (the doc 06 (c) canary anchor, D73).
func forbiddenClass() *identityv1.DigestCredClass {
	return &identityv1.DigestCredClass{
		Class: &identityv1.DigestCredClass_Forbidden_{
			Forbidden: &identityv1.DigestCredClass_Forbidden{},
		},
	}
}

// issuedEntry builds a well-formed session-scoped ISSUED digest entry (doc 14 §7
// frozen shape). Synthetic digest bytes only (D50).
func issuedEntry(keyID, serviceID string, tag identityv1.DigestVariantTag, digest []byte) *identityv1.DigestEntry {
	return &identityv1.DigestEntry{
		KeyId:      keyID,
		Algo:       hmacAlgo(),
		Digest:     digest,
		CredClass:  issuedClass(serviceID),
		Scope:      identityv1.DigestScope_DIGEST_SCOPE_SESSION,
		Expiry:     timestamppb.New(syntheticExpiry()),
		VariantTag: tag,
	}
}

// forbiddenEntry builds a well-formed session-scoped FORBIDDEN canary entry.
// Synthetic digest bytes only (D50).
func forbiddenEntry(keyID string, tag identityv1.DigestVariantTag, digest []byte) *identityv1.DigestEntry {
	return &identityv1.DigestEntry{
		KeyId:      keyID,
		Algo:       hmacAlgo(),
		Digest:     digest,
		CredClass:  forbiddenClass(),
		Scope:      identityv1.DigestScope_DIGEST_SCOPE_SESSION,
		Expiry:     timestamppb.New(syntheticExpiry()),
		VariantTag: tag,
	}
}

// fleetClassEntry builds a well-formed FLEET-class ISSUED entry — the producer
// stating a fleet-class digest's class on a publish batch (digest_feed.proto
// DigestScope.DIGEST_SCOPE_FLEET). It is a legitimate entry shape, NOT a refusal
// case; the session-lifecycle path ignores it for delivery. Synthetic bytes only.
func fleetClassEntry(keyID string, tag identityv1.DigestVariantTag, digest []byte) *identityv1.DigestEntry {
	return &identityv1.DigestEntry{
		KeyId:      keyID,
		Algo:       hmacAlgo(),
		Digest:     digest,
		CredClass:  issuedClass(synthServiceID),
		Scope:      identityv1.DigestScope_DIGEST_SCOPE_FLEET,
		Expiry:     timestamppb.New(syntheticExpiry()),
		VariantTag: tag,
	}
}

// syntheticExpiry is a fixed, obviously-synthetic absolute expiry so created
// entries are deterministic across real and fake. The suite never records the raw
// expiry value (allocation detail); it asserts the entry shape, not the clock.
func syntheticExpiry() time.Time {
	return time.Unix(synthExpiryUnix, 0).UTC()
}

// variantEntries returns the full set of encoded variants for one credential
// under a shared key id — N DigestEntry values sharing key_id/cred_class/scope/
// expiry, differing only in digest + variant_tag (doc 14 §7). This is the multi-
// variant publish a credential pushed in N encodings produces.
func variantEntries(keyID string) []*identityv1.DigestEntry {
	return []*identityv1.DigestEntry{
		issuedEntry(keyID, synthServiceID, identityv1.DigestVariantTag_DIGEST_VARIANT_TAG_RAW, synthDigestRaw),
		issuedEntry(keyID, synthServiceID, identityv1.DigestVariantTag_DIGEST_VARIANT_TAG_BASE64, synthDigestBase64),
		issuedEntry(keyID, synthServiceID, identityv1.DigestVariantTag_DIGEST_VARIANT_TAG_URLENC, synthDigestURLEnc),
		issuedEntry(keyID, synthServiceID, identityv1.DigestVariantTag_DIGEST_VARIANT_TAG_HEX, synthDigestHex),
	}
}

// --- dialers: real reference impl AND the generated fake --------------------
//
// Both ends of the seam need a matched pair of dialers (one for the real impl,
// one for the fake), so the only thing that varies across the two dual-run passes
// is which server is registered.

// RealDialer returns the dual-run Dialer for the reference impl.
func RealDialer() dualrun.Dialer {
	return dualrun.InProcess(NewRefImpl().Register)
}

// FakeDialer returns the dual-run Dialer for the GENERATED programmable fake,
// programmed to the same contract Suite() asserts. The fake is driven only
// through its canned-response surface (its per-verb responders), so the dual-run
// proves it is observationally identical to the real impl on every scenario.
func FakeDialer() dualrun.Dialer {
	f := programmedFake()
	return dualrun.InProcess(func(s grpc.ServiceRegistrar) {
		identityv1fake.RegisterDigestFeedService(s, f)
	})
}

// programmedFake programs the generated fake to the honest contract by routing
// its per-verb responders at a mirror RefImpl — so the fake and the real impl
// share one honest behavior definition (the digest shape validation, publish/
// revoke idempotency, the honest error paths). This is the programmable-fake-
// driven-only-through-its-surface pattern (doc 06 §2.1): the dual-run still proves
// the fake observationally matches the production impl when it lands, because the
// suite never touches the mirror directly.
func programmedFake() *identityv1fake.DigestFeedServiceFake {
	f := identityv1fake.NewDigestFeedServiceFake()
	mirror := NewRefImpl()
	f.DigestPublishResponder = mirror.DigestPublish
	f.DigestRevokeResponder = mirror.DigestRevoke
	return f
}
