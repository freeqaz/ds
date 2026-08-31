// SPDX-License-Identifier: Apache-2.0

// ds-fake-digest-publisher — the behavioral fake of the Identity-side digest
// producer (doc 14 §7, D73; doc 16 §6.6). It drives the frozen
// dreamserpent.identity.v1.DigestFeedService seam as a local process so
// boundary/consumer implementations (the host-agent ack-er per D109, the
// ds-tlsproxy SecretMatcher fan-out) can be exercised end-to-end without the
// real Identity plane. Scenarios follow the README spec in this directory.
//
// SYNTHETIC ONLY (D50): every digest this fake publishes is the HMAC of a
// synthetic `ds-fake-canary-*` value under a synthetic key — no real
// credential, or digest of one, ever appears here.
package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/timestamppb"

	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
)

// digest computes the truncated HMAC-SHA-256 a real producer would compute in
// the D39 trust zone — over a SYNTHETIC value only (D50).
func digest(key, value []byte, truncLen int) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(value)
	return mac.Sum(nil)[:truncLen]
}

func entries(sessionUUID string) []*identityv1.DigestEntry {
	const truncLen = 16
	key := []byte("ds-fake-hmac-key-0001")
	expiry := timestamppb.New(time.Now().Add(15 * time.Minute))
	mk := func(value string, class *identityv1.DigestCredClass, variant identityv1.DigestVariantTag) *identityv1.DigestEntry {
		return &identityv1.DigestEntry{
			KeyId: "ds-fake-key-0001",
			Algo: &identityv1.DigestAlgo{
				Family:             identityv1.DigestAlgo_FAMILY_HMAC_SHA256,
				TruncationLenBytes: truncLen,
			},
			Digest:     digest(key, []byte(value), truncLen),
			CredClass:  class,
			Scope:      identityv1.DigestScope_DIGEST_SCOPE_SESSION,
			Expiry:     expiry,
			VariantTag: variant,
		}
	}
	issued := &identityv1.DigestCredClass{Class: &identityv1.DigestCredClass_Issued_{Issued: &identityv1.DigestCredClass_Issued{ServiceId: "github"}}}
	forbidden := &identityv1.DigestCredClass{Class: &identityv1.DigestCredClass_Forbidden_{Forbidden: &identityv1.DigestCredClass_Forbidden{}}}
	return []*identityv1.DigestEntry{
		mk("ds-fake-canary-issued-"+sessionUUID, issued, identityv1.DigestVariantTag_DIGEST_VARIANT_TAG_RAW),
		mk("ds-fake-canary-issued-"+sessionUUID, issued, identityv1.DigestVariantTag_DIGEST_VARIANT_TAG_BASE64),
		mk("ds-fake-canary-forbidden-"+sessionUUID, forbidden, identityv1.DigestVariantTag_DIGEST_VARIANT_TAG_RAW),
	}
}

func run() error {
	target := flag.String("target", "127.0.0.1:9477", "DigestFeedService consumer address")
	scenario := flag.String("scenario", "happy", "happy | teardown-flush | fail-closed (per the README spec)")
	sessionUUID := flag.String("session-uuid", "00000000-0000-4000-8000-00000000fake", "session to publish for")
	timeout := flag.Duration("timeout", 5*time.Second, "per-RPC deadline")
	flag.Parse()

	conn, err := grpc.NewClient(*target, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("dial %s: %w", *target, err)
	}
	defer conn.Close()
	client := identityv1.NewDigestFeedServiceClient(conn)
	session := &identityv1.DigestSessionRef{SessionUuid: *sessionUUID}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	// Publish the synthetic batch (mint-before-attach write).
	pub, err := client.DigestPublish(ctx, &identityv1.DigestPublishRequest{
		Session: session,
		Entries: entries(*sessionUUID),
		BatchId: "ds-fake-batch-0001",
	})
	// FAIL-CLOSED (doc 14 §7): an error or an uncommitted ack means the session
	// must NOT be marked routable — the fake exits non-zero exactly like a real
	// producer would stall/fail session-create.
	if err != nil {
		return fmt.Errorf("DigestPublish: %w (fail-closed: session not routable)", err)
	}
	if !pub.GetCommitted() {
		return fmt.Errorf("DigestPublish ack uncommitted (consumer %q, batch %q) — fail-closed: session not routable",
			pub.GetConsumerId(), pub.GetBatchId())
	}
	log.Printf("published: batch=%s consumer=%s committed=%v (mint-before-attach satisfied)",
		pub.GetBatchId(), pub.GetConsumerId(), pub.GetCommitted())

	if *scenario == "teardown-flush" {
		rev, err := client.DigestRevoke(ctx, &identityv1.DigestRevokeRequest{
			Session: session,
			KeyIds:  []string{"ds-fake-key-0001"},
			Scope:   identityv1.DigestScope_DIGEST_SCOPE_SESSION,
		})
		if err != nil {
			return fmt.Errorf("DigestRevoke: %w", err)
		}
		if !rev.GetCommitted() {
			return fmt.Errorf("DigestRevoke ack uncommitted — teardown flush not confirmed")
		}
		log.Printf("revoked: consumer=%s committed=%v (teardown flush confirmed)", rev.GetConsumerId(), rev.GetCommitted())
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}
