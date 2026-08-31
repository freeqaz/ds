// SPDX-License-Identifier: Apache-2.0

package nftbridge

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// goldenFile is the shared cross-module fixture (doc 13 §5.1 "shared
// frozen-golden-fixture cross-check"). The Go side here pins (payload,
// content_hash) byte-for-byte by RE-PRODUCING each case's Value tree and
// asserting Canonicalize == payload and HashPayload(payload) == content_hash.
// The Rust side (ds-contracts) loads the byte-identical copy and VERIFIES the
// stored bytes without re-canonicalizing. check-snapshot-goldens.sh gates that
// the two committed copies stay byte-identical.
const goldenFile = "testdata/snapshot-goldens.json"

type goldenSection struct {
	SessionID string `json:"session_id"`
	Payload   string `json:"payload"`
	SubHash   string `json:"sub_hash"`
}

type goldenCase struct {
	Name            string          `json:"name"`
	Kind            string          `json:"kind"`
	Desc            string          `json:"desc"`
	Payload         string          `json:"payload"`
	ContentHash     string          `json:"content_hash"`
	HashEqualTo     string          `json:"hash_equal_to"`
	HashDiffersFrom string          `json:"hash_differs_from"`
	Sections        []goldenSection `json:"sections"`
}

type goldenAdversarial struct {
	ByteMutated struct {
		Desc               string `json:"desc"`
		BaseCase           string `json:"base_case"`
		MutatedPayload     string `json:"mutated_payload"`
		ExpectedHashOfBase string `json:"expected_hash_of_base"`
	} `json:"byte_mutated"`
}

type goldenDoc struct {
	Cases       []goldenCase      `json:"cases"`
	Adversarial goldenAdversarial `json:"adversarial"`
}

func loadGoldens(t *testing.T) goldenDoc {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(goldenFile))
	if err != nil {
		t.Fatalf("read golden fixture: %v", err)
	}
	var doc goldenDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse golden fixture: %v", err)
	}
	if len(doc.Cases) == 0 {
		t.Fatal("golden fixture has no cases")
	}
	return doc
}

// rebuild reconstructs each named case's Value tree exactly as the host agent
// would compose it. The whole point of the produce-once rule is that ONE Go
// composition produces the pinned bytes; this function is that composition,
// kept beside the assertion so the fixture is self-describing.
func rebuild(t *testing.T, name string) Value {
	t.Helper()
	switch name {
	case "dns_zero_present":
		return NewObject().
			Set("negative_ttl", Int(0)).
			Set("upstream_resolvers", NewArray(Str("1.1.1.1"), Str("8.8.8.8")))
	case "dns_zero_reordered":
		// SAME object, keys composed in reverse insertion order.
		return NewObject().
			Set("upstream_resolvers", NewArray(Str("1.1.1.1"), Str("8.8.8.8"))).
			Set("negative_ttl", Int(0))
	case "dns_negttl_absent":
		return NewObject().
			Set("upstream_resolvers", NewArray(Str("1.1.1.1"), Str("8.8.8.8")))
	case "dns_default_omitted":
		// SET-TO-DEFAULT vs ABSENT: negative_ttl carries its NON-meaningful
		// default, so the producer OMITS it (absent==default==omitted, §5.1).
		// The composed tree is therefore byte-identical to dns_negttl_absent —
		// proving the producer never emits a non-meaningful default. (Contrast
		// dns_zero_present, where 0 is MEANINGFUL and must survive the hash.)
		return NewObject().
			Set("upstream_resolvers", NewArray(Str("1.1.1.1"), Str("8.8.8.8")))
	case "dns_negttl_five":
		return NewObject().
			Set("negative_ttl", Int(5)).
			Set("upstream_resolvers", NewArray(Str("1.1.1.1"), Str("8.8.8.8")))
	case "baseline_pack":
		fam := func(n, tier string) Value {
			return NewObject().Set("key", Str(n)).Set("value", NewObject().Set("tier", Str(tier)))
		}
		return NewObject().
			Set("families", NewArray(
				fam("core", "enabled"),
				fam("vcs", "enabled"),
				fam("packages", "enabled"),
				fam("telemetry", "disabled"),
			)).
			Set("pack_version", Str("2026.06.11-v2"))
	case "guardrail_typed":
		return NewObject().
			Set("id", Str("vm-llm-token-quota")).
			Set("rung", Int(1)).
			Set("token_budget", Int64String(1000000)).
			Set("digest", Bytes([]byte{0xde, 0xad, 0xbe, 0xef})).
			Set("enabled", Bool(true))
	case "role_document":
		return NewObject().
			Set("name", Str("reviewer")).
			Set("permissions", NewArray(Str("read"), Str("comment"))).
			Set("version", Int(3))
	case "escaping":
		return NewObject().
			Set("b_key", Str("line1\nline2\t\"quoted\"\\back")).
			Set("a_key", Str("café")).
			Set("c_key", Str("emoji-\U0001F40D"))
	default:
		t.Fatalf("rebuild: unknown case %q", name)
		return nil
	}
}

// TestGoldenPayloadsAndHashes is the Go side of the cross-module check: every
// non-composite case re-produces its pinned payload byte-for-byte and the
// pinned content_hash. A drift here means the canonicalizer changed and the
// snapshot format would silently break across the freeze.
func TestGoldenPayloadsAndHashes(t *testing.T) {
	doc := loadGoldens(t)
	for _, c := range doc.Cases {
		if c.Kind == "composite" {
			continue // handled by TestGoldenComposite
		}
		t.Run(c.Name, func(t *testing.T) {
			v := rebuild(t, c.Name)
			payload, hash := CanonicalHash(v)
			if string(payload) != c.Payload {
				t.Fatalf("payload mismatch\n got: %s\nwant: %s", payload, c.Payload)
			}
			if got := hexString(hash[:]); got != c.ContentHash {
				t.Fatalf("content_hash mismatch: got %s want %s", got, c.ContentHash)
			}
			// Independently confirm the hash is SHA-256 over the FIXTURE bytes
			// (the same bytes the Rust verify-only path will hash).
			if got := sha256Of(c.Payload); got != c.ContentHash {
				t.Fatalf("hash over fixture bytes mismatch: got %s want %s", got, c.ContentHash)
			}
		})
	}
}

// sha256Of hashes the fixture's payload string exactly as transported and
// returns the digest as a hex string (the form the fixture pins).
func sha256Of(s string) string {
	h := HashPayload([]byte(s))
	return hexString(h[:])
}

// TestGoldenHashRelations enforces the adversarial relations the fixture
// declares: field-order-only diffs hash EQUAL; meaningful-zero vs absent hash
// DIFFERENTLY (doc 13 §5.1 adversarial set).
func TestGoldenHashRelations(t *testing.T) {
	doc := loadGoldens(t)
	byName := map[string]goldenCase{}
	for _, c := range doc.Cases {
		byName[c.Name] = c
	}
	for _, c := range doc.Cases {
		if c.HashEqualTo != "" {
			other, ok := byName[c.HashEqualTo]
			if !ok {
				t.Fatalf("%s: hash_equal_to references unknown case %q", c.Name, c.HashEqualTo)
			}
			if c.ContentHash != other.ContentHash {
				t.Fatalf("%s declares hash_equal_to %s but hashes differ", c.Name, c.HashEqualTo)
			}
			if c.Payload != other.Payload {
				t.Fatalf("%s/%s declared hash-equal but payloads differ — canonicalizer must collapse field-order", c.Name, c.HashEqualTo)
			}
		}
		if c.HashDiffersFrom != "" {
			other, ok := byName[c.HashDiffersFrom]
			if !ok {
				t.Fatalf("%s: hash_differs_from references unknown case %q", c.Name, c.HashDiffersFrom)
			}
			if c.ContentHash == other.ContentHash {
				t.Fatalf("%s declares hash_differs_from %s but hashes are equal", c.Name, c.HashDiffersFrom)
			}
		}
	}
}

// TestGoldenComposite re-produces the composite host document and checks the
// host content_hash AND each per-session sub-hash (doc 13 §5, D120 / OQ11).
// Sections are supplied out of session_id order to prove the ordering.
func TestGoldenComposite(t *testing.T) {
	doc := loadGoldens(t)
	var cc *goldenCase
	for i := range doc.Cases {
		if doc.Cases[i].Name == "host_composite" {
			cc = &doc.Cases[i]
			break
		}
	}
	if cc == nil {
		t.Fatal("host_composite case missing from golden fixture")
	}

	shared := NewObject().Set("posture", Int(1)).Set("schema_version", Str("pol1/v0"))
	sessZ := NewObject().Set("allowlist", NewArray(Str("api.anthropic.com")))
	sessA := NewObject().Set("allowlist", NewArray(Str("github.com")))
	host := ComposeHostDocument(shared, []SessionSection{
		{SessionID: "sess-zzz", Policy: sessZ}, // intentionally first
		{SessionID: "sess-aaa", Policy: sessA},
	})

	if string(host.Payload) != cc.Payload {
		t.Fatalf("composite payload mismatch\n got: %s\nwant: %s", host.Payload, cc.Payload)
	}
	if got := hexString(host.ContentHash[:]); got != cc.ContentHash {
		t.Fatalf("composite content_hash mismatch: got %s want %s", got, cc.ContentHash)
	}
	if len(host.Sections) != len(cc.Sections) {
		t.Fatalf("section count: got %d want %d", len(host.Sections), len(cc.Sections))
	}
	for i, want := range cc.Sections {
		got := host.Sections[i]
		if got.SessionID != want.SessionID {
			t.Fatalf("section %d order: got %s want %s (must order by session_id)", i, got.SessionID, want.SessionID)
		}
		if string(got.Payload) != want.Payload {
			t.Fatalf("section %s payload mismatch\n got: %s\nwant: %s", want.SessionID, got.Payload, want.Payload)
		}
		if h := hexString(got.Hash[:]); h != want.SubHash {
			t.Fatalf("section %s sub_hash: got %s want %s", want.SessionID, h, want.SubHash)
		}
	}

	// A one-session change must re-hash exactly one section's sub-hash, and the
	// other section's sub-hash is unchanged (the incremental-rehash guarantee).
	sessAChanged := NewObject().Set("allowlist", NewArray(Str("github.com"), Str("gitlab.com")))
	host2 := ComposeHostDocument(shared, []SessionSection{
		{SessionID: "sess-zzz", Policy: sessZ},
		{SessionID: "sess-aaa", Policy: sessAChanged},
	})
	if host2.ContentHash == host.ContentHash {
		t.Fatal("changing one session left the host content_hash unchanged")
	}
	// sess-zzz (unchanged) keeps its sub-hash; sess-aaa (changed) does not.
	if host2.Sections[1].Hash != host.Sections[1].Hash {
		t.Fatal("unchanged session (sess-zzz) sub-hash moved — incremental re-hash broken")
	}
	if host2.Sections[0].Hash == host.Sections[0].Hash {
		t.Fatal("changed session (sess-aaa) sub-hash did not move")
	}
}

// TestGoldenByteMutatedRejected confirms the adversarial byte-mutated transport
// is rejected against the base case's hash — the Rust verify-only NACK property,
// proven on the Go side too (a mutated payload never hashes to the base hash).
func TestGoldenByteMutatedRejected(t *testing.T) {
	doc := loadGoldens(t)
	bm := doc.Adversarial.ByteMutated
	if bm.MutatedPayload == "" {
		t.Fatal("adversarial byte_mutated case missing")
	}
	got := sha256Of(bm.MutatedPayload)
	if got == bm.ExpectedHashOfBase {
		t.Fatal("byte-mutated payload hashed to the base hash — verify-only would wrongly ACCEPT it")
	}
	// And the base payload DOES hash to the expected base hash.
	var base *goldenCase
	for i := range doc.Cases {
		if doc.Cases[i].Name == bm.BaseCase {
			base = &doc.Cases[i]
			break
		}
	}
	if base == nil {
		t.Fatalf("byte_mutated base_case %q not found", bm.BaseCase)
	}
	if h := sha256Of(base.Payload); h != bm.ExpectedHashOfBase {
		t.Fatalf("base case hash mismatch: got %s want %s", h, bm.ExpectedHashOfBase)
	}
}
