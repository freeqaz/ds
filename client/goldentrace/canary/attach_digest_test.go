// SPDX-License-Identifier: Apache-2.0
//
// attach_digest_test.go — the PLANTED-CANARY STDIN-ENTRY test variant for the
// attach-seam keyed-secret-digest matcher (D73 residual; doc 20 §4 canary row).
//
// This is the attach-path twin of the proxy plane's canary-secret (c) test (doc
// 12 §5.3): there, a planted canary credential is pushed to the keyed feed and
// the test proves it never egresses through ds-tlsproxy in any variant encoding.
// HERE, the same planted canary enters via the path the proxy never sees — a
// user PASTE into the client wrapper → CC stdin — and the test proves:
//
//   1. the attach matcher consumes the SAME keyed digest feed shape the proxy
//      plane consumes (identity.v1.DigestEntry — built by BuildAttachCanaryFeed,
//      the exact frozen entry-set of doc 14 §7);
//   2. a pasted swap-class secret IS matched + evented on the stdin path (in
//      raw, base64, url-encoded, AND hex paste forms);
//   3. NEVER-LOG-THE-SECRET (D73): the planted canary substring appears in ZERO
//      bytes of any emitted log / event / spool.
//
// SYNTHETIC ONLY (D50): the canary and HMAC key are made-up markers, never real
// provider token shapes; no live claude / ds-capture / podman / network.

package canary

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"

	claudecode "github.com/dream-serpent/dream-serpent/client/wrapper/adapters/claude-code"
)

// attachCanarySecret is a clearly-SYNTHETIC swap-class canary the user "pastes"
// into the session. Deliberately NOT a real provider token shape (no sk-ant-…,
// no Bearer + long body) so it cannot trip the D50 fixture-provenance value
// regexes; the distinctive infix is the never-log scan needle. It carries a
// trailing "+/" so its URL-encoded form (…%2B%2F) is genuinely DISTINCT from the
// raw bytes — exercising the urlenc variant as a separate matchable encoding.
const attachCanarySecret = "ds-test-attach-canary-PASTEDTOKEN-7Q2W9E+/"

// attachCanaryInfix is the high-entropy infix the never-log assertion scans for —
// matching it (not just the full string) hardens the check against partial
// leakage of the secret value.
const attachCanaryInfix = "PASTEDTOKEN-7Q2W9E"

// attachWSCanarySecret is a SYNTHETIC canary that CONTAINS EMBEDDED WHITESPACE —
// the case the old whitespace-only candidate split could never recover (it tore
// the secret into separate fields, none of which hashed to the whole-credential
// digest). The sliding-window scan must reach ACROSS the spaces to match it. It
// keeps the trailing "+/" so its url-encoded form is distinct from raw.
const attachWSCanarySecret = "ds-test attach canary EMBEDDED WS-INFIX-K4 token+/"

// attachWSCanaryInfix is the embedded-whitespace canary's distinctive infix
// (itself spanning a space) for the never-log scan.
const attachWSCanaryInfix = "EMBEDDED WS-INFIX-K4"

const (
	attachCanaryKeyID      = "synthetic-attach-key-epoch-1"
	attachCanaryServiceID  = "" // FORBIDDEN class: a guarded credential pasted in.
	attachCanaryDigestSetV = "attach-digest-set-v1"
)

// attachCanaryHMACKey is the SYNTHETIC per-host per-epoch HMAC key the producer
// "minted" the feed under and the matcher recomputes candidates against.
var attachCanaryHMACKey = []byte("synthetic-attach-hmac-key-do-not-use-in-prod")

// newAttachMatcher builds the matcher consumer from a synthetic keyed feed
// planted with the canary — the matcher-consumer wiring under test.
func newAttachMatcher(t *testing.T, serviceID string) *claudecode.AttachDigestMatcher {
	t.Helper()
	return newAttachMatcherFor(t, []byte(attachCanarySecret), serviceID)
}

// newAttachMatcherFor builds the matcher consumer from a feed planted with an
// arbitrary synthetic `secret` — so the punctuation-abutted and
// embedded-whitespace variants can plant their own canary shapes.
func newAttachMatcherFor(t *testing.T, secret []byte, serviceID string) *claudecode.AttachDigestMatcher {
	t.Helper()
	feed := BuildAttachCanaryFeed(attachCanaryKeyID, attachCanaryHMACKey, secret, serviceID, attachCanaryDigestSetV)
	m, err := claudecode.NewAttachDigestMatcher(feed.KeyID, feed.HMACKey, feed.TruncLen, feed.DigestSetVersion, feed.Entries)
	if err != nil {
		t.Fatalf("NewAttachDigestMatcher: %v", err)
	}
	return m
}

// encodeVariants renders `secret` in each of the four on-wire encodings the
// producer mints an entry per (raw/base64/urlenc/hex) — the exact same
// producer-side encodings as encodeAttachVariant, recomputed test-side so a
// "paste" can carry each form.
func encodeVariants(secret string) map[string]string {
	return map[string]string{
		"raw":    secret,
		"base64": base64.StdEncoding.EncodeToString([]byte(secret)),
		"urlenc": url.QueryEscape(secret),
		"hex":    hex.EncodeToString([]byte(secret)),
	}
}

// TestAttachPlantedCanaryMatchedOnStdinEntry is the headline planted-canary
// stdin-entry variant: a pasted canary, in each encoding the producer minted,
// IS matched + evented on the attach path.
func TestAttachPlantedCanaryMatchedOnStdinEntry(t *testing.T) {
	m := newAttachMatcher(t, attachCanaryServiceID)

	// Each "paste" is the canary in one encoding the feed carries, embedded in an
	// otherwise-innocuous prompt — the stdin-entry shape EncodeInput drives. The
	// encoded form is a whitespace-delimited token (the matcher's candidate-
	// extraction splits on whitespace), so it is recovered intact from the prompt.
	pastes := map[string]string{
		"raw":    "here is my token: " + attachCanarySecret + " please use it",
		"base64": "decoded creds " + base64.StdEncoding.EncodeToString([]byte(attachCanarySecret)) + " end",
		"urlenc": "url encoded form: " + url.QueryEscape(attachCanarySecret) + " end",
		"hex":    "hexdump " + hex.EncodeToString([]byte(attachCanarySecret)) + " end",
	}

	for name, pasted := range pastes {
		t.Run(name, func(t *testing.T) {
			in := claudecode.DriveInput{Text: pasted}
			matches := m.MatchInput(in)
			if len(matches) == 0 {
				t.Fatalf("attach matcher did NOT match a pasted %s canary — the stdin-entry residual is open", name)
			}
			// The matched event must carry fingerprint metadata identifying the
			// feed entry (key id, class) — and NOTHING that could be the secret.
			hit := matches[0]
			if hit.KeyID != attachCanaryKeyID {
				t.Errorf("match KeyID = %q, want %q", hit.KeyID, attachCanaryKeyID)
			}
			if hit.CredClass != "forbidden" {
				t.Errorf("match CredClass = %q, want %q", hit.CredClass, "forbidden")
			}
			if hit.DigestSetVersion != attachCanaryDigestSetV {
				t.Errorf("match DigestSetVersion = %q, want %q", hit.DigestSetVersion, attachCanaryDigestSetV)
			}
		})
	}
}

// TestAttachPlantedCanaryNeverLogged is the never-log-the-secret (D73)
// assertion: the matched canary value appears in ZERO bytes of any emitted log /
// event / spool. It drives a real match and then scans EVERY byte the matcher
// surfaces for the planted substring (and its high-entropy infix), requiring
// absence. The legitimate stdin TRANSPORT (EncodeInput) is NOT a log/event/spool
// and necessarily carries the user's own input verbatim — the invariant is about
// the matcher's OWN emissions, which must never echo the secret.
func TestAttachPlantedCanaryNeverLogged(t *testing.T) {
	m := newAttachMatcher(t, attachCanaryServiceID)

	pasted := "credentials: " + attachCanarySecret
	in := claudecode.DriveInput{Text: pasted}

	matches := m.MatchInput(in)
	if len(matches) == 0 {
		t.Fatalf("precondition: the canary must match for the never-log assertion to be meaningful")
	}

	// Collect EVERY byte the matcher emits about the match: the event(s) rendered
	// as Go values (%v / %+v / %#v) and as JSON (the on-the-wire event form a
	// caller would route to a log/event/spool sink). These are the surfaces a
	// secret could leak through.
	var emitted bytes.Buffer
	for _, hit := range matches {
		fmt.Fprintf(&emitted, "%v\n%+v\n%#v\n", hit, hit, hit)
		j, err := json.Marshal(hit)
		if err != nil {
			t.Fatalf("marshal match event: %v", err)
		}
		emitted.Write(j)
		emitted.WriteByte('\n')
	}

	// The planted secret — full value AND its high-entropy infix — must appear in
	// ZERO bytes of the matcher's emissions.
	hay := emitted.Bytes()
	if bytes.Contains(hay, []byte(attachCanarySecret)) {
		t.Fatalf("NEVER-LOG VIOLATION: the matched canary value leaked into an emitted event/log/spool")
	}
	if bytes.Contains(hay, []byte(attachCanaryInfix)) {
		t.Fatalf("NEVER-LOG VIOLATION: the matched canary infix leaked into an emitted event/log/spool")
	}
	// Belt-and-suspenders: the secret's keyed-hash variants are one-way and not
	// the plaintext; the emitted event must not even carry the digest hex (it is
	// fingerprint metadata only, by construction). The struct has no digest field,
	// so this also guards against a future field addition.
	rawDigestHex := hex.EncodeToString([]byte(attachCanarySecret))
	if bytes.Contains(hay, []byte(rawDigestHex)) {
		t.Fatalf("NEVER-LOG VIOLATION: the hex of the canary leaked into an emitted event")
	}
}

// TestAttachIssuedClassEventsServiceID proves the ISSUED{service_id} class is
// carried into the match event for attribution parity with the proxy plane,
// while STILL never leaking the secret.
func TestAttachIssuedClassEventsServiceID(t *testing.T) {
	const svc = "api.example-service"
	m := newAttachMatcher(t, svc)

	in := claudecode.DriveInput{Text: "token " + attachCanarySecret}
	matches := m.MatchInput(in)
	if len(matches) == 0 {
		t.Fatalf("issued-class canary must match")
	}
	hit := matches[0]
	if hit.CredClass != "issued" {
		t.Errorf("CredClass = %q, want issued", hit.CredClass)
	}
	if hit.ServiceID != svc {
		t.Errorf("ServiceID = %q, want %q", hit.ServiceID, svc)
	}
	// Never-log holds for the issued class too.
	if strings.Contains(fmt.Sprintf("%+v", hit), attachCanaryInfix) {
		t.Fatalf("NEVER-LOG VIOLATION: issued-class event leaked the canary infix")
	}
}

// TestAttachInnocuousInputDoesNotMatch proves the matcher does not false-positive
// on an ordinary prompt — a prompt with no planted canary yields no event.
func TestAttachInnocuousInputDoesNotMatch(t *testing.T) {
	m := newAttachMatcher(t, attachCanaryServiceID)
	in := claudecode.DriveInput{Text: "Please refactor the parser and add a test."}
	if matches := m.MatchInput(in); len(matches) != 0 {
		t.Fatalf("innocuous prompt matched %d entries; want 0 (false positive)", len(matches))
	}
}

// scanEmitted renders EVERY byte a slice of match events surfaces — the Go-value
// forms (%v/%+v/%#v) and the JSON wire form — into one buffer, the surfaces a
// secret could leak through. Shared by the never-log assertions below.
func scanEmitted(t *testing.T, matches []claudecode.DigestMatch) []byte {
	t.Helper()
	var emitted bytes.Buffer
	for _, hit := range matches {
		fmt.Fprintf(&emitted, "%v\n%+v\n%#v\n", hit, hit, hit)
		j, err := json.Marshal(hit)
		if err != nil {
			t.Fatalf("marshal match event: %v", err)
		}
		emitted.Write(j)
		emitted.WriteByte('\n')
	}
	return emitted.Bytes()
}

// assertNoLeak asserts the planted secret — full value, its high-entropy infix,
// and (belt-and-suspenders) the raw hex of the secret — appear in ZERO bytes of
// the matcher's emissions (D73 NEVER-LOG-THE-SECRET).
func assertNoLeak(t *testing.T, hay []byte, secret, infix string) {
	t.Helper()
	if bytes.Contains(hay, []byte(secret)) {
		t.Fatalf("NEVER-LOG VIOLATION: the matched canary value leaked into an emitted event/log/spool")
	}
	if bytes.Contains(hay, []byte(infix)) {
		t.Fatalf("NEVER-LOG VIOLATION: the matched canary infix leaked into an emitted event/log/spool")
	}
	if rawHex := hex.EncodeToString([]byte(secret)); bytes.Contains(hay, []byte(rawHex)) {
		t.Fatalf("NEVER-LOG VIOLATION: the hex of the canary leaked into an emitted event")
	}
}

// TestAttachPunctuationAbuttedPasteMatched is the headline parity case the
// sliding-window scan unlocks: a pasted canary ABUTTED BY PUNCTUATION — the form
// the old whitespace-only split could NOT recover, because the secret is not a
// standalone whitespace-delimited token. Every punctuation-abutted shape is
// exercised across raw/base64/urlenc/hex, and each must (a) match + event, and
// (b) leak ZERO secret bytes into any emission. This is the byte-span parity with
// ds-tlsproxy's bounded-window scan (scan.rs match_keyed) the unit delivers.
func TestAttachPunctuationAbuttedPasteMatched(t *testing.T) {
	m := newAttachMatcher(t, attachCanaryServiceID)

	// frame wraps the encoded secret in a punctuation-abutting context. %s is the
	// encoded canary; the surrounding punctuation has NO whitespace adjacent to it,
	// so a whitespace split would have tested the WHOLE framed token (e.g.
	// `token=<SECRET>`) and missed the secret. The window finds the secret inside.
	frames := map[string]string{
		"key=value":     "token=%s",
		"double-quoted": "\"%s\"",
		"single-quoted": "'%s'",
		"bracketed":     "[%s]",
		"angle-bracket": "<%s>",
		"prefix-colon":  "prefix:%s",
		"suffix-comma":  "%s,end",
		"json-field":    "{\"token\":\"%s\"}",
		"trailing-dot":  "use %s.",
		"paren-wrapped": "creds(%s)here",
	}

	for variant, encoded := range encodeVariants(attachCanarySecret) {
		for frameName, frameFmt := range frames {
			t.Run(variant+"/"+frameName, func(t *testing.T) {
				pasted := "here: " + fmt.Sprintf(frameFmt, encoded) + " thanks"
				in := claudecode.DriveInput{Text: pasted}
				matches := m.MatchInput(in)
				if len(matches) == 0 {
					t.Fatalf("punctuation-abutted %s paste (%s) did NOT match — the sliding-window parity gap is open", variant, frameName)
				}
				hit := matches[0]
				if hit.KeyID != attachCanaryKeyID {
					t.Errorf("match KeyID = %q, want %q", hit.KeyID, attachCanaryKeyID)
				}
				if hit.CredClass != "forbidden" {
					t.Errorf("match CredClass = %q, want forbidden", hit.CredClass)
				}
				assertNoLeak(t, scanEmitted(t, matches), attachCanarySecret, attachCanaryInfix)
			})
		}
	}
}

// TestAttachEmbeddedWhitespacePasteMatched plants a canary that CONTAINS
// whitespace and proves the sliding-window scan recovers it — the second case the
// old whitespace split structurally could not match (it tore the secret into
// fields, none of which was the whole credential). All four encodings of the
// spaced secret are exercised; each must match + event and leak zero secret
// bytes.
func TestAttachEmbeddedWhitespacePasteMatched(t *testing.T) {
	m := newAttachMatcherFor(t, []byte(attachWSCanarySecret), attachCanaryServiceID)

	for variant, encoded := range encodeVariants(attachWSCanarySecret) {
		t.Run(variant, func(t *testing.T) {
			// Embed the encoded form (the RAW one itself carries internal spaces) in
			// a longer prompt. The whole prompt is one inspected span; the window
			// scan reaches across any internal spaces in the RAW form.
			pasted := "user pasted: " + encoded + " <- creds above"
			in := claudecode.DriveInput{Text: pasted}
			matches := m.MatchInput(in)
			if len(matches) == 0 {
				t.Fatalf("embedded-whitespace %s paste did NOT match — the window must span internal whitespace", variant)
			}
			if matches[0].CredClass != "forbidden" {
				t.Errorf("CredClass = %q, want forbidden", matches[0].CredClass)
			}
			assertNoLeak(t, scanEmitted(t, matches), attachWSCanarySecret, attachWSCanaryInfix)
		})
	}
}

// TestAttachWhitespaceDelimitedStillMatches is the NO-REGRESSION pin: the
// whitespace-delimited paste forms that passed before the sliding-window change
// still match (the window subsumes the old whole-token split). It mirrors the
// pre-change TestAttachPlantedCanaryMatchedOnStdinEntry case set so a regression
// to the narrower extractor would fail here too.
func TestAttachWhitespaceDelimitedStillMatches(t *testing.T) {
	m := newAttachMatcher(t, attachCanaryServiceID)
	for variant, encoded := range encodeVariants(attachCanarySecret) {
		t.Run(variant, func(t *testing.T) {
			in := claudecode.DriveInput{Text: "here is my token: " + encoded + " please use it"}
			matches := m.MatchInput(in)
			if len(matches) == 0 {
				t.Fatalf("whitespace-delimited %s paste regressed — it matched before the window change", variant)
			}
			assertNoLeak(t, scanEmitted(t, matches), attachCanarySecret, attachCanaryInfix)
		})
	}
}

// TestAttachAbuttedNonSecretDoesNotMatch guards the false-positive side of the
// wider scan: a punctuation-dense prompt with NO planted canary must still yield
// zero events even though the window now tests far more substrings.
func TestAttachAbuttedNonSecretDoesNotMatch(t *testing.T) {
	m := newAttachMatcher(t, attachCanaryServiceID)
	in := claudecode.DriveInput{Text: `cfg={"a":1,"b":[2,3]}; run(x):=foo.bar/baz?q=1&r=2#frag`}
	if matches := m.MatchInput(in); len(matches) != 0 {
		t.Fatalf("punctuation-dense non-secret prompt matched %d entries; want 0 (window false positive)", len(matches))
	}
}

// TestAttachMatcherConsumesSameFeedShapeAsProxy is the doc-20 acceptance pin:
// the feed the attach matcher consumes is the SAME frozen identity.v1.DigestEntry
// shape ds-tlsproxy consumes — HMAC-SHA-256 family, agreed truncation length,
// one entry per encoding variant. It asserts the feed BuildAttachCanaryFeed mints
// has exactly that shape (no invented contract).
func TestAttachMatcherConsumesSameFeedShapeAsProxy(t *testing.T) {
	feed := BuildAttachCanaryFeed(attachCanaryKeyID, attachCanaryHMACKey, []byte(attachCanarySecret), attachCanaryServiceID, attachCanaryDigestSetV)
	if len(feed.Entries) != len(allAttachVariants) {
		t.Fatalf("feed has %d entries; want one per variant (%d)", len(feed.Entries), len(allAttachVariants))
	}
	seen := map[string]bool{}
	for _, e := range feed.Entries {
		if e.GetKeyId() != attachCanaryKeyID {
			t.Errorf("entry key_id = %q, want %q", e.GetKeyId(), attachCanaryKeyID)
		}
		if e.GetAlgo().GetFamily().String() != "FAMILY_HMAC_SHA256" {
			t.Errorf("entry algo family = %q, want FAMILY_HMAC_SHA256", e.GetAlgo().GetFamily())
		}
		if int(e.GetAlgo().GetTruncationLenBytes()) != feed.TruncLen {
			t.Errorf("entry trunc len = %d, want %d", e.GetAlgo().GetTruncationLenBytes(), feed.TruncLen)
		}
		if e.GetScope().String() != "DIGEST_SCOPE_SESSION" {
			t.Errorf("entry scope = %q, want DIGEST_SCOPE_SESSION", e.GetScope())
		}
		// The digest must be present and exactly TruncLen bytes — a digest, not
		// the plaintext (which is far longer/shorter and would never equal this).
		if len(e.GetDigest()) != feed.TruncLen {
			t.Errorf("entry digest len = %d, want %d", len(e.GetDigest()), feed.TruncLen)
		}
		if bytes.Contains(e.GetDigest(), []byte(attachCanaryInfix)) {
			t.Errorf("entry digest contains the plaintext infix — a digest must never carry plaintext")
		}
		seen[e.GetVariantTag().String()] = true
	}
	for _, v := range allAttachVariants {
		if !seen[v.String()] {
			t.Errorf("feed missing an entry for variant %s", v)
		}
	}
}
