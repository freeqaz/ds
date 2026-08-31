// driver.go — the WRITE half of the wrapper, the inverse of the read adapter
// (DRIVE-PROTOCOL.md). Where the Adapter projects CC stdout → attach.v1, the
// Driver projects attach.v1 (the thin client's input + the policy stream's
// grant) → CC stdin: a stream-json user-input record (P4) and a native
// control_response (P8). It is THE runtime-specific write code (D38): the
// CC-isms it speaks must never leak out of this package — the thin client and
// the policy stream upstream of it are runtime-ignorant.
//
// The build insight from DRIVE-PROTOCOL.md: "the driver is the mirror of the
// adapter." It reuses records.go's contentBlock verbatim and threads the same
// request_id/tool_use_id correlation the read side keys on (P8). The outbound
// message body and control_response envelope are minimal emit-shaped twins of
// records.go's decode structs (userInputMessage / controlResponseOut): the
// decode structs have no omitempty, so marshaling them directly would leak their
// full inbound key set onto the wire and diverge from the captured P4/P8 shapes —
// a direction difference in field-set, not a re-definition of the wire contract.
//
// CRITICAL invariant (D45/D53): the Driver holds NO approval state. It never
// stores a grant. A grant is a pure function input → control_response; a second
// grant cannot depend on a first because nothing from the first is retained.
// The grant is a TTL'd object on the policy stream (client/README seam: a
// one-way AskUserRequest answered by a TTL'd grant, never a second proxy-side
// response channel); the Driver merely turns it into CC's wire form inside the
// boundary.
//
// v0 SCOPE (DRIVE-PROTOCOL.md "the three gaps"): the two PROVEN-live pieces —
// P4 single-text-block input and P8 grants — plus the native control-channel
// control_response. The native control_response shape was FIRST structured from
// records.go's binary-extracted shapes and is now LIVE-VERIFIED: the keystone
// (01KTXBG14J, 2026-06-12) and the live-drive socket-bridge run (01KTXBGTJA)
// round-tripped this exact EncodeGrant output on CC 2.1.173 — CC accepted it and
// drove the correct allow/deny outcome (DRIVE-FINDINGS.md §1 + the re-pin pass
// 2026-06-12). Multi-block input, tool_result-as-input, images, and SendMessage
// continuation are out of scope (P17 open).
package claudecode

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
)

// --- attach.v1 WRITE-side shapes (locally declared) -------------------------
//
// The attach package (client/wrapper/attach) is, at this revision, the READ
// model only: it has no input or grant event type (the proto WRITE side, doc 15
// §6 rows 6/7, is task 01KTXBG16B — not yet landed). Per the unit charter, this
// driver depends on shapes it declares LOCALLY rather than on a sibling unit's
// not-yet-existing concrete types. These two structs are the documented write
// half of dreamserpent.attach.v1 — runtime-ignorant by construction (no CC
// vocabulary appears on them): the thin client emits DriveInput, the policy
// stream emits DriveGrant, and the Driver is the only place that knows how
// either becomes a CC record.

// DriveInput is one input event from the thin client (the write mirror of the
// read side's ChatMessage). v0 carries a single text body — the P4 envelope CC
// proved live accepts exactly one text block. Multi-block / tool_result-as-input
// / image inputs are deferred (DRIVE-PROTOCOL.md "the three gaps", P17 open);
// they are NOT modeled here so a caller cannot construct an unsupported input by
// accident.
type DriveInput struct {
	// Text is the user prompt to drive into the session. Empty Text is a
	// caller error (EncodeInput returns an error, never an empty CC record).
	Text string `json:"text"`
}

// DriveGrant is a policy-stream grant: the human's answer to an ask, returned
// as a TTL'd object on the policy stream (D18/D45/D53), NOT as a control_response
// punched back through the proxy. The Driver turns it into CC's control_response
// inside the boundary. The single correlation field is RequestID — the control
// request_id the ask carried (== the native channel's join key); a CC
// control_response correlates back on request_id, never on tool_use_id (P8: the
// success response carries request_id only). ToolUseID is carried for the
// adapter's id-triple bookkeeping and for the prompt-tool route, but it is NOT
// the control_response join key.
//
// The Driver stores none of this: EncodeGrant is a pure function of its
// argument.
type DriveGrant struct {
	// RequestID is the ask's control request_id — the control_response join key.
	RequestID string `json:"request_id"`
	// ToolUseID is the tool_use id the ask correlated on (P8 end-to-end key);
	// carried for adapter bookkeeping, not the control_response join.
	ToolUseID string `json:"tool_use_id"`
	// Allow is the grant decision: true ⇒ behavior "allow", false ⇒ "deny".
	Allow bool `json:"allow"`
	// UpdatedInput is the echoed-or-rewritten tool input the allow path returns
	// (P8: allow returns updatedInput). Optional; when nil the original input is
	// implied. Ignored on a deny.
	UpdatedInput json.RawMessage `json:"updated_input,omitempty"`
	// Message is the deny reason that propagates verbatim into the is_error
	// tool_result and result.permission_denials[] (P8). Ignored on an allow.
	Message string `json:"message,omitempty"`
}

// --- the Driver -------------------------------------------------------------

// Driver projects attach.v1 write events into CC stream-json records. It is
// STATELESS by construction: it holds no approval state and no per-session
// cursor (D45/D53). Every method is a pure function of its argument, so the
// same instance is safe to reuse across sessions and a second call never
// depends on a first. Construct one with NewDriver (it exists for symmetry with
// New and a future-proof config seam, not because it carries state).
type Driver struct{}

// NewDriver constructs a Driver. There are no options today; the constructor is
// the seam a future config (e.g. a max-input-bytes guard) would attach to,
// mirroring New's Option pattern without scaffolding an empty one now.
func NewDriver() *Driver { return &Driver{} }

// EncodeInput maps a DriveInput to the CC stream-json user-input record — the
// P4 envelope CC proved live accepts: {type:"user", message:{role:"user",
// content:[{type:"text", text:…}]}} with a single text block. CC mints the
// record uuid/session_id itself and acks the input back with isReplay:true
// (records.go userRecord.IsReplay) — the Driver therefore emits NEITHER: it
// writes the minimal accepted envelope and lets CC stamp identity, exactly the
// inverse of the read side which keys off CC's minted ids. Returns the marshaled
// NDJSON line (no trailing newline; the transport frames lines).
//
// It reuses records.go's contentBlock verbatim — the same wire type the read
// adapter DECODES, here ENCODED — so the text block is, by construction,
// byte-shaped like the blocks CC emits and the adapter parses. The message
// *wrapper* is the minimal emit shape (see userInputMessage): the decode-side
// `message` struct has no omitempty and would leak its full key set, diverging
// from the captured P4 echo body {role, content}.
func (d *Driver) EncodeInput(in DriveInput) ([]byte, error) {
	if in.Text == "" {
		return nil, fmt.Errorf("claudecode: EncodeInput: empty Text (v0 requires a single non-empty text block)")
	}
	rec := userInputRecord{
		Type: "user",
		Message: userInputMessage{
			Role: "user",
			Content: []contentBlock{
				{Type: "text", Text: in.Text},
			},
		},
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return nil, fmt.Errorf("claudecode: EncodeInput: marshal: %w", err)
	}
	return b, nil
}

// userInputRecord is the OUTBOUND user-input envelope (P4). It is deliberately
// the minimal accepted shape: type + message{role, content[]}, no uuid/
// session_id/parent_tool_use_id — CC mints those and echoes the record back as
// the isReplay:true ack the read-side userRecord models.
//
// We do NOT reuse records.go's `message` for the body, even though it is the
// single source of truth for an INBOUND message: `message` is a decode struct
// with no omitempty, so marshaling it emits the full key set with empty values
// (id:"", type:"", model:"", stop_reason:"", usage:null, …). The documented P4
// echo body is exactly `{content, role}` (PHASE2 P4: "the replay's message has
// only {content, role} — no id, no request_id"), so emitting those spurious
// keys would diverge from the captured wire shape. userInputMessage is the
// minimal outbound body — it reuses records.go's contentBlock verbatim (the
// single source of truth for a content block); only the message *wrapper*'s
// field set differs between the rich decode shape and the minimal emit shape,
// which is a direction difference, not a duplicated struct.
type userInputRecord struct {
	Type    string           `json:"type"`
	Message userInputMessage `json:"message"`
}

// userInputMessage is the outbound P4 message body: exactly {role, content}, the
// captured echo shape. contentBlock is records.go's, reused verbatim.
type userInputMessage struct {
	Role    string         `json:"role"`
	Content []contentBlock `json:"content"`
}

// EncodeGrant maps a DriveGrant to CC's native control_response (P8):
// control_response{response:{subtype:"success", request_id,
// response:{behavior, updatedInput?|message?}}}. It emits through the
// omitempty-correct twins of records.go's
// controlResponseRecord/controlResponseBody/controlDecision (controlResponseOut
// /controlResponseBodyOut/outboundDecision) — same field semantics, emit-shaped
// — so a grant the Driver writes decodes cleanly through the exact structs the
// read adapter uses, the same wire record viewed from two directions. The
// decode structs are NOT marshaled directly: lacking omitempty they would leak
// CC-minted envelope ids (uuid/session_id) and the initialize-handshake-only
// pending_* riders onto every can_use_tool answer (see the Out structs below).
//
// ── LIVE-VERIFIED 2026-06-12 (keystone 01KTXBG14J; re-pin pass) ─────────────
// The native control_request{subtype:"can_use_tool"} → control_response round
// trip was FIRST extracted from the binary, then EXERCISED LIVE against real CC
// 2.1.173 in a rootless podman container: the keystone (01KTXBG14J) round-tripped
// one allow and one deny over the native channel, and the live-drive socket-
// bridge run (01KTXBGTJA) drove this exact EncodeGrant output through the full
// transport stack (thin client → SocketTransport → Bridge → EncodeGrant) — the
// grant landed on CC stdin and the tool executed (allow → is_error:false; deny →
// is_error:true with the message verbatim + result.permission_denials[]). The
// re-pin pass (2026-06-12) re-confirmed the envelope live. The shape below is
// CONFIRMED CORRECT AS-IS: subtype:"success" envelope, request_id join key,
// camelCase updatedInput/updatedPermissions, behavior-conditional updatedInput
// (allow) | message (deny), and NO top-level uuid/session_id (CC mints none on a
// host answer). The snake_case permission_response{updated_input,...} that also
// appears in the binary belongs to the cloud PermissionSync path, NOT this local
// stdio channel — do not conflate them. The PROVEN-from-the-start grant path is
// the --permission-prompt-tool MCP route (P8 AVENUE-a); EncodeGrantPromptTool
// below emits that. Both ship: the native route is now the live-verified default
// for the stdio channel. See DRIVE-FINDINGS.md §1.
// ───────────────────────────────────────────────────────────────────────────
//
// The Driver stores nothing: the returned record is a pure function of grant.
func (d *Driver) EncodeGrant(grant DriveGrant) ([]byte, error) {
	if grant.RequestID == "" {
		return nil, fmt.Errorf("claudecode: EncodeGrant: empty RequestID (the control_response join key, P8)")
	}
	decision := outboundDecision{Behavior: grantBehavior(grant.Allow)}
	if grant.Allow {
		// allow returns updatedInput (P8); optional — omit when the caller did
		// not rewrite the input, so the field is absent rather than JSON null.
		decision.UpdatedInput = grant.UpdatedInput
	} else {
		// deny returns a message that propagates verbatim into the is_error
		// tool_result and result.permission_denials[] (P8).
		decision.Message = grant.Message
	}
	rec := controlResponseOut{
		Type: "control_response",
		Response: controlResponseBodyOut{
			Subtype:   "success", // the control-channel ENVELOPE outcome (the request was handled), not the grant decision — that is decision.Behavior (P8).
			RequestID: grant.RequestID,
			Response:  decision,
		},
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return nil, fmt.Errorf("claudecode: EncodeGrant: marshal: %w", err)
	}
	return b, nil
}

// The OUTBOUND control_response shapes. As with userInputMessage, we do not
// marshal records.go's controlResponseRecord/controlResponseBody/controlDecision
// directly: those are DECODE structs with no omitempty, so marshaling them emits
// the full inbound key set with empty values — the envelope's uuid/session_id
// (CC mints these, the grant must not), the initialize-handshake-only
// pending_permission_requests[]/pending_user_dialog_requests riders (P8: those
// belong ONLY to the initialize response, never to a can_use_tool answer), and
// the unset updatedPermissions/message on the allow path. The documented native
// shape (P8) is the minimal {response:{subtype, request_id, response:{behavior,
// updatedInput?|message?}}}; these omitempty-correct mirrors emit exactly that.
// They are direction-twins of the records.go decode structs (same field
// semantics, emit-shaped), not independent definitions of the wire contract.
type controlResponseOut struct {
	Type     string                 `json:"type"`
	Response controlResponseBodyOut `json:"response"`
}

type controlResponseBodyOut struct {
	Subtype   string           `json:"subtype"`
	RequestID string           `json:"request_id"`
	Response  outboundDecision `json:"response"`
}

// outboundDecision mirrors records.go's controlDecision but with omitempty so
// the allow path omits message and the deny path omits updatedInput — the
// behavior-conditional presence P8 documents (allow⇒updatedInput, deny⇒message).
type outboundDecision struct {
	Behavior           string          `json:"behavior"`
	UpdatedInput       json.RawMessage `json:"updatedInput,omitempty"`
	UpdatedPermissions json.RawMessage `json:"updatedPermissions,omitempty"`
	Message            string          `json:"message,omitempty"`
}

// EncodeGrantPromptTool maps a DriveGrant to the PROVEN-live grant form — the
// --permission-prompt-tool MCP route's response (P8 AVENUE-a, observed live):
// behavior "allow" returns updatedInput (+ optional updatedPermissions);
// behavior "deny" returns a message (+ optional interrupt). Unlike the native
// channel this carries NO request_id envelope — the prompt-tool framework
// correlates by the JSON-RPC call id out of band — so the join is the ask's
// tool_use_id (DriveGrant.ToolUseID), which the prompt-tool ask delivered as
// {tool_name, input, tool_use_id}. v0's default grant route.
//
// This is the response BODY a registered prompt-tool returns; the MCP JSON-RPC
// envelope around it is the transport's concern, not the Driver's (the Driver
// speaks the CC protocol body, the transport frames it).
func (d *Driver) EncodeGrantPromptTool(grant DriveGrant) ([]byte, error) {
	if grant.ToolUseID == "" {
		return nil, fmt.Errorf("claudecode: EncodeGrantPromptTool: empty ToolUseID (the prompt-tool correlation key, P8)")
	}
	body := outboundDecision{Behavior: grantBehavior(grant.Allow)}
	if grant.Allow {
		body.UpdatedInput = grant.UpdatedInput
	} else {
		body.Message = grant.Message
	}
	b, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("claudecode: EncodeGrantPromptTool: marshal: %w", err)
	}
	return b, nil
}

// grantBehavior maps the boolean grant decision onto CC's behavior enum (P8:
// the responder answers behavior "allow" | "deny"). The third wire value
// "cancelled" is a TIMEOUT outcome the engine resolves itself, never a grant
// the human emits, so it is intentionally unreachable from a DriveGrant.
func grantBehavior(allow bool) string {
	if allow {
		return "allow"
	}
	return "deny"
}

// --- attach-seam keyed secret-digest matcher (D73, doc 20 §4 canary row) -----
//
// THE GAP THIS CLOSES (doc 20 §4 canary row; doc 12 §10): the keyed
// secret-egress plane catches a planted credential at first egress on INSPECTED
// paths through ds-tlsproxy — but a user-PASTED token entering via the client
// wrapper → CC stdin NEVER traverses the proxy (it is written straight onto the
// session's stdin by the Driver below). That path is the D73 RESIDUAL the doc 20
// canary row names as "a tracked follow-on owned by Attach & client." This
// matcher is that consumer: it inspects the attach-seam stdin bytes against the
// SAME keyed digest feed the proxy plane consumes (the frozen
// identity.v1.DigestEntry feed — HMAC-SHA-256-truncated digests over each
// encoded variant, tagged ISSUED{service_id} | FORBIDDEN, doc 14 §7) and EVENTS
// a swap-class secret it sees — WITHOUT the plaintext ever leaving the matcher.
//
// WHY THE SAME FEED (not a new contract): the producer (Identity, in the D39
// secret-store trust zone) pushes ONE digest set per session; ds-tlsproxy's
// Rust SecretMatcher consumes it on the egress path and this Go consumer
// consumes the identical entries on the attach path. Both compute the keyed
// hash candidate-side and test set membership — neither ever holds the
// plaintext digest of a credential it did not see on the wire. Reusing the
// frozen DigestEntry shape is the doc-20 acceptance pin ("reuse the existing
// digest-feed contract, do not invent a new one").
//
// NEVER-LOG-THE-SECRET (D73) — load-bearing, asserted in the canary test:
//   - The matcher is handed the candidate bytes (the pasted token) ONLY
//     transiently, to compute their keyed hash; it retains NONE of them.
//   - A match yields a [DigestMatch] event whose fields are fingerprint-class
//     ONLY (key_id, cred class, service_id, variant tag, digest-set version) —
//     there is, by construction, NO field that can carry the secret value or any
//     slice of the inspected text. This mirrors the Rust [VerdictProvenance]
//     "incapable of carrying matched bytes by construction" property.
//   - The matcher emits no log line and spools nothing; the only output is the
//     event the caller chooses to route. The matched secret value appears in
//     ZERO bytes of any log, event, or spool.

// (No separate digestKey type: the matcher keys its set on the truncated
// keyed-hash digest bytes alone — see AttachDigestMatcher.set. The producer
// pre-encodes, minting one entry per encoding variant, so a candidate the
// matcher sees on the wire is tested AS-IS against every entry; the matched
// entry's variant tag is recovered from the entry, not from re-encoding
// candidate-side. This is exactly ds-tlsproxy's model — the proxy sees raw wire
// bytes and the producer's per-encoding entries make a base64'd / url-encoded /
// hex'd secret match without the consumer re-deriving the encoding.)

// DigestMatch is the attach-seam match EVENT — the fingerprint-only record the
// matcher emits when a pasted candidate's keyed hash is in the feed. It is the
// attach-path analogue of the proxy plane's POL-3 VerdictProvenance: it carries
// the metadata an operator needs to attribute the event and NOTHING that could
// reconstruct the secret.
//
// NEVER-LOG-THE-SECRET (D73): there is deliberately NO field on this struct that
// can hold the matched bytes, a slice of the inspected text, or the plaintext
// credential. The canary test asserts the planted secret appears in zero bytes
// of this event's rendering. Adding such a field would reopen D73.
type DigestMatch struct {
	// KeyID is the id of the HMAC key the matched digest was computed under
	// (DigestEntry.key_id) — fingerprint metadata, never the key material.
	KeyID string `json:"key_id"`
	// CredClass is "issued" or "forbidden" — which D73 class the matched entry
	// belongs to. A FORBIDDEN match on the attach seam is a guarded credential
	// the user pasted in; an ISSUED match is a minted credential whose
	// wrong-destination handling is the proxy plane's job, surfaced here for
	// attribution parity.
	CredClass string `json:"cred_class"`
	// ServiceID is the ISSUED entry's intended service_id (empty for FORBIDDEN).
	ServiceID string `json:"service_id,omitempty"`
	// VariantTag is which encoding of the candidate matched (raw/base64/urlenc/
	// hex) — the same DigestVariantTag the producer minted the entry under.
	VariantTag string `json:"variant_tag"`
	// DigestSetVersion is the matched entry's digest-set version (a SEPARATE,
	// non-policy version namespace, doc 14 §7) when the caller supplies one.
	DigestSetVersion string `json:"digest_set_version,omitempty"`
}

// AttachDigestMatcher consumes the keyed secret-digest feed (the frozen
// identity.v1.DigestEntry set, doc 14 §7) and matches user-pasted candidates on
// the attach/stdin path. It is the attach-seam twin of ds-tlsproxy's Rust
// SecretMatcher: same feed, same keyed-hash-then-set-membership test, computed
// candidate-side so the plaintext digest of an unseen credential never enters
// this process.
//
// It is constructed from a digest set + the HMAC key material the producer used
// for that set (the boundary host holds the key + the digests, doc 16 §6.3 —
// never the plaintext). On this client/attach seam the matcher is the same
// boundary-trust consumer: it needs the key to compute the candidate's keyed
// hash, exactly as the proxy does.
type AttachDigestMatcher struct {
	// keyID is the id of the HMAC key entries were registered under; the matcher
	// only tests entries that match this key id (rotation re-pushes a fresh set).
	keyID string
	// hmacKey is the per-host per-epoch HMAC key the producer used (doc 16 §6.3).
	hmacKey []byte
	// truncLen is the truncation length (bytes) the producer applied; producer
	// and matcher MUST agree (DigestAlgo.truncation_len_bytes) so candidates
	// truncate identically.
	truncLen int
	// digestSetVersion is the non-policy digest-set version stamped onto match
	// events for attribution (doc 14 §7); optional.
	digestSetVersion string
	// set is the matchable digest set keyed by the truncated keyed-hash digest
	// hex. The value is the fingerprint metadata to event on a hit (including the
	// producer's variant tag) — never any plaintext. Keying on the digest alone
	// mirrors ds-tlsproxy: a candidate is tested AS-IS, the producer having
	// pre-encoded one entry per variant.
	set map[string]DigestMatch
	// maxCandidateLen bounds the sliding-window candidate scan: every window of
	// length 1..=maxCandidateLen over every start position in the inspected text
	// is tested, exactly as ds-tlsproxy's DigestSetMatcher scans (scan.rs
	// match_keyed: max_w = max_candidate_len.min(span_len)). This is the proxy's
	// max_candidate_len parameter (= retain+1 there); it bounds the cost so a scan
	// is linear-ish in the text length × maxCandidateLen rather than quadratic in
	// the text. The bound is the ON-WIRE encoded length, NOT the raw-secret length:
	// for non-RAW variants (base64/urlenc/hex) the producer hashed the longer
	// encoded form, which is what appears on the wire, so the window must reach
	// that encoded length (same note as scan.rs ~L1163). A zero/unset value at
	// construction defaults to defaultMaxCandidateLen (mirroring the proxy's
	// saturating_sub(1) "a bound of 0 retains/scans nothing useful" semantics by
	// substituting a sane non-zero default instead of degrading to no scan).
	maxCandidateLen int
}

// defaultMaxCandidateLen is the sliding-window bound applied when a matcher is
// constructed without an explicit one (the additive default). It is the longest
// ON-WIRE candidate window the matcher will test — large enough to cover a
// realistic pasted credential in any encoding the producer mints (a long raw
// token plus the base64/url-encoding/hex inflation), while keeping the scan cost
// bounded (the proxy sizes the analogous max_candidate_len to its hold-back
// window). It mirrors the proxy's max_candidate_len being the encoded (on-wire)
// length bound, not the raw-secret length.
const defaultMaxCandidateLen = 512

// NewAttachDigestMatcher builds a matcher from the keyed digest feed `entries`
// (the SAME identity.v1.DigestEntry feed ds-tlsproxy consumes) and the HMAC key
// material the producer minted them under. keyID/hmacKey/truncLen reproduce the
// producer's keyed-hash parameters so a candidate truncates identically.
//
// It loads ONLY HMAC-SHA-256 entries whose key_id matches keyID and whose
// truncation length matches truncLen (the frozen Stage-0 algo, doc 14 §7);
// entries minted under a different key/algo/length belong to another epoch's set
// and are skipped (rotation re-pushes the live set under the new key, doc 16
// §6.3). No plaintext is read or stored — only the producer-supplied digest
// bytes and fingerprint metadata.
func NewAttachDigestMatcher(keyID string, hmacKey []byte, truncLen int, digestSetVersion string, entries []*identityv1.DigestEntry) (*AttachDigestMatcher, error) {
	if keyID == "" {
		return nil, fmt.Errorf("claudecode: NewAttachDigestMatcher: empty keyID")
	}
	if len(hmacKey) == 0 {
		return nil, fmt.Errorf("claudecode: NewAttachDigestMatcher: empty hmacKey")
	}
	if truncLen <= 0 || truncLen > sha256.Size {
		return nil, fmt.Errorf("claudecode: NewAttachDigestMatcher: truncLen %d out of range (1..%d)", truncLen, sha256.Size)
	}
	m := &AttachDigestMatcher{
		keyID:            keyID,
		hmacKey:          append([]byte(nil), hmacKey...),
		truncLen:         truncLen,
		digestSetVersion: digestSetVersion,
		set:              make(map[string]DigestMatch),
		// Default the sliding-window bound (mirrors ds-tlsproxy's
		// DigestSetMatcher::new(hasher, max_candidate_len) parameter). The existing
		// signature carries no explicit bound, so callers that do not care still get
		// a sane non-zero window — the saturating_sub(1) "0 ⇒ scan nothing" footgun
		// of a bare-zero bound is avoided by substituting defaultMaxCandidateLen. A
		// caller that wants to pin the bound calls SetMaxCandidateLen after
		// construction.
		maxCandidateLen: defaultMaxCandidateLen,
	}
	for _, e := range entries {
		if e == nil || e.GetKeyId() != keyID {
			continue
		}
		algo := e.GetAlgo()
		if algo.GetFamily() != identityv1.DigestAlgo_FAMILY_HMAC_SHA256 {
			continue // Stage-0 is HMAC-SHA-256 only; skip foreign families.
		}
		if int(algo.GetTruncationLenBytes()) != truncLen {
			continue // a different truncation belongs to a different parameterization.
		}
		variant := e.GetVariantTag()
		if variant == identityv1.DigestVariantTag_DIGEST_VARIANT_TAG_UNSPECIFIED {
			continue
		}
		if len(e.GetDigest()) != truncLen {
			continue // a digest of the wrong length cannot have been minted at this truncation.
		}
		m.set[hex.EncodeToString(e.GetDigest())] = DigestMatch{
			KeyID:            keyID,
			CredClass:        credClassLabel(e.GetCredClass()),
			ServiceID:        issuedServiceID(e.GetCredClass()),
			VariantTag:       variant.String(),
			DigestSetVersion: digestSetVersion,
		}
	}
	return m, nil
}

// SetMaxCandidateLen pins the sliding-window bound (the on-wire encoded length
// the scan reaches), mirroring ds-tlsproxy's DigestSetMatcher::new(hasher,
// max_candidate_len) parameter. It is additive: NewAttachDigestMatcher's
// signature is unchanged, so existing callers default to defaultMaxCandidateLen;
// a caller that knows its set's longest on-wire variant can tighten or widen the
// bound here. A non-positive value resets to the default (mirroring the proxy's
// saturating_sub(1) "0 scans nothing" being substituted for a sane default, so a
// caller can never accidentally disable the scan). The bound is the ENCODED
// (on-wire) length, not the raw-secret length — for non-RAW variants the
// producer hashed the longer encoded form (scan.rs ~L1163).
func (m *AttachDigestMatcher) SetMaxCandidateLen(n int) {
	if n <= 0 {
		m.maxCandidateLen = defaultMaxCandidateLen
		return
	}
	m.maxCandidateLen = n
}

// credClassLabel reduces a DigestCredClass oneof to its fingerprint label —
// "issued" | "forbidden" | "unspecified". Never the plaintext.
func credClassLabel(cc *identityv1.DigestCredClass) string {
	switch cc.GetClass().(type) {
	case *identityv1.DigestCredClass_Issued_:
		return "issued"
	case *identityv1.DigestCredClass_Forbidden_:
		return "forbidden"
	default:
		return "unspecified"
	}
}

// issuedServiceID returns the ISSUED class's service_id (empty for FORBIDDEN /
// unset) — fingerprint metadata the producer tagged the credential with.
func issuedServiceID(cc *identityv1.DigestCredClass) string {
	if iss := cc.GetIssued(); iss != nil {
		return iss.GetServiceId()
	}
	return ""
}

// MatchInput scans a DriveInput's text — the user-pasted bytes about to be
// written onto CC stdin by EncodeInput — against the keyed digest feed and
// returns the match events for every swap-class secret it recognizes. This is
// the attach-seam consumption point: the same bytes EncodeInput is about to
// drive are first offered to the matcher, so a pasted credential is EVENTED
// before (or as) it enters the session, closing the doc-20 §4 residual.
//
// NEVER-LOG-THE-SECRET (D73): the candidate text is used only to compute keyed
// hashes; it is never stored, logged, or copied into any returned value. The
// returned []DigestMatch carry fingerprint metadata exclusively. A nil/empty
// return means no feed entry matched (the common case for ordinary prompts).
func (m *AttachDigestMatcher) MatchInput(in DriveInput) []DigestMatch {
	return m.match(in.Text)
}

// match runs a BOUNDED SLIDING-WINDOW candidate scan over the inspected bytes,
// at byte-span parity with ds-tlsproxy's keyed plane (scan.rs match_keyed). For
// each window length 1..=min(maxCandidateLen, len(text)) and each start index, it
// computes the window's truncated keyed hash AS-IS and looks it up in the digest
// set; the producer pre-encoded (one entry per variant), so a secret pasted in
// raw / base64 / url-encoded / hex form is the byte-window the matcher sees on
// the wire and matches the producer's entry for that encoding without the matcher
// re-deriving it — exactly the proxy's model (doc 14 §7).
//
// Why a sliding window, not a whitespace split (the parity fix). A
// whitespace-delimited split tested only whole non-whitespace fields, so a secret
// ABUTTED BY PUNCTUATION (token=<SECRET>, "<SECRET>", <SECRET>, prefix:<SECRET>)
// or one containing EMBEDDED WHITESPACE was never offered to the test and was
// missed. The window subsumes the whitespace-delimited tokens (each is some
// window) AND every punctuation-abutted / whitespace-straddling substring, so the
// attach seam now recognizes the SAME candidate set the proxy's bounded-window
// scan does. The bound (maxCandidateLen) keeps the cost the proxy's
// max_w = max_candidate_len.min(span_len) — bytes×window, not quadratic in text.
//
// Returns one DigestMatch per matched feed entry, deduplicated (emitted) so the
// same entry events at most once per scan even though many windows hash to it.
// Short-circuit: a window's digest already in emitted is skipped before re-test.
//
// NEVER-LOG-THE-SECRET (D73): each window is a transient sub-slice of the input
// used ONLY to compute a keyed hash; no window byte escapes this function, and
// the returned DigestMatch values are fingerprint-only.
func (m *AttachDigestMatcher) match(text string) []DigestMatch {
	n := len(text)
	if n == 0 || len(m.set) == 0 {
		return nil
	}
	// Bound the window scan to the configured candidate length, exactly as the
	// proxy does: max_w = max_candidate_len.min(span_len) (scan.rs ~L1169). The
	// bound is the ON-WIRE encoded length, not the raw-secret length.
	maxW := m.maxCandidateLen
	if maxW <= 0 {
		maxW = defaultMaxCandidateLen
	}
	if maxW > n {
		maxW = n
	}
	// Inspect the bytes directly — the keyed hash is computed over wire bytes
	// AS-IS, and a []byte sub-slice is a transient view that never escapes.
	b := []byte(text)
	var matches []DigestMatch
	emitted := make(map[string]bool)
	for wlen := 1; wlen <= maxW; wlen++ {
		for start := 0; start+wlen <= n; start++ {
			window := b[start : start+wlen]
			digestHex := m.keyedDigestHex(window)
			if emitted[digestHex] {
				continue
			}
			if hit, ok := m.set[digestHex]; ok {
				matches = append(matches, hit)
				emitted[digestHex] = true
			}
		}
	}
	return matches
}

// keyedDigestHex computes HMAC-SHA-256 over `b`, truncates to truncLen bytes,
// and hex-encodes it — the producer's exact keyed-hash derivation (doc 14 §7),
// reproduced candidate-side. The HMAC of a candidate the matcher chose to hash
// is not the plaintext and is one-way.
func (m *AttachDigestMatcher) keyedDigestHex(b []byte) string {
	mac := hmac.New(sha256.New, m.hmacKey)
	mac.Write(b)
	sum := mac.Sum(nil)
	return hex.EncodeToString(sum[:m.truncLen])
}
