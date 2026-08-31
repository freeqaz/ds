// driver_test.go — table-driven unit tests for the WRITE half (driver.go), the
// inverse of the read adapter. They feed attach.v1 write events (DriveInput /
// DriveGrant sequences) and assert the emitted CC records match the documented
// P4 input envelope and P8 control_response shapes.
//
// Assertion discipline (DRIVE-PROTOCOL.md "Rules the replay tier MUST honor"):
// assert STRUCTURALLY and ID-RELATIVE, never on literal random uuids or
// wall-clock order. The Driver deliberately mints NO uuid/session_id (CC stamps
// those), so there is nothing wall-clock or random to assert against; tests
// check the envelope shape and that the correlation id the caller supplied
// threads through unchanged. Emitted bytes are decoded back through records.go's
// OWN structs (round-trip) so the test proves the write side is shaped like what
// the read side decodes — never by brittle byte/substring matching.
//
// Test-local identifiers are prefixed "drv" so this file's helpers never collide
// with the package-shared scope the peer *_test.go files declare into.
package claudecode

import (
	"bytes"
	"encoding/json"
	"testing"
)

// drvDecode unmarshals an emitted NDJSON line into T (one of records.go's wire
// structs), failing the test on a decode error. This is the round-trip: the
// Driver ENCODES with the same structs the Adapter DECODES.
func drvDecode[T any](t *testing.T, line []byte) T {
	t.Helper()
	var rec T
	if err := json.Unmarshal(line, &rec); err != nil {
		t.Fatalf("decode %T from %s: %v", rec, line, err)
	}
	return rec
}

// drvRawFields unmarshals a line into a generic map so a test can assert a field
// is ABSENT (CC mints uuid/session_id; the outbound record must not carry them).
func drvRawFields(t *testing.T, line []byte) map[string]json.RawMessage {
	t.Helper()
	m := map[string]json.RawMessage{}
	if err := json.Unmarshal(line, &m); err != nil {
		t.Fatalf("decode raw fields from %s: %v", line, err)
	}
	return m
}

// --- EncodeInput: the P4 single-text-block user-input envelope ---------------

func TestEncodeInput_P4Envelope(t *testing.T) {
	cases := []struct {
		name string
		text string
	}{
		{name: "ascii", text: "ship the driver"},
		{name: "unicode", text: "héllo — drive ⏩ the session"},
		{name: "newlines", text: "line one\nline two\n"},
		{name: "json-ish text stays a string", text: `{"not":"a control record"}`},
	}
	d := NewDriver()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			line, err := d.EncodeInput(DriveInput{Text: tc.text})
			if err != nil {
				t.Fatalf("EncodeInput: %v", err)
			}

			// Round-trip through the read-side userRecord: the inbound shape the
			// adapter parses. The write side must produce exactly that envelope.
			rec := drvDecode[userRecord](t, line)
			if rec.Type != "user" {
				t.Errorf("type = %q, want %q", rec.Type, "user")
			}
			if rec.Message.Role != "user" {
				t.Errorf("message.role = %q, want %q", rec.Message.Role, "user")
			}
			if got := len(rec.Message.Content); got != 1 {
				t.Fatalf("message.content has %d blocks, want exactly 1 (P4 single-block)", got)
			}
			block := rec.Message.Content[0]
			if block.Type != "text" {
				t.Errorf("content[0].type = %q, want %q", block.Type, "text")
			}
			if block.Text != tc.text {
				t.Errorf("content[0].text = %q, want %q (text must round-trip verbatim)", block.Text, tc.text)
			}
		})
	}
}

// CC mints the record identity and acks input with isReplay:true (records.go
// userRecord). The OUTBOUND record must therefore carry none of those fields —
// assert they are ABSENT, not merely zero-valued, so CC's stamp is authoritative.
func TestEncodeInput_OmitsMintedAndAckFields(t *testing.T) {
	d := NewDriver()
	line, err := d.EncodeInput(DriveInput{Text: "anything"})
	if err != nil {
		t.Fatalf("EncodeInput: %v", err)
	}
	fields := drvRawFields(t, line)
	for _, absent := range []string{"uuid", "session_id", "parent_tool_use_id", "isReplay", "tool_use_result", "timestamp"} {
		if _, present := fields[absent]; present {
			t.Errorf("outbound input record carries %q; CC mints/acks identity, it must be absent", absent)
		}
	}
	// Exactly the minimal envelope keys, nothing more.
	for k := range fields {
		if k != "type" && k != "message" {
			t.Errorf("unexpected top-level key %q on input record (want only type+message)", k)
		}
	}

	// The message BODY must be exactly {role, content} — the documented P4 echo
	// shape (PHASE2 P4: "the replay's message has only {content, role} — no id,
	// no request_id"). The read-side `message` struct has no omitempty, so a
	// naive reuse for emission would leak id:""/type:""/model:""/stop_reason:""/
	// usage:null; assert those decode-only keys are ABSENT, not just empty.
	msgFields := map[string]json.RawMessage{}
	if err := json.Unmarshal(fields["message"], &msgFields); err != nil {
		t.Fatalf("decode message body: %v", err)
	}
	for k := range msgFields {
		if k != "role" && k != "content" {
			t.Errorf("message body carries unexpected key %q; P4 echo body is exactly {role, content}", k)
		}
	}
	for _, spurious := range []string{"id", "type", "model", "stop_reason", "stop_sequence", "usage"} {
		if _, present := msgFields[spurious]; present {
			t.Errorf("message body carries decode-only key %q; it must be absent on the outbound P4 envelope", spurious)
		}
	}
}

func TestEncodeInput_EmptyTextIsError(t *testing.T) {
	d := NewDriver()
	if _, err := d.EncodeInput(DriveInput{Text: ""}); err == nil {
		t.Fatal("EncodeInput(empty) returned nil error; want an error (v0 requires a non-empty single text block)")
	}
}

// --- EncodeGrant: the native P8 control_response shape -----------------------

func TestEncodeGrant_NativeControlResponse(t *testing.T) {
	cases := []struct {
		name         string
		grant        DriveGrant
		wantBehavior string
		wantInput    string // expected updatedInput JSON, "" ⇒ field omitted
		wantMessage  string // expected deny message, "" ⇒ field omitted
	}{
		{
			name:         "allow with rewritten input",
			grant:        DriveGrant{RequestID: "req_A", ToolUseID: "toolu_A", Allow: true, UpdatedInput: json.RawMessage(`{"command":"echo ok"}`)},
			wantBehavior: "allow",
			wantInput:    `{"command":"echo ok"}`,
		},
		{
			name:         "allow without rewrite omits updatedInput",
			grant:        DriveGrant{RequestID: "req_B", ToolUseID: "toolu_B", Allow: true},
			wantBehavior: "allow",
		},
		{
			name:         "deny with message",
			grant:        DriveGrant{RequestID: "req_C", ToolUseID: "toolu_C", Allow: false, Message: "blocked by policy"},
			wantBehavior: "deny",
			wantMessage:  "blocked by policy",
		},
	}
	d := NewDriver()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			line, err := d.EncodeGrant(tc.grant)
			if err != nil {
				t.Fatalf("EncodeGrant: %v", err)
			}

			// Round-trip through the read-side controlResponseRecord: the exact
			// struct the adapter decodes off the control channel.
			rec := drvDecode[controlResponseRecord](t, line)
			if rec.Type != "control_response" {
				t.Errorf("type = %q, want %q", rec.Type, "control_response")
			}
			if rec.Response.Subtype != "success" {
				t.Errorf("response.subtype = %q, want %q (the envelope outcome, not the decision)", rec.Response.Subtype, "success")
			}
			// ID-relative: the join key threads through unchanged. The
			// control_response correlates on request_id, NOT tool_use_id (P8).
			if rec.Response.RequestID != tc.grant.RequestID {
				t.Errorf("response.request_id = %q, want %q (the control_response join key)", rec.Response.RequestID, tc.grant.RequestID)
			}
			if rec.Response.Response.Behavior != tc.wantBehavior {
				t.Errorf("behavior = %q, want %q", rec.Response.Response.Behavior, tc.wantBehavior)
			}

			// updatedInput / message presence is behavior-conditional (P8). The
			// shared records.go controlDecision.UpdatedInput has no omitempty
			// (it is the DECODE shape, where a JSON null RawMessage is benign),
			// so an unset value serializes as null — treated as "effectively
			// absent" here, which the read-side decode collapses to nil anyway.
			gotInput := string(rec.Response.Response.UpdatedInput)
			if tc.wantInput == "" {
				if !drvJSONAbsent(gotInput) {
					t.Errorf("updatedInput = %q, want absent/null on this case", gotInput)
				}
			} else if !jsonEqual(t, gotInput, tc.wantInput) {
				t.Errorf("updatedInput = %q, want %q", gotInput, tc.wantInput)
			}
			if got := rec.Response.Response.Message; got != tc.wantMessage {
				t.Errorf("message = %q, want %q", got, tc.wantMessage)
			}
		})
	}
}

// A control_response NEVER carries the request's tool_use_id as a join key (P8:
// the success response correlates on request_id only). The native record must
// not leak tool_use_id into the response envelope even though the grant carried
// it for bookkeeping.
func TestEncodeGrant_NoToolUseIDInResponse(t *testing.T) {
	d := NewDriver()
	line, err := d.EncodeGrant(DriveGrant{RequestID: "req_X", ToolUseID: "toolu_X_should_not_appear", Allow: true})
	if err != nil {
		t.Fatalf("EncodeGrant: %v", err)
	}
	if bytes.Contains(line, []byte("toolu_X_should_not_appear")) {
		t.Errorf("control_response leaked tool_use_id %q; it must correlate on request_id only (P8)\nline: %s", "toolu_X_should_not_appear", line)
	}
}

func TestEncodeGrant_EmptyRequestIDIsError(t *testing.T) {
	d := NewDriver()
	if _, err := d.EncodeGrant(DriveGrant{ToolUseID: "toolu_only", Allow: true}); err == nil {
		t.Fatal("EncodeGrant with empty RequestID returned nil error; want an error (request_id is the join key)")
	}
}

// The native control_response is the minimal P8 shape: the envelope carries only
// {type, response}; the body only {subtype, request_id, response}; the decision
// only {behavior, updatedInput?|message?}. The decode structs in records.go have
// no omitempty, so a naive reuse for emission would leak CC-minted envelope ids
// (uuid/session_id) and the initialize-handshake-only pending_* riders into every
// grant. Assert those are ABSENT and that the behavior-conditional fields appear
// only where P8 documents them (allow⇒updatedInput, never message; deny⇒message,
// never updatedInput).
func TestEncodeGrant_MinimalEnvelopeNoLeakage(t *testing.T) {
	d := NewDriver()

	// Envelope + handshake-only riders must never appear on a can_use_tool answer.
	for _, tc := range []struct {
		name  string
		grant DriveGrant
	}{
		{"allow", DriveGrant{RequestID: "req_1", Allow: true, UpdatedInput: json.RawMessage(`{"k":"v"}`)}},
		{"deny", DriveGrant{RequestID: "req_2", Allow: false, Message: "nope"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			line, err := d.EncodeGrant(tc.grant)
			if err != nil {
				t.Fatalf("EncodeGrant: %v", err)
			}
			top := drvRawFields(t, line)
			for k := range top {
				if k != "type" && k != "response" {
					t.Errorf("envelope carries unexpected key %q; want only {type, response}", k)
				}
			}
			for _, absent := range []string{"uuid", "session_id", "pending_permission_requests", "pending_user_dialog_requests"} {
				if _, present := top["response"]; present {
					var body map[string]json.RawMessage
					_ = json.Unmarshal(top["response"], &body)
					if _, leaked := body[absent]; leaked {
						t.Errorf("control_response body leaks %q; it must be absent on a can_use_tool answer (P8: handshake-only)", absent)
					}
				}
				if _, leaked := top[absent]; leaked {
					t.Errorf("control_response envelope leaks %q; CC mints/handshake-only, must be absent", absent)
				}
			}

			// The decision must carry only behavior + the one conditional field.
			var body struct {
				Response json.RawMessage `json:"response"`
			}
			if err := json.Unmarshal(line, &body); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			var dec map[string]json.RawMessage
			if err := json.Unmarshal(body.Response, &dec); err != nil {
				t.Fatalf("decode body fields: %v", err)
			}
			var innerRaw json.RawMessage = dec["response"]
			decision := map[string]json.RawMessage{}
			if err := json.Unmarshal(innerRaw, &decision); err != nil {
				t.Fatalf("decode decision: %v", err)
			}
			if _, ok := decision["behavior"]; !ok {
				t.Errorf("decision missing behavior")
			}
			if tc.grant.Allow {
				if _, leaked := decision["message"]; leaked {
					t.Errorf("allow decision carries message; P8 allow returns updatedInput, not message")
				}
				if _, ok := decision["updatedInput"]; !ok {
					t.Errorf("allow-with-rewrite decision missing updatedInput")
				}
			} else {
				if _, leaked := decision["updatedInput"]; leaked {
					t.Errorf("deny decision carries updatedInput; P8 deny returns message, not updatedInput")
				}
				if _, ok := decision["message"]; !ok {
					t.Errorf("deny decision missing message")
				}
			}
			if _, leaked := decision["updatedPermissions"]; leaked {
				t.Errorf("decision carries updatedPermissions for a grant that did not set one; must be omitted")
			}
		})
	}
}

// --- EncodeGrantPromptTool: the PROVEN-live --permission-prompt-tool body ----

func TestEncodeGrantPromptTool_ProvenRoute(t *testing.T) {
	cases := []struct {
		name         string
		grant        DriveGrant
		wantBehavior string
		wantInput    string
		wantMessage  string
	}{
		{
			name:         "allow echoes input",
			grant:        DriveGrant{ToolUseID: "toolu_P1", Allow: true, UpdatedInput: json.RawMessage(`{"text":"ds-ping"}`)},
			wantBehavior: "allow",
			wantInput:    `{"text":"ds-ping"}`,
		},
		{
			name:         "deny carries message",
			grant:        DriveGrant{ToolUseID: "toolu_P2", Allow: false, Message: "not allowed"},
			wantBehavior: "deny",
			wantMessage:  "not allowed",
		},
	}
	d := NewDriver()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			line, err := d.EncodeGrantPromptTool(tc.grant)
			if err != nil {
				t.Fatalf("EncodeGrantPromptTool: %v", err)
			}
			// The prompt-tool body is a bare controlDecision (no request_id
			// envelope — the JSON-RPC call id correlates out of band, P8).
			body := drvDecode[controlDecision](t, line)
			if body.Behavior != tc.wantBehavior {
				t.Errorf("behavior = %q, want %q", body.Behavior, tc.wantBehavior)
			}
			gotInput := string(body.UpdatedInput)
			if tc.wantInput == "" {
				if !drvJSONAbsent(gotInput) {
					t.Errorf("updatedInput = %q, want absent/null", gotInput)
				}
			} else if !jsonEqual(t, gotInput, tc.wantInput) {
				t.Errorf("updatedInput = %q, want %q", gotInput, tc.wantInput)
			}
			if body.Message != tc.wantMessage {
				t.Errorf("message = %q, want %q", body.Message, tc.wantMessage)
			}
			// The prompt-tool body has no request_id envelope.
			if fields := drvRawFields(t, line); func() bool { _, ok := fields["request_id"]; return ok }() {
				t.Errorf("prompt-tool body carries request_id; it must correlate out of band (P8)\nline: %s", line)
			}
		})
	}
}

func TestEncodeGrantPromptTool_EmptyToolUseIDIsError(t *testing.T) {
	d := NewDriver()
	if _, err := d.EncodeGrantPromptTool(DriveGrant{RequestID: "req_only", Allow: true}); err == nil {
		t.Fatal("EncodeGrantPromptTool with empty ToolUseID returned nil error; want an error (tool_use_id is the prompt-tool join key)")
	}
}

// --- D45/D53: the Driver holds NO approval state -----------------------------

// A second grant must not depend on a stored first. We prove statelessness by
// driving a sequence and showing each emission depends ONLY on its own argument:
// encoding grant N alone reproduces grant N's output byte-for-byte regardless of
// what was encoded before it (a stored first grant would perturb the second).
func TestDriver_NoApprovalStateAcrossGrants(t *testing.T) {
	d := NewDriver()

	first := DriveGrant{RequestID: "req_first", ToolUseID: "toolu_first", Allow: true, UpdatedInput: json.RawMessage(`{"command":"first"}`)}
	second := DriveGrant{RequestID: "req_second", ToolUseID: "toolu_second", Allow: false, Message: "deny the second"}

	// Drive first THEN second on the shared instance.
	if _, err := d.EncodeGrant(first); err != nil {
		t.Fatalf("EncodeGrant(first): %v", err)
	}
	secondAfterFirst, err := d.EncodeGrant(second)
	if err != nil {
		t.Fatalf("EncodeGrant(second after first): %v", err)
	}

	// Now encode second on a FRESH instance that never saw first.
	fresh := NewDriver()
	secondAlone, err := fresh.EncodeGrant(second)
	if err != nil {
		t.Fatalf("EncodeGrant(second alone): %v", err)
	}

	if !bytes.Equal(secondAfterFirst, secondAlone) {
		t.Errorf("second grant differs depending on whether a first was encoded — approval state was retained (D45/D53 violation)\n  after-first: %s\n  alone:       %s", secondAfterFirst, secondAlone)
	}

	// And the reverse: re-encoding first after second still reproduces first's
	// output — nothing from second leaked forward either.
	firstAgain, err := d.EncodeGrant(first)
	if err != nil {
		t.Fatalf("EncodeGrant(first again): %v", err)
	}
	firstAlone, err := NewDriver().EncodeGrant(first)
	if err != nil {
		t.Fatalf("EncodeGrant(first alone): %v", err)
	}
	if !bytes.Equal(firstAgain, firstAlone) {
		t.Errorf("re-encoding first after second differs from encoding it fresh — state was retained (D45/D53 violation)\n  again: %s\n  alone: %s", firstAgain, firstAlone)
	}
}

// The same statelessness for inputs: an input encoded after others equals the
// same input encoded by a fresh Driver — no per-session cursor is retained.
func TestDriver_NoInputStateAcrossCalls(t *testing.T) {
	d := NewDriver()
	for _, prior := range []string{"first prompt", "second prompt", "third prompt"} {
		if _, err := d.EncodeInput(DriveInput{Text: prior}); err != nil {
			t.Fatalf("EncodeInput(%q): %v", prior, err)
		}
	}
	target := DriveInput{Text: "the input under test"}
	afterPriors, err := d.EncodeInput(target)
	if err != nil {
		t.Fatalf("EncodeInput(target after priors): %v", err)
	}
	fresh, err := NewDriver().EncodeInput(target)
	if err != nil {
		t.Fatalf("EncodeInput(target fresh): %v", err)
	}
	if !bytes.Equal(afterPriors, fresh) {
		t.Errorf("input encoding depends on prior calls — state was retained\n  after-priors: %s\n  fresh:        %s", afterPriors, fresh)
	}
}

// --- A drive sequence: input → ask-answer grant, the v0 loop -----------------

// The minimal closed loop: the client sends an input, CC asks (read side, not
// exercised here), the human grants on the policy stream, the Driver turns the
// grant into a control_response. Assert the grant's control_response correlates
// on the SAME request_id the ask carried — id-relative, the join the read
// adapter's handleControlResponse keys on (askByRequestID).
func TestDriveSequence_InputThenGrantCorrelatesOnRequestID(t *testing.T) {
	d := NewDriver()

	// 1. Input drives the turn (P4).
	inputLine, err := d.EncodeInput(DriveInput{Text: "delete the scratch dir"})
	if err != nil {
		t.Fatalf("EncodeInput: %v", err)
	}
	in := drvDecode[userRecord](t, inputLine)
	if in.Type != "user" || len(in.Message.Content) != 1 {
		t.Fatalf("input not a single-block user record: %s", inputLine)
	}

	// 2. The ask arrived (read side) carrying request_id "req_seq_1" /
	//    tool_use_id "toolu_seq_1". The human grants allow.
	const askRequestID = "req_seq_1"
	const askToolUseID = "toolu_seq_1"
	grantLine, err := d.EncodeGrant(DriveGrant{
		RequestID:    askRequestID,
		ToolUseID:    askToolUseID,
		Allow:        true,
		UpdatedInput: json.RawMessage(`{"command":"rm -rf /work/scratch"}`),
	})
	if err != nil {
		t.Fatalf("EncodeGrant: %v", err)
	}
	resp := drvDecode[controlResponseRecord](t, grantLine)
	if resp.Response.RequestID != askRequestID {
		t.Errorf("control_response.request_id = %q, want %q (must match the ask's request_id so the read side's askByRequestID correlates)", resp.Response.RequestID, askRequestID)
	}
	if resp.Response.Response.Behavior != "allow" {
		t.Errorf("behavior = %q, want allow", resp.Response.Response.Behavior)
	}
}

// drvJSONAbsent reports whether a decoded json.RawMessage field is effectively
// absent: empty (the field never appeared) or the JSON null literal (the shared
// records.go decode struct has no omitempty, so an unset RawMessage serializes
// as null — the read side collapses both to nil). Either is "not present" for
// the behavior-conditional P8 fields.
func drvJSONAbsent(s string) bool { return s == "" || s == "null" }

// jsonEqual compares two JSON texts semantically (key order / whitespace
// independent), so updatedInput round-trips are not brittle to re-marshaling.
func jsonEqual(t *testing.T, a, b string) bool {
	t.Helper()
	var av, bv any
	if err := json.Unmarshal([]byte(a), &av); err != nil {
		t.Fatalf("jsonEqual: bad json %q: %v", a, err)
	}
	if err := json.Unmarshal([]byte(b), &bv); err != nil {
		t.Fatalf("jsonEqual: bad json %q: %v", b, err)
	}
	an, _ := json.Marshal(av)
	bn, _ := json.Marshal(bv)
	return bytes.Equal(an, bn)
}
