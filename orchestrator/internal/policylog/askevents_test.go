// SPDX-License-Identifier: Apache-2.0

package policylog

import (
	"testing"

	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
)

// TestProjectAskIssued proves the AskIssued projection (doc 16 §9): the session
// join key and the resource kind/name the ask is about ride onto the event, the
// D60 consent class maps through, and NO approver is stamped (issuance precedes the
// decision).
func TestProjectAskIssued(t *testing.T) {
	res := AskResolution{
		SessionUUID:  "sess-1",
		ResourceKind: "domain",
		ResourceName: "github.com",
		Target:       AskDispatchPrompt,
	}
	ev := ProjectAskIssued(res, boundaryv1.AskConsentClass_ASK_CONSENT_CLASS_SESSION)
	if ev.GetSessionRef().GetSessionUuid() != "sess-1" {
		t.Errorf("SessionRef = %q, want sess-1", ev.GetSessionRef().GetSessionUuid())
	}
	if ev.GetResourceKind() != "domain" || ev.GetResourceName() != "github.com" {
		t.Errorf("resource = (%q,%q), want (domain,github.com)", ev.GetResourceKind(), ev.GetResourceName())
	}
	if ev.GetConsentClass() != identityv1.ConsentClass_CONSENT_CLASS_SESSION {
		t.Errorf("ConsentClass = %v, want CONSENT_CLASS_SESSION", ev.GetConsentClass())
	}
}

// TestProjectAskApproved_StampsApprover proves the doc 16 §8.2 "+approver"
// attribution: an AskApproved event carries the resolved approver principal (the
// launching user or, for allow-always, the org-admin acceptor) and the session join
// key. This is the LOG-1 surface the §8.2 routing projects its computed approver
// onto.
func TestProjectAskApproved_StampsApprover(t *testing.T) {
	cases := []struct {
		name string
		res  AskResolution
		want string
	}{
		{
			name: "launching-user approver (allow-once)",
			res:  AskResolution{SessionUUID: "sess-1", ApproverPrincipalID: "p-ada"},
			want: "p-ada",
		},
		{
			name: "org-admin acceptor (allow-always, D45)",
			res:  AskResolution{SessionUUID: "sess-2", ApproverPrincipalID: "p-admin", EscalatedToOrgAdmin: true},
			want: "p-admin",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := ProjectAskApproved(tc.res, boundaryv1.AskConsentClass_ASK_CONSENT_CLASS_UNSPECIFIED)
			if ev.GetApproverPrincipal() != tc.want {
				t.Errorf("ApproverPrincipal = %q, want %q", ev.GetApproverPrincipal(), tc.want)
			}
			if ev.GetSessionRef().GetSessionUuid() != tc.res.SessionUUID {
				t.Errorf("SessionRef = %q, want %q", ev.GetSessionRef().GetSessionUuid(), tc.res.SessionUUID)
			}
		})
	}
}

// TestProjectAskDenied_StampsApproverAndReason proves the doc 16 §8.2 deny
// projection: an AskDenied event carries the DENYING approver principal AND the D77
// machine-readable reason (so retries fast-fail against the session-scoped deny
// memo, D118) alongside the session join key.
func TestProjectAskDenied_StampsApproverAndReason(t *testing.T) {
	res := AskResolution{SessionUUID: "sess-1", ApproverPrincipalID: "p-ada"}
	ev := ProjectAskDenied(res, "denied-by-approver", boundaryv1.AskConsentClass_ASK_CONSENT_CLASS_UNSPECIFIED)
	if ev.GetApproverPrincipal() != "p-ada" {
		t.Errorf("ApproverPrincipal = %q, want p-ada", ev.GetApproverPrincipal())
	}
	if ev.GetMachineReadableReason() != "denied-by-approver" {
		t.Errorf("MachineReadableReason = %q, want denied-by-approver (D77)", ev.GetMachineReadableReason())
	}
	if ev.GetSessionRef().GetSessionUuid() != "sess-1" {
		t.Errorf("SessionRef = %q, want sess-1", ev.GetSessionRef().GetSessionUuid())
	}
}

// TestAskConsentClassMapping proves the boundary->identity D60 consent-class tag
// mirrors value-for-value (doc 14 §2b / doc 16 §9 OQ5), and that an unrecognized
// boundary value maps to UNSPECIFIED (the projection never panics on a future tag —
// reserve/tag only, no population behavior frozen).
func TestAskConsentClassMapping(t *testing.T) {
	cases := []struct {
		in   boundaryv1.AskConsentClass
		want identityv1.ConsentClass
	}{
		{boundaryv1.AskConsentClass_ASK_CONSENT_CLASS_UNSPECIFIED, identityv1.ConsentClass_CONSENT_CLASS_UNSPECIFIED},
		{boundaryv1.AskConsentClass_ASK_CONSENT_CLASS_METADATA, identityv1.ConsentClass_CONSENT_CLASS_METADATA},
		{boundaryv1.AskConsentClass_ASK_CONSENT_CLASS_SESSION, identityv1.ConsentClass_CONSENT_CLASS_SESSION},
		{boundaryv1.AskConsentClass_ASK_CONSENT_CLASS_WORKLOAD, identityv1.ConsentClass_CONSENT_CLASS_WORKLOAD},
		{boundaryv1.AskConsentClass(99), identityv1.ConsentClass_CONSENT_CLASS_UNSPECIFIED}, // future/unknown tag
	}
	for _, tc := range cases {
		if got := askConsentClass(tc.in); got != tc.want {
			t.Errorf("askConsentClass(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestProjectAskApproved_CarriesConsentClass proves the reserved D60 consent class
// rides onto the approved/denied events too (not just AskIssued), so the whole ask
// triple tags the same consent class the boundary supplied.
func TestProjectAskApproved_CarriesConsentClass(t *testing.T) {
	res := AskResolution{SessionUUID: "sess-1", ApproverPrincipalID: "p-ada"}
	approved := ProjectAskApproved(res, boundaryv1.AskConsentClass_ASK_CONSENT_CLASS_WORKLOAD)
	if approved.GetConsentClass() != identityv1.ConsentClass_CONSENT_CLASS_WORKLOAD {
		t.Errorf("approved ConsentClass = %v, want CONSENT_CLASS_WORKLOAD", approved.GetConsentClass())
	}
	denied := ProjectAskDenied(res, "reason", boundaryv1.AskConsentClass_ASK_CONSENT_CLASS_METADATA)
	if denied.GetConsentClass() != identityv1.ConsentClass_CONSENT_CLASS_METADATA {
		t.Errorf("denied ConsentClass = %v, want CONSENT_CLASS_METADATA", denied.GetConsentClass())
	}
}
