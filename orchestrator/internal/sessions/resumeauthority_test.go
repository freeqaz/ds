// SPDX-License-Identifier: Apache-2.0

// Tests for the production resume-authority gate (resumeauthority.go): the doc 15
// §3 note 3 / §4.3 / doc 16 §8.2 SPLIT RESUME AUTHORITIES, enforced fail-closed.
// These are the production-side proof of the contract the credfu6 e2e smoke (LEG
// B) proved in-process — keyed on the FROZEN attach.v1.SuspendReason, with the
// landed-approval read dependency-injected behind a SYNTHETIC fake (D50). No
// live host / boundary / KVM / OpenBao dependency; the decision is offline.

package sessions

import (
	"context"
	"errors"
	"testing"

	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
)

// fakeApprovalPresence is the SYNTHETIC ApprovalPresence (D50): an in-process map
// of session → landed-approval, plus an optional injected read error. It mirrors
// the real policy_log ask-grant read seam without touching any store, so the gate
// can be exercised offline.
type fakeApprovalPresence struct {
	landed map[string]bool
	err    error
	// calls records the sessions the gate asked about, so a test can assert the
	// non-policy_breach arms do NOT consult the approval read.
	calls []string
}

func (f *fakeApprovalPresence) HasLandedApproval(_ context.Context, sessionUUID string) (bool, error) {
	f.calls = append(f.calls, sessionUUID)
	if f.err != nil {
		return false, f.err
	}
	return f.landed[sessionUUID], nil
}

// TestRequiredResumeAuthority pins the §3 note 3 split: the frozen reason → resume
// authority map, with UNSPECIFIED / unknown reasons fail-closed to None.
func TestRequiredResumeAuthority(t *testing.T) {
	cases := []struct {
		name   string
		reason attachv1.SuspendReason
		want   ResumeAuthority
	}{
		{"user", attachv1.SuspendReason_SUSPEND_REASON_USER, ResumeAuthorityUser},
		{"policy_breach", attachv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH, ResumeAuthorityHumanApproval},
		{"rebalance", attachv1.SuspendReason_SUSPEND_REASON_REBALANCE, ResumeAuthorityScheduler},
		{"unspecified", attachv1.SuspendReason_SUSPEND_REASON_UNSPECIFIED, ResumeAuthorityNone},
		{"out-of-range", attachv1.SuspendReason(99), ResumeAuthorityNone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := RequiredResumeAuthority(tc.reason); got != tc.want {
				t.Errorf("RequiredResumeAuthority(%v) = %v, want %v", tc.reason, got, tc.want)
			}
		})
	}
}

// TestResumeAuthorityString covers the trace/refusal rendering including the
// fail-closed zero value.
func TestResumeAuthorityString(t *testing.T) {
	cases := map[ResumeAuthority]string{
		ResumeAuthorityNone:          "none",
		ResumeAuthorityUser:          "user",
		ResumeAuthorityHumanApproval: "human-approval",
		ResumeAuthorityScheduler:     "scheduler",
		ResumeAuthority(42):          "none", // unknown renders the fail-closed default
	}
	for a, want := range cases {
		if got := a.String(); got != want {
			t.Errorf("ResumeAuthority(%d).String() = %q, want %q", int(a), got, want)
		}
	}
}

// TestAuthorizeResume_User: a user-reason suspension resumes on user authority,
// and does NOT consult the approval read (its authority IS the gate).
func TestAuthorizeResume_User(t *testing.T) {
	f := &fakeApprovalPresence{}
	dec, err := AuthorizeResume(context.Background(), ResumeRequest{
		Reason:             attachv1.SuspendReason_SUSPEND_REASON_USER,
		PresentedAuthority: ResumeAuthorityUser,
		SessionUUID:        "s-user",
	}, f)
	if err != nil {
		t.Fatalf("AuthorizeResume(user) error = %v, want nil", err)
	}
	if !dec.Permitted {
		t.Errorf("user resume Permitted = false, want true (reason: %q)", dec.Reason)
	}
	if dec.Required != ResumeAuthorityUser {
		t.Errorf("Required = %v, want user", dec.Required)
	}
	if len(f.calls) != 0 {
		t.Errorf("user arm consulted approval read %v times, want 0 (its authority is the gate)", len(f.calls))
	}
}

// TestAuthorizeResume_Scheduler: a rebalance suspension resumes on scheduler
// authority, no approval read.
func TestAuthorizeResume_Scheduler(t *testing.T) {
	f := &fakeApprovalPresence{}
	dec, err := AuthorizeResume(context.Background(), ResumeRequest{
		Reason:             attachv1.SuspendReason_SUSPEND_REASON_REBALANCE,
		PresentedAuthority: ResumeAuthorityScheduler,
	}, f)
	if err != nil {
		t.Fatalf("AuthorizeResume(rebalance) error = %v, want nil", err)
	}
	if !dec.Permitted {
		t.Errorf("rebalance resume Permitted = false, want true (reason: %q)", dec.Reason)
	}
	if len(f.calls) != 0 {
		t.Errorf("scheduler arm consulted approval read %v times, want 0", len(f.calls))
	}
}

// TestAuthorizeResume_NonPolicyBreach_NilApprovalSafe proves a nil
// ApprovalPresence is safe for the non-policy_breach arms (no read is performed).
func TestAuthorizeResume_NonPolicyBreach_NilApprovalSafe(t *testing.T) {
	for _, tc := range []struct {
		name      string
		reason    attachv1.SuspendReason
		authority ResumeAuthority
	}{
		{"user", attachv1.SuspendReason_SUSPEND_REASON_USER, ResumeAuthorityUser},
		{"rebalance", attachv1.SuspendReason_SUSPEND_REASON_REBALANCE, ResumeAuthorityScheduler},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dec, err := AuthorizeResume(context.Background(), ResumeRequest{
				Reason:             tc.reason,
				PresentedAuthority: tc.authority,
			}, nil)
			if err != nil {
				t.Fatalf("AuthorizeResume(%s, nil approvals) error = %v", tc.name, err)
			}
			if !dec.Permitted {
				t.Errorf("%s resume with nil approvals Permitted = false, want true", tc.name)
			}
		})
	}
}

// TestAuthorizeResume_PolicyBreach_WithLandedApproval: THE happy path of the BIC
// arm — a genuine rung-2 approval has landed, human-approval authority resumes.
func TestAuthorizeResume_PolicyBreach_WithLandedApproval(t *testing.T) {
	f := &fakeApprovalPresence{landed: map[string]bool{"s-bic": true}}
	dec, err := AuthorizeResume(context.Background(), ResumeRequest{
		Reason:             attachv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH,
		PresentedAuthority: ResumeAuthorityHumanApproval,
		SessionUUID:        "s-bic",
	}, f)
	if err != nil {
		t.Fatalf("AuthorizeResume(policy_breach, landed) error = %v", err)
	}
	if !dec.Permitted {
		t.Errorf("policy_breach resume with landed approval Permitted = false, want true (reason: %q)", dec.Reason)
	}
	if dec.Required != ResumeAuthorityHumanApproval {
		t.Errorf("Required = %v, want human-approval", dec.Required)
	}
	if len(f.calls) != 1 || f.calls[0] != "s-bic" {
		t.Errorf("approval read calls = %v, want exactly [s-bic]", f.calls)
	}
}

// TestAuthorizeResume_PolicyBreach_NoLandedApproval is THE KEY ASSERTION: a
// policy_breach suspension with NO landed approval must be DENIED — the §3
// SUSPENDED─►RESUMING edge does not auto-traverse without the §8.2 human approval.
func TestAuthorizeResume_PolicyBreach_NoLandedApproval(t *testing.T) {
	f := &fakeApprovalPresence{landed: map[string]bool{}} // no approval landed
	dec, err := AuthorizeResume(context.Background(), ResumeRequest{
		Reason:             attachv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH,
		PresentedAuthority: ResumeAuthorityHumanApproval,
		SessionUUID:        "s-bic",
	}, f)
	if err != nil {
		t.Fatalf("AuthorizeResume(policy_breach, no approval) error = %v, want nil (a policy denial, not a fault)", err)
	}
	if dec.Permitted {
		t.Fatal("KEY ASSERTION VIOLATED: policy_breach resumed without a landed human approval")
	}
	if dec.Reason == "" {
		t.Error("denial Reason is empty, want an explanation")
	}
}

// TestAuthorizeResume_PolicyBreach_ReadError: an approval-read error fails closed
// (deny) AND surfaces ErrResumeApprovalReadFailed so the driver can tell a fault
// from a policy refusal.
func TestAuthorizeResume_PolicyBreach_ReadError(t *testing.T) {
	wantErr := errors.New("policy_log unavailable")
	f := &fakeApprovalPresence{err: wantErr}
	dec, err := AuthorizeResume(context.Background(), ResumeRequest{
		Reason:             attachv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH,
		PresentedAuthority: ResumeAuthorityHumanApproval,
		SessionUUID:        "s-bic",
	}, f)
	if dec.Permitted {
		t.Fatal("read error must fail closed (Permitted=false)")
	}
	if !errors.Is(err, ErrResumeApprovalReadFailed) {
		t.Errorf("err = %v, want wrapping ErrResumeApprovalReadFailed", err)
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("err = %v, want wrapping the underlying read error", err)
	}
}

// TestAuthorizeResume_PolicyBreach_NilReader: the BIC arm with no wired reader is
// a fail-closed denial (the gate cannot prove an approval landed).
func TestAuthorizeResume_PolicyBreach_NilReader(t *testing.T) {
	dec, err := AuthorizeResume(context.Background(), ResumeRequest{
		Reason:             attachv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH,
		PresentedAuthority: ResumeAuthorityHumanApproval,
		SessionUUID:        "s-bic",
	}, nil)
	if err != nil {
		t.Fatalf("nil reader error = %v, want nil (a policy denial)", err)
	}
	if dec.Permitted {
		t.Fatal("policy_breach with nil reader must fail closed")
	}
}

// TestAuthorizeResume_PolicyBreach_EmptySession: the BIC arm refuses an empty
// session key (it cannot scope the landed-approval lookup) without consulting the
// reader.
func TestAuthorizeResume_PolicyBreach_EmptySession(t *testing.T) {
	f := &fakeApprovalPresence{landed: map[string]bool{"": true}} // even a "" key landed
	dec, err := AuthorizeResume(context.Background(), ResumeRequest{
		Reason:             attachv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH,
		PresentedAuthority: ResumeAuthorityHumanApproval,
		SessionUUID:        "",
	}, f)
	if err != nil {
		t.Fatalf("empty session error = %v, want nil", err)
	}
	if dec.Permitted {
		t.Fatal("policy_breach with empty session UUID must fail closed")
	}
	if len(f.calls) != 0 {
		t.Errorf("approval read consulted %v times for an empty session, want 0 (refused before the read)", len(f.calls))
	}
}

// TestAuthorizeResume_AuthorityMismatch: presenting the WRONG authority for the
// reason is a structural refusal across every reason, including a user/scheduler
// presenting on the policy_breach arm (which never reaches the approval read).
func TestAuthorizeResume_AuthorityMismatch(t *testing.T) {
	cases := []struct {
		name      string
		reason    attachv1.SuspendReason
		presented ResumeAuthority
	}{
		{"user-reason resumed by scheduler", attachv1.SuspendReason_SUSPEND_REASON_USER, ResumeAuthorityScheduler},
		{"user-reason resumed by human-approval", attachv1.SuspendReason_SUSPEND_REASON_USER, ResumeAuthorityHumanApproval},
		{"rebalance resumed by user", attachv1.SuspendReason_SUSPEND_REASON_REBALANCE, ResumeAuthorityUser},
		{"policy_breach resumed by user", attachv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH, ResumeAuthorityUser},
		{"policy_breach resumed by scheduler", attachv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH, ResumeAuthorityScheduler},
		{"policy_breach with no authority presented", attachv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH, ResumeAuthorityNone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Even with an approval landed, the wrong authority is refused (and the
			// approval read is never reached — the authority match precedes it).
			f := &fakeApprovalPresence{landed: map[string]bool{"s": true}}
			dec, err := AuthorizeResume(context.Background(), ResumeRequest{
				Reason:             tc.reason,
				PresentedAuthority: tc.presented,
				SessionUUID:        "s",
			}, f)
			if err != nil {
				t.Fatalf("AuthorizeResume error = %v, want nil", err)
			}
			if dec.Permitted {
				t.Errorf("authority mismatch permitted resume (reason %v, presented %v)", tc.reason, tc.presented)
			}
			if len(f.calls) != 0 {
				t.Errorf("authority mismatch consulted approval read %v times, want 0 (match precedes the read)", len(f.calls))
			}
		})
	}
}

// TestAuthorizeResume_UnspecifiedReason: an UNSPECIFIED reason demands None, which
// no requestor can satisfy — fail-closed, even if a "matching" None is presented.
func TestAuthorizeResume_UnspecifiedReason(t *testing.T) {
	for _, presented := range []ResumeAuthority{ResumeAuthorityNone, ResumeAuthorityUser, ResumeAuthorityHumanApproval, ResumeAuthorityScheduler} {
		dec, err := AuthorizeResume(context.Background(), ResumeRequest{
			Reason:             attachv1.SuspendReason_SUSPEND_REASON_UNSPECIFIED,
			PresentedAuthority: presented,
			SessionUUID:        "s",
		}, &fakeApprovalPresence{})
		if err != nil {
			t.Fatalf("AuthorizeResume(unspecified, presented=%v) error = %v", presented, err)
		}
		if dec.Permitted {
			t.Errorf("unspecified reason permitted resume (presented %v), want fail-closed deny", presented)
		}
		if dec.Required != ResumeAuthorityNone {
			t.Errorf("Required for unspecified = %v, want none", dec.Required)
		}
	}
}
