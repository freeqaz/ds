// SPDX-License-Identifier: Apache-2.0

package hypervisor

import (
	"context"
	"io"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/dream-serpent/dream-serpent/assurance/contract-harness/dualrun"

	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
	hypervisorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hypervisor/v1"
	"github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hypervisor/v1/hypervisorv1fake"
)

// Synthetic fixtures (D50). Every identifier is obviously-synthetic — no real
// session ids, hosts, or paths. The two session uuids are stable so the suite's
// idempotency scenarios can re-issue the same content-addressed request.
// synthSessionA / synthSessionB are reserved for the RecoverSessions readback:
// both dialers pre-seed them (the "post-restart" inherited sessions) and NO
// scenario mutates them, so the re-adoption report is stable regardless of
// scenario order. Every mutating scenario uses its own dedicated session uuid so
// scenarios stay independent across the shared in-process connection.
const (
	synthSessionA     = "ses-aaaaaaaa-0000-4000-8000-aaaaaaaaaaaa"
	synthSessionB     = "ses-bbbbbbbb-1111-4111-8111-bbbbbbbbbbbb"
	synthSessClone    = "ses-c10ec10e-2222-4222-8222-cccccccccccc"
	synthSessAttach   = "ses-a77ac77a-3333-4333-8333-dddddddddddd"
	synthSessSnapshot = "ses-5na95na9-4444-4444-8444-eeeeeeeeeeee"
	synthSessSuspend  = "ses-50595059-5555-4555-8555-ffffffffffff"
	synthSessBreach   = "ses-b4eac4ea-6666-4666-8666-aaaabbbbcccc"
	synthSessDestroy  = "ses-de57de57-7777-4777-8777-ddddeeeeffff"
	synthSessMigrate  = "ses-m1g4m1g4-8888-4888-8888-000011112222"
	synthSessDelta    = "ses-de17ade1-9999-4999-8999-333344445555"
	// synthSessUnknown is a session that is NEVER cloned/seeded on either end, so
	// every verb keyed on it observes NotFound consistently real-vs-fake. It is
	// deliberately distinct from synthSessionA/B (pre-seeded for RecoverSessions)
	// and from every mutating scenario's uuid, so it cannot be brought into
	// existence by scenario order. Synthetic fixtures only (D50).
	synthSessUnknown = "ses-00000000-dead-4dead-8dead-000000000000"
	synthHostID      = "host-synthetic-01"
	synthImageID     = "img-synthetic-cafef00d"
	synthRuleID      = "rule-synthetic-deny-42"
	synthIndexA      = uint64(101)
	synthIndexB      = uint64(102)
)

// Suite is the hypervisor seam's single conformance suite (doc 06 §3a: one
// suite, run against real + fake). Every scenario is stated purely in terms of
// the frozen hypervisor.v1 contract so the same suite is meaningful against any
// faithful implementation. The suite drives a CAPABLE driver (all three D35
// flags true) so every verb — including the capability-gated Migrate /
// ExportDiskDelta — exercises its success path here; the false-flag REFUSAL half
// of the honesty property (D32/D35) is the separate CapabilityHonestySuite,
// which runs against the EC2-style incapable driver. Splitting them keeps each
// dual-run self-consistent: within one run the real impl and the fake must agree
// on the same capability profile.
func Suite() dualrun.Suite {
	return dualrun.Suite{
		Seam:      "orchestrator<->hypervisor(capable)",
		Scenarios: append(capableScenarios(), negativeScenarios()...),
	}
}

// CapabilityHonestySuite is the second conformance suite: it drives an EC2-style
// INCAPABLE driver (all three D35 flags false) and asserts every capability-
// gated verb is REFUSED (FailedPrecondition) rather than no-op-claiming success
// — the EC2 honesty test (D32). Run real-vs-fake like Suite().
func CapabilityHonestySuite() dualrun.Suite {
	return dualrun.Suite{
		Seam:      "orchestrator<->hypervisor(ec2-incapable)",
		Scenarios: honestyScenarios(),
	}
}

// capableScenarios exercises every verb against a fully-capable driver and
// asserts idempotency, the gated-verb success paths, restart re-adoption, and
// the observed-state report shape.
func capableScenarios() []dualrun.Scenario {
	return []dualrun.Scenario{
		{
			Name: "get-capabilities/capable-driver-reports-all-true",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := hypervisorv1.NewHypervisorDriverServiceClient(conn)
				resp, err := cl.GetCapabilities(ctx, &hypervisorv1.GetCapabilitiesRequest{})
				obs := dualrun.NewObservation()
				if err != nil {
					obs.Set("status", status.Code(err).String())
					return obs, nil
				}
				return capabilitiesObservation(obs, resp.GetCapabilities()), nil
			},
		},
		{
			Name: "clone-from-image/idempotent-on-session-uuid",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := hypervisorv1.NewHypervisorDriverServiceClient(conn)
				req := &hypervisorv1.CloneFromImageRequest{Spec: synthSpec(synthSessClone)}
				first, err := cl.CloneFromImage(ctx, req)
				if err != nil {
					return errObservation(err), nil
				}
				// Re-issue the SAME content-addressed request: idempotent on
				// session_uuid (doc 15 §5.1) — the binding must be identical, not
				// a freshly-allocated second one.
				second, err := cl.CloneFromImage(ctx, req)
				if err != nil {
					return errObservation(err), nil
				}
				obs := dualrun.NewObservation()
				obs.Set("status", codes.OK.String())
				obs.Setf("idempotent_binding", "%t", bindingsEqual(first, second))
				return bindingObservation(obs, second), nil
			},
		},
		{
			Name: "issue-attach-handle/echoes-session-and-role",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := hypervisorv1.NewHypervisorDriverServiceClient(conn)
				if _, err := cl.CloneFromImage(ctx, &hypervisorv1.CloneFromImageRequest{Spec: synthSpec(synthSessAttach)}); err != nil {
					return errObservation(err), nil
				}
				resp, err := cl.IssueAttachHandle(ctx, &hypervisorv1.IssueAttachHandleRequest{
					SessionUuid: synthSessAttach,
					Role:        attachv1.Role_ROLE_WRITER,
				})
				if err != nil {
					return errObservation(err), nil
				}
				obs := dualrun.NewObservation()
				obs.Set("status", codes.OK.String())
				obs.Set("handle_session_uuid", resp.GetHandle().GetSessionUuid())
				obs.Set("handle_role", resp.GetHandle().GetRole().String())
				return obs, nil
			},
		},
		{
			Name: "snapshot/idempotent-ref-on-session-uuid",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := hypervisorv1.NewHypervisorDriverServiceClient(conn)
				if _, err := cl.CloneFromImage(ctx, &hypervisorv1.CloneFromImageRequest{Spec: synthSpec(synthSessSnapshot)}); err != nil {
					return errObservation(err), nil
				}
				req := &hypervisorv1.SnapshotRequest{SessionUuid: synthSessSnapshot, Label: "synthetic-label"}
				first, err := cl.Snapshot(ctx, req)
				if err != nil {
					return errObservation(err), nil
				}
				second, err := cl.Snapshot(ctx, req)
				if err != nil {
					return errObservation(err), nil
				}
				obs := dualrun.NewObservation()
				obs.Set("status", codes.OK.String())
				obs.Set("snapshot_ref", second.GetSnapshotRef())
				obs.Setf("idempotent_ref", "%t", first.GetSnapshotRef() == second.GetSnapshotRef())
				return obs, nil
			},
		},
		{
			Name: "suspend-resume/round-trip-acknowledged",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := hypervisorv1.NewHypervisorDriverServiceClient(conn)
				if _, err := cl.CloneFromImage(ctx, &hypervisorv1.CloneFromImageRequest{Spec: synthSpec(synthSessSuspend)}); err != nil {
					return errObservation(err), nil
				}
				if _, err := cl.Suspend(ctx, &hypervisorv1.SuspendRequest{
					SessionUuid: synthSessSuspend,
					Reason:      hypervisorv1.SuspendReason_SUSPEND_REASON_USER,
				}); err != nil {
					return errObservation(err), nil
				}
				// Idempotent re-suspend is a no-op acknowledged the same way.
				if _, err := cl.Suspend(ctx, &hypervisorv1.SuspendRequest{
					SessionUuid: synthSessSuspend,
					Reason:      hypervisorv1.SuspendReason_SUSPEND_REASON_USER,
				}); err != nil {
					return errObservation(err), nil
				}
				if _, err := cl.Resume(ctx, &hypervisorv1.ResumeRequest{SessionUuid: synthSessSuspend}); err != nil {
					return errObservation(err), nil
				}
				obs := dualrun.NewObservation()
				obs.Set("status", codes.OK.String())
				obs.Set("round_trip", "ok")
				return obs, nil
			},
		},
		{
			Name: "suspend/policy-breach-requires-provenance",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := hypervisorv1.NewHypervisorDriverServiceClient(conn)
				if _, err := cl.CloneFromImage(ctx, &hypervisorv1.CloneFromImageRequest{Spec: synthSpec(synthSessBreach)}); err != nil {
					return errObservation(err), nil
				}
				// POLICY_BREACH WITHOUT provenance — must be rejected (D77).
				_, missingErr := cl.Suspend(ctx, &hypervisorv1.SuspendRequest{
					SessionUuid: synthSessBreach,
					Reason:      hypervisorv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH,
				})
				// POLICY_BREACH WITH provenance — accepted.
				_, withErr := cl.Suspend(ctx, &hypervisorv1.SuspendRequest{
					SessionUuid: synthSessBreach,
					Reason:      hypervisorv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH,
					Provenance:  synthProvenance(),
				})
				obs := dualrun.NewObservation()
				obs.Set("missing_provenance_status", status.Code(missingErr).String())
				obs.Set("with_provenance_status", status.Code(withErr).String())
				return obs, nil
			},
		},
		{
			Name: "destroy/idempotent-retry-succeeds",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := hypervisorv1.NewHypervisorDriverServiceClient(conn)
				if _, err := cl.CloneFromImage(ctx, &hypervisorv1.CloneFromImageRequest{Spec: synthSpec(synthSessDestroy)}); err != nil {
					return errObservation(err), nil
				}
				req := &hypervisorv1.DestroyRequest{SessionUuid: synthSessDestroy}
				if _, err := cl.Destroy(ctx, req); err != nil {
					return errObservation(err), nil
				}
				// Retried Destroy on an already-gone session SUCCEEDS (idempotent
				// teardown, doc 15 §4.2/§5.1) — it must not error NotFound.
				_, retryErr := cl.Destroy(ctx, req)
				obs := dualrun.NewObservation()
				obs.Set("first_status", codes.OK.String())
				obs.Set("retry_status", status.Code(retryErr).String())
				return obs, nil
			},
		},
		{
			Name: "migrate/capable-driver-returns-target-binding",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := hypervisorv1.NewHypervisorDriverServiceClient(conn)
				if _, err := cl.CloneFromImage(ctx, &hypervisorv1.CloneFromImageRequest{Spec: synthSpec(synthSessMigrate)}); err != nil {
					return errObservation(err), nil
				}
				resp, err := cl.Migrate(ctx, &hypervisorv1.MigrateRequest{
					SessionUuid:  synthSessMigrate,
					TargetHostId: "host-synthetic-target",
				})
				if err != nil {
					return errObservation(err), nil
				}
				obs := dualrun.NewObservation()
				obs.Set("status", codes.OK.String())
				obs.Setf("has_target_binding", "%t", resp.GetTargetBinding() != nil)
				// The target tap is a fresh per-host name on the new host; record
				// only its presence shape, not the order-sensitive index, so the
				// observation is the contract fact (a binding was returned).
				obs.Setf("has_target_tap", "%t", resp.GetTargetBinding().GetTapName() != "")
				return obs, nil
			},
		},
		{
			Name: "export-disk-delta/capable-driver-streams-frames",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := hypervisorv1.NewHypervisorDriverServiceClient(conn)
				if _, err := cl.CloneFromImage(ctx, &hypervisorv1.CloneFromImageRequest{Spec: synthSpec(synthSessDelta)}); err != nil {
					return errObservation(err), nil
				}
				stream, err := cl.ExportDiskDelta(ctx, &hypervisorv1.ExportDiskDeltaRequest{SessionUuid: synthSessDelta})
				if err != nil {
					return errObservation(err), nil
				}
				return deltaStreamObservation(stream), nil
			},
		},
		{
			Name: "recover-sessions/re-adopts-after-restart",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := hypervisorv1.NewHypervisorDriverServiceClient(conn)
				// Stand up two live sessions, then enumerate them via
				// RecoverSessions — the restart re-adoption path (doc 15 §5.1).
				// Both ends were pre-seeded with the SAME synthetic sessions by
				// their dialers, so the report shape must match.
				resp, err := cl.RecoverSessions(ctx, &hypervisorv1.RecoverSessionsRequest{HostId: synthHostID})
				if err != nil {
					return errObservation(err), nil
				}
				return recoverObservation(resp), nil
			},
		},
	}
}

// negativeScenarios is the error / validation-path contract: the half of the
// behavior the happy-path scenarios above do not exercise. Every scenario here
// asserts an OBSERVABLE gRPC status code (the contract fact the seam promises on
// bad input), consistently real-vs-fake — the fake routes each verb at a mirror
// RefImpl, so a status-code divergence here is a lying fake or a drifted impl,
// exactly as for the happy paths. These run inside the CAPABLE Suite() (all D35
// flags true) so the capability-gated verbs (Migrate / ExportDiskDelta) reach
// their argument/lookup branches rather than the FailedPrecondition refusal —
// the false-flag refusal is CapabilityHonestySuite's job.
//
// Three contract properties are covered:
//
//   - NotFound on an unknown session: a verb that requires the session to exist
//     (Snapshot / Suspend / Resume / Migrate / IssueAttachHandle /
//     ExportDiskDelta) keyed on synthSessUnknown — never cloned or seeded on
//     either end — returns NotFound. Destroy is intentionally absent: its
//     teardown is idempotent (doc 15 §4.2/§5.1), so an unknown session is a
//     no-op SUCCESS, not NotFound — asserted positively by the happy-path
//     destroy/idempotent-retry-succeeds scenario.
//   - InvalidArgument on an empty session_uuid: every uuid-keyed verb
//     (CloneFromImage via VmSpec.session_uuid, Snapshot, Suspend, Resume,
//     Destroy, Migrate, IssueAttachHandle, ExportDiskDelta) rejects "" before
//     any lookup — every verb is idempotent on session_uuid, so it is required.
//   - InvalidArgument on an empty host_id for RecoverSessions, and the D77
//     provenance guard: Suspend(POLICY_BREACH) WITHOUT provenance is refused
//     (InvalidArgument) — the provenance is mandatory for the genuine-threat
//     reason class.
func negativeScenarios() []dualrun.Scenario {
	return []dualrun.Scenario{
		{
			Name: "snapshot/unknown-session-not-found",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := hypervisorv1.NewHypervisorDriverServiceClient(conn)
				_, err := cl.Snapshot(ctx, &hypervisorv1.SnapshotRequest{SessionUuid: synthSessUnknown, Label: "synthetic-label"})
				return statusObservation(err), nil
			},
		},
		{
			Name: "suspend/unknown-session-not-found",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := hypervisorv1.NewHypervisorDriverServiceClient(conn)
				_, err := cl.Suspend(ctx, &hypervisorv1.SuspendRequest{
					SessionUuid: synthSessUnknown,
					Reason:      hypervisorv1.SuspendReason_SUSPEND_REASON_USER,
				})
				return statusObservation(err), nil
			},
		},
		{
			Name: "resume/unknown-session-not-found",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := hypervisorv1.NewHypervisorDriverServiceClient(conn)
				_, err := cl.Resume(ctx, &hypervisorv1.ResumeRequest{SessionUuid: synthSessUnknown})
				return statusObservation(err), nil
			},
		},
		{
			Name: "migrate/unknown-session-not-found",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := hypervisorv1.NewHypervisorDriverServiceClient(conn)
				_, err := cl.Migrate(ctx, &hypervisorv1.MigrateRequest{
					SessionUuid:  synthSessUnknown,
					TargetHostId: "host-synthetic-target",
				})
				return statusObservation(err), nil
			},
		},
		{
			Name: "issue-attach-handle/unknown-session-not-found",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := hypervisorv1.NewHypervisorDriverServiceClient(conn)
				_, err := cl.IssueAttachHandle(ctx, &hypervisorv1.IssueAttachHandleRequest{
					SessionUuid: synthSessUnknown,
					Role:        attachv1.Role_ROLE_WRITER,
				})
				return statusObservation(err), nil
			},
		},
		{
			Name: "export-disk-delta/unknown-session-not-found",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := hypervisorv1.NewHypervisorDriverServiceClient(conn)
				// The NotFound may surface at open or on the first Recv depending on
				// when the server validates; fold both into one observable status so
				// the real impl and the fake (which returns the error eagerly) agree.
				return streamOpenStatusObservation(cl.ExportDiskDelta(ctx, &hypervisorv1.ExportDiskDeltaRequest{SessionUuid: synthSessUnknown})), nil
			},
		},
		{
			Name: "clone-from-image/empty-session-uuid-invalid-argument",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := hypervisorv1.NewHypervisorDriverServiceClient(conn)
				_, err := cl.CloneFromImage(ctx, &hypervisorv1.CloneFromImageRequest{Spec: synthSpec("")})
				return statusObservation(err), nil
			},
		},
		{
			Name: "snapshot/empty-session-uuid-invalid-argument",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := hypervisorv1.NewHypervisorDriverServiceClient(conn)
				_, err := cl.Snapshot(ctx, &hypervisorv1.SnapshotRequest{SessionUuid: "", Label: "synthetic-label"})
				return statusObservation(err), nil
			},
		},
		{
			Name: "suspend/empty-session-uuid-invalid-argument",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := hypervisorv1.NewHypervisorDriverServiceClient(conn)
				_, err := cl.Suspend(ctx, &hypervisorv1.SuspendRequest{
					SessionUuid: "",
					Reason:      hypervisorv1.SuspendReason_SUSPEND_REASON_USER,
				})
				return statusObservation(err), nil
			},
		},
		{
			Name: "resume/empty-session-uuid-invalid-argument",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := hypervisorv1.NewHypervisorDriverServiceClient(conn)
				_, err := cl.Resume(ctx, &hypervisorv1.ResumeRequest{SessionUuid: ""})
				return statusObservation(err), nil
			},
		},
		{
			Name: "destroy/empty-session-uuid-invalid-argument",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := hypervisorv1.NewHypervisorDriverServiceClient(conn)
				_, err := cl.Destroy(ctx, &hypervisorv1.DestroyRequest{SessionUuid: ""})
				return statusObservation(err), nil
			},
		},
		{
			Name: "migrate/empty-session-uuid-invalid-argument",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := hypervisorv1.NewHypervisorDriverServiceClient(conn)
				_, err := cl.Migrate(ctx, &hypervisorv1.MigrateRequest{
					SessionUuid:  "",
					TargetHostId: "host-synthetic-target",
				})
				return statusObservation(err), nil
			},
		},
		{
			Name: "issue-attach-handle/empty-session-uuid-invalid-argument",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := hypervisorv1.NewHypervisorDriverServiceClient(conn)
				_, err := cl.IssueAttachHandle(ctx, &hypervisorv1.IssueAttachHandleRequest{
					SessionUuid: "",
					Role:        attachv1.Role_ROLE_WRITER,
				})
				return statusObservation(err), nil
			},
		},
		{
			Name: "export-disk-delta/empty-session-uuid-invalid-argument",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := hypervisorv1.NewHypervisorDriverServiceClient(conn)
				return streamOpenStatusObservation(cl.ExportDiskDelta(ctx, &hypervisorv1.ExportDiskDeltaRequest{SessionUuid: ""})), nil
			},
		},
		{
			Name: "recover-sessions/empty-host-id-invalid-argument",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := hypervisorv1.NewHypervisorDriverServiceClient(conn)
				_, err := cl.RecoverSessions(ctx, &hypervisorv1.RecoverSessionsRequest{HostId: ""})
				return statusObservation(err), nil
			},
		},
		{
			Name: "suspend/policy-breach-without-provenance-refused",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := hypervisorv1.NewHypervisorDriverServiceClient(conn)
				// POLICY_BREACH with NO provenance is refused BEFORE any session
				// lookup (the provenance guard precedes the store), so this needs no
				// cloned session and stays independent of every mutating scenario.
				_, err := cl.Suspend(ctx, &hypervisorv1.SuspendRequest{
					SessionUuid: synthSessUnknown,
					Reason:      hypervisorv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH,
				})
				return statusObservation(err), nil
			},
		},
	}
}

// honestyScenarios drives the EC2-style incapable driver and asserts every
// capability-gated verb is REFUSED rather than silently succeeding (D32/D35).
func honestyScenarios() []dualrun.Scenario {
	return []dualrun.Scenario{
		{
			Name: "get-capabilities/ec2-driver-reports-all-false",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := hypervisorv1.NewHypervisorDriverServiceClient(conn)
				resp, err := cl.GetCapabilities(ctx, &hypervisorv1.GetCapabilitiesRequest{})
				obs := dualrun.NewObservation()
				if err != nil {
					obs.Set("status", status.Code(err).String())
					return obs, nil
				}
				return capabilitiesObservation(obs, resp.GetCapabilities()), nil
			},
		},
		{
			Name: "migrate/refused-when-supports-migrate-false",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := hypervisorv1.NewHypervisorDriverServiceClient(conn)
				_, err := cl.Migrate(ctx, &hypervisorv1.MigrateRequest{
					SessionUuid:  synthSessionA,
					TargetHostId: "host-synthetic-target",
				})
				obs := dualrun.NewObservation()
				// The contract-honest outcome is a REFUSAL, not a no-op success.
				obs.Set("status", status.Code(err).String())
				return obs, nil
			},
		},
		{
			Name: "export-disk-delta/refused-when-supports-delta-export-false",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := hypervisorv1.NewHypervisorDriverServiceClient(conn)
				stream, err := cl.ExportDiskDelta(ctx, &hypervisorv1.ExportDiskDeltaRequest{SessionUuid: synthSessionA})
				obs := dualrun.NewObservation()
				if err != nil {
					obs.Set("status", status.Code(err).String())
					return obs, nil
				}
				// The refusal may surface on the first Recv of the stream rather
				// than at open — fold it into the same observable status.
				_, recvErr := stream.Recv()
				obs.Set("status", status.Code(recvErr).String())
				return obs, nil
			},
		},
	}
}

// --- Observation builders ----------------------------------------------------

func errObservation(err error) *dualrun.Observation {
	obs := dualrun.NewObservation()
	obs.Set("status", status.Code(err).String())
	return obs
}

// statusObservation records ONLY the observable gRPC status code of a verb
// outcome — the contract fact the error / validation-path scenarios turn on. A
// nil error records OK (status.Code(nil) == codes.OK), so a verb that wrongly
// succeeds on one end and errors on the other diverges loudly rather than
// silently passing. It is errObservation by another name, kept distinct so the
// negative scenarios read as "assert the status" rather than "an error happened".
func statusObservation(err error) *dualrun.Observation {
	obs := dualrun.NewObservation()
	obs.Set("status", status.Code(err).String())
	return obs
}

// streamOpenStatusObservation folds a server-streaming verb's rejection into one
// observable status, whether it surfaces at open (err != nil) or on the first
// Recv. The capable refimpl validates and returns the error before sending any
// frame, and the generated fake's responder returns the error eagerly (the
// dualrun stream adapter replays it on the first Recv); folding both keeps the
// observation identical across real and fake.
func streamOpenStatusObservation(stream grpc.ServerStreamingClient[hypervisorv1.ExportDiskDeltaResponse], openErr error) *dualrun.Observation {
	if openErr != nil {
		return statusObservation(openErr)
	}
	_, recvErr := stream.Recv()
	return statusObservation(recvErr)
}

func capabilitiesObservation(obs *dualrun.Observation, c *hypervisorv1.Capabilities) *dualrun.Observation {
	obs.Set("status", codes.OK.String())
	obs.Setf("supports_migrate", "%t", c.GetSupportsMigrate())
	obs.Setf("supports_instant_clone", "%t", c.GetSupportsInstantClone())
	obs.Setf("supports_disk_delta_export", "%t", c.GetSupportsDiskDeltaExport())
	return obs
}

// bindingObservation records the contract-observable SHAPE of a host-side
// attachment binding: the overlay path (derived from session identity, so
// stable), the never-recycled index/tap PRESENCE, and the guest address FAMILY +
// byte length. It records the address family + length, not raw bytes, so the
// observation stays at the contract level (D75: family-agnostic, never
// IPv4-assumed). The raw host index is intentionally NOT recorded — its value is
// an allocation detail; the idempotency fact (re-issue returns the same binding)
// is asserted separately via idempotent_binding.
func bindingObservation(obs *dualrun.Observation, b *hypervisorv1.CloneFromImageResponse) *dualrun.Observation {
	obs.Set("overlay_path", b.GetOverlayPath())
	obs.Setf("has_host_index", "%t", b.GetHostSessionIndex() != 0)
	obs.Setf("has_tap_name", "%t", b.GetTapName() != "")
	obs.Set("guest_ip_family", b.GetGuestIp().GetFamily().String())
	obs.Setf("guest_ip_len", "%d", len(b.GetGuestIp().GetAddress()))
	return obs
}

func bindingsEqual(a, b *hypervisorv1.CloneFromImageResponse) bool {
	return a.GetHostSessionIndex() == b.GetHostSessionIndex() &&
		a.GetTapName() == b.GetTapName() &&
		a.GetOverlayPath() == b.GetOverlayPath()
}

// deltaStreamObservation drains the ExportDiskDelta stream and records the
// frame count, total bytes, and final status — the contract-observable shape of
// the streamed delta.
func deltaStreamObservation(stream grpc.ServerStreamingClient[hypervisorv1.ExportDiskDeltaResponse]) *dualrun.Observation {
	obs := dualrun.NewObservation()
	var frames, total uint64
	var lastOffset uint64
	for {
		frame, err := stream.Recv()
		if err == io.EOF {
			obs.Set("status", codes.OK.String())
			break
		}
		if err != nil {
			obs.Set("status", status.Code(err).String())
			break
		}
		frames++
		total += uint64(len(frame.GetData()))
		lastOffset = frame.GetOffset()
	}
	obs.Setf("delta_frames", "%d", frames)
	obs.Setf("delta_total_bytes", "%d", total)
	obs.Setf("delta_last_offset", "%d", lastOffset)
	return obs
}

// recoverObservation records the heartbeat / observed-state report shape: the
// number of re-adopted sessions and, per session (ordered by host index), the
// observable join keys and §3 state. This is the same ObservedSession element
// the hostagent.v1 heartbeat carries (doc 15 §5.2), so the suite proves the
// re-adoption report matches across real and fake.
func recoverObservation(resp *hypervisorv1.RecoverSessionsResponse) *dualrun.Observation {
	obs := dualrun.NewObservation()
	obs.Set("status", codes.OK.String())
	obs.Setf("recovered_count", "%d", len(resp.GetSessions()))
	// Record each observed session under a stable, index-ordered key so the
	// canonical (sorted) observation is deterministic.
	for i, s := range resp.GetSessions() {
		obs.Set(indexKey("uuid", i), s.GetSessionUuid())
		obs.Set(indexKey("domain", i), s.GetDomainUuid())
		obs.Setf(indexKey("index", i), "%d", s.GetHostSessionIndex())
		obs.Set(indexKey("tap", i), s.GetTapName())
		obs.Set(indexKey("overlay", i), s.GetOverlayPath())
		obs.Set(indexKey("state", i), s.GetObservedState().GetName().String())
	}
	return obs
}

func indexKey(field string, i int) string {
	return "observed[" + decimal(uint64(i)) + "]." + field
}

// --- synthetic fixture constructors (D50) ------------------------------------

func synthSpec(uuid string) *hypervisorv1.VmSpec {
	return &hypervisorv1.VmSpec{
		SessionUuid:         uuid,
		ImageId:             synthImageID,
		EntrypointConfigRef: "entrypoint-synthetic-ref",
		Floors: &hypervisorv1.ResourceFloors{
			VcpuFloor:      2,
			VcpuBurst:      8,
			MemoryLowBytes: 4 << 30,
			IoWeight:       100,
		},
		Material: &hypervisorv1.SessionMaterial{
			CaBundleRef:     "ca-bundle-synthetic-ref",
			SessionTokenRef: "token-synthetic-ref",
		},
	}
}

func synthProvenance() *boundaryv1.Provenance {
	return &boundaryv1.Provenance{
		RuleId:        synthRuleID,
		PolicyLayer:   "synthetic-layer",
		PolicyVersion: 7,
	}
}

// --- dialers: real reference impl AND the generated fake --------------------
//
// Both the capable suite and the honesty suite need a matched pair of dialers
// (one for the real impl, one for the fake) configured to the SAME capability
// profile and pre-seeded with the SAME synthetic sessions, so the only thing
// that varies across the two dual-run passes is which server is registered.

// capableProfile is the fully-capable driver profile the main Suite() drives.
var capableProfile = struct{ migrate, instantClone, deltaExport bool }{true, true, true}

// RealDialer returns the dual-run Dialer for the capable reference impl. It
// pre-seeds the two synthetic sessions RecoverSessions must re-adopt — the
// "post-restart" driver inherits live sessions (doc 15 §5.1).
func RealDialer() dualrun.Dialer {
	impl := NewRefImpl(capableProfile.migrate, capableProfile.instantClone, capableProfile.deltaExport)
	impl.SeedSession(synthSessionA, synthIndexA, attachv1.SessionStateName_SESSION_STATE_NAME_READY)
	impl.SeedSession(synthSessionB, synthIndexB, attachv1.SessionStateName_SESSION_STATE_NAME_SUSPENDED)
	return dualrun.InProcess(impl.Register)
}

// FakeDialer returns the dual-run Dialer for the GENERATED programmable fake,
// programmed to the same capable contract Suite() asserts. The fake is driven
// only through its canned-response surface; the dual-run proves it is
// observationally identical to the real impl on every scenario. The fake is
// pre-seeded with the two synthetic sessions RecoverSessions must re-adopt.
func FakeDialer() dualrun.Dialer {
	f, mirror := programmedFake(capableProfile.migrate, capableProfile.instantClone, capableProfile.deltaExport)
	mirror.SeedSession(synthSessionA, synthIndexA, attachv1.SessionStateName_SESSION_STATE_NAME_READY)
	mirror.SeedSession(synthSessionB, synthIndexB, attachv1.SessionStateName_SESSION_STATE_NAME_SUSPENDED)
	return dualrun.InProcess(func(s grpc.ServiceRegistrar) {
		hypervisorv1fake.RegisterHypervisorDriverService(s, f)
	})
}

// IncapableRealDialer / IncapableFakeDialer are the matched pair for
// CapabilityHonestySuite — the EC2-style all-false driver.
func IncapableRealDialer() dualrun.Dialer {
	impl := NewRefImpl(false, false, false)
	return dualrun.InProcess(impl.Register)
}

func IncapableFakeDialer() dualrun.Dialer {
	f, _ := programmedFake(false, false, false)
	return dualrun.InProcess(func(s grpc.ServiceRegistrar) {
		hypervisorv1fake.RegisterHypervisorDriverService(s, f)
	})
}

// programmedFake programs the generated fake to the honest contract by routing
// its per-verb responders at a mirror RefImpl — so the fake and the real impl
// share one honest behavior definition (idempotency on session_uuid, capability
// gating, the §4.2 idempotent Destroy). It returns both the fake (to register)
// and the mirror (so a dialer can pre-seed restart-re-adoption sessions). This
// is the programmable-fake-driven-only-through-its-surface pattern (doc 06 §2.1):
// the dual-run still proves the fake observationally matches the production impl
// when it lands, because the suite never touches the mirror directly.
func programmedFake(supportsMigrate, supportsInstantClone, supportsDeltaExport bool) (*hypervisorv1fake.HypervisorDriverServiceFake, *RefImpl) {
	f := hypervisorv1fake.NewHypervisorDriverServiceFake()
	mirror := NewRefImpl(supportsMigrate, supportsInstantClone, supportsDeltaExport)

	f.GetCapabilitiesResponder = mirror.GetCapabilities
	f.CloneFromImageResponder = mirror.CloneFromImage
	f.IssueAttachHandleResponder = mirror.IssueAttachHandle
	f.SnapshotResponder = mirror.Snapshot
	f.SuspendResponder = mirror.Suspend
	f.ResumeResponder = mirror.Resume
	f.DestroyResponder = mirror.Destroy
	f.MigrateResponder = mirror.Migrate
	f.RecoverSessionsResponder = mirror.RecoverSessions
	f.ExportDiskDeltaResponder = func(_ context.Context, req *hypervisorv1.ExportDiskDeltaRequest) ([]*hypervisorv1.ExportDiskDeltaResponse, error) {
		if !supportsDeltaExport {
			return nil, status.Error(codes.FailedPrecondition, "driver does not support ExportDiskDelta (supports_disk_delta_export=false)")
		}
		if req.GetSessionUuid() == "" {
			return nil, status.Error(codes.InvalidArgument, "ExportDiskDeltaRequest.session_uuid is required")
		}
		if !mirror.HasSession(req.GetSessionUuid()) {
			return nil, status.Error(codes.NotFound, "no such session")
		}
		return deltaFrames(req.GetSessionUuid()), nil
	}
	return f, mirror
}
