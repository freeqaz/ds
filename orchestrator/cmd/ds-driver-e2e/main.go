// SPDX-License-Identifier: Apache-2.0

// ds-driver-e2e — a live full-lifecycle client harness for the host-agent's
// frozen hypervisor.v1 HypervisorDriverService (taskdb 01KV6PDSEF). It dials a
// RUNNING host-agent (started with DS_HOSTAGENT_LIVE=1) and drives the verb
// lifecycle against REAL libvirt on the virtual-metal box:
//
//	GetCapabilities -> CloneFromImage -> IssueAttachHandle -> Suspend -> Resume -> Snapshot ->
//	ExportDiskDelta -> Destroy  (+ idempotency round-trips)
//
// It is REPORT-STYLE: every verb is driven and its result recorded even if an
// earlier one failed, so one state-dependent libvirt quirk (e.g. a qemu-img
// overlay write-lock while the domain runs) surfaces as a FINDING rather than
// aborting the whole sweep. CloneFromImage and Destroy are the CRITICAL verbs:
// the process exits non-zero only if one of those fails. This is the live
// counterpart of the offline recordingRunner tests — run ONLY against a live
// host-agent on a host with /dev/kvm + libvirt + qemu-img; never in CI.
//
// The clone/recover/lifecycle modes all dial the host-agent's
// HypervisorDriverService DIRECTLY — they boot (or recover) a VM with NO
// orchestrator session record, which is exactly what the host-agent reconciler
// quarantines as an orphan ("observed VM has no session record (orphan)") and
// re-suspends every 5s. The -mode orch-create path instead dials the
// ORCHESTRATOR control plane (SessionService.CreateSession + Attach), so the
// authoritative session RECORD exists before any VM is observed — the placement
// then reconciles instead of being quarantined, and the minted WRITER handle is
// the seat the :4242 drive uses.
//
// Usage:
//
//	ds-driver-e2e -addr 127.0.0.1:18091 -session e2e-1               # host-agent lifecycle
//	ds-driver-e2e -mode orch-create -orch-addr 127.0.0.1:18090       # control-plane create + attach
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
	hypervisorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hypervisor/v1"
	orchestratorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/orchestrator/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:18091", "host-agent HypervisorDriverService gRPC address")
	session := flag.String("session", "e2e-1", "session_uuid to drive the lifecycle for")
	hostID := flag.String("host-id", "host-local", "host_id for RecoverSessions (matches the host-agent --host-id)")
	mode := flag.String("mode", "lifecycle", "lifecycle (full sweep) | clone (RecoverSessions + CloneFromImage only, leave the session resident — for the restart/recovery proof) | recover (RecoverSessions ONLY — opens the recover-before-serve latch on a recovery-wired host so the orchestrator can place; no VM boot) | orch-create (dial the ORCHESTRATOR SessionService.CreateSession + Attach so a session RECORD exists; no host-agent dial)")
	bootWait := flag.Duration("boot-wait", 12*time.Second, "settle time after CloneFromImage before the domain is RUNNING")
	orchAddr := flag.String("orch-addr", "127.0.0.1:18090", "orchestrator SessionService gRPC address (mode orch-create)")
	repo := flag.String("repo", "demo", "repo_id for CreateSession (D56 enrollment key; mode orch-create)")
	envConfigRef := flag.String("env-config-ref", "demo-env", "env_config_ref for CreateSession (D7/D56 second key; mode orch-create)")
	launchingUser := flag.String("launching-user", "mvp-user", "launching_user for CreateSession (D99 attribution root; mode orch-create)")
	flag.Parse()

	r := &report{}
	if *mode == "orch-create" {
		// orch-create: dial the ORCHESTRATOR control plane so an authoritative
		// session RECORD is created (and a WRITER attach handle minted) BEFORE any
		// VM is observed — the placement reconciles instead of the host-agent
		// reconciler quarantining the VM as a recordless orphan. CreateSession is
		// the CRITICAL verb: a failure exits non-zero. No host-agent dial.
		ok := driveOrchCreate(*orchAddr, *repo, *envConfigRef, *launchingUser, r)
		r.print()
		if !ok {
			fmt.Println("E2E-ORCH-CREATE: FAILED (CreateSession did not produce a session record — see FINDINGS)")
			os.Exit(1)
		}
		fmt.Println("E2E-ORCH-CREATE: OK (session record exists; WRITER seat minted — reconciler will place, not quarantine)")
		return
	}
	if *mode == "recover" {
		// recover-only: open the recover-before-serve latch (D66) on a recovery-wired
		// host so the orchestrator's first CloneFromImage may serve, then stop (no VM
		// boot). This is the host-bring-up step the single-box MVP runs once after the
		// host-agent starts, standing in for an orchestrator-driven RecoverSessions on
		// host registration (the latch is set once, idempotently).
		ok := driveRecoverOnly(*addr, *hostID, r)
		r.print()
		if !ok {
			fmt.Println("E2E-RECOVER: FAILED (RecoverSessions did not open the latch — see FINDINGS)")
			os.Exit(1)
		}
		fmt.Println("E2E-RECOVER: OK (recover-before-serve latch open; orchestrator may now place)")
		return
	}
	critical := drive(*addr, *session, *hostID, *mode == "clone", *bootWait, r)
	r.print()
	if !critical {
		fmt.Println("E2E-LIFECYCLE: FAILED (a critical verb did not pass — see FINDINGS)")
		os.Exit(1)
	}
	fmt.Println("E2E-LIFECYCLE: OK (critical verbs passed; review any FINDINGS)")
}

type step struct {
	name   string
	ok     bool
	detail string
}

type report struct{ steps []step }

func (r *report) add(name string, ok bool, format string, a ...any) bool {
	r.steps = append(r.steps, step{name: name, ok: ok, detail: fmt.Sprintf(format, a...)})
	return ok
}

func (r *report) print() {
	fmt.Println("=== ds-driver-e2e lifecycle report ===")
	for _, s := range r.steps {
		mark := "FINDING"
		if s.ok {
			mark = "PASS"
		}
		fmt.Printf("  [%-7s] %-22s %s\n", mark, s.name, s.detail)
	}
}

// driveRecoverOnly dials the host-agent and calls RecoverSessions ONLY — the
// host-bring-up step that opens the recover-before-serve latch (D66) on a
// recovery-wired host so the orchestrator's first CloneFromImage may serve. It
// boots no VM. Returns true iff RecoverSessions succeeded (the latch is now open;
// it is idempotent, so a re-run is harmless).
func driveRecoverOnly(addr, hostID string, r *report) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		r.add("dial", false, "%v", err)
		return false
	}
	defer conn.Close()
	c := hypervisorv1.NewHypervisorDriverServiceClient(conn)

	rec, err := c.RecoverSessions(ctx, &hypervisorv1.RecoverSessionsRequest{HostId: hostID})
	if err != nil {
		return r.add("RecoverSessions", false, "%v", err)
	}
	idxs := make([]uint64, 0, len(rec.GetSessions()))
	for _, s := range rec.GetSessions() {
		idxs = append(idxs, s.GetHostSessionIndex())
	}
	return r.add("RecoverSessions", true, "recovered=%d indices=%v (latch open)", len(rec.GetSessions()), idxs)
}

// driveOrchCreate dials the ORCHESTRATOR control plane and runs the §4.1
// canonical create (SessionService.CreateSession) followed by Attach for the
// WRITER role on the returned session. It is the control-plane counterpart of
// the host-agent clone/lifecycle modes: where those boot a recordless VM the
// reconciler quarantines as an orphan, this creates the authoritative session
// RECORD first so placement reconciles instead. CreateSession is the CRITICAL
// verb — returns false iff it fails (the caller exits non-zero). Attach is
// reported as a FINDING but does not gate (the writer seat the :4242 drive uses).
func driveOrchCreate(orchAddr, repo, envConfigRef, launchingUser string, r *report) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	conn, err := grpc.NewClient(orchAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		r.add("dial", false, "%v", err)
		return false
	}
	defer conn.Close()
	c := orchestratorv1.NewSessionServiceClient(conn)
	return runOrchCreate(ctx, c, repo, envConfigRef, launchingUser, r)
}

// runOrchCreate is the dial-free core of driveOrchCreate so it is exercisable
// against the controlplane fakes (a bufconn-served SessionServiceFake) without a
// live orchestrator. It calls CreateSession (CRITICAL) then Attach(WRITER) and
// prints the two stable single-line tokens the runner greps:
//
//	E2E-ORCH-CREATE: session=<uuid> index=<host_session_index> tap=<tap_name> state=<state>
//	E2E-ORCH-ATTACH: endpoint=<address> token=<base64-or-raw>
//
// Returns true iff CreateSession returned a session with a non-empty uuid.
func runOrchCreate(ctx context.Context, c orchestratorv1.SessionServiceClient, repo, envConfigRef, launchingUser string, r *report) bool {
	// 1. CreateSession (CRITICAL) — the §4.1 canonical create with the D56 two
	// keys (repo_id + env_config_ref) on behalf of launching_user. The returned
	// Session record is what keeps the reconciler from orphan-quarantining the VM.
	resp, err := c.CreateSession(ctx, &orchestratorv1.CreateSessionRequest{
		RepoId:        repo,
		EnvConfigRef:  envConfigRef,
		LaunchingUser: launchingUser,
	})
	if err != nil {
		r.add("CreateSession", false, "%v", err)
		return false
	}
	sess := resp.GetSession()
	uuid := sess.GetSessionUuid()
	if uuid == "" {
		r.add("CreateSession", false, "session record has empty session_uuid")
		return false
	}
	r.add("CreateSession", true, "uuid=%s index=%d tap=%s state=%s launching_user=%s",
		uuid, sess.GetHostSessionIndex(), sess.GetTapName(), sess.GetState().GetName(), sess.GetLaunchingUser())
	// The stable line the runner greps for the created session's uuid.
	fmt.Printf("E2E-ORCH-CREATE: session=%s index=%d tap=%s state=%s\n",
		uuid, sess.GetHostSessionIndex(), sess.GetTapName(), sess.GetState().GetName())

	// 2. Attach(WRITER) — mint the D79 transport-ambivalent handle for the writer
	// seat on the freshly-created session. Reported as a FINDING (does not gate);
	// the first endpoint's address + the auth token are the seat the :4242 drive
	// dials.
	att, err := c.Attach(ctx, &orchestratorv1.AttachRequest{
		SessionUuid: uuid,
		Role:        attachv1.Role_ROLE_WRITER,
	})
	if err != nil {
		r.add("Attach", false, "%v", err)
		return true // CreateSession is the critical verb; Attach is a FINDING.
	}
	h := att.GetHandle()
	endpoint := ""
	if eps := h.GetEndpoints(); len(eps) > 0 {
		endpoint = eps[0].GetAddress()
	}
	token := h.GetAuth().GetToken()
	ok := endpoint != "" && len(token) > 0 && h.GetRole() == attachv1.Role_ROLE_WRITER
	r.add("Attach", ok, "endpoint=%s token_len=%d role=%v expires_at=%d",
		endpoint, len(token), h.GetRole(), h.GetExpiresAt())
	// The stable line the runner greps for the writer-seat endpoint + token.
	fmt.Printf("E2E-ORCH-ATTACH: endpoint=%s token=%s\n", endpoint, string(token))

	return true
}

// drive runs the full lifecycle; returns true iff the CRITICAL verbs (Clone,
// Destroy) passed.
func drive(addr, session, hostID string, cloneOnly bool, bootWait time.Duration, r *report) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		r.add("dial", false, "%v", err)
		return false
	}
	defer conn.Close()
	c := hypervisorv1.NewHypervisorDriverServiceClient(conn)

	// 0. RecoverSessions — on a recovery-wired host this OPENS the recover-before-
	// serve latch (D66) so CloneFromImage may serve, AND reports any resident
	// sessions re-adopted after a host-agent restart (their never-recycled indices).
	if rec, err := c.RecoverSessions(ctx, &hypervisorv1.RecoverSessionsRequest{HostId: hostID}); err != nil {
		r.add("RecoverSessions", false, "%v", err)
	} else {
		idxs := make([]uint64, 0, len(rec.GetSessions()))
		for _, s := range rec.GetSessions() {
			idxs = append(idxs, s.GetHostSessionIndex())
		}
		r.add("RecoverSessions", true, "recovered=%d indices=%v", len(rec.GetSessions()), idxs)
	}

	// 1. GetCapabilities — honest libvirt flags.
	if caps, err := c.GetCapabilities(ctx, &hypervisorv1.GetCapabilitiesRequest{}); err != nil {
		r.add("GetCapabilities", false, "%v", err)
	} else {
		cp := caps.GetCapabilities()
		r.add("GetCapabilities", true, "instant_clone=%v disk_delta=%v migrate=%v",
			cp.GetSupportsInstantClone(), cp.GetSupportsDiskDeltaExport(), cp.GetSupportsMigrate())
	}

	// 2. CloneFromImage (CRITICAL) — real overlay-create.sh clone + virsh boot.
	cloneOK := false
	clone, err := c.CloneFromImage(ctx, &hypervisorv1.CloneFromImageRequest{
		Spec: &hypervisorv1.VmSpec{
			SessionUuid:         session,
			ImageId:             "m0-base",
			EntrypointConfigRef: "e2e-entrypoint",
			Material:            &hypervisorv1.SessionMaterial{CaBundleRef: "e2e-ca-ref"},
		},
	})
	if err != nil {
		r.add("CloneFromImage", false, "%v", err)
	} else {
		cloneOK = clone.GetOverlayPath() != ""
		r.add("CloneFromImage", cloneOK, "index=%d tap=%s overlay=%s guest_ip_family=%v",
			clone.GetHostSessionIndex(), clone.GetTapName(), clone.GetOverlayPath(), clone.GetGuestIp().GetFamily())
	}
	if !cloneOK {
		return false // nothing to drive a lifecycle on
	}

	// clone mode (the restart/recovery proof): stop after CloneFromImage and leave
	// the session RESIDENT so a host-agent restart can re-adopt it. The caller
	// kills + restarts the host-agent, then runs again to RecoverSessions it.
	if cloneOnly {
		return cloneOK
	}

	// 2b. IssueAttachHandle (D79, doc 15 §5.4) — mint a WRITER attach handle for the
	// freshly-cloned session's recorded binding. Asserts the M0 DIRECT endpoint
	// (guest IP + the fixed runtime attach port), a non-empty session-scoped auth
	// token, the faithful role, and a bounded expiry; then a second mint to prove the
	// idempotent-on-(session,role) re-issue (same endpoint + token + expiry).
	if resp, err := c.IssueAttachHandle(ctx, &hypervisorv1.IssueAttachHandleRequest{
		SessionUuid: session, Role: attachv1.Role_ROLE_WRITER,
	}); err != nil {
		r.add("IssueAttachHandle", false, "%v", err)
	} else {
		h := resp.GetHandle()
		eps := h.GetEndpoints()
		ok := len(eps) == 1 &&
			eps[0].GetTransport() == attachv1.EndpointTransport_ENDPOINT_TRANSPORT_DIRECT &&
			eps[0].GetAddress() != "" &&
			len(h.GetAuth().GetToken()) > 0 &&
			h.GetRole() == attachv1.Role_ROLE_WRITER &&
			h.GetExpiresAt() > 0
		addr := ""
		if len(eps) > 0 {
			addr = eps[0].GetAddress()
		}
		r.add("IssueAttachHandle", ok, "endpoint=%s token_len=%d role=%v expires_at=%d",
			addr, len(h.GetAuth().GetToken()), h.GetRole(), h.GetExpiresAt())

		if resp2, err := c.IssueAttachHandle(ctx, &hypervisorv1.IssueAttachHandleRequest{
			SessionUuid: session, Role: attachv1.Role_ROLE_WRITER,
		}); err != nil {
			r.add("IssueAttachHandle idemp", false, "%v", err)
		} else {
			h2 := resp2.GetHandle()
			same := len(h2.GetEndpoints()) == 1 &&
				h2.GetEndpoints()[0].GetAddress() == addr &&
				string(h2.GetAuth().GetToken()) == string(h.GetAuth().GetToken()) &&
				h2.GetExpiresAt() == h.GetExpiresAt()
			r.add("IssueAttachHandle idemp", same, "re-issued equivalent handle (endpoint+token+expiry stable)")
		}
	}

	// Let the domain reach RUNNING before the lifecycle verbs.
	time.Sleep(bootWait)

	// 3. Suspend (virsh suspend — the D77 freeze-in-place).
	if _, err := c.Suspend(ctx, &hypervisorv1.SuspendRequest{
		SessionUuid: session, Reason: hypervisorv1.SuspendReason_SUSPEND_REASON_USER,
	}); err != nil {
		r.add("Suspend", false, "%v", err)
	} else {
		r.add("Suspend", true, "virsh suspend OK")
	}

	// 4. Resume (virsh resume — the inverse of the D77 freeze).
	if _, err := c.Resume(ctx, &hypervisorv1.ResumeRequest{SessionUuid: session}); err != nil {
		r.add("Resume", false, "%v", err)
	} else {
		r.add("Resume", true, "virsh resume OK")
	}

	// 4b. Suspend/Resume idempotency round-trip (re-suspend, re-resume = no-op success).
	{
		_, e1 := c.Suspend(ctx, &hypervisorv1.SuspendRequest{SessionUuid: session, Reason: hypervisorv1.SuspendReason_SUSPEND_REASON_USER})
		_, e2 := c.Resume(ctx, &hypervisorv1.ResumeRequest{SessionUuid: session})
		if e1 != nil || e2 != nil {
			r.add("Suspend/Resume idemp", false, "re-suspend=%v re-resume=%v", e1, e2)
		} else {
			r.add("Suspend/Resume idemp", true, "round-trip converged")
		}
	}

	// 5. Snapshot (virsh external-snapshot) + idempotency.
	var snapRef string
	if snap, err := c.Snapshot(ctx, &hypervisorv1.SnapshotRequest{SessionUuid: session, Label: "e2e-snap"}); err != nil {
		r.add("Snapshot", false, "%v", err)
	} else {
		snapRef = snap.GetSnapshotRef()
		r.add("Snapshot", snapRef != "", "ref=%s", snapRef)
		if snap2, err := c.Snapshot(ctx, &hypervisorv1.SnapshotRequest{SessionUuid: session, Label: "e2e-snap"}); err != nil {
			r.add("Snapshot idemp", false, "%v", err)
		} else {
			r.add("Snapshot idemp", snap2.GetSnapshotRef() == snapRef, "ref2=%s", snap2.GetSnapshotRef())
		}
	}

	// 6. ExportDiskDelta (full overlay, since_snapshot_ref="") — reassemble the stream.
	if stream, err := c.ExportDiskDelta(ctx, &hypervisorv1.ExportDiskDeltaRequest{SessionUuid: session}); err != nil {
		r.add("ExportDiskDelta", false, "open: %v", err)
	} else {
		var total, frames uint64
		var rerr error
		for {
			frame, e := stream.Recv()
			if e == io.EOF {
				break
			}
			if e != nil {
				rerr = e
				break
			}
			total += uint64(len(frame.GetData()))
			frames++
		}
		if rerr != nil {
			r.add("ExportDiskDelta", false, "after %d frames/%d bytes: %v", frames, total, rerr)
		} else {
			r.add("ExportDiskDelta", true, "streamed %d bytes in %d frames (full overlay)", total, frames)
		}
	}

	// 6b. ExportDiskDelta incremental since the captured snapshot_ref (loop closure).
	if snapRef != "" {
		if stream, err := c.ExportDiskDelta(ctx, &hypervisorv1.ExportDiskDeltaRequest{SessionUuid: session, SinceSnapshotRef: snapRef}); err != nil {
			r.add("ExportDiskDelta incr", false, "open: %v", err)
		} else {
			var total uint64
			var rerr error
			for {
				frame, e := stream.Recv()
				if e == io.EOF {
					break
				}
				if e != nil {
					rerr = e
					break
				}
				total += uint64(len(frame.GetData()))
			}
			if rerr != nil {
				r.add("ExportDiskDelta incr", false, "%v", rerr)
			} else {
				r.add("ExportDiskDelta incr", true, "streamed %d bytes since %s", total, snapRef)
			}
		}
	}

	// 7. Destroy (CRITICAL) + idempotency.
	destroyOK := false
	if _, err := c.Destroy(ctx, &hypervisorv1.DestroyRequest{SessionUuid: session}); err != nil {
		r.add("Destroy", false, "%v", err)
	} else {
		destroyOK = true
		r.add("Destroy", true, "§4.2 teardown OK")
		if _, err := c.Destroy(ctx, &hypervisorv1.DestroyRequest{SessionUuid: session}); err != nil {
			r.add("Destroy idemp", false, "%v", err)
		} else {
			r.add("Destroy idemp", true, "re-destroy converged")
		}
	}

	return cloneOK && destroyOK
}
