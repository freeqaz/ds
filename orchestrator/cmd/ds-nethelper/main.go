// SPDX-License-Identifier: Apache-2.0

// ds-nethelper — the STATELESS per-operation privileged helper for the
// bare-metal dogfood host (ROOT-HELPER privilege model, maintainer ruling 2026-07-09).
//
// One invocation = one validated privileged action = one audit line = exit.
//
//	ds-nethelper <op>        # op ∈ nethelperproto.Ops(); params: ONE JSON
//	                         # object on stdin (≤ MaxParamsBytes, unknown
//	                         # fields rejected); result: ONE JSON line on
//	                         # stdout; audit: ONE JSON line on stderr.
//
// PRIVILEGE. The binary carries `setcap cap_net_admin+eip` (effective +
// inheritable — NOT +ep; the backend execs ip/nft and file caps cross execve
// only via the inheritable/ambient path, raised per-call by the live backend;
// see caps.go and the README "Capability Propagation"); the invoking
// host-agent carries NOTHING. setcap does not change uids, so os.Getuid()
// here is the caller's uid — the owner-uid==caller rule in the proto package
// rides that. Filesystem perms are the authn boundary (install 0750,
// root:<agent-group>; scripts/install-ds-nethelper.sh).
//
// NO LONG-LIVED PRIVILEGED PROCESS, NO GENERIC VERB. The vocabulary is the
// closed five-verb ds-nft write subset + the read-only probe; a request that
// fails validation exits BEFORE any privileged path is reachable.
//
// ENVIRONMENT. The environment is NOT trusted: PATH is pinned to the fixed
// sbin/bin set before the backend runs (ds-nft execs `ip`/`nft` — mechanism
// only), and no other variable is read.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/nethelper/nethelperproto"
)

// pinnedPATH is the fixed exec search path the backend (ds-nft's ip/nft
// shell-outs) runs under — never the caller's PATH.
const pinnedPATH = "/usr/sbin:/usr/bin:/sbin:/bin"

// auditRecord is the ONE stderr line per invocation — every privileged action
// is attributable: who (uid/pid/ppid), what (op + validated identity keys),
// outcome, duration. Params carry no secrets on this boundary.
type auditRecord struct {
	TS         string `json:"ts"`
	Op         string `json:"op"`
	UID        int    `json:"uid"`
	PID        int    `json:"pid"`
	PPID       int    `json:"ppid"`
	TapName    string `json:"tap_name,omitempty"`
	Index      uint32 `json:"host_session_index,omitempty"`
	OwnerUID   uint32 `json:"owner_uid,omitempty"`
	GuestMAC   string `json:"guest_mac,omitempty"`
	Code       string `json:"code"`
	Message    string `json:"message,omitempty"`
	DurationMS int64  `json:"duration_ms"`
}

func main() {
	// Full env scrub BEFORE anything can shell out: the helper inherits the
	// (unprivileged) caller's environment verbatim, and its ip/nft children are
	// NOT in glibc secure-execution mode (setcap is not setuid), so nothing
	// would otherwise strip a hostile variable the caller planted. Clear
	// everything, then pin only PATH. (README "Env Scrub".)
	os.Clearenv()
	_ = os.Setenv("PATH", pinnedPATH)
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, newBackend(), os.Getuid()))
}

// run is the testable core: argv (op only), capped stdin params, injected
// backend + caller uid. It returns the process exit code and writes exactly
// one Result line to stdout and one audit line to stderr.
func run(argv []string, stdin io.Reader, stdout, stderr io.Writer, be backend, callerUID int) int {
	start := time.Now()
	rec := auditRecord{
		TS:   start.UTC().Format(time.RFC3339Nano),
		UID:  callerUID,
		PID:  os.Getpid(),
		PPID: os.Getppid(),
	}

	finish := func(res nethelperproto.Result, exit int) int {
		res.V = nethelperproto.ProtocolVersion
		rec.Op = res.Op
		rec.Code = res.Code
		rec.Message = res.Message
		rec.DurationMS = time.Since(start).Milliseconds()
		// Result first (the machine channel), audit second.
		enc := json.NewEncoder(stdout)
		_ = enc.Encode(res)
		aenc := json.NewEncoder(stderr)
		_ = aenc.Encode(rec)
		return exit
	}

	// Exactly one positional op, no flags — anything else is a usage
	// rejection before any stdin byte is read.
	if len(argv) != 1 {
		return finish(nethelperproto.Result{
			Op:      "",
			OK:      false,
			Code:    nethelperproto.CodeValidation,
			Message: "usage: ds-nethelper <op> (exactly one op; params on stdin; ops: " + strings.Join(nethelperproto.Ops(), " ") + ")",
		}, nethelperproto.ExitValidation)
	}
	op := argv[0]
	if err := nethelperproto.ValidateOp(op); err != nil {
		return finish(nethelperproto.Result{
			Op: op, OK: false, Code: nethelperproto.CodeValidation, Message: err.Error(),
		}, nethelperproto.ExitValidation)
	}

	// Probe is read-only: no stdin, no privileged path. It reports the
	// effective, inheritable, and ambient-raisable CAP_NET_ADMIN posture so a
	// +ep-only install (helper effective-green, ip/nft children stranded) is
	// caught at bring-up rather than at the first live op (README "Capability
	// Propagation"). probeCaps() never mutates capability state.
	if op == nethelperproto.OpProbe {
		cs := probeCaps()
		return finish(nethelperproto.Result{
			Op:                     op,
			OK:                     true,
			Code:                   nethelperproto.CodeOK,
			Built:                  built,
			CapNetAdminEffective:   cs.Effective,
			CapNetAdminInheritable: cs.Inheritable,
			AmbientRaiseOK:         cs.AmbientRaiseOK,
			CapNetAdmin:            cs.Effective, // legacy alias
		}, nethelperproto.ExitOK)
	}

	// Decode the ONE params object: capped, strict (unknown fields rejected),
	// and nothing may trail it.
	dec := json.NewDecoder(io.LimitReader(stdin, nethelperproto.MaxParamsBytes+1))
	dec.DisallowUnknownFields()

	protoFault := func(msg string) int {
		return finish(nethelperproto.Result{
			Op: op, OK: false, Code: nethelperproto.CodeProtocol, Message: msg,
		}, nethelperproto.ExitProtocol)
	}
	validationFault := func(err error) int {
		return finish(nethelperproto.Result{
			Op: op, OK: false, Code: nethelperproto.CodeValidation, Message: err.Error(),
		}, nethelperproto.ExitValidation)
	}
	outcome := func(err error) int {
		switch {
		case err == nil:
			return finish(nethelperproto.Result{Op: op, OK: true, Code: nethelperproto.CodeOK}, nethelperproto.ExitOK)
		case err == errNotBuilt:
			return finish(nethelperproto.Result{
				Op: op, OK: false, Code: nethelperproto.CodeNotBuilt, Message: err.Error(),
			}, nethelperproto.ExitNotBuilt)
		default:
			return finish(nethelperproto.Result{
				Op: op, OK: false, Code: nethelperproto.CodeBackend, Message: err.Error(),
			}, nethelperproto.ExitBackend)
		}
	}

	switch op {
	// table-present is the other READ-ONLY verb (with probe). It answers the
	// agent's boundary-readiness question — "is the floor table installed?" —
	// using the HELPER's CAP_NET_ADMIN, because `nft list` needs that capability
	// merely to initialise its netlink cache and the D148 agent is unprivileged.
	// It mutates nothing and never touches the ds-nft backend, so it is handled
	// here and is deliberately absent from the five-verb `backend` interface,
	// which stays signature-pinned to the nftbridge WRITE edge.
	case nethelperproto.OpTablePresent:
		var p nethelperproto.TablePresentParams
		if err := decodeOne(dec, &p); err != nil {
			return protoFault(err.Error())
		}
		if err := nethelperproto.ValidateTablePresent(p); err != nil {
			return validationFault(err)
		}
		// Absent table AND nft mechanism fault both return non-OK: the agent's
		// readiness verdict is fail-closed either way, and the reason travels in
		// Message so "floor missing" and "nft unusable" stay distinguishable in
		// the agent log instead of collapsing to a bare exit code.
		if err := listTableInet(p.Table); err != nil {
			return finish(nethelperproto.Result{
				Op: op, OK: false, Code: nethelperproto.CodeBackend,
				Message: fmt.Sprintf("table inet %s not present: %v", p.Table, err),
			}, nethelperproto.ExitBackend)
		}
		return finish(nethelperproto.Result{
			Op: op, OK: true, Code: nethelperproto.CodeOK,
		}, nethelperproto.ExitOK)
	case nethelperproto.OpCreateTap:
		var p nethelperproto.CreateTapParams
		if err := decodeOne(dec, &p); err != nil {
			return protoFault(err.Error())
		}
		rec.TapName, rec.Index, rec.OwnerUID, rec.GuestMAC = p.TapName, p.HostSessionIndex, p.OwnerUID, p.GuestMAC
		if err := nethelperproto.ValidateCreateTap(p, uint32(callerUID)); err != nil {
			return validationFault(err)
		}
		// hasUID is always true here: ValidateCreateTap has already required a
		// non-zero owner_uid == the invoking uid, so the tap is always owned
		// (the qemu:///session posture). The bool rides the nftbridge signature
		// pin (backend.go) so the deferred live pass-through stays field-exact.
		return outcome(be.CreateTap(p.TapName, p.OwnerUID, true, p.HostSessionIndex, p.GuestMAC))
	default:
		// The four (tap, idx)-keyed verbs share one params shape + gate.
		var p nethelperproto.SessionParams
		if err := decodeOne(dec, &p); err != nil {
			return protoFault(err.Error())
		}
		rec.TapName, rec.Index = p.TapName, p.HostSessionIndex
		if err := nethelperproto.ValidateSession(p); err != nil {
			return validationFault(err)
		}
		switch op {
		case nethelperproto.OpDeleteTap:
			return outcome(be.DeleteTap(p.TapName))
		case nethelperproto.OpInstantiateSession:
			return outcome(be.InstantiateSession(p.TapName, p.HostSessionIndex))
		case nethelperproto.OpFlushSession:
			return outcome(be.FlushSession(p.TapName, p.HostSessionIndex))
		case nethelperproto.OpTeardownSession:
			return outcome(be.TeardownSession(p.TapName, p.HostSessionIndex))
		}
		// Unreachable: ValidateOp admitted only the vocabulary above.
		return protoFault(fmt.Sprintf("internal: op %q validated but not dispatched", op))
	}
}

// decodeOne decodes exactly ONE JSON object and requires clean EOF after it —
// trailing bytes (a second object, shell junk) are a protocol fault.
func decodeOne(dec *json.Decoder, v any) error {
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("params: %v", err)
	}
	if dec.More() {
		return fmt.Errorf("params: trailing data after the one params object")
	}
	return nil
}

// (CAP_NET_ADMIN capability introspection for OpProbe lives in caps.go /
// caps_linux.go — probeCaps() reads the effective/inheritable/permitted sets
// and predicts the ambient-raise precondition, side-effect free.)
