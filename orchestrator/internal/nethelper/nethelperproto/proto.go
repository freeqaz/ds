// SPDX-License-Identifier: Apache-2.0

// Package nethelperproto pins the TRUST-BOUNDARY protocol between the
// unprivileged host-agent and the setcap'd `ds-nethelper` privileged helper
// (the ROOT-HELPER model for the Arch-1 bare-metal dogfood host — NOT the D66
// netns production endpoint).
//
// SHAPE OF THE BOUNDARY. The helper is a STATELESS per-operation binary: the
// host-agent forks it once per privileged action, the helper validates its
// inputs, performs exactly ONE action from a CLOSED verb vocabulary, emits ONE
// machine-readable Result line on stdout plus ONE audit line on stderr, and
// exits. There is NO long-lived privileged process, NO socket, NO generic
// "apply this ruleset" verb — the vocabulary below is the exact CAP_NET_ADMIN
// subset of the ds-nft write edge (orchestrator/internal/nftbridge writeedge.go,
// doc 14 §6), nothing more. The capability lives on the helper binary
// (`setcap cap_net_admin+eip ds-nethelper` — effective + inheritable, so the
// backend's exec'd ip/nft children are not stranded; see the README), never on
// the agent.
//
// WIRE. op = argv[1] (exactly one argument, no flags — the op is visible in
// exec auditing); params = ONE JSON object on stdin, capped at MaxParamsBytes,
// unknown fields REJECTED; response = ONE JSON Result line on stdout; outcome
// also lands in the process exit code (Exit*) so a caller that cannot parse
// stdout still gets a fail-closed signal. Both sides compile this ONE package,
// so the grammar cannot drift (final home:
// orchestrator/internal/nethelper/nethelperproto).
//
// VALIDATION IS THE HELPER'S JOB. The helper never trusts the caller: every
// param is re-validated here on the privileged side of the boundary
// (Validate*), including the tap-name↔index cross-check (the binding
// three-keys-agree discipline, doc 14 §4) and the owner-uid==caller-uid rule
// (the agent may only mint taps owned by itself; setcap does not change uids,
// so os.Getuid() in the helper IS the invoking uid).
package nethelperproto

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// ProtocolVersion is echoed in every Result so a skewed agent/helper pair
// fails loudly instead of misparsing (the client rejects a version it does
// not speak).
const ProtocolVersion = 1

// The closed verb vocabulary — exactly the CAP_NET_ADMIN subset of the ds-nft
// write edge (writeedge.go), plus the read-only Probe. There is deliberately
// NO generic ruleset-apply verb: per-session policy (allow-set contents) flows
// through ds-dnsgate, the OTHER ds-nft linker — the helper only ever creates/
// destroys the per-session admit SURFACE and the tap netdev.
const (
	// OpProbe is the read-only self-check: reports the protocol version,
	// whether the privileged backend is linked into this build (Built), and
	// whether CAP_NET_ADMIN is effective on this process. It performs NO
	// privileged action; the agent's bring-up/readiness composition calls it.
	OpProbe = "probe"
	// OpCreateTap programs the per-session `dstap-<idx>` routed tap
	// (ds_nft_create_tap: netdev + 10.77.<idx>.0/31 gateway + /32 route +
	// optional static neigh). Idempotent.
	OpCreateTap = "create-tap"
	// OpDeleteTap removes the tap netdev (ds_nft_delete_tap). Idempotent
	// (absent tap = success). The AGENT owns the destroy decision (§4.2
	// ordering / create rollback); the helper only executes it.
	OpDeleteTap = "delete-tap"
	// OpInstantiateSession creates the EMPTY per-session allow4_<idx>/
	// allow6_<idx> sets in `inet ds_filter` (ds_nft_instantiate_session —
	// admit SURFACE only, no floor). Idempotent.
	OpInstantiateSession = "instantiate-session"
	// OpFlushSession runs the unconditional NFT-6 conntrack-by-mark flush
	// (ds_nft_flush_session).
	OpFlushSession = "flush-session"
	// OpTeardownSession removes the per-session allow-sets
	// (ds_nft_teardown_session — the named-set half of NFT-6; a full teardown
	// is flush THEN teardown THEN delete-tap).
	OpTeardownSession = "teardown-session"
	// OpTablePresent is the second READ-ONLY verb (with OpProbe): it reports
	// whether one `inet <table>` exists, via a read-only `nft list table`.
	// It mutates NOTHING and does not touch the ds-nft backend at all.
	//
	// WHY IT HAS TO LIVE HERE. The agent's boundary-readiness probe verifies the
	// three floor tables are present before admitting a session, and it did that
	// by exec'ing `nft list` IN-PROCESS. That worked only because the agent was
	// root. Under D148 the agent is unprivileged, and `nft list` needs
	// CAP_NET_ADMIN just to initialise its netlink cache ("Operation not
	// permitted (you must be root)"), so the probe would fail closed and refuse
	// EVERY CreateSession for a floor that is actually installed — with the
	// helper's own probe passing, which makes it maddening to diagnose. The
	// capability lives on the helper, so the read has to come with it.
	//
	// This does NOT widen the write surface: it is not a ruleset-apply verb (see
	// the note above), it takes no ruleset, and it cannot create or destroy
	// anything. It stays out of the five-verb `backend` interface — which is
	// signature-pinned to the nftbridge WRITE edge — and is answered directly in
	// the dispatcher beside OpProbe.
	OpTablePresent = "table-present"
)

// Ops lists every valid op (the dispatch whitelist). Returned fresh so a
// caller cannot mutate the canonical set.
func Ops() []string {
	return []string{OpProbe, OpCreateTap, OpDeleteTap, OpInstantiateSession, OpFlushSession, OpTeardownSession, OpTablePresent}
}

// Exit codes — the parse-free half of the outcome signal. A caller that lost
// stdout still fails closed on a non-zero exit.
const (
	// ExitOK: the one action succeeded.
	ExitOK = 0
	// ExitValidation: the request was REJECTED at the trust boundary (bad op,
	// bad params, uid rule, cross-check failure). Nothing privileged ran.
	ExitValidation = 2
	// ExitBackend: validation passed but the privileged backend (ds-nft)
	// failed; Result.Message carries ds_nft_last_error(). Kernel state may be
	// partial — the agent drives the idempotent teardown trio to converge.
	ExitBackend = 3
	// ExitNotBuilt: this helper build has no privileged backend linked (the
	// cgo-free default build; mirrors nftbridge writeedge_stub.go). Nothing
	// privileged ran.
	ExitNotBuilt = 4
	// ExitProtocol: malformed stdin (over-cap, not one JSON object, unknown
	// fields) or an internal fault. Nothing privileged ran.
	ExitProtocol = 5
)

// Result codes (Result.Code) — stable machine strings mirroring the exit map.
const (
	CodeOK         = "OK"
	CodeValidation = "EARG"
	CodeBackend    = "EBACKEND"
	CodeNotBuilt   = "ENOTBUILT"
	CodeProtocol   = "EPROTO"
)

// MaxParamsBytes caps the stdin params object. Every request here is a
// handful of scalar fields; 4 KiB bounds a malformed/hostile writer without
// ever constraining a legitimate one.
const MaxParamsBytes = 4096

// MaxResultBytes caps the stdout Result line the client will read (the
// symmetric bound on the response leg).
const MaxResultBytes = 16384

// tapNameMaxLen is the IFNAMSIZ-1 ceiling a Linux interface name must fit.
const tapNameMaxLen = 15

// MaxHostSessionIndex is the never-recycled host session index ceiling the
// mark space admits (the 14-bit ct-mark residue, D76; seams.go relies on the
// same bound for its lossless uint32 narrowing).
const MaxHostSessionIndex = 1<<14 - 1

// MaxRoutedSessionIndex is the TIGHTER create-tap ceiling: the routed
// addressing puts the index in the third octet of 10.77.<idx>.0/31
// (ds_nft.h), so a tap can only be created for an index that fits one octet.
// Flush/teardown keep the wider mark-space bound (they must be able to tear
// down anything that could ever have carried a mark).
const MaxRoutedSessionIndex = 255

// tapNameRe pins the `dstap-<idx>` grammar (doc 14 §4: the authoritative join
// key). No leading zeros, so exactly one spelling exists per index and the
// suffix↔index cross-check is byte-exact.
var tapNameRe = regexp.MustCompile(`^dstap-(0|[1-9][0-9]{0,4})$`)

// macRe pins the guest MAC grammar: six lowercase colon-separated hex octets.
// Lowercase-only keeps one canonical spelling crossing the trust boundary
// (the agent lowercases before invoking).
var macRe = regexp.MustCompile(`^([0-9a-f]{2}:){5}[0-9a-f]{2}$`)

// tableNameRe bounds OpTablePresent's one parameter to an nft identifier.
// Command injection is not the risk being managed here — the helper execs nft
// via argv, never a shell — this simply refuses input that could not name a real
// table, so a malformed request is a validation rejection rather than a confusing
// "table absent" verdict.
var tableNameRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

// TablePresentParams is OpTablePresent's request body.
type TablePresentParams struct {
	// Table is the `inet` family table name to test for existence.
	Table string `json:"table"`
}

// ValidateTablePresent gates OpTablePresent at the trust boundary. There is no
// uid rule here as there is on CreateTap: the verb is read-only and reveals only
// whether a table exists, which any caller allowed to exec the helper at all
// (0750 root:<agent-group>) can already learn from the bring-up script's own
// root-run `nft list` preflight.
func ValidateTablePresent(p TablePresentParams) error {
	if p.Table == "" {
		return fmt.Errorf("table is empty")
	}
	if !tableNameRe.MatchString(p.Table) {
		return fmt.Errorf("table %q is not a valid nft table identifier", p.Table)
	}
	return nil
}

// CreateTapParams is the stdin object for OpCreateTap.
type CreateTapParams struct {
	// TapName is `dstap-<idx>` — must cross-check against HostSessionIndex.
	TapName string `json:"tap_name"`
	// OwnerUID is the uid the tap is created owned by (`ip tuntap add ...
	// user <uid>`). The helper REQUIRES OwnerUID == the invoking uid: the
	// agent may only mint taps it can itself open (the qemu:///session
	// posture), and never a root-owned or other-user tap.
	OwnerUID uint32 `json:"owner_uid"`
	// HostSessionIndex is the never-recycled host-local index (D66); the
	// routed /31 authority for this tap. Must be ≤ MaxRoutedSessionIndex.
	HostSessionIndex uint32 `json:"host_session_index"`
	// GuestMAC is the OPTIONAL static-neigh lladdr; empty ⇒ the neigh leg is
	// skipped backend-side (a recoverable gap, never a failure).
	GuestMAC string `json:"guest_mac,omitempty"`
}

// SessionParams is the stdin object for the four (tap, idx)-keyed verbs
// (delete-tap ignores HostSessionIndex kernel-side but still cross-checks it
// against the name, so a caller can never delete a tap under a mismatched
// identity).
type SessionParams struct {
	TapName          string `json:"tap_name"`
	HostSessionIndex uint32 `json:"host_session_index"`
}

// Result is the ONE stdout line the helper emits.
type Result struct {
	// V is ProtocolVersion; the client refuses a version it does not speak.
	V int `json:"v"`
	// Op echoes the executed op; the client cross-checks it against what it
	// asked for (a mismatched echo is a protocol fault, fail-closed).
	Op string `json:"op"`
	// OK is true iff the one action succeeded.
	OK bool `json:"ok"`
	// Code is the stable machine outcome (Code*).
	Code string `json:"code"`
	// Message is the human/audit detail (e.g. ds_nft_last_error()); never a
	// secret (nothing on this boundary is one).
	Message string `json:"message,omitempty"`
	// Built is populated by OpProbe only: whether the privileged ds-nft
	// backend is linked into this build (the stub reports false).
	Built bool `json:"built,omitempty"`
	// The Cap*/Ambient* fields are populated by OpProbe only — the
	// CAP_NET_ADMIN posture that distinguishes the pinned `+eip` setcap from a
	// naive `+ep` half-configuration AT BRING-UP (see cmd/ds-nethelper
	// caps.go). ds-nft execs `ip`/`nft`, and file capabilities do NOT survive
	// execve, so `+ep` alone strands every child unprivileged; the live
	// backend raises CAP_NET_ADMIN into the AMBIENT set (scoped to its call)
	// so children inherit it, which needs the capability permitted AND
	// inheritable. Hence three answers, not one:
	//
	//   CapNetAdminEffective   — in the EFFECTIVE set (`+e` landed: setcap ran
	//                            on the installed binary at all).
	//   CapNetAdminInheritable — in the INHERITABLE set (`+i` landed): the
	//                            precondition that catches the `+ep`-only host,
	//                            effective-green yet child-stranded.
	//   AmbientRaiseOK         — an ambient raise is EXPECTED to succeed
	//                            (permitted ∧ inheritable, the kernel
	//                            precondition), PREDICTED read-only, never
	//                            trial-raised. The field the live-path
	//                            readiness gate keys on.
	//
	// All false ⇒ setcap did not land / not a Linux host.
	CapNetAdminEffective   bool `json:"cap_net_admin_effective,omitempty"`
	CapNetAdminInheritable bool `json:"cap_net_admin_inheritable,omitempty"`
	AmbientRaiseOK         bool `json:"ambient_raise_ok,omitempty"`
	// CapNetAdmin is the retained coarse EFFECTIVE-set alias
	// (== CapNetAdminEffective) so an older agent reading only this legacy
	// field still sees whether setcap landed. New readiness keys on
	// ProbeReady()/AmbientRaiseOK.
	CapNetAdmin bool `json:"cap_net_admin,omitempty"`
}

// ProbeReady reports whether a probe Result describes a host on which the
// privileged edge can actually run: the backend is linked AND CAP_NET_ADMIN is
// present both effective (the helper itself can act) and ambient-raisable (so
// the ds-nft-exec'd `ip`/`nft` children are not stranded — permitted ∧
// inheritable). This is the exact predicate the LANDED readiness re-key keys on
// (D148 — cmd/host-agent/nethelperseams.go verifyHelperReady, FATAL under
// DS_HOSTAGENT_LIVE when a helper path is configured, plus the per-admission
// helperProbeReadiness fold). AmbientRaiseOK already implies inheritable, so a
// `+ep`-only host (effective-green, inheritable-false) fails this gate.
func (r Result) ProbeReady() bool {
	return r.Built && r.CapNetAdminEffective && r.AmbientRaiseOK
}

// ValidateOp rejects anything outside the closed verb vocabulary.
func ValidateOp(op string) error {
	for _, v := range Ops() {
		if op == v {
			return nil
		}
	}
	return fmt.Errorf("unknown op %q (valid: %s)", op, strings.Join(Ops(), " "))
}

// validateTapIdentity is the shared (tap_name, host_session_index) gate:
// grammar, IFNAMSIZ, index ceiling, and the byte-exact suffix↔index
// cross-check (the helper re-derives the expected name; it never trusts the
// caller's pairing — doc 14 §4 three-keys-agree at the privilege boundary).
func validateTapIdentity(tapName string, idx uint32, maxIdx uint32) error {
	if tapName == "" {
		return fmt.Errorf("tap_name is empty")
	}
	if len(tapName) > tapNameMaxLen {
		return fmt.Errorf("tap_name %q exceeds IFNAMSIZ ceiling (%d chars)", tapName, tapNameMaxLen)
	}
	if !tapNameRe.MatchString(tapName) {
		return fmt.Errorf("tap_name %q does not match dstap-<idx>", tapName)
	}
	if idx > maxIdx {
		return fmt.Errorf("host_session_index %d exceeds ceiling %d", idx, maxIdx)
	}
	if want := "dstap-" + strconv.FormatUint(uint64(idx), 10); tapName != want {
		return fmt.Errorf("tap_name %q disagrees with host_session_index %d (want %q)", tapName, idx, want)
	}
	return nil
}

// ValidateCreateTap gates OpCreateTap params at the trust boundary.
// callerUID is the helper's own os.Getuid() — the invoking identity.
func ValidateCreateTap(p CreateTapParams, callerUID uint32) error {
	if err := validateTapIdentity(p.TapName, p.HostSessionIndex, MaxRoutedSessionIndex); err != nil {
		return err
	}
	if p.OwnerUID == 0 {
		return fmt.Errorf("owner_uid 0 (root) is never a valid tap owner")
	}
	if p.OwnerUID != callerUID {
		return fmt.Errorf("owner_uid %d is not the invoking uid %d (the agent may only mint taps it owns)", p.OwnerUID, callerUID)
	}
	if p.GuestMAC != "" {
		if !macRe.MatchString(p.GuestMAC) {
			return fmt.Errorf("guest_mac %q is not six lowercase colon-separated hex octets", p.GuestMAC)
		}
		if p.GuestMAC == "00:00:00:00:00:00" {
			return fmt.Errorf("guest_mac all-zero is not a valid unicast lladdr")
		}
		// Multicast bit (LSB of the first octet) set ⇒ never a valid guest
		// unicast lladdr for the static-neigh leg.
		var first byte
		if _, err := fmt.Sscanf(p.GuestMAC[:2], "%02x", &first); err != nil {
			return fmt.Errorf("guest_mac %q first octet unparseable", p.GuestMAC)
		}
		if first&0x01 != 0 {
			return fmt.Errorf("guest_mac %q is multicast (I/G bit set), not a unicast lladdr", p.GuestMAC)
		}
	}
	return nil
}

// ValidateSession gates the (tap, idx)-keyed verbs. The teardown-side verbs
// keep the WIDER mark-space ceiling so anything that could ever have existed
// can be torn down.
func ValidateSession(p SessionParams) error {
	return validateTapIdentity(p.TapName, p.HostSessionIndex, MaxHostSessionIndex)
}
