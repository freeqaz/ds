// SPDX-License-Identifier: Apache-2.0

// entrypointconfig — the host-agent's runtime-aware EntrypointConfig builder (the
// gap-1 of the M0 host↔guest entrypoint path; D38, doc 15 §4.1 step 8). The
// orchestrator stays runtime-IGNORANT: it passes only the opaque
// entrypoint-config ref in VmSpec and never learns runtime internals. The HOST
// AGENT — which alone knows the GuestIP, the per-session overlay/event-socket
// paths, the injected ca_bundle_path, and the egress-gateway address — resolves
// that ref into the STRUCTURED runtimev1.EntrypointConfig this builder assembles,
// then marshals it to the config.pb payload the in-guest ds-entrypoint reads
// (vm/entrypoint, OQ-C: the delivery encoding is free; this builder produces the
// canonical binary-serialized message).
//
// REFERENCES, NEVER MATERIAL (D17/D39/D8): the EgressWiring carries the
// ca_bundle PATH and proxy addresses only; the session token is fetched in-guest
// from the D22 shim at session_token_endpoint, never carried here. The
// role_overlay_ref rides as OPAQUE bytes pass-through (the EntrypointConfigSource
// fetched them by ref) — the orchestrator never inspects them, and this builder
// only carries them onto the wire.
//
// STDLIB-ONLY + offline (doc.go / seams.go posture): the build is a pure
// data→data assembly + a proto.Marshal; it touches no KVM/libvirt/exec/network.
// The same build runs in the sandbox / CI / every unit test. The D80 cross-tree
// rule is honored: this NON-test code crosses trees ONLY via proto/gen/go
// (runtimev1 + boundaryv1), never vm/entrypoint.
//
// IN-TREE VALIDITY INVARIANTS: the guest-side ds-entrypoint TOTALLY validates the
// config it loads (vm/entrypoint/config.go validate()); this builder asserts the
// SAME structural invariants host-side (validateEntrypointConfig below) so a
// malformed config is rejected at the source, before boot — replicated in-tree
// (a non-empty launch command, an ABSOLUTE event-socket path, an absolute
// ca_bundle_path when named, and no credential material on any reference field),
// NEVER by importing vm/entrypoint (D80).

package libvirt

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"google.golang.org/protobuf/proto"

	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
	runtimev1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/runtime/v1"
)

// EntrypointBuildInput is the host-side input to the EntrypointConfig builder —
// carried as plain DATA (the orchestrator module is stdlib-only; the proto
// message is assembled HERE, host-side, from these resolved facts). It pairs the
// session identity + the recorded Binding (the host-side attachment artifact,
// binding.go) with the host-agent-resolved launch surface and the egress/attach
// wiring the host alone knows. Every reference field is a PATH/ADDRESS, never
// credential material (D17/D39); the role overlay rides as opaque bytes.
type EntrypointBuildInput struct {
	// SessionUUID is the global session identity — the join key the guest echoes
	// back through EntrypointService so the host agent joins the readiness/exit
	// report to the authoritative session record (boundaryv1.SessionRef.session_uuid).
	SessionUUID string
	// HostID is the host the session is placed on (boundaryv1.SessionRef.host_id) —
	// a host bring-up fact (doc 13 §4) the orchestrator placed the session on, never
	// derived inside this module.
	HostID string

	// Binding is the recorded three-keys-agree binding (D44/D66): it supplies the
	// never-recycled HostSessionIndex and the `dstap-<idx>` TapName that complete
	// the SessionRef join quartet. The GuestIP is carried for callers that derive
	// the attach endpoint from it; this builder reads only the join-key fields.
	Binding Binding

	// Launch is the exec/supervise surface the host agent resolved from the D7 env
	// config (the pinned CC command + args/env/working_dir). Runtime-IGNORANT: a
	// generic process-launch spec, never a CC-specific field (D20/D49).
	Launch LaunchSpecInput

	// Stdio is how the host agent wires the runtime's stdio at launch (the additive
	// serpent-CLI terminal-MVP rider; runtimev1.StdioDisposition). The zero value
	// (UNSPECIFIED) MUST be byte-identical to today (== PIPES, the headless path); PTY
	// selects the terminal launch mode. The EntrypointProducer derives this from the
	// resolved SessionMode (sessionmode.go); a direct BuildEntrypointConfig caller may
	// leave it zero for the historical structured behavior.
	Stdio runtimev1.StdioDisposition

	// InitialWindow is the pty window size seeded at launch (runtimev1.TerminalSize),
	// so a PTY runtime paints at the right geometry from frame 1 (§A7 / G9). Nil = the
	// host agent's default; only meaningful when Stdio is PTY. The producer seeds it
	// for a terminal session; a structured session leaves it nil (byte-identical).
	InitialWindow *runtimev1.TerminalSize

	// Posture is the runtime-facing permission disposition (doc 13 §2). An INPUT to
	// the runtime, never a guardrail (the boundary is the authority, D42). A
	// resolved config MUST set a concrete posture; UNSPECIFIED is rejected.
	Posture runtimev1.PermissionPosture

	// Budget is the runtime-facing self-limiting envelope (doc 15 §8, D81). Zero
	// values mean "no runtime-facing ceiling"; the authoritative meter is
	// session-record-derived (doc 15 §5.6), never these numbers.
	Budget BudgetInput

	// EventSocketPath is the guest-local UDS the runtime wrapper emits attach events
	// onto, terminated host-side at the host agent (AttachWiring, D38). MUST be an
	// ABSOLUTE guest-filesystem path.
	EventSocketPath string

	// Egress is the runtime's view of the TLS-terminating egress gateway + the
	// injected per-session CA — REFERENCES ONLY (addresses + a bundle PATH), never
	// material (D17/D39/D8).
	Egress EgressWiringInput

	// RoleOverlayRef is the OPAQUE role-axis runtime overlay (OQ-A), pass-through
	// from the EntrypointConfigSource fetch. The orchestrator NEVER inspects it; an
	// empty value = no overlay (the role's `runtime: null`).
	RoleOverlayRef []byte

	// SessionTokenEndpoint is WHERE the guest reaches the host-local D22 shim to
	// fetch its short-lived session token at boot. An ADDRESS/REFERENCE only, NEVER
	// the token VALUE (D39). Empty when the host folds token delivery elsewhere.
	SessionTokenEndpoint string
}

// LaunchSpecInput is the host-resolved exec/supervise surface (runtimev1.LaunchSpec).
type LaunchSpecInput struct {
	// Command is the entrypoint program to exec inside the guest (absolute path or
	// PATH-resolved name). REQUIRED — there is nothing to supervise without it.
	Command string
	// Args are the entrypoint arguments, in order. Empty for a bare command.
	Args []string
	// Env are additional KEY=VALUE environment entries (non-secret, D7/D39). NEVER
	// credential material; each entry MUST be KEY=VALUE with no NUL byte.
	Env []string
	// WorkingDir is where the runtime execs (e.g. the repo clone root). Empty = the
	// runtime's default.
	WorkingDir string
}

// BudgetInput is the host-resolved runtime-facing budget envelope (runtimev1.Budget).
type BudgetInput struct {
	// WallClockSeconds is the runtime's wall-clock ceiling, seconds (0 = no
	// runtime-facing ceiling).
	WallClockSeconds uint64
	// TokenMicroUnits is a token/cost ceiling the wrapper MAY surface, in
	// implementation-defined micro-units (0 = unset).
	TokenMicroUnits uint64
}

// EgressWiringInput is the host-resolved egress-gateway view (runtimev1.EgressWiring)
// — references only, never material (D17/D39/D8).
type EgressWiringInput struct {
	// HTTPProxy is the host:port the runtime sets HTTP_PROXY to (the ds-tlsproxy
	// egress gateway). Address only.
	HTTPProxy string
	// HTTPSProxy is the host:port the runtime sets HTTPS_PROXY to (the same gateway).
	HTTPSProxy string
	// NoProxy is the NO_PROXY list — host-local aliases reached WITHOUT the egress
	// boundary (the git mirror / package cache).
	NoProxy []string
	// CABundlePath is the guest-filesystem PATH to the already-injected per-session
	// interception CA bundle (step 7, D17). A REFERENCE to an on-disk bundle, NEVER
	// the cert/key material. When named, MUST be an absolute path.
	CABundlePath string
}

// BuildEntrypointConfig assembles the structured runtimev1.EntrypointConfig from
// the host-resolved input + the opaque role-overlay bytes (already fetched by the
// EntrypointConfigSource). It VALIDATES the assembled config against the same
// structural invariants the guest-side ds-entrypoint enforces (replicated in-tree,
// not imported) so a malformed config is rejected host-side before boot, then
// returns the message. The orchestrator stays runtime-ignorant; this lives
// host-side.
func BuildEntrypointConfig(in EntrypointBuildInput) (*runtimev1.EntrypointConfig, error) {
	cfg := &runtimev1.EntrypointConfig{
		SessionRef: &boundaryv1.SessionRef{
			SessionUuid:      in.SessionUUID,
			HostId:           in.HostID,
			HostSessionIndex: in.Binding.HostSessionIndex,
			TapName:          in.Binding.TapName,
		},
		Launch: &runtimev1.LaunchSpec{
			Command:    in.Launch.Command,
			Args:       append([]string(nil), in.Launch.Args...),
			Env:        append([]string(nil), in.Launch.Env...),
			WorkingDir: in.Launch.WorkingDir,
			// Stdio/InitialWindow are the additive terminal-MVP launch-mode riders. The
			// zero value (UNSPECIFIED stdio, nil window) is byte-identical to today's
			// headless config — every structured session carries no stdio field on the
			// wire. The InitialWindow is COPIED (never aliased) so the caller's message
			// cannot mutate the built config.
			Stdio:         in.Stdio,
			InitialWindow: cloneTerminalSize(in.InitialWindow),
		},
		Posture: in.Posture,
		Budget: &runtimev1.Budget{
			WallClockSeconds: in.Budget.WallClockSeconds,
			TokenMicroUnits:  in.Budget.TokenMicroUnits,
		},
		Attach: &runtimev1.AttachWiring{
			EventSocketPath: in.EventSocketPath,
		},
		Egress: &runtimev1.EgressWiring{
			HttpProxy:    in.Egress.HTTPProxy,
			HttpsProxy:   in.Egress.HTTPSProxy,
			NoProxy:      append([]string(nil), in.Egress.NoProxy...),
			CaBundlePath: in.Egress.CABundlePath,
		},
		// role_overlay_ref rides as OPAQUE bytes pass-through — copied so the caller's
		// slice can never be aliased into the message (the orchestrator never inspects
		// these bytes; an empty/nil value = no overlay).
		RoleOverlayRef:       append([]byte(nil), in.RoleOverlayRef...),
		SessionTokenEndpoint: in.SessionTokenEndpoint,
	}
	if err := validateEntrypointConfig(cfg); err != nil {
		return nil, fmt.Errorf("build entrypoint config for session %s: %w", in.SessionUUID, err)
	}
	return cfg, nil
}

// BuildEntrypointConfigBytes is the convenience that builds AND marshals the
// config to the binary config.pb payload the in-guest ds-entrypoint reads
// (deterministic on the input; proto.Marshal). It is the host-agent's drop
// producer: the bytes are written to the per-session config drop the boot step
// delivers via the read-only config-drive (U5). A build/validation failure
// returns no bytes (fail-closed — never a partial drop).
func BuildEntrypointConfigBytes(in EntrypointBuildInput) ([]byte, error) {
	cfg, err := BuildEntrypointConfig(in)
	if err != nil {
		return nil, err
	}
	raw, err := proto.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("marshal entrypoint config for session %s: %w", in.SessionUUID, err)
	}
	return raw, nil
}

// EntrypointFacts are the host-resolved, SESSION-INDEPENDENT facts the create-path
// EntrypointProducer folds into every per-session EntrypointConfig it builds: the host
// identity (the SessionRef.host_id join key), the runtime launch/budget/egress surface the
// host agent resolved from the D7 env config, the per-session event-socket convention, and
// the optional session-token endpoint. They are the host bring-up FACTS (doc 13 §4) the
// daemon composition root supplies once at construction; the per-session bits (the
// SessionUUID, the recorded Binding, the fetched opaque role-overlay bytes) are filled per
// create. References only, never credential material (D17/D39) — the same posture
// BuildEntrypointConfig validates.
type EntrypointFacts struct {
	// HostID is the host the session is placed on (SessionRef.host_id). A host bring-up
	// fact; never derived inside this module.
	HostID string
	// Launch is the host-resolved exec/supervise surface (the pinned CC command + args/env/
	// working_dir, D7/D20). Runtime-ignorant — a generic process-launch spec.
	Launch LaunchSpecInput
	// Posture is the runtime-facing permission disposition (doc 13 §2). A resolved config
	// MUST set a concrete posture; UNSPECIFIED is rejected by BuildEntrypointConfig.
	Posture runtimev1.PermissionPosture
	// Budget is the runtime-facing self-limiting envelope (doc 15 §8, D81). Zero values mean
	// "no runtime-facing ceiling".
	Budget BudgetInput
	// EventSocketPath is the guest-local UDS the runtime wrapper emits attach events onto
	// (terminated host-side, D38). MUST be an ABSOLUTE guest-filesystem path.
	EventSocketPath string
	// Egress is the runtime's view of the TLS-terminating egress gateway + the injected
	// per-session CA — references only (addresses + a bundle PATH), never material.
	Egress EgressWiringInput
	// SessionTokenEndpoint is WHERE the guest reaches the host-local D22 shim to fetch its
	// short-lived session token at boot — an address/reference only, never the token VALUE.
	SessionTokenEndpoint string
	// RoutedTap reports whether this host runs the per-session ROUTED TAP egress path
	// (the nft4 keystone) rather than the M0-minimal usermode SLIRP NIC (LiveConfig.RoutedTap,
	// DEFAULT false). When true the producer ALSO renders the per-session guest static net
	// config (ds-net.env, netconfig.go) onto the config-drive as a SECOND file so the guest
	// can address its routed tap; when false (the default, SLIRP/offline) NO net config is
	// rendered and the config-drive is byte-identical to the historical single-file drive. It
	// gates ONLY the net-config emission; the tap + the per-session gateway are U3 / the
	// dataplane lane, not this module.
	RoutedTap bool

	// DefaultMode is the per-host DEFAULT session launch mode (the -session-mode flag;
	// sessionmode.go) the producer resolves a session to when the per-session opaque
	// overlay carries no mode hint. The zero value (SessionModeStructured) is the
	// historical headless stream-json path — so a host that never sets -session-mode is
	// byte-identical to today. A per-session terminal hint in the overlay body overrides
	// this default (the resolution order, doc 04 §2.3). NEVER on the wire (D38).
	DefaultMode SessionMode

	// InitialWindow is the per-host pty window the producer seeds onto a TERMINAL
	// session's LaunchSpec.initial_window (§A7 / G9), so CC paints at the right geometry
	// from frame 1. A zero value (both dims 0) falls back to DefaultInitialWindow (80x24)
	// for a terminal session; it is IGNORED for a structured session (which seeds no
	// window). NEVER on the wire.
	InitialWindow TerminalWindow
}

// EntrypointProducer is the create-path gap-1 producer: at the step-7/8 boot site it
// resolves the opaque entrypoint-config ref the create carries into the host-built
// config.pb delivered into the guest. It is the SINGLE-SOURCE assembly the orchestrator
// stays out of (runtime-ignorant): it (1) fetches the opaque role-overlay bytes via the
// EntrypointConfigSource (by the VmSpec entrypoint_config_ref), (2) folds them with the
// recorded Binding + the host-resolved EntrypointFacts into the STRUCTURED
// runtimev1.EntrypointConfig via BuildEntrypointConfigBytes (which validates the same
// invariants the guest enforces, fail-closed before boot), and (3) hands those bytes to the
// config-drive EntrypointDeliverer, which packs them onto a per-session READ-ONLY
// config-drive the boot attaches. It owns the host-resolved facts; the per-session bits are
// passed to Produce.
//
// OFFLINE-FAKEABLE (the package posture): both seams are interfaces the daemon constructs
// gate-aware — the offline fakes (a fixture source + a no-touch deliverer) off
// DS_HOSTAGENT_LIVE, the real host store + iso9660 writer on. So the create choreography
// drives build+deliver entirely offline against fixtures (D50): no orchestrator drop, no
// genisoimage, no KVM. ADDITIVE: a HostAgent with no producer wired is byte-identical to the
// historical create path (the producer is an OPTIONAL seam, create.go).
type EntrypointProducer struct {
	source  EntrypointConfigSource
	deliver EntrypointDeliverer
	facts   EntrypointFacts
	// modes is the OPTIONAL per-session resolved-mode persistence (sessionmodestore.go).
	// When non-nil, Produce resolves the session's SessionMode once and persists it
	// here so the U-HOST-SERVE serving leg + attach minter read the SAME resolution the
	// LaunchSpec.stdio was built from (the doc 04 §5 drift guard). nil (the offline
	// default, and any caller that does not wire a store) persists nothing — the config
	// build is unaffected; an unset DefaultMode still resolves structured, byte-identical.
	modes SessionModeStore
}

// NewEntrypointProducer assembles the create-path producer from its fetch + deliver seams
// and the host-resolved facts. A nil seam is a programming error surfaced at construction
// (the NewHostAgent nil-dependency posture) — never a silent nil-deref at the step-8
// boundary. The facts are validated lazily (per session) inside BuildEntrypointConfig, so
// an under-filled facts (e.g. a missing launch command) fails closed at Produce, naming the
// session, exactly as a guest-side load would.
func NewEntrypointProducer(source EntrypointConfigSource, deliver EntrypointDeliverer, facts EntrypointFacts) (*EntrypointProducer, error) {
	if source == nil {
		return nil, fmt.Errorf("libvirt entrypoint producer requires a config source")
	}
	if deliver == nil {
		return nil, fmt.Errorf("libvirt entrypoint producer requires a config deliverer")
	}
	return &EntrypointProducer{source: source, deliver: deliver, facts: facts}, nil
}

// WithModeStore wires the OPTIONAL per-session resolved-mode persistence
// (sessionmodestore.go) into the producer — a SETTER (not a NewEntrypointProducer
// parameter) so every existing call site stays byte-identical and only the daemon
// composition root that has a store opts in (the destroyer.WithPostDestroyHook
// posture). A nil store (the offline default, and any caller that does not opt in)
// leaves the producer persisting nothing — the config build is unaffected. Returns
// the receiver for fluent wiring. It MUST be called before Produce (construction-time
// wiring, never mid-flight).
func (p *EntrypointProducer) WithModeStore(modes SessionModeStore) *EntrypointProducer {
	p.modes = modes
	return p
}

// resolveSessionMode resolves the per-session launch mode from the opaque overlay
// bytes (the per-session hint, if present and well-formed) falling back to the
// per-host DefaultMode (the -session-mode flag). This is the single resolution the
// LaunchSpec build + the persisted marker both derive from (doc 04 §2.3 order):
//
//  1. a well-formed per-session hint in the opaque overlay body → that mode;
//  2. else the per-host EntrypointFacts.DefaultMode (default structured);
//
// The overlay is OPAQUE bytes the orchestrator never inspects (D38); the host agent
// MAY read a host-private sentinel from it WITHOUT making the orchestrator
// runtime-aware. A malformed hint is fail-loud (an explicit, mistyped hint must not
// silently fall through to the host default and mask an operator error); an ABSENT
// hint is the normal case and falls through to the default with no error.
func (p *EntrypointProducer) resolveSessionMode(overlayBytes []byte) (SessionMode, error) {
	hint, present := sessionModeHintFromOverlay(overlayBytes)
	if present {
		mode, err := ParseSessionMode(hint)
		if err != nil {
			return SessionModeStructured, fmt.Errorf("per-session mode hint: %w", err)
		}
		return mode, nil
	}
	return p.facts.DefaultMode, nil
}

// ProduceInput is the per-create input to ProduceConfig — the per-session bits the create
// path threads in at the step-7/8 boot site, paired with the producer's session-INDEPENDENT
// EntrypointFacts. A struct (not a growing positional parameter list) keeps the call site
// readable as the per-create surface grows: the orchestrator-resolved per-session permission
// posture rides here without churning every Produce call.
type ProduceInput struct {
	// SessionUUID is the global session identity (the join key the guest echoes back).
	// REQUIRED — an empty value fails closed.
	SessionUUID string
	// Binding is the recorded three-keys-agree binding the build folds in (the
	// never-recycled HostSessionIndex + `dstap-<idx>` TapName join keys; the U4 net-config
	// derivation source).
	Binding Binding
	// EntrypointConfigRef is the opaque role-overlay ref the source fetches. REQUIRED —
	// the create only invokes Produce when the VmSpec carried a ref; an empty value fails
	// closed.
	EntrypointConfigRef string
	// Posture is the OPTIONAL orchestrator-resolved per-session permission posture (doc 13
	// §2). A CONCRETE value WINS; UNSPECIFIED (the zero value = "the orchestrator supplied
	// none") falls back to the daemon-pinned EntrypointFacts.Posture (the M0 default-deny
	// LOCKED). The value handed to BuildEntrypointConfig is ALWAYS concrete after this
	// fallback, so the builder's UNSPECIFIED-rejection invariant is unchanged.
	Posture runtimev1.PermissionPosture
}

// ProduceConfig runs the fetch → build → deliver pipeline for one session at the step-7/8 boot
// site. It resolves the per-session permission posture (in.Posture WINS when concrete; else
// the daemon-pinned EntrypointFacts.Posture, doc 13 §2), fetches the opaque role-overlay bytes
// for in.EntrypointConfigRef (fail-closed: a missing drop is an error, never a silent empty
// overlay), assembles + validates the structured EntrypointConfig from the recorded binding +
// the host facts + the resolved posture, and packs the marshaled config.pb onto a per-session
// read-only config-drive. It returns the host path of the delivered drive (the carrier the
// boot wires as the 2nd disk on the live path) so the create path can record it for
// diagnostics. An empty ref is a caller error (the create only invokes it when the VmSpec
// carried a ref). The whole pipeline is fail-closed: any fetch/build/deliver fault returns a
// non-nil error so the create aborts before boot rather than booting a guest that cannot read
// its config (D38). The resolved posture is ALWAYS concrete after the fallback, so a
// final-UNSPECIFIED (both per-create AND facts unset) still fails closed at the build.
func (p *EntrypointProducer) ProduceConfig(ctx context.Context, in ProduceInput) (configDrivePath string, err error) {
	sessionUUID := in.SessionUUID
	binding := in.Binding
	entrypointConfigRef := in.EntrypointConfigRef
	if sessionUUID == "" {
		return "", fmt.Errorf("entrypoint produce: empty session uuid")
	}
	if entrypointConfigRef == "" {
		return "", fmt.Errorf("entrypoint produce for session %s: empty entrypoint config ref", sessionUUID)
	}

	// Resolve the per-session permission posture (doc 13 §2): the orchestrator-resolved
	// per-create posture WINS when concrete; an UNSPECIFIED per-create posture ("none
	// supplied") falls back to the daemon-pinned EntrypointFacts.Posture (the M0 default-deny
	// LOCKED). The resolved value is ALWAYS handed to the builder below — whose
	// UNSPECIFIED-rejection invariant is preserved: a final-UNSPECIFIED (both per-create AND
	// facts unset, a mis-constructed producer) still fails closed at BuildEntrypointConfig.
	posture := in.Posture
	if posture == runtimev1.PermissionPosture_PERMISSION_POSTURE_UNSPECIFIED {
		posture = p.facts.Posture
	}

	// (1) Fetch the opaque role-overlay bytes the orchestrator pre-materialized (fail-closed
	// on a missing/empty drop — the builder never carries a phantom overlay).
	overlayBytes, err := p.source.FetchEntrypointRef(ctx, entrypointConfigRef)
	if err != nil {
		return "", fmt.Errorf("entrypoint produce for session %s: fetch ref: %w", sessionUUID, err)
	}

	// (1b) Resolve the per-session launch MODE ONCE (the opaque overlay hint, else the
	// per-host default; sessionmode.go), then fold it into the launch surface: the
	// stream-json argv is stripped + stdio set PTY + the window seeded for a TERMINAL
	// session, and left byte-identical for a STRUCTURED session (the unset/default path).
	// This is the SINGLE mode resolution — the persisted marker (1c) and the LaunchSpec
	// below both derive from it, so the handle transport (U-HOST-SERVE), the serving
	// child's mode, and LaunchSpec.stdio can never disagree (doc 04 §5 drift guard).
	mode, err := p.resolveSessionMode(overlayBytes)
	if err != nil {
		return "", fmt.Errorf("entrypoint produce for session %s: resolve session mode: %w", sessionUUID, err)
	}
	launch, stdio, initialWindow := applyLaunchMode(p.facts.Launch, mode, p.facts.InitialWindow)

	// (1c) PERSIST the resolved mode (when a store is wired) BEFORE the build/deliver, so
	// the U-HOST-SERVE serving leg + attach minter read the SAME resolution off the
	// host-readable marker. A persist fault is fail-closed (a session whose mode cannot be
	// recorded would later mis-route its handle — better to abort the create than serve a
	// structured handle for a pty session). nil store (offline default) persists nothing.
	if p.modes != nil {
		if err := p.modes.PutMode(ctx, sessionUUID, mode); err != nil {
			return "", fmt.Errorf("entrypoint produce for session %s: persist session mode: %w", sessionUUID, err)
		}
	}

	// (2) Assemble + validate the STRUCTURED config from the recorded binding + host facts +
	// the fetched opaque overlay bytes, then marshal it to config.pb (fail-closed on a
	// malformed config — rejected host-side before boot, never dropped into the guest). The
	// mode-folded launch + stdio/window ride the LaunchSpec (UNSPECIFIED stdio + nil window
	// for a structured session = byte-identical to today).
	configPB, err := BuildEntrypointConfigBytes(EntrypointBuildInput{
		SessionUUID:          sessionUUID,
		HostID:               p.facts.HostID,
		Binding:              binding,
		Launch:               launch,
		Stdio:                stdio,
		InitialWindow:        initialWindow,
		Posture:              posture,
		Budget:               p.facts.Budget,
		EventSocketPath:      p.facts.EventSocketPath,
		Egress:               p.facts.Egress,
		RoleOverlayRef:       overlayBytes,
		SessionTokenEndpoint: p.facts.SessionTokenEndpoint,
	})
	if err != nil {
		return "", fmt.Errorf("entrypoint produce for session %s: %w", sessionUUID, err)
	}

	// (2b) When the host runs the routed tap (U4), ALSO render the per-session guest static
	// net config (ds-net.env) from the recorded binding's never-recycled HostSessionIndex —
	// the SAME join key the tap name + vsock CID derive from (alloc.go). It is delivered as a
	// SECOND file on the SAME config-drive (the guest applies 10.77.<idx>.1/31 via
	// 10.77.<idx>.0 to its tap NIC). Fail-closed on an out-of-range index (a wider index
	// would alias another session's /31). When RoutedTap is false (the default, SLIRP/offline)
	// netConfigPB stays nil and the config-drive is byte-identical to the historical single-file
	// (config.pb) drive — the SLIRP boot path is unchanged. config.pb is untouched either way.
	var netConfigPB []byte
	if p.facts.RoutedTap {
		netConfigPB, err = renderNetConfigEnvForIndex(binding.HostSessionIndex)
		if err != nil {
			return "", fmt.Errorf("entrypoint produce for session %s: render guest net config: %w", sessionUUID, err)
		}
	}

	// (3) Deliver config.pb (+ the optional ds-net.env second file) into the guest via a
	// per-session read-only config-drive (the live deliverer writes a real iso9660 image; the
	// offline fake renders the deterministic path and touches nothing). Idempotent on
	// session_uuid (the drive path is a pure function of the session) so a step-8 retry
	// converges.
	drive, err := p.deliver.BuildConfigDrive(ctx, sessionUUID, configPB, netConfigPB)
	if err != nil {
		return "", fmt.Errorf("entrypoint produce for session %s: deliver config drive: %w", sessionUUID, err)
	}
	return drive, nil
}

// Produce is the posture-DEFAULTING form of ProduceConfig, retained for callers that carry no
// per-create permission posture. It forwards an UNSPECIFIED posture, so ProduceConfig falls
// back to the daemon-pinned EntrypointFacts.Posture (the M0 default-deny LOCKED) — BYTE-IDENTICAL
// to before the per-session posture-override seam. Callers that resolve a per-session posture
// (the create path, threading CreateRequest.Posture) use ProduceConfig directly.
func (p *EntrypointProducer) Produce(ctx context.Context, sessionUUID string, binding Binding, entrypointConfigRef string) (configDrivePath string, err error) {
	return p.ProduceConfig(ctx, ProduceInput{
		SessionUUID:         sessionUUID,
		Binding:             binding,
		EntrypointConfigRef: entrypointConfigRef,
		// Posture left UNSPECIFIED ⇒ ProduceConfig falls back to p.facts.Posture (LOCKED).
	})
}

// NewGatedEntrypointProducer is the gate-aware composition the daemon root calls: it builds
// the EntrypointConfigSource + EntrypointDeliverer from the same DS_HOSTAGENT_LIVE gate +
// LiveConfig the overlay/boot bindings ride (the offline fakes off the gate, the real host
// store + iso9660 writer on), folds in the host-resolved facts, and returns the producer.
// fixtures seeds the offline source (the synthetic role-overlay bytes the offline create
// path exercises); it is ignored on the live path (the real host store reads the
// orchestrator drop). It mirrors NewEntrypointConfigSource / NewEntrypointDeliverer so the
// producer's live/offline choice rides the one source of truth, never a scattered env check.
func NewGatedEntrypointProducer(cfg LiveConfig, facts EntrypointFacts, fixtures map[string][]byte) (*EntrypointProducer, error) {
	source, err := NewEntrypointConfigSource(cfg, fixtures)
	if err != nil {
		return nil, fmt.Errorf("entrypoint producer: build config source: %w", err)
	}
	deliver, err := NewEntrypointDeliverer(cfg)
	if err != nil {
		return nil, fmt.Errorf("entrypoint producer: build deliverer: %w", err)
	}
	p, err := NewEntrypointProducer(source, deliver, facts)
	if err != nil {
		return nil, err
	}
	// Wire the gate-aware per-session mode store so the resolved mode is persisted for the
	// U-HOST-SERVE serving leg + attach minter to read back (the doc 04 §5 drift guard). nil
	// off DS_HOSTAGENT_LIVE — the offline create path persists nothing (the serving leg
	// no-launches), and the config build stays byte-identical.
	modes, err := NewSessionModeStore(cfg)
	if err != nil {
		return nil, fmt.Errorf("entrypoint producer: build session mode store: %w", err)
	}
	return p.WithModeStore(modes), nil
}

// validateEntrypointConfig enforces the structural invariants the guest-side
// ds-entrypoint relies on (vm/entrypoint/config.go validate()), REPLICATED IN-TREE
// rather than imported (D80: this NON-test code may cross trees only via
// proto/gen/go). Asserting them host-side means a malformed config is rejected at
// the source — the host agent never drops a config the guest would fail-closed on:
//
//	(1) the session join key (session_uuid) is present — a config the host agent
//	    cannot join back to a record is structurally a misdelivery;
//	(2) a concrete permission posture is set — UNSPECIFIED is "never set", never a
//	    wire default for "locked";
//	(3) the launch command is non-empty — there is nothing to supervise without it;
//	(4) every env entry is KEY=VALUE with no NUL byte;
//	(5) the event-socket path is present and ABSOLUTE — the D38 attach byte-path;
//	(6) the ca_bundle_path, WHEN named, is absolute (an injected on-disk reference);
//	(7) no reference field carries inline credential MATERIAL (D17/D39/D8 defense
//	    in depth — a misdelivered PEM/JWT becomes a rejection, not a leak).
func validateEntrypointConfig(cfg *runtimev1.EntrypointConfig) error {
	if cfg == nil {
		return fmt.Errorf("entrypoint config is nil")
	}
	var errs []string

	if cfg.GetSessionRef().GetSessionUuid() == "" {
		errs = append(errs, "session_ref.session_uuid is required")
	}

	if cfg.GetPosture() == runtimev1.PermissionPosture_PERMISSION_POSTURE_UNSPECIFIED {
		errs = append(errs, "posture must be a concrete PermissionPosture (UNSPECIFIED means unset)")
	}

	if cfg.GetLaunch().GetCommand() == "" {
		errs = append(errs, "launch.command is required")
	}
	for i, e := range cfg.GetLaunch().GetEnv() {
		if err := validateEntrypointEnvEntry(e); err != nil {
			errs = append(errs, fmt.Sprintf("launch.env[%d] %q: %v", i, e, err))
		}
	}

	sock := cfg.GetAttach().GetEventSocketPath()
	if sock == "" {
		errs = append(errs, "attach.event_socket_path is required")
	} else if !filepath.IsAbs(sock) {
		errs = append(errs, fmt.Sprintf("attach.event_socket_path %q must be absolute", sock))
	}

	if p := cfg.GetEgress().GetCaBundlePath(); p != "" && !filepath.IsAbs(p) {
		errs = append(errs, fmt.Sprintf("egress.ca_bundle_path %q must be absolute", p))
	}

	for _, ref := range []struct{ name, val string }{
		{"egress.http_proxy", cfg.GetEgress().GetHttpProxy()},
		{"egress.https_proxy", cfg.GetEgress().GetHttpsProxy()},
		{"egress.ca_bundle_path", cfg.GetEgress().GetCaBundlePath()},
		{"session_token_endpoint", cfg.GetSessionTokenEndpoint()},
	} {
		if looksLikeEntrypointCredentialMaterial(ref.val) {
			errs = append(errs, fmt.Sprintf("%s must be a reference, not credential material", ref.name))
		}
	}
	// The role overlay is opaque bytes the orchestrator never inspects; we do NOT
	// validate its CONTENT (that is the runtime/adapter's concern in-guest). But a
	// reference (not material) channel must not smuggle a PEM/private key through
	// these structured bytes either — a coarse fail-closed guard, defense in depth.
	if looksLikeEntrypointCredentialMaterial(string(cfg.GetRoleOverlayRef())) {
		errs = append(errs, "role_overlay_ref must be an opaque ref/overlay, not credential material")
	}

	if len(errs) > 0 {
		return fmt.Errorf("invalid entrypoint config: %s", strings.Join(errs, "; "))
	}
	return nil
}

// cloneTerminalSize returns a defensive copy of the pty initial-window proto (nil ->
// nil) so the built EntrypointConfig never aliases the caller's message — the same
// copy-in posture the Args/Env/overlay fields take.
func cloneTerminalSize(w *runtimev1.TerminalSize) *runtimev1.TerminalSize {
	if w == nil {
		return nil
	}
	return &runtimev1.TerminalSize{Rows: w.GetRows(), Cols: w.GetCols()}
}

// validateEntrypointEnvEntry mirrors vm/entrypoint's env-entry rule IN-TREE: each
// entry must be KEY=VALUE with a non-empty key and carry no NUL byte (the exec
// layer would otherwise truncate or error opaquely). Replicated, never imported.
func validateEntrypointEnvEntry(e string) error {
	if strings.IndexByte(e, 0) >= 0 {
		return fmt.Errorf("contains NUL byte")
	}
	if i := strings.IndexByte(e, '='); i <= 0 {
		return fmt.Errorf("not KEY=VALUE")
	}
	return nil
}

// looksLikeEntrypointCredentialMaterial is the coarse defense-in-depth guard that a
// REFERENCE field is not carrying inline secret MATERIAL (D17/D39/D8). It mirrors
// vm/entrypoint's check IN-TREE (a PEM block header or a private-key marker) so a
// misdelivered PEM/JWT turns into a fail-closed rejection host-side rather than a
// leak — replicated, never imported (D80).
func looksLikeEntrypointCredentialMaterial(v string) bool {
	if v == "" {
		return false
	}
	for _, marker := range []string{
		"-----BEGIN", // PEM block (cert, key, certificate request, ...)
		"PRIVATE KEY",
	} {
		if strings.Contains(v, marker) {
			return true
		}
	}
	return false
}
