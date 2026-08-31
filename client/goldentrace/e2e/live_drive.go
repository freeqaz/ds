// live_drive.go — the LIVE-DRIVE tier (DRIVE-PROTOCOL.md "The e2e harness, in
// tiers", tier 1+2 fused): a thin client speaking ONLY attach.v1 drives a REAL
// Claude Code process in a rootless podman container, across the D79 transport.
//
// THE TOPOLOGY (closing the loop):
//
//		thin client ──attach.v1 over framed UDS──▶ host-agent (Server+Bridge) ──┐
//		  (SocketTransport.Dial; DriveInput/DriveGrant)    │ wrapper            │
//		                                                    │ driver+adapter     │
//		                                  CC stdin/stdout (podman -i pipes)      │
//		                                                    ▼                    │
//		                              REAL claude --input-format stream-json …   │
//		                              inside a rootless podman container ◀───────┘
//
//	  - The THIN CLIENT (driveThin) speaks attach.v1 and nothing else: it Dials an
//	    AttachHandle over the REAL hostbridge.SocketTransport (a framed UDS crossing
//	    a process boundary on the host), ranges over attach.Events, and answers a
//	    tool ask with a DriveGrant on the policy path. It names no CC vocabulary.
//	  - The HOST-AGENT is hostbridge: NewBridge (the wrapper adapter+driver),
//	    NewServer (D61 seat arbitration), ServeBridge (the UDS server). The Bridge
//	    owns the CC process's stdin/stdout — projecting stdout → attach.v1 and
//	    encoding DriveInput/DriveGrant → CC stdin THROUGH THE EXISTING wrapper.
//	  - CC is a REAL claude binary in a rootless podman container, launched with
//	    --permission-prompt-tool stdio so a tool ask arrives as the native
//	    control_request{can_use_tool} the host answers (DRIVE-FINDINGS §1).
//
// Where the boundary sits (and why this is the closest realizable D79 crossing):
// the host-agent fronts the container — it must, because it owns the CC process
// lifecycle (podman -i pipes). So the CC stdio crosses the CONTAINER/namespace
// boundary via podman's pipes, and the attach.v1 transport (the UDS) crosses a
// real PROCESS boundary on the host between the thin client and the host-agent.
// Putting the UDS *inside* the container would require the host-agent inside too,
// which defeats the fronting design. This is exactly DRIVE-PROTOCOL.md tier 2:
// "CC in the container with stdio bridged to a minimal host-agent ... the thin
// client attaches from outside and drives in."
//
// GATING: the whole file is behind DS_E2E_LIVE=1, the single documented gate
// (e2e/README.md "One gate story"). With it unset — the default and every CI /
// `go test` run — DriveLiveSocketBridge returns ErrLiveGateUnset and launches
// NOTHING: no podman, no claude, no cia. Stdlib + hostbridge only.
//
// SAFETY (fail-closed self-checks run BEFORE any container starts): rootless
// (uid != 0), --model sonnet, a budget cap, NO forbidden host bind mount, the
// in-container cc-sandbox-entry assert wired, and the default rootless userns
// (NO --userns=auto, crun-broken on this kernel — DRIVE-FINDINGS §drift 2). Any
// failure aborts before podman runs. Captures are raw-class and stay in the job
// dir; nothing real is ever returned to a committed artifact.
package e2e

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/dream-serpent/dream-serpent/client/hostbridge"
	"github.com/dream-serpent/dream-serpent/client/wrapper/attach"
)

// LiveDriveConfig parameterizes one live-drive run. Zero-value-friendly: the
// constructor LiveDriveConfigDefaults fills the proven recipe.
type LiveDriveConfig struct {
	// Image is the D49-pinned runtime tag (ds/cc-sandbox:2.1.173). Never :latest.
	Image string
	// ClaudeBinHost is the host path mounted read-only at /opt/claude-code (the
	// in-image npm build is broken under TLS interception — DRIVE-FINDINGS §drift
	// 1). Default /opt/claude-code.
	ClaudeBinHost string
	// ProxyPort is the host-loopback CIA egress proxy (read-only proxy use; the
	// daemon is never bound/killed by this harness). Default 18080.
	ProxyPort int
	// CAHost is the mitmproxy CA the egress gateway terminates TLS with. It is
	// STAGED to a non-host scratch path before mounting (a HOME-rooted bind would
	// be a forbidden mount). Default $HOME/.mitmproxy/mitmproxy-ca-cert.pem.
	CAHost string
	// BudgetUSD caps CC's per-session spend (--max-budget-usd). Default "1.0".
	BudgetUSD string
	// ScratchDir is a non-host-prefix job dir for the staged CA and the UDS.
	// Default os.MkdirTemp. Raw-class; never committed.
	ScratchDir string
	// SocketPath is the framed-UDS path the host-agent serves and the thin client
	// dials. Default <ScratchDir>/attach.sock.
	SocketPath string
	// Model is pinned to "sonnet" (a safety rail); overriding it fails the gate.
	Model string
	// PodmanNetwork is the egress network for the container. Default the
	// proven-live pasta forward to the host-loopback proxy.
	PodmanNetwork string
	// WorkdirHost, when set, is a host directory bind-mounted read-WRITE at the
	// container's /work (the CC cwd). It exists so a scripted drive can assert a
	// VM-SIDE EFFECT: a turn that instructs CC to write a proof file under /work
	// lands the file HERE on the host, where the gated test reads it back —
	// proving CC actually executed the instruction, not merely streamed text. It
	// MUST be a non-sensitive scratch dir under ~/tmp (the staged-artifact
	// convention); assertNoForbiddenMount rejects a host /tmp, host HOME, or
	// ~/.claude target by construction. Empty ⇒ no /work mount (the conformance
	// scenario does not need one — its tool runs inside the ephemeral container
	// fs); only the side-effect scripted drive sets it.
	WorkdirHost string

	// OAuthToken is the CLAUDE_CODE_OAUTH_TOKEN the container needs to authenticate
	// the live API call (the box uses an OAuth subscription token, not an API key;
	// CC's init reports account.tokenSource:CLAUDE_CODE_OAUTH_TOKEN). It is passed
	// to the container by ENV ONLY (never a file mount, never logged, never
	// committed). Empty ⇒ read from CredentialsFile at launch. The token is a
	// long-lived-ish secret; it is held only in memory and the child env, and the
	// harness scrubs it from any printed argv.
	OAuthToken string
	// CredentialsFile is the host OAuth credentials JSON the OAuthToken is read
	// from when OAuthToken is empty. Default $HOME/.claude/.credentials.json
	// (.claudeAiOauth.accessToken). Read-only; never mounted into the container.
	CredentialsFile string

	// ccCommand is the CC-launch seam: nil ⇒ the real podman container (the live
	// path). A test injects a fake-CC exec here to drive the host-agent +
	// thin-client wiring without a live container — the in-fleet, always-on half
	// of the live-drive test, exercising the exact Bridge/Server/SocketTransport/
	// thinClient code the live path uses, only with CC's "brain" replaced by a
	// scripted stdio fake. NEVER set on the gated live run.
	ccCommand func(ctx context.Context) *exec.Cmd

	// KVMAttach selects the per-session KVM-VM tier: a TRANSPORT-TARGET swap, not
	// a scenario change. When KVMAttach.Endpoint is set, the harness does NOT
	// launch a podman container or stand up a local host-agent — the per-session
	// KVM VM is ALREADY running Claude Code, and the ds-hostbridge serving child
	// (post-boot, inside the M1 create→boot path) ALREADY advertises a writer-seat
	// over attach.v1 at a host-local endpoint (the host side of the framed UDS the
	// in-guest forwarder splices to GuestIP:4242). The thin client just dials that
	// pre-advertised endpoint with the SAME hostbridge.SocketTransport the podman
	// tier dials its local UDS with, then drives the SAME scenario and collects the
	// SAME projected attach.v1 stream. Zero value ⇒ the podman tier (KVMAttach
	// ignored). It is resolved from env at runtime (DS_KVM_LIVE_*), never
	// hardcoded — see kvmAttachFromEnv / DriveKVMScripted.
	KVMAttach KVMAttachConfig
}

// KVMAttachConfig is the per-session KVM-VM attach endpoint the writer-seat tier
// dials. It is the host-local endpoint the ds-hostbridge serving child advertises
// for the live session (LIVE-VALIDATION.md tier D; the §A topology in
// orchestrator/cmd/host-agent/LIVE-SMOKE.md). Every field is operator-supplied at
// runtime — there is NO box-specific UDS/CID/address baked in: the test resolves
// these from DS_KVM_LIVE_* env so it dials whatever writer-seat the live host-agent
// minted for this session, on whatever box it runs on.
type KVMAttachConfig struct {
	// Endpoint is the host-local writer-seat address the serving child advertises:
	// the host side of the per-session framed UDS (e.g.
	// /run/ds/attach/<uuid>.sock, hostagent.DefaultAttachSocketDir-rooted). Empty
	// ⇒ the KVM tier is not selected. Resolved from DS_KVM_LIVE_ATTACH_UDS.
	Endpoint string
	// Transport names the carrier the SocketTransport dials. M1 advertises a
	// host-local UDS (TransportUnix); a future vsock-direct carrier slots in here
	// behind the SAME EndpointCandidate shape with no scenario change. Empty ⇒
	// TransportUnix (the M1 host-local writer-seat UDS).
	Transport hostbridge.EndpointTransport
	// SessionUUID joins the AttachHandle to the session record the serving child
	// knows (the writer seat lives in the session record, not the handle). It MUST
	// match the live session the host-agent created. Resolved from
	// DS_KVM_LIVE_SESSION.
	SessionUUID string
	// Token is the short-lived, session-scoped attach credential the serving child
	// validates against its per-session token store (D39: never a long-lived
	// cred). Resolved from DS_KVM_LIVE_TOKEN (or a file via DS_KVM_LIVE_TOKEN_FILE).
	// Held in memory only; never logged or committed (D50/raw-class).
	Token string
}

// writerHandle builds the WRITER AttachHandle the thin client presents to the
// serving child: the advertised host-local endpoint, the session-scoped token,
// the session UUID, and a short forward-dated expiry (the live serving child
// re-validates the token + expiry — this handle is only the dial request, the
// authority is the host-agent's per-session token store). It carries no CC
// vocabulary and mints no credential of its own.
func (k KVMAttachConfig) writerHandle() hostbridge.AttachHandle {
	transport := k.Transport
	if transport == "" {
		transport = hostbridge.TransportUnix
	}
	return hostbridge.AttachHandle{
		SessionUUID: k.SessionUUID,
		Endpoints: []hostbridge.EndpointCandidate{
			{Transport: transport, Address: k.Endpoint},
		},
		Auth:      hostbridge.AuthMaterial{Token: k.Token},
		Role:      hostbridge.RoleWriter,
		ExpiresAt: time.Now().Add(time.Hour),
	}
}

// LiveDriveConfigDefaults returns the proven-recipe config (DRIVE-FINDINGS §"How
// it ran"): the pinned image, the host claude binary, the :18080 proxy via
// pasta, the mitmproxy CA, a sonnet model, and a $1 budget cap.
func LiveDriveConfigDefaults() LiveDriveConfig {
	home, _ := os.UserHomeDir()
	return LiveDriveConfig{
		Image:           "ds/cc-sandbox:2.1.173",
		ClaudeBinHost:   "/opt/claude-code",
		ProxyPort:       18080,
		CAHost:          filepath.Join(home, ".mitmproxy", "mitmproxy-ca-cert.pem"),
		BudgetUSD:       "1.0",
		Model:           "sonnet",
		PodmanNetwork:   "pasta:-T,18080",
		CredentialsFile: filepath.Join(home, ".claude", ".credentials.json"),
	}
}

// resolveOAuthToken returns cfg.OAuthToken if set, else reads
// .claudeAiOauth.accessToken from cfg.CredentialsFile. The token is returned to
// the caller only to place it in the child process env; it is NEVER logged or
// returned in any result.
func (cfg LiveDriveConfig) resolveOAuthToken() (string, error) {
	if cfg.OAuthToken != "" {
		return cfg.OAuthToken, nil
	}
	raw, err := os.ReadFile(cfg.CredentialsFile)
	if err != nil {
		return "", fmt.Errorf("read credentials %s: %w", cfg.CredentialsFile, err)
	}
	var creds struct {
		ClaudeAIOAuth struct {
			AccessToken string `json:"accessToken"`
		} `json:"claudeAiOauth"`
	}
	if err := json.Unmarshal(raw, &creds); err != nil {
		return "", fmt.Errorf("parse credentials %s: %w", cfg.CredentialsFile, err)
	}
	if creds.ClaudeAIOAuth.AccessToken == "" {
		return "", fmt.Errorf("no .claudeAiOauth.accessToken in %s", cfg.CredentialsFile)
	}
	return creds.ClaudeAIOAuth.AccessToken, nil
}

// LiveDriveResult is the structured outcome of a live-drive run — the evidence
// the gated test asserts and the README records. It carries the projected
// attach.v1 event stream (the conformance signal) and the raw-capture location
// (raw-class; never committed).
type LiveDriveResult struct {
	// Events is the full attach.v1 projection the host-agent's Bridge produced
	// from the live CC stdout, delivered to the thin client over the UDS. This is
	// what the structural / id-relative assertions run against.
	Events []attach.Event
	// AskAnswered is true if the thin client saw an ask.requested and answered it
	// with a DriveGrant (the ask round-trip closed live).
	AskAnswered bool
	// GrantRoute records which proven driver encoding the grant took
	// (native control_response, the --permission-prompt-tool stdio channel).
	GrantRoute hostbridge.GrantRoute
	// RawCapturePath is the job-dir ndjson of every CC stdout line (raw-class).
	RawCapturePath string
	// Warnings are the adapter's non-fatal projection warnings (drift is recorded,
	// never a crash).
	Warnings []string
}

// ErrLiveDriveGateUnset is returned by DriveLiveSocketBridge when DS_E2E_LIVE !=
// "1": the live-drive tier launches nothing. It wraps the package-shared gate
// signal so a caller's errors.Is(err, ErrLiveGateUnset) holds.
var ErrLiveDriveGateUnset = fmt.Errorf("e2e: live-drive socket-bridge tier is gated: %w", ErrLiveGateUnset)

// driveScenario is the thin-client conversation a run drives. It is a closure so
// a test can pin the exact multi-turn sequence (chat → spawn → ask) without this
// package naming any CC-ism: it receives the thin-client surface (Drive / Grant)
// and the live event stream, and returns when the conversation is complete.
type driveScenario func(ctx context.Context, tc *thinClient) error

// DriveLivePrompt is the exported one-prompt entry point for an operator CLI
// (cmd/serpent): it drives a single operator-supplied prompt through the live
// socket-bridge tier and returns the attach.v1 projection, auto-answering at most
// one native tool ask (allow unless allow=false). It is GATED exactly like
// DriveLiveSocketBridge — with DS_E2E_LIVE unset it launches nothing and returns
// ErrLiveDriveGateUnset. The driveScenario type is unexported (it names the
// internal thin-client surface), so this is the supported way to drive a custom
// prompt from outside the package.
func DriveLivePrompt(ctx context.Context, cfg LiveDriveConfig, sessionUUID, prompt string, allow bool) (*LiveDriveResult, error) {
	return DriveLiveSocketBridge(ctx, cfg, sessionUUID, drivePromptScenario(prompt, allow))
}

// drivePromptScenario drives one operator prompt and returns as soon as the turn
// reaches a result, answering at most one native ask along the way. Unlike
// driveChatSpawnAskScenario (which pins a fixed chat→spawn→ask sequence for the
// conformance test), it polls for an ask OR the result together, so a no-tool
// prompt returns promptly instead of stalling on the ask deadline.
func drivePromptScenario(prompt string, allow bool) driveScenario {
	return func(ctx context.Context, tc *thinClient) error {
		if err := tc.DriveText(prompt); err != nil {
			return fmt.Errorf("drive prompt: %w", err)
		}
		deadline := time.Now().Add(120 * time.Second)
		answered := false
		for {
			var askID, nodeID string
			var input []byte
			sawAsk := false
			results := 0
			for _, ev := range tc.snapshot() {
				switch {
				case ev.Type == attach.TypeAskRequested && ev.AskRequested != nil && !answered:
					sawAsk = true
					askID, nodeID, input = ev.AskRequested.AskID, ev.AskRequested.NodeID, ev.AskRequested.Input
				case ev.Type == attach.TypeSessionAccounted:
					results++
				}
			}
			if sawAsk {
				var updatedInput []byte
				denyMsg := ""
				if allow {
					updatedInput = input // echo the tool input on allow (P8)
				} else {
					denyMsg = "Denied via `serpent claude` (operator did not allow)."
				}
				if err := tc.GrantAsk(askID, nodeID, allow, updatedInput, denyMsg); err != nil {
					return fmt.Errorf("grant ask: %w", err)
				}
				answered = true
			}
			if results >= 1 {
				return nil
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			if time.Now().After(deadline) {
				return errors.New("the prompt did not reach a result within the deadline")
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
}

// KVMLiveGateEnv is the SEPARATE live gate for the per-session KVM-VM writer-seat
// tier (LIVE-VALIDATION.md tier D). It is distinct from DS_E2E_LIVE (the podman
// tier's single gate) on purpose: the KVM tier launches NO podman/claude/cia of
// its own — it dials a writer-seat a live host-agent already serves — so arming
// it is an independent operator step ("there is a live VM serving this session"),
// not "run real CC in a local container." Unset (every CI / sandbox / go test
// run) ⇒ DriveKVMScripted dials nothing and the gated test skips CLEAN.
const KVMLiveGateEnv = "DS_KVM_LIVE"

// kvmGateArmed reports whether the per-session KVM-VM writer-seat tier is armed
// (DS_KVM_LIVE=1). Unset ⇒ the tier dials nothing (the offline default).
func kvmGateArmed() bool { return os.Getenv(KVMLiveGateEnv) == "1" }

// ErrKVMLiveGateUnset is returned by DriveKVMScripted when DS_KVM_LIVE != "1": the
// KVM-VM writer-seat tier dials nothing.
var ErrKVMLiveGateUnset = fmt.Errorf("e2e: per-session KVM-VM writer-seat tier is gated: set %s=1 to arm (this is the M1 deferred manual live step — there must be a live VM serving the session)", KVMLiveGateEnv)

// kvmAttachFromEnv resolves the KVM writer-seat endpoint from the DS_KVM_LIVE_*
// knobs (mirroring how the podman tier reads DS_LIVE_PROXY_PORT/DS_LIVE_CA), so the
// test dials whatever per-session writer-seat the live ds-hostbridge serving child
// advertised — NEVER a box-specific UDS/CID/address baked into the code:
//
//	DS_KVM_LIVE_ATTACH_UDS  — the host-local writer-seat address the serving child
//	                          advertises (e.g. /run/ds/attach/<uuid>.sock). Required.
//	DS_KVM_LIVE_SESSION     — the live session UUID the host-agent created (the
//	                          AttachHandle joins the session record on it). Required.
//	DS_KVM_LIVE_TOKEN       — the short-lived session-scoped attach token, OR
//	DS_KVM_LIVE_TOKEN_FILE  — a file the token is read from (the per-session token
//	                          store the libvirt attach minter wrote; raw-class).
//	                          Exactly one of the two is required.
//	DS_KVM_LIVE_TRANSPORT   — optional carrier override (default "unix"); a future
//	                          vsock-direct carrier slots in here unchanged.
//
// It returns a populated KVMAttachConfig or an error naming the first missing knob,
// so an operator who half-arms the gate gets a precise diagnostic, never a silent
// dial of an empty address. The token is held in memory only.
func kvmAttachFromEnv() (KVMAttachConfig, error) {
	var k KVMAttachConfig
	k.Endpoint = strings.TrimSpace(os.Getenv("DS_KVM_LIVE_ATTACH_UDS"))
	if k.Endpoint == "" {
		return KVMAttachConfig{}, fmt.Errorf("e2e: %s=1 but DS_KVM_LIVE_ATTACH_UDS is unset (the writer-seat the host-agent serving child advertises)", KVMLiveGateEnv)
	}
	k.SessionUUID = strings.TrimSpace(os.Getenv("DS_KVM_LIVE_SESSION"))
	if k.SessionUUID == "" {
		return KVMAttachConfig{}, fmt.Errorf("e2e: %s=1 but DS_KVM_LIVE_SESSION is unset (the live session UUID the AttachHandle joins)", KVMLiveGateEnv)
	}
	if tok := strings.TrimSpace(os.Getenv("DS_KVM_LIVE_TOKEN")); tok != "" {
		k.Token = tok
	} else if tf := strings.TrimSpace(os.Getenv("DS_KVM_LIVE_TOKEN_FILE")); tf != "" {
		raw, err := os.ReadFile(tf)
		if err != nil {
			return KVMAttachConfig{}, fmt.Errorf("e2e: read DS_KVM_LIVE_TOKEN_FILE %s: %w", tf, err)
		}
		k.Token = strings.TrimSpace(string(raw))
		if k.Token == "" {
			return KVMAttachConfig{}, fmt.Errorf("e2e: DS_KVM_LIVE_TOKEN_FILE %s is empty", tf)
		}
	} else {
		return KVMAttachConfig{}, fmt.Errorf("e2e: %s=1 but neither DS_KVM_LIVE_TOKEN nor DS_KVM_LIVE_TOKEN_FILE is set (the session-scoped attach token)", KVMLiveGateEnv)
	}
	if tr := strings.TrimSpace(os.Getenv("DS_KVM_LIVE_TRANSPORT")); tr != "" {
		k.Transport = hostbridge.EndpointTransport(tr)
	}
	return k, nil
}

// DriveKVMScripted is the per-session KVM-VM writer-seat tier: it drives the GIVEN
// scenario against a REAL Claude Code running INSIDE a per-session KVM VM, by a
// TRANSPORT-TARGET SWAP — it reuses the EXACT thin client + scenario the podman
// tier uses, but instead of launching a local CC + host-agent it DIALS the
// writer-seat the live ds-hostbridge serving child already advertises (cfg.KVMAttach,
// resolved from DS_KVM_LIVE_* by kvmAttachFromEnv). It is GATED behind DS_KVM_LIVE=1;
// unset, it dials nothing and returns ErrKVMLiveGateUnset.
//
// Sequence (no container, no local host-agent — the VM already runs both):
//  1. require the gate + a populated KVMAttach endpoint;
//  2. build a WRITER AttachHandle for the advertised endpoint;
//  3. thin client: hostbridge.SocketTransport.Dial(handle) → the SAME SocketConn
//     the podman tier dials its local UDS with;
//  4. run the SAME scenario (e.g. DriveScriptScenario over proof.jsonl), answering
//     asks on the SAME grant path; collect the SAME projected attach.v1 stream;
//  5. close the writer input + conn, drain, return the projection.
//
// The serving child owns the CC process lifecycle and the token validation; this
// tier touches neither — it is a pure attach.v1 client, the closest realizable M1
// "drive the VM from the writer seat" crossing.
func DriveKVMScripted(ctx context.Context, cfg LiveDriveConfig, scenario driveScenario) (*LiveDriveResult, error) {
	if !kvmGateArmed() {
		return nil, ErrKVMLiveGateUnset
	}
	if cfg.KVMAttach.Endpoint == "" {
		return nil, errors.New("e2e: DriveKVMScripted requires a KVMAttach.Endpoint (the advertised writer-seat); resolve it from DS_KVM_LIVE_* via kvmAttachFromEnv")
	}
	return driveKVMSocketBridge(ctx, cfg, scenario)
}

// driveKVMSocketBridge dials the live writer-seat and runs the scenario over it.
// It is the KVM-tier analogue of driveSocketBridge's (5)+(6)+(7) — the dial, the
// drive, and the drain — with steps (1)–(4) (self-check, CA stage, container
// launch, local host-agent serve) ELIDED because the per-session VM already runs
// CC and the serving child already serves the writer seat. The thin client and
// scenario are byte-for-byte the same as the podman tier; only the dial target
// differs (the transport-target swap).
func driveKVMSocketBridge(ctx context.Context, cfg LiveDriveConfig, scenario driveScenario) (*LiveDriveResult, error) {
	handle := cfg.KVMAttach.writerHandle()
	conn, err := hostbridge.NewSocketTransport().Dial(handle)
	if err != nil {
		return nil, fmt.Errorf("e2e: KVM-tier thin client dial over the advertised writer-seat: %w", err)
	}

	tc := &thinClient{conn: conn}
	tc.collectStart()

	scenErr := scenario(ctx, tc)

	// End the conversation: close the writer conn (the serving child sees the
	// drive-reader EOF and releases the seat — the VM's CC process is NOT reaped by
	// this tier; the host-agent owns its lifecycle), then drain the event stream.
	_ = conn.Close()
	tc.collectWait()

	if scenErr != nil {
		return nil, fmt.Errorf("e2e: KVM-tier drive scenario: %w", scenErr)
	}

	return &LiveDriveResult{
		Events:      tc.events(),
		AskAnswered: tc.askAnswered,
		GrantRoute:  hostbridge.GrantRouteNativeControl,
		Warnings:    nil,
	}, nil
}

// DriveLiveSocketBridge runs the full live-drive topology against a REAL CC
// container and returns the projected attach.v1 stream. It is GATED behind
// DS_E2E_LIVE=1; unset, it launches nothing and returns ErrLiveDriveGateUnset.
//
// Sequence (the loop, closed):
//  1. fail-closed self-checks (rootless, sonnet, budget, no forbidden mount);
//  2. stage the CA to a non-host scratch path;
//  3. podman run -i the pinned image (CC stdin/stdout = the container pipes);
//  4. host-agent: NewBridge(ccStdin) + NewServer + AddSession; go Bridge.Pump
//     over the tee'd CC stdout (raw capture in parallel); go ServeBridge(UDS);
//  5. issue a WRITER AttachHandle for the UDS endpoint;
//  6. thin client: SocketTransport.Dial(handle) → drive the scenario, answering
//     the ask via DriveGrant on the native control route;
//  7. close input, drain events, reap podman, return the projection.
func DriveLiveSocketBridge(ctx context.Context, cfg LiveDriveConfig, sessionUUID string, scenario driveScenario) (*LiveDriveResult, error) {
	if !liveGateArmed() {
		return nil, ErrLiveDriveGateUnset
	}
	if cfg.ccCommand != nil {
		// The live entry NEVER takes the fake-CC seam: that would let the gated
		// path silently run a fake instead of the real container.
		return nil, errors.New("e2e: DriveLiveSocketBridge with a fake-CC ccCommand is forbidden on the gated live path")
	}
	if err := cfg.selfCheck(); err != nil {
		return nil, fmt.Errorf("e2e: live-drive fail-closed self-check: %w", err)
	}
	return driveSocketBridge(ctx, cfg, sessionUUID, scenario, true)
}

// driveFakeSocketBridge is the in-fleet, always-on twin: it drives the SAME
// host-agent + UDS transport + thin-client wiring as the live path, but with CC
// replaced by the cfg.ccCommand fake-CC exec. It is NOT gated (no real container,
// claude, cia, or podman is touched) and skips the container-only self-checks
// (CA staging, host binary). It exercises every line of the conformance path the
// live run does — Bridge.Pump → adapter projection → SocketTransport fan-out →
// thinClient → DriveGrant → driver encoding → fake CC stdin — only the model's
// choice to call the tool is scripted instead of live. This is how the test
// proves the wiring is green without a live session.
func driveFakeSocketBridge(ctx context.Context, cfg LiveDriveConfig, sessionUUID string, scenario driveScenario) (*LiveDriveResult, error) {
	if cfg.ccCommand == nil {
		return nil, errors.New("e2e: driveFakeSocketBridge requires a fake-CC ccCommand")
	}
	return driveSocketBridge(ctx, cfg, sessionUUID, scenario, false)
}

// driveSocketBridge is the shared core of both the live and fake paths. live
// selects whether the CC process is the real podman container (true) or the
// injected fake-CC exec (false), which also gates CA staging (real only).
func driveSocketBridge(ctx context.Context, cfg LiveDriveConfig, sessionUUID string, scenario driveScenario, live bool) (*LiveDriveResult, error) {
	scratch := cfg.ScratchDir
	if scratch == "" {
		var err error
		scratch, err = os.MkdirTemp(scratchRoot(), "ds-live-drive-")
		if err != nil {
			return nil, fmt.Errorf("e2e: scratch dir: %w", err)
		}
		defer os.RemoveAll(scratch)
	}
	if cfg.SocketPath == "" {
		cfg.SocketPath = filepath.Join(scratch, "attach.sock")
	}

	// (2) Stage the CA to a non-host path (a HOME bind would be a forbidden
	// mount). The staged copy lives in the job dir and is mounted read-only.
	// Only the real container needs it.
	stagedCA := filepath.Join(scratch, "mitmproxy-ca.crt")
	if live {
		if err := copyFile(cfg.CAHost, stagedCA); err != nil {
			return nil, fmt.Errorf("e2e: stage CA: %w", err)
		}
	}

	rawPath := filepath.Join(scratch, "cc-stdout.raw.ndjson")
	rawFile, err := os.Create(rawPath)
	if err != nil {
		return nil, fmt.Errorf("e2e: raw capture file: %w", err)
	}
	defer rawFile.Close()

	// (3) Build and launch the CC process. podman -i (live) gives us the real CC
	// process's stdin/stdout pipes — the stream-json wire crossing the container
	// boundary; the fake-CC exec (fleet) gives the same pipe shape with a scripted
	// stdio. Either way the host-agent below treats it as opaque CC stdio.
	argv := cfg.podmanArgv(stagedCA)
	if err := assertNoForbiddenMount(argv); err != nil {
		return nil, fmt.Errorf("e2e: forbidden-mount self-check: %w", err)
	}
	var cmd *exec.Cmd
	if cfg.ccCommand != nil {
		cmd = cfg.ccCommand(ctx)
	} else {
		cmd = exec.CommandContext(ctx, "podman", argv...)
		// Pass the OAuth token to the container by ENV only: the argv carries just
		// `-e CLAUDE_CODE_OAUTH_TOKEN` (name, no value — so the token never appears
		// in the process argv / ps output), and podman forwards the VALUE from its
		// own environment, which we set here. The token is held in memory only and
		// is never logged or returned.
		token, terr := cfg.resolveOAuthToken()
		if terr != nil {
			return nil, fmt.Errorf("e2e: resolve oauth token: %w", terr)
		}
		cmd.Env = append(os.Environ(), "CLAUDE_CODE_OAUTH_TOKEN="+token)
	}
	cmd.Stderr = os.Stderr
	ccStdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	ccStdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("e2e: podman start: %w", err)
	}
	// Always reap the container.
	defer func() { _ = cmd.Wait() }()

	// (4) Host-agent: the wrapper adapter+driver behind the Bridge, the Server's
	// D61 seat arbitration, and the UDS server. NO second copy of adapter/driver —
	// the Bridge imports them verbatim (hostbridge.NewBridge).
	bridge := hostbridge.NewBridge(ccStdin, hostbridge.BridgeConfig{})
	srv := hostbridge.NewServer()
	srv.AddSession(sessionUUID, bridge)

	// Tee CC stdout to the raw capture (raw-class) AND to the Bridge pump. The
	// pump projects each stdout line → attach.v1 through the existing adapter.
	teedStdout := io.TeeReader(ccStdout, rawFile)
	pumpDone := make(chan error, 1)
	go func() { pumpDone <- bridge.Pump(ctx, teedStdout) }()

	// (5)+(6) Serve the UDS and run the thin client over the real SocketTransport.
	serveCtx, serveCancel := context.WithCancel(ctx)
	defer serveCancel()
	serveErr := make(chan error, 1)
	go func() { serveErr <- hostbridge.ServeBridge(serveCtx, cfg.SocketPath, srv) }()
	if err := waitForUDS(cfg.SocketPath, 5*time.Second); err != nil {
		return nil, err
	}

	handle, err := srv.IssueHandleFor(sessionUUID, hostbridge.RoleWriter, hostbridge.TransportUnix, cfg.SocketPath, time.Hour)
	if err != nil {
		return nil, fmt.Errorf("e2e: issue writer handle: %w", err)
	}
	conn, err := hostbridge.NewSocketTransport().Dial(handle)
	if err != nil {
		return nil, fmt.Errorf("e2e: thin client dial over UDS: %w", err)
	}

	tc := &thinClient{conn: conn}
	// The thin client collects every attach.v1 event off the wire as it drives.
	tc.collectStart()

	scenErr := scenario(ctx, tc)

	// (7) End the conversation: close the writer input (CC sees EOF and finishes),
	// then drain the event stream and tear down.
	_ = bridge.CloseInput()
	_ = conn.Close()
	tc.collectWait()
	serveCancel()
	<-serveErr
	<-pumpDone

	if scenErr != nil {
		return nil, fmt.Errorf("e2e: drive scenario: %w", scenErr)
	}

	return &LiveDriveResult{
		Events:         tc.events(),
		AskAnswered:    tc.askAnswered,
		GrantRoute:     hostbridge.GrantRouteNativeControl,
		RawCapturePath: rawPath,
		Warnings:       bridge.Warnings(),
	}, nil
}

// thinClient is the attach.v1-only client surface the scenario drives through.
// It speaks NO CC vocabulary: DriveInput is a text prompt, GrantAsk is an
// allow/deny answer on the policy path, and Events are attach.v1 deltas. All CC
// knowledge lives behind the wrapper, on the far side of the UDS.
type thinClient struct {
	conn *hostbridge.SocketConn

	mu          sync.Mutex
	collected   []attach.Event
	askAnswered bool

	wg sync.WaitGroup
}

// collectStart begins draining the conn's event stream into a buffer in the
// background; collectWait blocks until the stream closes.
func (tc *thinClient) collectStart() {
	tc.wg.Add(1)
	go func() {
		defer tc.wg.Done()
		for ev := range tc.conn.Events() {
			tc.mu.Lock()
			tc.collected = append(tc.collected, ev)
			tc.mu.Unlock()
		}
	}()
}

func (tc *thinClient) collectWait() { tc.wg.Wait() }

func (tc *thinClient) events() []attach.Event {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	return append([]attach.Event(nil), tc.collected...)
}

// snapshot returns the events seen so far (for polling mid-scenario).
func (tc *thinClient) snapshot() []attach.Event {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	return append([]attach.Event(nil), tc.collected...)
}

// DriveText drives one user prompt into the live session over the writer seat
// (attach.v1 input → CC stdin via the wrapper driver). The thin client never
// shapes a CC record itself.
func (tc *thinClient) DriveText(text string) error {
	return tc.conn.DriveInput(hostbridge.DriveInput{Text: text})
}

// GrantAsk answers an open ask with a TTL'd policy-stream grant (D18/D45/D53):
// the thin client renders the ask and chooses; the grant returns on the policy
// path, and the wrapper turns it into CC's control_response INSIDE the boundary.
// route selects the native control_response channel (the --permission-prompt-tool
// stdio path). requestID is the ask's control request_id (the join key);
// toolUseID is carried for bookkeeping.
func (tc *thinClient) GrantAsk(requestID, toolUseID string, allow bool, updatedInput []byte, denyMsg string) error {
	g := hostbridge.DriveGrant{
		RequestID:    requestID,
		ToolUseID:    toolUseID,
		Allow:        allow,
		UpdatedInput: updatedInput,
		Message:      denyMsg,
	}
	if err := tc.conn.DriveGrant(g, hostbridge.GrantRouteNativeControl); err != nil {
		return err
	}
	tc.mu.Lock()
	tc.askAnswered = true
	tc.mu.Unlock()
	return nil
}

// waitForAsk polls the live event stream until an ask.requested arrives (the
// native control_request projected to attach.v1) or the deadline passes. It
// returns the first open ask's request_id + tool_use_id + input — the keys the
// grant joins on. This is the thin client's "render the ask" step.
func (tc *thinClient) waitForAsk(ctx context.Context, timeout time.Duration) (askID, nodeID string, input []byte, ok bool) {
	deadline := time.Now().Add(timeout)
	for {
		for _, ev := range tc.snapshot() {
			if ev.Type == attach.TypeAskRequested && ev.AskRequested != nil {
				return ev.AskRequested.AskID, ev.AskRequested.NodeID, ev.AskRequested.Input, true
			}
		}
		select {
		case <-ctx.Done():
			return "", "", nil, false
		default:
		}
		if time.Now().After(deadline) {
			return "", "", nil, false
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// waitForResult polls until at least n session-accounted/terminal-result events
// (attach.v1 session.accounted) have arrived, the safe "turn complete" boundary
// to drive the next input on (DRIVE-FINDINGS §3: inject the next input after the
// previous result).
func (tc *thinClient) waitForResults(ctx context.Context, n int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		count := 0
		for _, ev := range tc.snapshot() {
			if ev.Type == attach.TypeSessionAccounted {
				count++
			}
		}
		if count >= n {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		default:
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// --- the container launch (built directly; cc_sandbox.sh is print-only) ------

// podmanArgv builds the podman run argv for the live container. It mirrors the
// cc_sandbox.sh plan (the gate/plan oracle) but is the actual executor, because
// launch_live is a planner not a launcher (DRIVE-FINDINGS §drift 3). stagedCA is
// the non-host CA path to mount read-only.
func (cfg LiveDriveConfig) podmanArgv(stagedCA string) []string {
	proxy := fmt.Sprintf("http://127.0.0.1:%d", cfg.ProxyPort)
	args := []string{
		"run", "--rm", "-i",
		// Isolation floor over the DEFAULT rootless userns (NO --userns=auto —
		// crun-broken on kernel 7.0.10, DRIVE-FINDINGS §drift 2).
		"--cap-drop=ALL", "--security-opt=no-new-privileges",
		// Egress: pasta forward to the host-loopback CIA proxy, and NOTHING else
		// routes (the API is reachable only THROUGH the proxy).
		"--network=" + cfg.PodmanNetwork,
		// Container-local config (G3): never the host HOME/.claude.
		"-e", "HOME=/home/cc",
		"-e", "CLAUDE_CONFIG_DIR=/home/cc/.claude",
		// Proxy env (undici honours it only with NODE_USE_ENV_PROXY=1, PHASE2 P6).
		"-e", "HTTPS_PROXY=" + proxy,
		"-e", "HTTP_PROXY=" + proxy,
		"-e", "NODE_USE_ENV_PROXY=1",
		"-e", "NODE_EXTRA_CA_CERTS=/ca/mitmproxy.crt",
		// OAuth token by NAME only (value forwarded from podman's env, set on
		// cmd.Env) so the secret never appears in the process argv.
		"-e", "CLAUDE_CODE_OAUTH_TOKEN",
		// Mounts: the host claude binary (in-image build broken, DRIVE-FINDINGS
		// §drift 1) and the staged CA — both read-only, both non-host container
		// paths.
		"-v", cfg.ClaudeBinHost + ":/opt/claude-code:ro",
		"-v", stagedCA + ":/ca/mitmproxy.crt:ro",
	}
	// Optional read-WRITE /work mount so a scripted drive's VM-side effect (a
	// proof file CC writes under /work) is observable on the host. Only the
	// side-effect scripted-drive test sets WorkdirHost; the forbidden-mount
	// self-check still rejects a sensitive target (it must be a ~/tmp scratch dir).
	if cfg.WorkdirHost != "" {
		args = append(args, "-v", cfg.WorkdirHost+":/work:rw")
	}
	args = append(args,
		cfg.Image,
		// The in-container runtime assert (G7) re-checks the namespace then exec's
		// claude with the argv below.
		"/usr/local/bin/cc-sandbox-entry",
		"--input-format", "stream-json",
		"--output-format", "stream-json",
		"--verbose",
		"--no-session-persistence",
		"--model", cfg.Model,
		"--permission-mode", "default",
		// The NATIVE control-channel switch (DRIVE-FINDINGS §1): a tool ask arrives
		// as a control_request{can_use_tool}; NO --allowedTools, so it is not
		// auto-suppressed.
		"--permission-prompt-tool", "stdio",
		"--max-budget-usd", cfg.BudgetUSD,
	)
	return args
}

// selfCheck runs the fail-closed safety self-checks BEFORE any container starts.
// Any failure aborts the launch. These mirror the cc_sandbox.sh G-gates the live
// harness cannot delegate to (the script is print-only) and the task safety rails.
func (cfg LiveDriveConfig) selfCheck() error {
	var problems []string
	// Rootless: refuse to launch as uid 0 (PHASE2 §5 — rootless = fresh userns).
	if os.Geteuid() == 0 {
		problems = append(problems, "refusing to live-drive as uid 0 (rootless podman required, PHASE2 §5)")
	}
	// Image pin (G5): never :latest, must carry the version pin.
	if cfg.Image == "" || strings.HasSuffix(cfg.Image, ":latest") {
		problems = append(problems, fmt.Sprintf("image %q must be a D49-pinned tag, never :latest", cfg.Image))
	}
	// Model rail: pinned to sonnet.
	if cfg.Model != "sonnet" {
		problems = append(problems, fmt.Sprintf("model %q is not the pinned 'sonnet' (safety rail)", cfg.Model))
	}
	// Budget rail: a cost cap must be set (record mode reaches the live API).
	if cfg.BudgetUSD == "" {
		problems = append(problems, "empty BudgetUSD (a --max-budget-usd cost guard is required for the live API)")
	}
	// The CA must exist to stage.
	if _, err := os.Stat(cfg.CAHost); err != nil {
		problems = append(problems, fmt.Sprintf("mitmproxy CA %q not readable: %v", cfg.CAHost, err))
	}
	// The host claude binary must exist to mount.
	if _, err := os.Stat(cfg.ClaudeBinHost); err != nil {
		problems = append(problems, fmt.Sprintf("host claude binary %q not present: %v", cfg.ClaudeBinHost, err))
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

// scratchRoot picks the default job-dir root: a dedicated subdir of the user's
// home (~/tmp — the non-tmpfs scratch convention the staged-CA path relies on),
// falling back to the system temp root only when home is unavailable. The
// system default honors TMPDIR, which on CI runners is the host /tmp — exactly
// what the G4 twin (forbiddenHostMount) rejects by design — so a default job
// dir there would fail the harness's own self-check before anything ran.
func scratchRoot() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	root := filepath.Join(home, "tmp")
	if err := os.MkdirAll(root, 0o700); err != nil {
		return ""
	}
	return root
}

// assertNoForbiddenMount re-checks the built podman argv for a forbidden host
// bind mount (the G4 invariant, in Go): no /tmp/cc-daemon-*, host /tmp, host
// HOME, ~/.claude, or ~/.cia source. The harness builds its OWN argv, so it must
// re-assert G4 itself (the script's G4 cannot gate an argv it did not print).
func assertNoForbiddenMount(argv []string) error {
	home, _ := os.UserHomeDir()
	for i := 0; i < len(argv); i++ {
		if argv[i] != "-v" && argv[i] != "--volume" {
			continue
		}
		if i+1 >= len(argv) {
			continue
		}
		host := argv[i+1]
		if idx := strings.IndexByte(host, ':'); idx >= 0 {
			host = host[:idx]
		}
		if forbiddenHostMount(host, home) {
			return fmt.Errorf("forbidden host bind mount in built argv: %s", host)
		}
	}
	return nil
}

// forbiddenHostMount is the Go twin of cc_sandbox.sh's forbidden_host_path,
// guarding the SAME hazards: the same-uid CC daemon dir, the host /tmp (tmpfs),
// the host HOME ROOT, and the sensitive config dirs ~/.claude / ~/.cia. It does
// NOT blanket-reject every $HOME/* path (the script's broad rule), because the
// harness stages its OWN artifacts — a public CA cert and the UDS — in a
// dedicated job dir under ~/tmp (the btrfs scratch CLAUDE.md mandates), which is
// non-sensitive and must be mountable. The hazard is the daemon dir + the host
// config/tmpfs, not the harness's own scratch; those exact targets are still
// rejected. (The script's plan-printer keeps its broad rule for the CA — it
// points the operator to stage to a non-host path; the harness IS that staging,
// so it allows its own job dir while still failing closed on the real hazards.)
func forbiddenHostMount(p, home string) bool {
	switch {
	case strings.HasPrefix(p, "/tmp/cc-daemon"):
		return true
	case p == "/tmp" || strings.HasPrefix(p, "/tmp/"):
		return true
	case strings.HasSuffix(p, "/.claude") || strings.Contains(p, "/.claude/") || strings.HasSuffix(p, "/.claude.json"):
		return true
	case strings.HasSuffix(p, "/.cia") || strings.Contains(p, "/.cia/"):
		return true
	case home != "" && p == home:
		// the HOME ROOT itself (leaks the whole home); a dedicated subdir is fine.
		return true
	}
	return false
}

// --- small fileutil / wait helpers (stdlib) ----------------------------------

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}

// waitForUDS polls until the host-agent has bound the socket (ServeBridge) or the
// timeout passes.
func waitForUDS(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("e2e: UDS %s never appeared within %s (host-agent did not bind)", path, timeout)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// liveProjectionContains reports whether the projected stream carries at least
// one event of the given type — a small structural predicate the assertions and
// the README evidence share. Kept here (not the test) so a non-test caller (the
// runbook tool) can reuse it.
func liveProjectionContains(evs []attach.Event, t attach.Type) bool {
	for _, ev := range evs {
		if ev.Type == t {
			return true
		}
	}
	return false
}
