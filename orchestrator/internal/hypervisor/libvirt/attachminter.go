// SPDX-License-Identifier: Apache-2.0

// attachminter — the M0 host-side AttachHandleMinter (the IssueAttachHandle seam,
// doc 15 §5.4 / D79). It turns "this session is bound on this host" (the recorded
// Binding) into "here is how a client attaches to it": the DIRECT EndpointCandidate
// (the host-local SERVED UDS path) plus a short-lived, session-scoped AuthMaterial token
// drawn from a host-readable token store (D39 — NEVER a long-lived cred; the long-lived
// credentials never enter the VM and never ride this handle), the requested D61 role,
// and a whole-handle expiry.
//
// THE DIRECT ENDPOINT IS THE SERVED HOST-LOCAL UDS (not GuestIP:port). The realized
// DIRECT carrier serpent-tui dials is the framed UDS the host-agent AttachBridge serves
// (hostbridge.TransportUnix), so the candidate Address is the per-session host-local
// SOCKET PATH the bridge binds — NOT the in-guest carriage target. The guest carriage
// (the host→guest leg) moved off TCP GuestIP:4242 onto virtio-vsock guestCID:port
// (m1-live-session-transport spike); that leg is the host serve child's business, never a
// client-facing address. Emitting GuestIP:port here would hand serpent-tui a TCP host:port
// it then tries to dial as a UDS path (its DIRECT→TransportUnix mapping), so the minted
// endpoint MUST be the served UDS path — keyed exactly like the orchestrator endpoint
// resolver (controlplane attachendpoint.go: one socket per session under the shared attach
// socket dir, sanitized session UUID + ".sock"), so the two sides name the SAME socket.
//
// M0 SCOPE (the standing M0-minimal, doc 05 §5; doc 15 §5.4 "M0 is direct
// client→host-agent ONLY"): the endpoint names the served host-local UDS path; the auth
// token is minted + persisted per session in a host-readable store so the mint is
// DETERMINISTIC + idempotent on the session — a retried IssueAttachHandle after a
// control-plane blip re-issues an EQUIVALENT handle (same endpoint, same token, same
// expiry) rather than forking a second seat. The token store is the SAME host-readable
// artifact the host-agent attach-bridge serving leg validates against: mint here, validate
// there, one shared store.
//
// Same posture as live.go / sessionrecord.go / durablecounter.go: reachable on the
// live path (NewAttachHandleMinter under DS_HOSTAGENT_LIVE, offline.go), STDLIB-ONLY
// (crypto/rand + os + encoding/json, no cgo, no identity-service dial yet — the D22
// per-session token mint is the post-M0 swap behind this same AttachTokenSource
// seam). Tokens are JSON files at <OverlayDir>/.ds-attach-tokens/<sessionUUID>.json,
// written ATOMICALLY (temp + rename) so a crash mid-write never leaves a torn token.

package libvirt

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/trustpath"
)

// DefaultAttachPort is the fixed in-guest AF_VSOCK attach port the host→guest carriage
// leg dials when LiveConfig.AttachPort is unset (0). It is a host bring-up fact (doc 13
// §4) surfaced as a default so the offline module never hardcodes a wire port; the
// operator overrides it per host.
//
// THE CROSS-MODULE VSOCK PORT AGREEMENT (m1-live-session-transport spike). This one
// value is the single source of the vsock attach port reused across modules: the
// host-agent serve leg (hostagent.AttachBridgeConfig.VsockPort falls back to it), the
// ds-hostbridge vsock dial (--guest-vsock-port defaults to it), and the in-guest
// forwarder (vm/attachfwd) all name THIS port. It is no longer a TCP/IP port — the attach
// carriage rides virtio-vsock (guestCID:port), no tap/guest-IP/nft on the attach path.
const DefaultAttachPort uint16 = 4242

// DefaultAttachSocketDir is the host-local directory the minted DIRECT UDS candidate is
// rendered under when a minter is built with no explicit socket dir. It MUST equal
// hostagent.DefaultAttachSocketDir (the one home the host-agent AttachBridge serves under
// and the orchestrator endpoint resolver advertises): the minted endpoint, the served
// socket, and the resolver's advertised candidate all name the SAME per-session UDS path.
// The libvirt tree cannot import the hostagent tree (the import direction is
// hostagent → libvirt), so the value is replicated here as the documented file contract at
// the seam (the cabundlesource ref→bytes posture); the daemon composition root threads the
// per-host override into the minter from the SAME config value it passes the AttachBridge,
// so a live host single-sources the dir. A drift between this literal and
// hostagent.DefaultAttachSocketDir would point a client at a socket no bridge serves; the
// offline minter test pins them equal across the seam.
const DefaultAttachSocketDir = "/run/ds/attach"

// attachSocketSuffix is the per-session UDS filename suffix — the SAME suffix the
// host-agent AttachBridge serves under and the orchestrator endpoint resolver advertises
// (one shared path).
const attachSocketSuffix = ".sock"

// attachHandleTTL bounds the whole handle AND its auth credential (doc 15 §5.4: the
// AuthMaterial is short-lived, D39). A token is re-minted once the live one has
// expired; within the TTL the mint is idempotent (the same token is returned).
const attachHandleTTL = 15 * time.Minute

// attachToken is the persisted per-session credential: the opaque bearer token and
// its expiry. Stored as JSON so the serving leg (the next increment) reads the same
// shape to validate an attach against the minted token.
type attachToken struct {
	Token     string `json:"token"`      // hex-encoded opaque bearer material (D39)
	ExpiresAt int64  `json:"expires_at"` // unix seconds; credential expiry
}

// AttachTokenSource yields the short-lived, session-scoped attach token for a
// session. It is DETERMINISTIC + idempotent on sessionUUID within a token's lifetime:
// a repeat call returns the SAME (token, expiry) so a retried mint re-issues an
// equivalent handle, minting a fresh token only when none is live (the first call, or
// the prior token expired). The token is the D39 short-lived credential — NEVER a
// long-lived cred. The M0 impl is a host-readable file store; the post-M0 swap is the
// identity-D22 per-session mint behind this same seam.
type AttachTokenSource interface {
	TokenFor(ctx context.Context, sessionUUID string) (token []byte, expiresAt time.Time, err error)
}

// AttachTokenPeeker is the READ-ONLY view of the attach-token store: it returns the live
// persisted (token, expiry) for a session WITHOUT the mint-on-read side effect of
// TokenFor. Unlike TokenFor it NEVER creates a token file and NEVER rewrites an expired
// one — a peek is a pure disk read. This is the seam the W2 writer-seat validator and the
// W3 drive sink resolve through: both are read-only paths (they check whether a caller
// already holds a live attach, they never provision one), so building them on TokenFor
// turned a validate/resolve for an unknown OR expired session into a disk WRITE — a caller
// past the identity gate could fill the host overlay dir with token files for sessions no
// handle was ever issued for, and a real session's expired token got silently re-minted on
// validate. TokenPeek closes both: no live token ⇒ a clean read-only miss, no file touched.
type AttachTokenPeeker interface {
	// TokenPeek returns the live persisted (token, expiry) for the session. ok=false is a
	// clean "no live token" — the token file is absent, OR the persisted token has expired
	// — with NO side effect (no mint, no rewrite). err is a genuine store fault (an
	// unreadable or corrupt/undecodable token file), never a "not found".
	TokenPeek(ctx context.Context, sessionUUID string) (token []byte, expiresAt time.Time, ok bool, err error)
}

// AttachTokenDisposer is the TEARDOWN view of the attach-token store: it REMOVES a
// session's persisted token file at the §4.2 teardown (doc 15 §4.2), the third role on
// the same store beside the minting AttachTokenSource and the read-only
// AttachTokenPeeker. Without it a DESTROYED session's bearer token stayed on disk until
// its TTL lapsed (attachHandleTTL, 15 minutes) — and the TTL is this store's ONLY
// revocation mechanism (doc 19 §7), so a torn-down session's D39 credential outlived the
// session it scoped. That is precisely the doc 06 §(b) clean-teardown row's "no leftover
// minted identity": the session is gone, so its credential must be too.
//
// It is an EXTENSION interface (the MintClient→MintExpiryClient posture, identityseams.go)
// rather than a widening of AttachTokenSource, so every existing token-source consumer and
// fake is untouched: the composition root type-asserts the gate-aware store it already
// built up to this role and hands it to the §4.2 purge.
type AttachTokenDisposer interface {
	// RemoveToken deletes the session's persisted attach token (the §4.2 teardown).
	// IDEMPOTENT: an ABSENT token file is a CLEAN SUCCESS, never an error — a session
	// that never minted (the offline no-launch path, a create that rolled back before the
	// post-boot mint) and a §4.2 re-drive over an already-purged session both converge.
	// A genuine store fault (an unremovable file, a read-only dir) surfaces so the
	// teardown is truthful about a credential still on disk.
	RemoveToken(ctx context.Context, sessionUUID string) error
}

// fileAttachTokenStore is the production AttachTokenSource: one JSON token file per
// session under <OverlayDir>/.ds-attach-tokens, minted with crypto/rand and persisted
// atomically. It is the host-readable store the standing M0-minimal names; the
// serving leg validates an attach against the same files.
type fileAttachTokenStore struct {
	dir string
	ttl time.Duration
	now func() time.Time
	mu  sync.Mutex // serializes read-or-mint-then-persist so concurrent mints converge
}

// NewFileAttachTokenStore builds the token store under baseDir/.ds-attach-tokens,
// creating the directory if absent. baseDir is the host's OverlayDir (the per-session
// state area). A non-positive ttl falls back to attachHandleTTL.
func NewFileAttachTokenStore(baseDir string, ttl time.Duration) (*fileAttachTokenStore, error) {
	if baseDir == "" {
		return nil, fmt.Errorf("attach token store: empty base dir")
	}
	if ttl <= 0 {
		ttl = attachHandleTTL
	}
	dir := trustpath.AttachTokensSubdirPath(baseDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("attach token store: mkdir %q: %w", dir, err)
	}
	return &fileAttachTokenStore{dir: dir, ttl: ttl, now: time.Now}, nil
}

// tokenPath is the deterministic JSON path for a session's token. The subdir + the
// sanitize+".json" leaf are single-sourced through trustpath (s.dir is already
// trustpath.AttachTokensSubdirPath(baseDir)), so this consumer carries no inline
// subdir/extension transform of its own.
func (s *fileAttachTokenStore) tokenPath(sessionUUID string) string {
	return filepath.Join(s.dir, trustpath.AttachTokenFilename(sessionUUID))
}

// TokenFor returns the live token for the session, minting + persisting a fresh one
// only when none exists or the persisted one has expired. The read-then-mint is
// serialized under mu so two concurrent IssueAttachHandle calls for the same session
// converge on one token rather than racing two files.
func (s *fileAttachTokenStore) TokenFor(_ context.Context, sessionUUID string) ([]byte, time.Time, error) {
	if sessionUUID == "" {
		return nil, time.Time{}, fmt.Errorf("attach token store: empty session uuid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()

	// Reuse a live persisted token (idempotent on the session within the TTL). A
	// corrupt/undecodable token is fail-loud — never silently re-minted (it would
	// invalidate a handle already in a client's hand).
	if raw, exp, ok, err := s.readLive(sessionUUID, now); err != nil {
		return nil, time.Time{}, err
	} else if ok {
		return raw, exp, nil
	}

	// Mint + persist a fresh token (the first call, or the prior one expired).
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, time.Time{}, fmt.Errorf("attach token store: mint %s: %w", sessionUUID, err)
	}
	exp := now.Add(s.ttl)
	tok := attachToken{Token: hex.EncodeToString(raw), ExpiresAt: exp.Unix()}
	if err := s.persist(s.tokenPath(sessionUUID), tok); err != nil {
		return nil, time.Time{}, err
	}
	// Re-read the persisted second-granularity expiry so the returned expiry matches
	// exactly what a later reuse (and the serving leg) will see.
	return raw, time.Unix(exp.Unix(), 0), nil
}

// readLive is the ONE decode of a persisted token file, shared by TokenFor's reuse arm
// and TokenPeek (so the mint path and the read-only validate/resolve paths can never
// drift on the file format or the liveness rule). It returns ok=true + (token, expiry)
// only when a persisted token exists AND is still live at now; an absent file OR an
// expired token is a clean ok=false with nil err and NO disk write. An unreadable or
// corrupt/undecodable token file is fail-loud (err), never silently treated as absent.
// Callers hold s.mu.
func (s *fileAttachTokenStore) readLive(sessionUUID string, now time.Time) ([]byte, time.Time, bool, error) {
	data, err := os.ReadFile(s.tokenPath(sessionUUID))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, time.Time{}, false, nil
		}
		return nil, time.Time{}, false, fmt.Errorf("attach token store: read %s: %w", sessionUUID, err)
	}
	var tok attachToken
	if err := json.Unmarshal(data, &tok); err != nil {
		return nil, time.Time{}, false, fmt.Errorf("attach token store: unmarshal %s: %w", sessionUUID, err)
	}
	exp := time.Unix(tok.ExpiresAt, 0)
	if !exp.After(now) {
		return nil, time.Time{}, false, nil
	}
	raw, err := hex.DecodeString(tok.Token)
	if err != nil {
		return nil, time.Time{}, false, fmt.Errorf("attach token store: decode %s: %w", sessionUUID, err)
	}
	return raw, exp, true, nil
}

func (s *fileAttachTokenStore) persist(path string, tok attachToken) error {
	data, err := json.Marshal(tok)
	if err != nil {
		return fmt.Errorf("attach token store: marshal: %w", err)
	}
	tmp, err := os.CreateTemp(s.dir, ".ds-tok-*.tmp")
	if err != nil {
		return fmt.Errorf("attach token store: stage temp: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("attach token store: write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("attach token store: close temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("attach token store: rename -> %q: %w", path, err)
	}
	return nil
}

// TokenPeek reads the session's live persisted token WITHOUT ever minting or rewriting
// (the read-only twin of TokenFor). It returns ok=true + the token only when a persisted
// token exists AND is still live; an absent file OR an expired token is a clean ok=false
// with NO disk write (an expired token is left exactly as-is on disk — TokenPeek never
// re-mints it, so a validate/resolve for an expired session cannot rewrite the store). A
// corrupt/undecodable token is fail-loud (err), never silently treated as absent. Holds mu
// so a peek is consistent against a concurrent TokenFor mint, and reads through the SAME
// readLive decode the mint path reuses — the two paths cannot drift on the file format or
// the liveness rule.
func (s *fileAttachTokenStore) TokenPeek(_ context.Context, sessionUUID string) ([]byte, time.Time, bool, error) {
	if sessionUUID == "" {
		return nil, time.Time{}, false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readLive(sessionUUID, s.now())
}

// RemoveToken deletes the session's persisted token file (the §4.2 teardown purge of the
// D39 short-lived credential). It holds mu — the SAME mutex the mint and the peek take —
// so a purge can never interleave with a concurrent TokenFor read-or-mint and leave a
// freshly-minted token behind the removal. An ABSENT file is a clean no-op success (the
// idempotency contract: a never-minted session and a re-driven teardown both converge);
// any OTHER remove fault surfaces, so a credential the host could not delete is never
// reported as cleanly torn down. An empty sessionUUID is a caller error — never a bare
// "<dir>/session.json" purge (Sanitize maps "" to the literal "session", so a blind
// removal would delete an unrelated store leaf).
func (s *fileAttachTokenStore) RemoveToken(_ context.Context, sessionUUID string) error {
	if sessionUUID == "" {
		return fmt.Errorf("attach token store: empty session uuid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.Remove(s.tokenPath(sessionUUID)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("attach token store: remove %s: %w", sessionUUID, err)
	}
	return nil
}

var _ AttachTokenSource = (*fileAttachTokenStore)(nil)
var _ AttachTokenPeeker = (*fileAttachTokenStore)(nil)
var _ AttachTokenDisposer = (*fileAttachTokenStore)(nil)

// liveAttachHandleMinter is the production AttachHandleMinter: it renders the endpoint
// as the host-local SERVED UDS path (keyed on the session UUID under the attach socket
// dir — the SAME socket the AttachBridge serves), draws the session-scoped token from
// the AttachTokenSource, and tags the endpoint transport from the session's RESOLVED
// mode (DIRECT for structured, RAW_TERMINAL for terminal). Stdlib-only; touches no
// KVM/libvirt/exec — only the token dir, the mode marker, and a path render.
type liveAttachHandleMinter struct {
	tokens    AttachTokenSource
	socketDir string // host-local served-UDS dir (single-sourced with hostagent.DefaultAttachSocketDir)
	// modes is the SINGLE-SOURCE per-session resolved-mode store the EntrypointProducer
	// wrote at create (sessionmodestore.go; doc 04 §2.7). The minter reads ModeFor at
	// mint time so the handle transport tag (DIRECT vs RAW_TERMINAL) derives from the
	// SAME resolution as the serving child's --mode and the LaunchSpec.stdio — they
	// cannot drift. nil ⇒ every session mints DIRECT (the structured default; an absent
	// marker also reads structured), so a minter built without a mode store is
	// byte-identical to the pre-terminal behavior.
	modes SessionModeStore
}

// NewLiveAttachHandleMinter builds the real minter from the host facts. Reachable on
// the live path; constructible offline for unit tests (it touches no substrate — only
// a token dir under OverlayDir). The minted DIRECT endpoint is the served host-local UDS
// path under DefaultAttachSocketDir (LiveConfig carries no per-host socket-dir override;
// the gate-aware NewAttachHandleMinterFromTokens path threads the daemon's single-sourced
// dir). The LiveConfig.AttachPort is the vsock CARRIAGE port (the host serve leg's
// business), not the client-facing endpoint, so it is no longer read here.
func NewLiveAttachHandleMinter(cfg LiveConfig) (AttachHandleMinter, error) {
	if cfg.OverlayDir == "" {
		return nil, fmt.Errorf("live attach minter requires an overlay/state dir for the token store (DS_HOSTAGENT_LIVE)")
	}
	tokens, err := NewFileAttachTokenStore(cfg.OverlayDir, attachHandleTTL)
	if err != nil {
		return nil, err
	}
	// The per-session resolved-mode store the EntrypointProducer wrote (sessionmodestore.go)
	// lives under the SAME OverlayDir; the minter reads it so the endpoint transport tag
	// (DIRECT vs RAW_TERMINAL) derives from the SAME resolution as the serving child's
	// --mode and the LaunchSpec.stdio (doc 04 §2.7 / §5 drift guard). An absent marker
	// reads structured → DIRECT, so a session created before the terminal MVP mints
	// exactly as before.
	modes, err := NewFileSessionModeStore(cfg.OverlayDir)
	if err != nil {
		return nil, err
	}
	return &liveAttachHandleMinter{tokens: tokens, socketDir: DefaultAttachSocketDir, modes: modes}, nil
}

// NewAttachTokenStore returns the gate-aware SHARED per-session attach token store —
// the ONE store both the IssueAttachHandle minter and the create-path serving-leg
// mint draw from. Live (DS_HOSTAGENT_LIVE) → the host-readable file store under
// <OverlayDir>/.ds-attach-tokens; nil otherwise (offline: no token store, the minter
// stays Unimplemented and the serving leg no-launches). Sharing ONE store is what
// makes the token minted at create (so the serving child has something to validate
// against) the SAME token IssueAttachHandle hands the client (TokenFor is idempotent
// within the TTL), instead of two file-backed stores racing a fresh mint.
func NewAttachTokenStore(cfg LiveConfig) (AttachTokenSource, error) {
	if !LiveEnabled() {
		return nil, nil
	}
	if cfg.OverlayDir == "" {
		return nil, fmt.Errorf("live attach token store requires an overlay/state dir (DS_HOSTAGENT_LIVE)")
	}
	return NewFileAttachTokenStore(cfg.OverlayDir, attachHandleTTL)
}

// NewAttachHandleMinterFromTokens builds the gate-aware minter over a PROVIDED token
// source so the minter and the create-path serving-leg mint share ONE store (mint
// once at create, return the same idempotent token at issue). Live with a non-nil
// store → the minter over those tokens + the served-UDS socket dir; offline or a nil store
// → nil (the honest-Unimplemented posture). Pair it with NewAttachTokenStore.
//
// socketDir is the host-local served-UDS dir the minted DIRECT candidate is keyed under —
// the daemon composition root threads the SAME value it passes the AttachBridge
// (hostagent.DefaultAttachSocketDir, or the per-host override), so the minted endpoint and
// the served socket name the SAME path. An empty socketDir falls back to
// DefaultAttachSocketDir (== hostagent.DefaultAttachSocketDir).
// modes is the SINGLE-SOURCE per-session resolved-mode store (sessionmodestore.go) the
// minter reads at mint time to tag the endpoint transport (DIRECT vs RAW_TERMINAL) from
// the SAME resolution the EntrypointProducer persisted — the daemon root threads the
// SAME store it wires into the producer, so the handle, the serving child's --mode, and
// the LaunchSpec.stdio cannot drift. A nil store (or an absent per-session marker) mints
// DIRECT (the structured default), keeping a no-mode-store minter byte-identical to the
// pre-terminal behavior.
func NewAttachHandleMinterFromTokens(cfg LiveConfig, tokens AttachTokenSource, socketDir string, modes SessionModeStore) (AttachHandleMinter, error) {
	if !LiveEnabled() || tokens == nil {
		return nil, nil
	}
	_ = cfg // LiveConfig.AttachPort is the vsock carriage port (the serve leg's), not the client endpoint.
	if socketDir == "" {
		socketDir = DefaultAttachSocketDir
	}
	return &liveAttachHandleMinter{tokens: tokens, socketDir: socketDir, modes: modes}, nil
}

// directEndpoint renders the M0 DIRECT EndpointCandidate: the host-local SERVED UDS path
// (the socket the AttachBridge binds for the session — what serpent-tui's
// DIRECT→TransportUnix carrier actually dials), keyed on the sanitized session UUID under
// the attach socket dir, exactly like the orchestrator endpoint resolver. The recorded
// binding is still validated fail-closed (a malformed binding — the three-keys precondition
// broken — must never yield a servable handle), but the binding's guest IP is no longer the
// endpoint address (the guest carriage is the vsock leg, the serve child's business, never
// a client-facing address). ServerName is empty at M0 (the host-local direct hop has no SNI
// to verify; the per-session CA guards the EXTERNAL path).
// mode selects the transport TAG (the byte-format the serving child realizes):
// SessionModeStructured → DIRECT (the attach.v1 framed UDS); SessionModeTerminal →
// RAW_TERMINAL (the raw pty byte duplex + resize). The UDS PATH render is identical
// either way — RAW_TERMINAL is a fourth byte-format on the SAME host-local DIRECT hop
// (doc 04 §2.7), not a new network transport; serpent-tui reads the tag and picks its
// carrier (DialTerminal vs Dial), exactly as it picks DIRECT→TransportUnix today.
func directEndpoint(socketDir, sessionUUID string, b Binding, mode SessionMode) (*attachv1.EndpointCandidate, error) {
	if _, err := b.GuestIP.Addr(); err != nil {
		return nil, fmt.Errorf("render attach endpoint: %w", err)
	}
	udsPath := filepath.Join(socketDir, sanitizeAnchorComponent(sessionUUID)+attachSocketSuffix)
	transport := attachv1.EndpointTransport_ENDPOINT_TRANSPORT_DIRECT
	if mode == SessionModeTerminal {
		transport = attachv1.EndpointTransport_ENDPOINT_TRANSPORT_RAW_TERMINAL
	}
	return &attachv1.EndpointCandidate{
		Transport: transport,
		Address:   udsPath,
	}, nil
}

// MintAttachHandle mints the attach.v1 handle for the session's recorded binding in
// the requested role (the AttachHandleMinter seam). DETERMINISTIC + idempotent on
// (sessionUUID, role): the endpoint is a pure function of the binding and the token
// source returns the SAME live token within the TTL, so a retry yields an equivalent
// handle. The role is carried through faithfully (the WatchSession terminator
// arbitrates the seat, not the minter). AuthMaterial.expires_at == the whole-handle
// expires_at (the credential and the handle share the one TTL at M0).
func (m *liveAttachHandleMinter) MintAttachHandle(ctx context.Context, sessionUUID string, b Binding, role attachv1.Role) (*attachv1.AttachHandle, error) {
	if sessionUUID == "" {
		return nil, fmt.Errorf("mint attach handle: empty session uuid")
	}
	// Read the SINGLE-SOURCE resolved mode the producer persisted (doc 04 §2.7): the
	// endpoint transport tag (DIRECT vs RAW_TERMINAL) derives from it, NOT from a wire
	// field (the orchestrator stays runtime-ignorant — it asks "give me a WRITER handle
	// for session S", the host answers with the transport the session's mode dictates).
	// An absent marker / nil store reads structured → DIRECT (the byte-identical default);
	// a CORRUPT marker is fail-loud (it must not silently downgrade a terminal session to
	// a DIRECT handle and mis-route the client onto the wrong carrier).
	mode := SessionModeStructured
	if m.modes != nil {
		resolved, _, err := m.modes.ModeFor(ctx, sessionUUID)
		if err != nil {
			return nil, fmt.Errorf("mint attach handle for session %s: resolve session mode: %w", sessionUUID, err)
		}
		mode = resolved
	}
	endpoint, err := directEndpoint(m.socketDir, sessionUUID, b, mode)
	if err != nil {
		return nil, err
	}
	token, exp, err := m.tokens.TokenFor(ctx, sessionUUID)
	if err != nil {
		return nil, err
	}
	expUnix := uint64(exp.Unix())
	return &attachv1.AttachHandle{
		SessionUuid: sessionUUID,
		Endpoints:   []*attachv1.EndpointCandidate{endpoint},
		Auth: &attachv1.AuthMaterial{
			Token:     token,
			ExpiresAt: expUnix,
		},
		Role:      role,
		ExpiresAt: expUnix,
	}, nil
}

var _ AttachHandleMinter = (*liveAttachHandleMinter)(nil)
