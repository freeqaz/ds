// SPDX-License-Identifier: Apache-2.0

// Package nethelperclient is the UNPRIVILEGED agent-side leg of the
// ROOT-HELPER model: it forks the setcap'd `ds-nethelper` binary once per
// privileged operation, feeds the params object on stdin, parses the one
// Result line on stdout, and maps outcomes to sentinel errors the agent's
// create/rollback choreography can branch on.
//
// WIRING (LANDED, D148): this client is the body of the host-agent's live
// AttachPrimitive (orchestrator/cmd/host-agent/nethelperseams.go helperAttach):
// CreateTap ⇒ Client.CreateTap, InstantiateSessionNFT ⇒ Client.InstantiateSession,
// FlushSession ⇒ Client.FlushSession + Client.TeardownSession — the same
// verb-for-verb surface as internal/nftbridge, so the seam swap changed NO
// interface. The host-agent now builds WITHOUT `-tags nftgatelive` forever (a
// tagged build is a compile error, cmd/host-agent/nftgatelive_refuse.go): the
// capability lives on the helper binary and the agent process runs unprivileged.
//
// ROLLBACK / ERROR SIGNALING. Every helper verb is idempotent (the ds-nft
// contract), so the agent's converge-on-retry discipline carries across the
// process boundary unchanged. On a mid-create fault the agent drives
// TeardownAll (flush → teardown → delete-tap): best-effort, each step
// idempotent, errors joined — the NFT-6 unwind plus tap removal.
package nethelperclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/nethelper/nethelperproto"
)

// Sentinel errors the agent branches on (errors.Is).
var (
	// ErrValidation: the helper REJECTED the request at its trust boundary —
	// a caller-side bug (bad binding keys, uid rule); never retried.
	ErrValidation = errors.New("ds-nethelper rejected the request at the trust boundary")
	// ErrBackend: validation passed but ds-nft failed; kernel state may be
	// partial — the agent runs TeardownAll to converge, then may retry.
	ErrBackend = errors.New("ds-nethelper privileged backend (ds-nft) failed")
	// ErrNotBuilt: the installed helper has no privileged backend linked (a
	// stub build) — a deployment fault, surfaced at bring-up by Probe.
	ErrNotBuilt = errors.New("ds-nethelper built without the privileged backend")
	// ErrProtocol: the helper answered something this client cannot trust
	// (bad JSON, version skew, op-echo mismatch, oversized output) or the
	// exec itself failed. Fail-closed: treat the op as NOT performed only if
	// the exit code also says so; otherwise as unknown → converge via
	// idempotent retry/teardown.
	ErrProtocol = errors.New("ds-nethelper protocol fault")
)

// DefaultTimeout bounds one helper invocation. Each op is one netdev/nft
// mutation (sub-second healthy); a stuck `ip`/`nft` must never wedge the
// agent's create path.
const DefaultTimeout = 10 * time.Second

// Client forks the helper per op. Zero-value is not usable: construct with
// New so the helper path is always explicit (never resolved via PATH — the
// agent invokes the ONE installed, setcap'd binary by absolute path).
type Client struct {
	helperPath string
	timeout    time.Duration
}

// New builds a Client over the ABSOLUTE path of the installed helper binary.
// A relative path is rejected: resolving the privileged binary through a
// caller-controlled cwd/PATH would let an attacker substitute it.
func New(helperPath string) (*Client, error) {
	if helperPath == "" {
		return nil, fmt.Errorf("nethelperclient: empty helper path")
	}
	if !strings.HasPrefix(helperPath, "/") {
		return nil, fmt.Errorf("nethelperclient: helper path %q is not absolute (the privileged binary is always invoked by absolute path)", helperPath)
	}
	return &Client{helperPath: helperPath, timeout: DefaultTimeout}, nil
}

// WithTimeout overrides the per-invocation ceiling (<=0 keeps the default).
func (c *Client) WithTimeout(d time.Duration) *Client {
	if d > 0 {
		c.timeout = d
	}
	return c
}

// invoke runs ONE helper op: argv = [op], params marshaled to stdin, stdout
// parsed as the one Result line. The Result is cross-checked (version,
// op echo) before any field is believed.
func (c *Client) invoke(ctx context.Context, op string, params any) (*nethelperproto.Result, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	var stdin bytes.Buffer
	if params != nil {
		if err := json.NewEncoder(&stdin).Encode(params); err != nil {
			return nil, fmt.Errorf("%w: encode params for %s: %v", ErrProtocol, op, err)
		}
	}

	cmd := exec.CommandContext(ctx, c.helperPath, op)
	cmd.Stdin = &stdin
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &limitedWriter{w: &stdout, n: nethelperproto.MaxResultBytes}
	cmd.Stderr = &limitedWriter{w: &stderr, n: nethelperproto.MaxResultBytes}
	runErr := cmd.Run()

	// Parse the Result line first — it is more specific than the bare exit
	// code and carries the backend message for the audit trail.
	var res nethelperproto.Result
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &res); err != nil {
		if runErr != nil {
			return nil, fmt.Errorf("%w: %s: exec failed with no parseable result: %v (stderr: %s)", ErrProtocol, op, runErr, strings.TrimSpace(stderr.String()))
		}
		return nil, fmt.Errorf("%w: %s: unparseable result line: %v", ErrProtocol, op, err)
	}
	if res.V != nethelperproto.ProtocolVersion {
		return nil, fmt.Errorf("%w: %s: helper speaks protocol v%d, client speaks v%d", ErrProtocol, op, res.V, nethelperproto.ProtocolVersion)
	}
	if res.Op != op {
		return nil, fmt.Errorf("%w: asked %q, helper echoed %q", ErrProtocol, op, res.Op)
	}
	if res.OK {
		return &res, nil
	}
	switch res.Code {
	case nethelperproto.CodeValidation:
		return &res, fmt.Errorf("%w: %s: %s", ErrValidation, op, res.Message)
	case nethelperproto.CodeBackend:
		return &res, fmt.Errorf("%w: %s: %s", ErrBackend, op, res.Message)
	case nethelperproto.CodeNotBuilt:
		return &res, fmt.Errorf("%w: %s", ErrNotBuilt, op)
	default:
		return &res, fmt.Errorf("%w: %s: code=%s: %s", ErrProtocol, op, res.Code, res.Message)
	}
}

// ── the verb surface (verb-for-verb with internal/nftbridge) ──────────────

// CreateTap programs the per-session routed tap via the helper.
func (c *Client) CreateTap(ctx context.Context, tapName string, ownerUID, hostSessionIndex uint32, guestMAC string) error {
	_, err := c.invoke(ctx, nethelperproto.OpCreateTap, nethelperproto.CreateTapParams{
		TapName: tapName, OwnerUID: ownerUID, HostSessionIndex: hostSessionIndex, GuestMAC: guestMAC,
	})
	return err
}

// DeleteTap removes the tap netdev (idempotent; absent tap = success).
func (c *Client) DeleteTap(ctx context.Context, tapName string, hostSessionIndex uint32) error {
	_, err := c.invoke(ctx, nethelperproto.OpDeleteTap, nethelperproto.SessionParams{
		TapName: tapName, HostSessionIndex: hostSessionIndex,
	})
	return err
}

// InstantiateSession creates the empty per-session allow-sets.
func (c *Client) InstantiateSession(ctx context.Context, tapName string, hostSessionIndex uint32) error {
	_, err := c.invoke(ctx, nethelperproto.OpInstantiateSession, nethelperproto.SessionParams{
		TapName: tapName, HostSessionIndex: hostSessionIndex,
	})
	return err
}

// FlushSession runs the unconditional NFT-6 conntrack flush.
func (c *Client) FlushSession(ctx context.Context, tapName string, hostSessionIndex uint32) error {
	_, err := c.invoke(ctx, nethelperproto.OpFlushSession, nethelperproto.SessionParams{
		TapName: tapName, HostSessionIndex: hostSessionIndex,
	})
	return err
}

// TeardownSession removes the per-session allow-sets.
func (c *Client) TeardownSession(ctx context.Context, tapName string, hostSessionIndex uint32) error {
	_, err := c.invoke(ctx, nethelperproto.OpTeardownSession, nethelperproto.SessionParams{
		TapName: tapName, HostSessionIndex: hostSessionIndex,
	})
	return err
}

// TablePresent reports whether `inet <table>` exists. nil => present; a non-nil
// error means absent OR nft was unusable, and the caller (the agent's
// boundary-readiness probe) treats both as not-ready — fail closed.
//
// This exists because `nft list` needs CAP_NET_ADMIN just to initialise its
// netlink cache, so the unprivileged D148 agent cannot answer the question
// itself; the capability is on the helper, so the read goes with it. Read-only:
// it cannot alter the floor it reports on.
func (c *Client) TablePresent(ctx context.Context, table string) error {
	_, err := c.invoke(ctx, nethelperproto.OpTablePresent, nethelperproto.TablePresentParams{
		Table: table,
	})
	return err
}

// ProbeStatus is the bring-up readiness answer — the full CAP_NET_ADMIN
// posture, so the agent's readiness gate can tell a `+ep`-only host (helper
// effective-green, but every ds-nft-exec'd ip/nft child stranded unprivileged)
// from a correctly `+eip`-configured one.
type ProbeStatus struct {
	// Built: the installed helper links the privileged ds-nft backend.
	Built bool
	// CapNetAdminEffective: CAP_NET_ADMIN was in the helper's EFFECTIVE set —
	// i.e. setcap actually landed on the installed binary (the rebuilt-binary
	// footgun surfaces HERE, at bring-up, not mid-create).
	CapNetAdminEffective bool
	// CapNetAdminInheritable: CAP_NET_ADMIN was in the INHERITABLE set (the
	// `+i` of `+eip`) — the precondition for the ambient raise the live
	// backend does so its ip/nft children inherit the capability.
	CapNetAdminInheritable bool
	// AmbientRaiseOK: the helper predicted an ambient raise of CAP_NET_ADMIN
	// will succeed (permitted ∧ inheritable). This is the field Ready() gates
	// the live path on.
	AmbientRaiseOK bool
}

// Ready is the fail-closed bring-up predicate the boundary-readiness re-key
// keys on (LANDED as D148: the host-agent's verifyHelperReady +
// helperProbeReadiness replaced the old nftbridge.Built gate): the backend is
// linked AND CAP_NET_ADMIN is both effective and ambient-raisable. A `+ep`-only
// host is NOT ready.
func (p ProbeStatus) Ready() bool {
	return p.Built && p.CapNetAdminEffective && p.AmbientRaiseOK
}

// Probe runs the read-only self-check. The agent's boundary-readiness
// composition treats !status.Ready() as NOT ready — fail-closed before any
// session is admitted.
func (c *Client) Probe(ctx context.Context) (ProbeStatus, error) {
	res, err := c.invoke(ctx, nethelperproto.OpProbe, nil)
	if err != nil {
		return ProbeStatus{}, err
	}
	return ProbeStatus{
		Built:                  res.Built,
		CapNetAdminEffective:   res.CapNetAdminEffective,
		CapNetAdminInheritable: res.CapNetAdminInheritable,
		AmbientRaiseOK:         res.AmbientRaiseOK,
	}, nil
}

// TeardownAll is the agent's rollback/destroy trio in the fixed NFT-6 order:
// flush conntrack (kill live flows first), remove the allow-sets, delete the
// tap. BEST-EFFORT: every step runs regardless of earlier failures (each is
// idempotent, so a partial unwind converges on retry); errors are joined so
// the caller sees every leg that did not confirm.
func (c *Client) TeardownAll(ctx context.Context, tapName string, hostSessionIndex uint32) error {
	var errs []error
	if err := c.FlushSession(ctx, tapName, hostSessionIndex); err != nil {
		errs = append(errs, fmt.Errorf("flush: %w", err))
	}
	if err := c.TeardownSession(ctx, tapName, hostSessionIndex); err != nil {
		errs = append(errs, fmt.Errorf("teardown: %w", err))
	}
	if err := c.DeleteTap(ctx, tapName, hostSessionIndex); err != nil {
		errs = append(errs, fmt.Errorf("delete-tap: %w", err))
	}
	return errors.Join(errs...)
}

// limitedWriter caps captured helper output so a misbehaving helper can never
// balloon the agent's memory; overflow bytes are dropped (the parse then
// fails loud as a protocol fault).
type limitedWriter struct {
	w io.Writer
	n int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if l.n <= 0 {
		return len(p), nil // swallow overflow; report full write so exec keeps draining
	}
	take := p
	if len(take) > l.n {
		take = take[:l.n]
	}
	if _, err := l.w.Write(take); err != nil {
		return 0, err
	}
	l.n -= len(take)
	return len(p), nil
}
