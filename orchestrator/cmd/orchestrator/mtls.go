package main

// mtls.go is the cmd-side composition point for the orchestrator's live-dial mutual-TLS
// transport-credentials option (D35). doc 15 §2 places the orchestrator, the per-host host
// agent (the D35 HypervisorDriver v1 gRPC contract), and the Identity D22/D82 service on the
// same internal, network-isolated bare-metal fabric; a deployment that fronts those live
// links with mutual TLS supplies the client cert/key the orchestrator presents plus the CA
// that pins each peer's server cert. The controlplane seams already accept a variadic
// DialOption tail (NewDialRegistry, NewIdentityClients) and export both the env-var NAMES the
// deployment sets (controlplane.EnvDialTLSCert/Key/CA) and the SINGLE credentials builder
// (controlplane.MTLSDialOptionFromEnv); this file reads those PATHS at live-edge construction
// (main.go's liveDeps under DS_ORCH_LIVE=1) and composes the resulting option into the
// registry-/Identity-shaped variadic tail BOTH live dial legs thread.
//
// ONE CREDENTIALS BUILDER, ONE COMPOSITION POINT. The crypto/tls→credentials resolution
// itself lives ONCE, in controlplane.MTLSDialOptionFromEnv (the dial-site that already owns
// the gRPC + crypto/tls dependency, per dialregistry.go's gRPC-confinement header): the
// TLS-1.2 floor, the CA-pinned RootCAs, and the half-config hard-error contract have a single
// source of truth there. This cmd file owns only the bootstrap COMPOSITION — turning that
// (option, configured) result into the variadic DialOption tail main.go's liveDeps passes
// into the live constructors, exactly as it already owns parsing DS_ORCH_HOST_DRIVERS into
// the endpoint map and resolving the store/Identity edges. No new dependency: it imports only
// the controlplane package the bootstrap already depends on.
//
// LIVE-EDGE GATING (D50). This is reached ONLY from liveDeps (under DS_ORCH_LIVE=1); it
// performs NO dial — controlplane.MTLSDialOptionFromEnv constructs the credentials from the
// env-named PEM files and returns the option — so it is exercised with SYNTHETIC in-test
// certs (a test writes a throwaway CA + client keypair to temp files, points the env at them,
// asserts the option is built without opening a socket). With NONE of the three env vars set
// the internal, network-isolated links keep the constructors' insecure default (doc 15 §2); a
// non-live run never reaches here.

import (
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/controlplane"
)

// liveDialOpts resolves the DialOption tail liveDeps threads into BOTH of the orchestrator's
// live dial legs — the per-host hypervisor.v1 driver dial (controlplane.NewDialRegistry) and
// the Identity D22/D82 dial (controlplane.NewIdentityClients) — under DS_ORCH_LIVE=1. It is
// the single, transport-neutral composition point for those edges' mTLS posture: it builds
// the mTLS option from the env via the ONE controlplane credentials builder
// (controlplane.MTLSDialOptionFromEnv) and, when configured, returns it as the constructors'
// variadic dial-option tail; with the env unset (the internal, network-isolated default
// wanted) it returns an empty tail so each constructor applies its insecure default unchanged
// (doc 15 §2). A half-configured triplet is surfaced as an error (a live run fails loudly at
// construction, never half-wiring transport security).
//
// Because BOTH live legs draw their tail from this one helper, the "same mTLS posture for
// both internal-fabric edges" invariant is STRUCTURAL: a future change to the live dial's
// transport posture has exactly one place to land, and the two edges cannot silently diverge.
func liveDialOpts() ([]controlplane.DialOption, error) {
	opt, configured, err := controlplane.MTLSDialOptionFromEnv()
	if err != nil {
		return nil, err
	}
	if !configured {
		// The internal, network-isolated orchestrator↔peer links keep the constructors'
		// insecure default (doc 15 §2): no transport option, so NewDialRegistry /
		// NewIdentityClients apply their default unchanged.
		return nil, nil
	}
	return []controlplane.DialOption{opt}, nil
}
