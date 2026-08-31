// SPDX-License-Identifier: Apache-2.0

// Package entrypoint is the guest-side implementation of the D38 VM entrypoint
// contract (the D20 runtime seam, dreamserpent.runtime.v1). It is the binary the
// host agent launches inside a session VM at boot (baked at
// /usr/local/bin/ds-entrypoint, started by ds-entrypoint.service): it loads and
// TOTALLY validates the EntrypointConfig the host agent dropped, launches and
// supervises the agent runtime, wires the runtime's stdio onto the guest-local
// event socket that terminates at the host agent, and reports
// readiness/exit — FAIL-CLOSED at every step.
//
// RUNTIME-AGNOSTIC, ALWAYS (D20/D38). This package launches a LaunchSpec
// (command/args/env/working_dir), copies bytes (io.Copy) between the runtime and
// a UDS, and supervises a process lifecycle. It NEVER parses the runtime's
// protocol (no stream-json, no CC-isms): all Claude-Code-specific code lives in
// client/wrapper/adapters/claude-code/, never here. Swapping the runtime is a
// config change, not a code change.
//
// FAIL-CLOSED (doc 16 §1): no valid config => no runtime => no egress. A missing,
// unreadable, malformed, or invalid config aborts the boot with a nonzero exit;
// the unit's Restart=no means the session is then over (the host agent drives the
// lifecycle, doc 15 §4.2). The boundary is the security authority regardless
// (D42) — this binary failing closed denies the agent a process to run, it does
// not relax any guardrail.
//
// CONFIG-PRESENCE LAUNCH SIGNAL (maintainer ruling 2026-06-15): a valid
// EntrypointConfig present in DS_ENTRYPOINT_CONFIG_DIR is ITSELF the signal to
// launch the runtime — there is no separate env gate. The no-launch path is
// exactly loadConfig failing (absent/empty/invalid config.pb), which is the
// boot-validate / dry-boot case (it drops no config).
//
// NO CREDENTIALS IN-GUEST (D17/D39/D50). The config carries only REFERENCES:
// proxy/CA addresses+paths (EgressWiring) and the session-token FETCH endpoint.
// The session token itself is fetched in-guest from the host-local D22 shim at
// session_token_endpoint; it is never embedded in the config and never handled by
// this binary.
package entrypoint

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// configFileName is the file the host agent drops inside DS_ENTRYPOINT_CONFIG_DIR
// (m0-image.env: /run/ds/entrypoint). The delivery encoding is FREE (OQ-C); this
// binary reads a binary-serialized runtimev1.EntrypointConfig at this path. The
// host agent writes it before boot; the entrypoint refuses to launch without it.
const configFileName = "config.pb"

// configDirEnv is the environment variable ds-entrypoint.service sets to the
// host-agent config drop dir.
const configDirEnv = "DS_ENTRYPOINT_CONFIG_DIR"

// loadConfig reads, decodes, and TOTALLY validates the EntrypointConfig from the
// directory named by DS_ENTRYPOINT_CONFIG_DIR. Every failure mode is fail-closed:
// an unset env var, an absent/unreadable file, a malformed blob, or a config that
// fails validation all return an error and NO config — the caller must then abort
// the boot (no runtime is launched).
func loadConfig(getenv func(string) string) (entrypointConfig, error) {
	dir := getenv(configDirEnv)
	if dir == "" {
		return entrypointConfig{}, fmt.Errorf("%s is unset: refusing to launch without a config", configDirEnv)
	}
	path := filepath.Join(dir, configFileName)
	raw, err := os.ReadFile(path)
	if err != nil {
		return entrypointConfig{}, fmt.Errorf("read entrypoint config %q: %w", path, err)
	}
	if len(raw) == 0 {
		return entrypointConfig{}, fmt.Errorf("entrypoint config %q is empty", path)
	}
	cfg, err := decodeConfig(raw)
	if err != nil {
		return entrypointConfig{}, err
	}
	if err := cfg.validate(); err != nil {
		return entrypointConfig{}, fmt.Errorf("invalid entrypoint config: %w", err)
	}
	return cfg, nil
}

// validate enforces the TOTAL set of invariants the rest of the package relies
// on. It is the single home for "what makes a config launchable", independent of
// the wire format. A config that fails any check is rejected wholesale
// (fail-closed) — the entrypoint never launches a runtime from a partial config.
func (c entrypointConfig) validate() error {
	var errs []error

	// The session join key MUST be present — the host agent joins the
	// readiness/exit report back to the authoritative session record by it
	// (a report the host agent cannot join is useless, and a config with no
	// session is structurally a misdelivery).
	if c.session.sessionUUID == "" {
		errs = append(errs, errors.New("session_ref.session_uuid is required"))
	}

	// The launch surface MUST name a command — there is nothing to supervise
	// without one. Args/env/working_dir are optional.
	if c.launch.command == "" {
		errs = append(errs, errors.New("launch.command is required"))
	}
	// Reject NUL bytes in env entries (the exec layer would otherwise truncate
	// or error opaquely) and require KEY=VALUE shape so a malformed env can never
	// silently drop a setting.
	for i, e := range c.launch.env {
		if err := validateEnvEntry(e); err != nil {
			errs = append(errs, fmt.Errorf("launch.env[%d] %q: %w", i, e, err))
		}
	}

	// The event socket path MUST be present and absolute — the runtime's stdio
	// is bridged onto it (the D38 attach byte-path); a relative or empty path is
	// a misconfiguration we will not guess around.
	if c.attach.eventSocketPath == "" {
		errs = append(errs, errors.New("attach.event_socket_path is required"))
	} else if !filepath.IsAbs(c.attach.eventSocketPath) {
		errs = append(errs, fmt.Errorf("attach.event_socket_path %q must be absolute", c.attach.eventSocketPath))
	}

	// The CA bundle, when named, MUST be an absolute path (it is injected into
	// the guest trust store before boot, doc 15 §4.1 step 7 — a relative ref is
	// meaningless). Empty is allowed: a session with no egress CA.
	if p := c.egress.caBundlePath; p != "" && !filepath.IsAbs(p) {
		errs = append(errs, fmt.Errorf("egress.ca_bundle_path %q must be absolute", p))
	}

	// Defense in depth against a credential leaking through a reference field
	// (D17/D39/D50): none of the egress reference fields may carry PEM material.
	for _, ref := range []struct {
		name, val string
	}{
		{"egress.http_proxy", c.egress.httpProxy},
		{"egress.https_proxy", c.egress.httpsProxy},
		{"egress.ca_bundle_path", c.egress.caBundlePath},
		{"session_token_endpoint", c.sessionTokenEndpoint},
	} {
		if looksLikeCredentialMaterial(ref.val) {
			errs = append(errs, fmt.Errorf("%s must be a reference, not credential material", ref.name))
		}
	}

	return errors.Join(errs...)
}
