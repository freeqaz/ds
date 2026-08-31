// SPDX-License-Identifier: Apache-2.0

package entrypoint

import (
	"fmt"
	"strings"
)

// env.go builds the runtime process environment and guards the credential-free
// invariant. It threads the EgressWiring proxy/CA REFERENCES (D17/D39) into the
// launched runtime's env — addresses and a bundle PATH only, never material —
// plus NODE_USE_ENV_PROXY=1 (undici, which Node's HTTP stack uses, ignores
// HTTPS_PROXY unless this is set, so without it the runtime would silently
// bypass the TLS-terminating egress gateway).
//
// The session TOKEN is never set here: it is fetched in-guest from the
// host-local D22 shim at session_token_endpoint (D39/D50), not embedded.

// proxyEnvKeys is the set of proxy/CA env vars this binary OWNS — it always sets
// them from EgressWiring (or removes them when the wiring is empty), so a stale
// value in LaunchSpec.env can never let the runtime bypass the egress gateway.
var proxyEnvKeys = []string{
	"HTTP_PROXY", "http_proxy",
	"HTTPS_PROXY", "https_proxy",
	"NO_PROXY", "no_proxy",
	"NODE_USE_ENV_PROXY",
	// TLS trust: Node and most clients honor these for a custom CA bundle.
	"NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE",
}

// buildRuntimeEnv composes the environment for the launched runtime from the
// LaunchSpec env (the env-spec-resolved, non-secret base) plus the egress
// proxy/CA references, with the proxy/CA keys this binary owns taking
// precedence. The result is deterministic (sorted-by-insertion via the base then
// owned overrides) and contains no credential material.
//
// base is the parent environment (typically os.Environ()); LaunchSpec.env layers
// over it; the owned proxy/CA keys layer last so they are authoritative.
func buildRuntimeEnv(base []string, c entrypointConfig) []string {
	merged := map[string]string{}
	var order []string
	put := func(k, v string) {
		if _, seen := merged[k]; !seen {
			order = append(order, k)
		}
		merged[k] = v
	}

	for _, e := range base {
		if k, v, ok := splitEnv(e); ok {
			put(k, v)
		}
	}
	for _, e := range c.launch.env {
		if k, v, ok := splitEnv(e); ok {
			put(k, v)
		}
	}

	// This binary OWNS the proxy/CA keys: clear any inherited/spec value first,
	// then set exactly what EgressWiring names. An empty wiring means the keys
	// stay cleared (no egress reference => the runtime gets no proxy env, which
	// under default-deny networking means no egress — fail-closed).
	for _, k := range proxyEnvKeys {
		delete(merged, k)
	}
	owned := ownedProxyEnv(c.egress)
	for _, k := range proxyEnvKeyOrder {
		if v, ok := owned[k]; ok {
			put(k, v)
		}
	}

	out := make([]string, 0, len(order))
	for _, k := range order {
		if _, ok := merged[k]; ok {
			out = append(out, k+"="+merged[k])
		}
	}
	return out
}

// proxyEnvKeyOrder fixes a deterministic emission order for the owned keys.
var proxyEnvKeyOrder = []string{
	"HTTP_PROXY", "http_proxy",
	"HTTPS_PROXY", "https_proxy",
	"NO_PROXY", "no_proxy",
	"NODE_USE_ENV_PROXY",
	"NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE",
}

// ownedProxyEnv computes the proxy/CA env this binary sets from EgressWiring.
// Lower- and upper-case proxy vars are both set (clients disagree on which they
// read). NODE_USE_ENV_PROXY=1 is set whenever a proxy is named (undici needs it).
func ownedProxyEnv(e egressWiring) map[string]string {
	out := map[string]string{}
	proxied := false
	if e.httpProxy != "" {
		out["HTTP_PROXY"] = e.httpProxy
		out["http_proxy"] = e.httpProxy
		proxied = true
	}
	if e.httpsProxy != "" {
		out["HTTPS_PROXY"] = e.httpsProxy
		out["https_proxy"] = e.httpsProxy
		proxied = true
	}
	if len(e.noProxy) > 0 {
		joined := strings.Join(e.noProxy, ",")
		out["NO_PROXY"] = joined
		out["no_proxy"] = joined
	}
	if proxied {
		// undici (Node's HTTP client) ignores HTTPS_PROXY without this.
		out["NODE_USE_ENV_PROXY"] = "1"
	}
	if e.caBundlePath != "" {
		out["NODE_EXTRA_CA_CERTS"] = e.caBundlePath
		out["SSL_CERT_FILE"] = e.caBundlePath
	}
	return out
}

// splitEnv splits a KEY=VALUE entry. Entries without '=' or with an empty key
// are dropped (ok=false).
func splitEnv(e string) (key, val string, ok bool) {
	i := strings.IndexByte(e, '=')
	if i <= 0 {
		return "", "", false
	}
	return e[:i], e[i+1:], true
}

// validateEnvEntry rejects an env entry that is not KEY=VALUE shaped or contains
// a NUL byte (which the exec layer cannot carry). Keys must be non-empty.
func validateEnvEntry(e string) error {
	if strings.IndexByte(e, 0) >= 0 {
		return fmt.Errorf("contains NUL byte")
	}
	i := strings.IndexByte(e, '=')
	if i <= 0 {
		return fmt.Errorf("not KEY=VALUE")
	}
	return nil
}

// looksLikeCredentialMaterial is a coarse guard that a REFERENCE field (a proxy
// address, a CA bundle PATH, a token-fetch endpoint) is not actually carrying
// inline secret MATERIAL (D17/D39/D50). It is defense in depth, not the primary
// control — the contract already says these fields are references — but it turns
// a misdelivered PEM/JWT into a fail-closed rejection instead of a leak.
func looksLikeCredentialMaterial(v string) bool {
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
