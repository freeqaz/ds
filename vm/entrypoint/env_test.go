// SPDX-License-Identifier: Apache-2.0

package entrypoint

import (
	"strings"
	"testing"
)

func envMap(entries []string) map[string]string {
	m := map[string]string{}
	for _, e := range entries {
		if i := strings.IndexByte(e, '='); i > 0 {
			m[e[:i]] = e[i+1:]
		}
	}
	return m
}

func TestBuildRuntimeEnv_ThreadsProxyAndCA(t *testing.T) {
	cfg := entrypointConfig{
		launch: launchSpec{env: []string{"FOO=bar"}},
		egress: egressWiring{
			httpProxy:    "127.0.0.1:18080",
			httpsProxy:   "127.0.0.1:18080",
			noProxy:      []string{"127.0.0.1", "::1"},
			caBundlePath: "/etc/ds/ca.pem",
		},
	}
	env := envMap(buildRuntimeEnv([]string{"BASE=1"}, cfg))

	if env["BASE"] != "1" {
		t.Errorf("base env not preserved: %v", env["BASE"])
	}
	if env["FOO"] != "bar" {
		t.Errorf("launch env not layered: %v", env["FOO"])
	}
	if env["HTTP_PROXY"] != "127.0.0.1:18080" || env["http_proxy"] != "127.0.0.1:18080" {
		t.Errorf("HTTP_PROXY not threaded: %v / %v", env["HTTP_PROXY"], env["http_proxy"])
	}
	if env["HTTPS_PROXY"] != "127.0.0.1:18080" {
		t.Errorf("HTTPS_PROXY not threaded: %v", env["HTTPS_PROXY"])
	}
	if env["NO_PROXY"] != "127.0.0.1,::1" {
		t.Errorf("NO_PROXY not joined: %v", env["NO_PROXY"])
	}
	// undici needs NODE_USE_ENV_PROXY=1 or it ignores HTTPS_PROXY.
	if env["NODE_USE_ENV_PROXY"] != "1" {
		t.Errorf("NODE_USE_ENV_PROXY not set: %v", env["NODE_USE_ENV_PROXY"])
	}
	if env["NODE_EXTRA_CA_CERTS"] != "/etc/ds/ca.pem" || env["SSL_CERT_FILE"] != "/etc/ds/ca.pem" {
		t.Errorf("CA bundle not threaded: %v / %v", env["NODE_EXTRA_CA_CERTS"], env["SSL_CERT_FILE"])
	}
}

func TestBuildRuntimeEnv_OwnsProxyKeys(t *testing.T) {
	// A stale proxy value in base/launch env must NOT survive — this binary owns
	// the proxy keys, so a runtime can never bypass the egress gateway.
	cfg := entrypointConfig{
		launch: launchSpec{env: []string{"HTTPS_PROXY=evil:9999"}},
		egress: egressWiring{httpsProxy: "127.0.0.1:18080"},
	}
	env := envMap(buildRuntimeEnv([]string{"HTTP_PROXY=stale:1"}, cfg))
	if env["HTTPS_PROXY"] != "127.0.0.1:18080" {
		t.Errorf("stale HTTPS_PROXY not overridden: %v", env["HTTPS_PROXY"])
	}
	// No egress http_proxy named => the inherited stale one must be cleared.
	if _, ok := env["HTTP_PROXY"]; ok {
		t.Errorf("stale inherited HTTP_PROXY not cleared: %v", env["HTTP_PROXY"])
	}
}

func TestBuildRuntimeEnv_NoEgress_ClearsProxy(t *testing.T) {
	// Empty egress wiring => no proxy env at all (default-deny network => no
	// egress; fail-closed).
	cfg := entrypointConfig{egress: egressWiring{}}
	env := envMap(buildRuntimeEnv([]string{"HTTP_PROXY=stale:1", "HTTPS_PROXY=stale:2"}, cfg))
	for _, k := range proxyEnvKeys {
		if _, ok := env[k]; ok {
			t.Errorf("proxy key %q should be cleared with no egress wiring", k)
		}
	}
}

func TestBuildRuntimeEnv_NoCredentials(t *testing.T) {
	// The session token is never set; only references thread through.
	cfg := entrypointConfig{
		sessionTokenEndpoint: "http://169.254.0.2/token",
		egress:               egressWiring{caBundlePath: "/etc/ds/ca.pem"},
	}
	env := envMap(buildRuntimeEnv(nil, cfg))
	for k, v := range env {
		if strings.Contains(strings.ToUpper(k), "TOKEN") {
			t.Errorf("token-bearing env leaked: %s=%s", k, v)
		}
	}
}

func TestLooksLikeCredentialMaterial(t *testing.T) {
	creds := []string{
		"-----BEGIN CERTIFICATE-----",
		"-----BEGIN PRIVATE KEY-----",
		"some PRIVATE KEY blob",
	}
	for _, c := range creds {
		if !looksLikeCredentialMaterial(c) {
			t.Errorf("should flag credential material: %q", c)
		}
	}
	refs := []string{"", "127.0.0.1:18080", "/etc/ds/ca.pem", "http://host/token"}
	for _, r := range refs {
		if looksLikeCredentialMaterial(r) {
			t.Errorf("should NOT flag reference: %q", r)
		}
	}
}
