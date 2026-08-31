// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	kvclient "github.com/dream-serpent/dream-serpent/identity/kv-client"
)

// withState points the CLI's fixture at a fresh temp state file (so the demo
// state does not touch the developer's home), default-off live path.
func withState(t *testing.T) {
	t.Helper()
	t.Setenv(defaultStateEnv, t.TempDir()+"/state.json")
	t.Setenv("FLEETREG_VAULT_ADDR", "") // ensure the synthetic fixture path
}

func runCLI(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	var out, errb bytes.Buffer
	err := run(args, &out, &errb)
	return out.String(), errb.String(), err
}

// TestCLIListDefaultNone: with nothing designated, `list` reports the default-none
// posture — an unconfigured surface designates nothing (doc 16 §11.3 step 1).
func TestCLIListDefaultNone(t *testing.T) {
	withState(t)
	out, _, err := runCLI(t, "list")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if !strings.Contains(out, "NONE") {
		t.Fatalf("default-none list should report NONE, got: %q", out)
	}
}

// TestCLIDesignateRegisterRevokeList drives the full CLI lifecycle against the
// synthetic fixture: designate a prefix, register a per-secret escape hatch,
// list, then revoke — each verb appends to the (fake) policy_log and the consent
// surface persists across invocations (a demo).
func TestCLIDesignateRegisterRevokeList(t *testing.T) {
	withState(t)

	// 1. designate a prefix (org admin). The seeded synthetic tree has two
	//    secrets under secret/data/dreamserpent.
	out, _, err := runCLI(t, "designate", "--mount", "secret", "--prefix", "data/dreamserpent",
		"--actor", "admin@idp", "--role", "org_admin")
	if err != nil {
		t.Fatalf("designate: %v", err)
	}
	if !strings.Contains(out, "policy_log seq=1 committed=true") || !strings.Contains(out, "digested 2 secret") {
		t.Fatalf("designate output unexpected: %q", out)
	}

	// 2. register a per-secret escape hatch OUTSIDE the prefix.
	out, _, err = runCLI(t, "register", "--mount", "secret", "--path", "data/teams/ci/deploy",
		"--actor", "admin@idp", "--role", "org_admin")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if !strings.Contains(out, "escape-hatch") {
		t.Fatalf("register output unexpected: %q", out)
	}

	// 3. list shows both, persisted across the prior invocations.
	out, _, err = runCLI(t, "list")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if !strings.Contains(out, "1 designation(s), 1 escape-hatch") ||
		!strings.Contains(out, "secret/data/dreamserpent") ||
		!strings.Contains(out, "secret/data/teams/ci/deploy") {
		t.Fatalf("list output unexpected: %q", out)
	}

	// 4. revoke the prefix; list then shows only the escape hatch.
	if _, _, err = runCLI(t, "revoke", "--mount", "secret", "--path", "data/dreamserpent",
		"--actor", "admin@idp", "--role", "org_admin"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	out, _, err = runCLI(t, "list")
	if err != nil {
		t.Fatalf("list after revoke: %v", err)
	}
	if !strings.Contains(out, "0 designation(s), 1 escape-hatch") {
		t.Fatalf("list after revoke unexpected: %q", out)
	}
}

// TestCLIAuthorityRefused: a developer cannot designate an org prefix — the CLI
// surfaces the D84 authority refusal and writes nothing.
func TestCLIAuthorityRefused(t *testing.T) {
	withState(t)
	_, _, err := runCLI(t, "designate", "--mount", "secret", "--prefix", "data/dreamserpent",
		"--actor", "alice@idp", "--role", "developer")
	if err == nil {
		t.Fatalf("developer designating an org prefix should be refused")
	}
	// The surface must still be default-none.
	out, _, _ := runCLI(t, "list")
	if !strings.Contains(out, "NONE") {
		t.Fatalf("a refused designation must not mutate the surface; got: %q", out)
	}
}

// TestCLIUnknownCommand / TestCLINoCommand: usage + non-zero on misuse.
func TestCLIMisuse(t *testing.T) {
	withState(t)
	if _, _, err := runCLI(t); err == nil {
		t.Fatalf("no command should error")
	}
	if _, _, err := runCLI(t, "bogus"); err == nil {
		t.Fatalf("unknown command should error")
	}
}

// TestLiveVaultIsDeferredManualStep: setting FLEETREG_VAULT_ADDR is refused with
// a deferred-manual-step message — the live path is env-gated and OFF by default
// (D50). No live store is ever dialed in this wave.
func TestLiveVaultIsDeferredManualStep(t *testing.T) {
	t.Setenv("FLEETREG_VAULT_ADDR", "https://vault.invalid:8200")
	_, _, err := runCLI(t, "list")
	if err == nil || !strings.Contains(err.Error(), "deferred manual step") {
		t.Fatalf("live Vault should be refused as a deferred manual step, got: %v", err)
	}
}

// TestKVAdapterAgainstFakeOpenBao proves the cross-module seam: the kvSourceAdapter
// drives identity/kv-client.Client against an httptest fake OpenBao/Vault server
// (D50 — synthetic, no live store), walking a designated tree and reading a leaf
// through the SAME ListKeys/ReadSecret surface kv-client exposes (doc 16 §11.3).
func TestKVAdapterAgainstFakeOpenBao(t *testing.T) {
	// KV-v2 logical paths (kv-client inserts the data/ + metadata/ infix). The
	// server tree is keyed by the resulting <mount>/data/<logical> API path.
	srv := fakeOpenBao(t, map[string]map[string]any{
		"secret/data/dreamserpent/github": {"token": "ds-synth-github"},
		"secret/data/dreamserpent/aws":    {"key": "ds-synth-aws"},
	})
	defer srv.Close()

	c, err := kvclient.New(srv.URL, "secret",
		kvclient.JWTOIDCAuth{Role: "platform", JWT: "ds-synth-jwt"},
		kvclient.WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatalf("kvclient.New: %v", err)
	}
	src := newKVSource(c)

	leaves, err := src.ListLeaves(context.Background(), "secret", "dreamserpent")
	if err != nil {
		t.Fatalf("ListLeaves: %v", err)
	}
	sort.Strings(leaves)
	want := []string{"dreamserpent/aws", "dreamserpent/github"}
	if strings.Join(leaves, ",") != strings.Join(want, ",") {
		t.Fatalf("ListLeaves = %v, want %v", leaves, want)
	}

	pt, err := src.ReadSecret(context.Background(), "secret", "dreamserpent/github")
	if err != nil {
		t.Fatalf("ReadSecret: %v", err)
	}
	if !strings.Contains(string(pt), "ds-synth-github") {
		t.Fatalf("ReadSecret plaintext should carry the synthetic value, got %q", pt)
	}
	// Determinism: a re-read produces identical bytes (digest-stable, so a re-sync
	// of an unchanged secret yields the same digest).
	pt2, _ := src.ReadSecret(context.Background(), "secret", "dreamserpent/github")
	if !bytes.Equal(pt, pt2) {
		t.Fatalf("canonical secret bytes must be deterministic across reads")
	}
}

// fakeOpenBao is a minimal httptest server speaking the Vault KV-v2 + jwt-login
// wire shapes kv-client expects. Keys are canonical "mount/data/<path>".
func fakeOpenBao(t *testing.T, tree map[string]map[string]any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/v1/")
		switch {
		case strings.HasPrefix(p, "auth/") && strings.HasSuffix(p, "/login"):
			writeJSON(w, map[string]any{"auth": map[string]any{"client_token": "ds-synth-token"}})
		case strings.Contains(p, "/metadata/") || strings.HasSuffix(p, "/metadata"):
			// LIST under <mount>/metadata/<prefix>?list=true → immediate children.
			prefix := metadataLogical(p)
			children := map[string]struct{}{}
			for full := range tree {
				// Tree keys are "secret/data/<logical>"; the metadata LIST is over
				// the LOGICAL tree (no data/ infix), so the prefix kv-client
				// requested is e.g. "dreamserpent".
				logical := strings.TrimPrefix(full, "secret/data/")
				if logical == prefix || strings.HasPrefix(logical, prefix+"/") {
					rest := strings.TrimPrefix(strings.TrimPrefix(logical, prefix), "/")
					seg, _, more := strings.Cut(rest, "/")
					if more {
						children[seg+"/"] = struct{}{}
					} else {
						children[seg] = struct{}{}
					}
				}
			}
			keys := make([]string, 0, len(children))
			for k := range children {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			writeJSON(w, map[string]any{"data": map[string]any{"keys": keys}})
		case strings.Contains(p, "/data/"):
			data, ok := tree[p]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				writeJSON(w, map[string]any{"errors": []string{"not found"}})
				return
			}
			writeJSON(w, map[string]any{"data": map[string]any{"data": data, "metadata": map[string]any{"version": 1}}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// metadataLogical extracts the logical prefix from a "secret/metadata/<prefix>"
// API path (the data/ infix the KV-v2 list maps onto data-tree keys).
func metadataLogical(apiPath string) string {
	idx := strings.Index(apiPath, "/metadata")
	if idx < 0 {
		return ""
	}
	rest := strings.TrimPrefix(apiPath[idx:], "/metadata")
	rest = strings.Trim(rest, "/")
	// kv-client lists under the LOGICAL prefix; our tree keys are under data/.
	if rest == "" {
		return ""
	}
	return rest
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
