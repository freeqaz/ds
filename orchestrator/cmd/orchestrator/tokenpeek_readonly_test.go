// SPDX-License-Identifier: Apache-2.0

package main

// tokenpeek_readonly_test.go pins the read-only contract the W2 writer-seat attach-auth
// validator and the W3 drive-sink endpoint resolver both now depend on: BOTH resolve the
// session's live token through the store's read-only libvirt.AttachTokenPeeker (TokenPeek),
// never TokenFor, so a validate/resolve for a session with NO live token cannot mint or
// rewrite a token file. The prior os.Stat pre-gate closed only the UNKNOWN-session arm; a
// REAL session whose persisted token had EXPIRED still slipped past the stat probe and got
// silently RE-MINTED (TokenFor mints on expiry), rewriting the store. These tests assert the
// token store directory is BYTE-UNCHANGED (entry set + each file's content + modtime) after
// a validate and a resolve, for BOTH the unknown and the expired arms.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/trustpath"
)

// storeDirSnapshot captures every file under the attach-token store dir by relative path →
// (content bytes, modtime), so a later comparison detects a newly-minted file, a rewritten
// (re-minted) token, or a staged temp file. A missing store dir snapshots as empty.
func storeDirSnapshot(t *testing.T, overlayDir string) map[string]string {
	t.Helper()
	root := trustpath.AttachTokensSubdirPath(overlayDir)
	snap := map[string]string{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if os.IsNotExist(err) && path == root {
				return nil // the store dir may not exist yet — an empty snapshot
			}
			return err
		}
		if info.IsDir() {
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		// content + modtime: a re-mint rewrites both; a fresh mint adds a new key.
		snap[rel] = info.ModTime().UTC().Format(time.RFC3339Nano) + "|" + string(data)
		return nil
	})
	if err != nil {
		t.Fatalf("snapshot store dir %q: %v", root, err)
	}
	return snap
}

func assertSnapshotsEqual(t *testing.T, label string, before, after map[string]string) {
	t.Helper()
	if len(before) != len(after) {
		t.Fatalf("%s: store dir entry count changed %d -> %d (a validate/resolve touched the store)", label, len(before), len(after))
	}
	keys := make([]string, 0, len(after))
	for k := range after {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b, ok := before[k]
		if !ok {
			t.Fatalf("%s: store dir gained file %q after a read-only validate/resolve (mint/rewrite leaked)", label, k)
		}
		if b != after[k] {
			t.Fatalf("%s: store file %q was rewritten by a read-only validate/resolve (expired re-mint leaked)", label, k)
		}
	}
}

// writeExpiredTokenFile plants a persisted-but-EXPIRED token file for a session directly on
// disk, in the store's own JSON shape ({"token": <hex>, "expires_at": <unix>}), so the test
// can prove a validate/resolve of a REAL session with an expired token does not re-mint it.
func writeExpiredTokenFile(t *testing.T, overlayDir, sessionUUID string) {
	t.Helper()
	dir := trustpath.AttachTokensSubdirPath(overlayDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir token store: %v", err)
	}
	body, err := json.Marshal(struct {
		Token     string `json:"token"`
		ExpiresAt int64  `json:"expires_at"`
	}{Token: "6465616462656566", ExpiresAt: time.Now().Add(-time.Hour).Unix()}) // "deadbeef" hex, expired 1h ago
	if err != nil {
		t.Fatalf("marshal expired token: %v", err)
	}
	if err := os.WriteFile(trustpath.AttachTokenPath(overlayDir, sessionUUID), body, 0o600); err != nil {
		t.Fatalf("write expired token file: %v", err)
	}
}

// TestWriterAuthValidate_ReadOnlyForUnknownAndExpired proves the W2 attach-auth validator's
// production overlay path (TokenPeek) never mints for an unknown session nor re-mints an
// expired one: the store dir is byte-identical after both refusals.
func TestWriterAuthValidate_ReadOnlyForUnknownAndExpired(t *testing.T) {
	overlay := t.TempDir()
	writeExpiredTokenFile(t, overlay, "sess-expired")

	v, err := newAttachTokenAuthValidatorForOverlay(overlay)
	if err != nil {
		t.Fatalf("newAttachTokenAuthValidatorForOverlay: %v", err)
	}

	before := storeDirSnapshot(t, overlay)

	// Unknown session: no persisted token at all. A clean refusal that writes nothing.
	if ok, err := v.ValidateAttachAuth(context.Background(), "sess-unknown", []byte("6465616462656566")); ok || err != nil {
		t.Fatalf("unknown-session validate: ok=%v err=%v; want false,nil (fail-closed)", ok, err)
	}
	// Expired session: a REAL persisted token that has expired. The prior os.Stat pre-gate
	// let this reach TokenFor, which re-minted (rewriting the file); TokenPeek must refuse
	// WITHOUT touching disk — even when the presented token byte-matches the expired one.
	if ok, err := v.ValidateAttachAuth(context.Background(), "sess-expired", []byte("deadbeef")); ok || err != nil {
		t.Fatalf("expired-session validate: ok=%v err=%v; want false,nil (fail-closed, no re-mint)", ok, err)
	}

	assertSnapshotsEqual(t, "validate", before, storeDirSnapshot(t, overlay))
}

// TestDriveResolve_ReadOnlyForUnknownAndExpired proves the W3 drive-sink resolver's
// production overlay path (TokenPeek) is likewise read-only: resolving an unknown or an
// expired session is a fail-closed miss that leaves the store dir byte-identical.
func TestDriveResolve_ReadOnlyForUnknownAndExpired(t *testing.T) {
	overlay := t.TempDir()
	writeExpiredTokenFile(t, overlay, "sess-expired")

	r, err := newOverlayDriveEndpointResolver(overlay, "/run/ds/attach")
	if err != nil {
		t.Fatalf("newOverlayDriveEndpointResolver: %v", err)
	}

	before := storeDirSnapshot(t, overlay)

	if _, ok, err := r.ResolveRelayEndpoint(context.Background(), "sess-unknown"); ok || err != nil {
		t.Fatalf("unknown-session resolve: ok=%v err=%v; want false,nil (fail-closed)", ok, err)
	}
	if _, ok, err := r.ResolveRelayEndpoint(context.Background(), "sess-expired"); ok || err != nil {
		t.Fatalf("expired-session resolve: ok=%v err=%v; want false,nil (fail-closed, no re-mint)", ok, err)
	}

	assertSnapshotsEqual(t, "resolve", before, storeDirSnapshot(t, overlay))
}
