// SPDX-License-Identifier: Apache-2.0

package libvirt

// attachminter_tokenpeek_test.go pins the read-only TokenPeek contract on the
// fileAttachTokenStore: it returns a live persisted token but NEVER mints (unknown session)
// and NEVER rewrites (expired session) — the property the W2 validator and W3 drive sink
// rely on to keep validate/resolve read-only. The consumer-level store-dir-unchanged proofs
// live in cmd/orchestrator/tokenpeek_readonly_test.go; this pins the store method directly.

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/trustpath"
)

func TestTokenPeek_ReturnsLiveTokenWithoutMinting(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileAttachTokenStore(dir, time.Hour)
	if err != nil {
		t.Fatalf("NewFileAttachTokenStore: %v", err)
	}
	minted, exp, err := store.TokenFor(context.Background(), "sess-live")
	if err != nil {
		t.Fatalf("TokenFor mint: %v", err)
	}

	got, gotExp, ok, err := store.TokenPeek(context.Background(), "sess-live")
	if err != nil || !ok {
		t.Fatalf("peek live token: ok=%v err=%v; want true,nil", ok, err)
	}
	if string(got) != string(minted) {
		t.Fatal("peeked token != minted token")
	}
	if !gotExp.Equal(exp) {
		t.Fatalf("peeked expiry = %v; want %v", gotExp, exp)
	}
}

func TestTokenPeek_UnknownSessionIsReadOnlyMiss(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileAttachTokenStore(dir, time.Hour)
	if err != nil {
		t.Fatalf("NewFileAttachTokenStore: %v", err)
	}

	_, _, ok, err := store.TokenPeek(context.Background(), "sess-none")
	if ok || err != nil {
		t.Fatalf("peek unknown session: ok=%v err=%v; want false,nil (miss)", ok, err)
	}
	// No token file may have been minted.
	entries, err := os.ReadDir(trustpath.AttachTokensSubdirPath(dir))
	if err != nil {
		t.Fatalf("read store dir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("peek of an unknown session minted %d file(s); want 0 (read-only)", len(entries))
	}
}

func TestTokenPeek_ExpiredTokenIsMissAndNotRewritten(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileAttachTokenStore(dir, time.Hour)
	if err != nil {
		t.Fatalf("NewFileAttachTokenStore: %v", err)
	}
	// Plant an expired token file in the store's own JSON shape.
	body, err := json.Marshal(attachToken{Token: "6465616462656566", ExpiresAt: time.Now().Add(-time.Hour).Unix()})
	if err != nil {
		t.Fatalf("marshal expired token: %v", err)
	}
	path := trustpath.AttachTokenPath(dir, "sess-expired")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write expired token: %v", err)
	}
	beforeInfo, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat expired token: %v", err)
	}

	_, _, ok, err := store.TokenPeek(context.Background(), "sess-expired")
	if ok || err != nil {
		t.Fatalf("peek expired token: ok=%v err=%v; want false,nil (expired miss, no re-mint)", ok, err)
	}
	// The expired file must be byte-identical — TokenPeek never rewrites (unlike TokenFor).
	afterData, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read expired token after peek: %v", err)
	}
	if string(afterData) != string(body) {
		t.Fatal("expired token file was rewritten by TokenPeek; want byte-unchanged")
	}
	afterInfo, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat expired token after peek: %v", err)
	}
	if !afterInfo.ModTime().Equal(beforeInfo.ModTime()) {
		t.Fatal("expired token modtime changed after TokenPeek; want untouched")
	}
}

func TestTokenPeek_CorruptTokenIsFailLoud(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileAttachTokenStore(dir, time.Hour)
	if err != nil {
		t.Fatalf("NewFileAttachTokenStore: %v", err)
	}
	if err := os.WriteFile(trustpath.AttachTokenPath(dir, "sess-corrupt"), []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write corrupt token: %v", err)
	}
	if _, _, ok, err := store.TokenPeek(context.Background(), "sess-corrupt"); ok || err == nil {
		t.Fatalf("peek corrupt token: ok=%v err=%v; want false + a fail-loud error", ok, err)
	}
}
