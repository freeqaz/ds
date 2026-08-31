// SPDX-License-Identifier: Apache-2.0

// writeedge_contract_test.go is the OFFLINE guard on the Go↔Rust write edge: it
// pins the exact C-ABI signatures the cgo binding (writeedge.go) binds and
// asserts each is present, verbatim, in the authoritative header
// dataplane/crates/ds-nft/include/ds_nft.h. The edge cannot drift silently — a
// signature change on the Rust side (ffi.rs → ds_nft.h) breaks this test until
// the Go wrapper + this pin are updated in lockstep (doc 15 OQ3 / doc 13 OQ2,
// the contract-test home, doc 06 §2.1). It carries NO build tag and NO cgo, so
// it runs in the default offline `go test ./...` and in CI — the same posture
// the package's content_hash contract test holds.

package nftbridge

import (
	"os"
	"strings"
	"testing"
)

// pinnedDSNFTSignatures are the six extern-C declarations writeedge.go's cgo
// wrappers bind. Kept verbatim from include/ds_nft.h; whitespace is normalized
// before comparison so the pin is robust to header reformatting but not to a
// real type/arity/name change.
var pinnedDSNFTSignatures = []string{
	"int32_t ds_nft_create_tap(const char *name, uint32_t owner_uid, int has_uid, uint32_t host_session_index, const char *guest_mac);",
	"int32_t ds_nft_delete_tap(const char *name);",
	"int32_t ds_nft_flush_session(const char *tap_name, uint32_t host_session_index);",
	"int32_t ds_nft_instantiate_session(const char *tap_name, uint32_t host_session_index);",
	"int32_t ds_nft_teardown_session(const char *tap_name, uint32_t host_session_index);",
	"const char *ds_nft_last_error(void);",
}

// dsNFTHeaderRel is the in-tree path to the authoritative C header, relative to
// this package dir (orchestrator/internal/nftbridge → repo root → dataplane/…).
const dsNFTHeaderRel = "../../../dataplane/crates/ds-nft/include/ds_nft.h"

func TestDSNFTHeaderContract(t *testing.T) {
	raw, err := os.ReadFile(dsNFTHeaderRel)
	if err != nil {
		t.Fatalf("read ds_nft.h (%s): %v", dsNFTHeaderRel, err)
	}
	header := normalizeWhitespace(string(raw))
	for _, sig := range pinnedDSNFTSignatures {
		if !strings.Contains(header, normalizeWhitespace(sig)) {
			t.Errorf("ds_nft.h is missing the C-ABI signature the cgo edge binds:\n  %s\n"+
				"the Rust FFI surface drifted — update writeedge.go's wrapper AND this pin in lockstep", sig)
		}
	}
}

// normalizeWhitespace collapses every run of whitespace to a single space and
// trims, so a header reformat (line wraps, alignment) does not spuriously fail
// the contract while a genuine signature change still does.
func normalizeWhitespace(s string) string { return strings.Join(strings.Fields(s), " ") }
