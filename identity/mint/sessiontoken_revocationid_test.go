// SPDX-License-Identifier: Apache-2.0

package mint

import (
	"strings"
	"testing"
)

// TestRevocationBlockID_OQ6 is the executable record of the doc 19 §7 OQ6
// resolution: a Biscuit native per-block revocation id (from Mint/Attenuate)
// keys a fleet-revocation entry's block id DIRECTLY — 64-byte Ed25519 block
// signature → exactly 128 lower-hex characters, an even-length bounded lower-hex
// identifier of the shape fleetreg.RevocationEntryFromBlockID accepts (its bound
// is 128). No SHA-256 fingerprint reduction is needed for the native substrate.
func TestRevocationBlockID_OQ6(t *testing.T) {
	s, err := newBiscuitSigner()
	if err != nil {
		t.Fatalf("newBiscuitSigner: %v", err)
	}
	_, revIDs, err := s.Mint(SessionTokenClaims{SessionUUID: "sess-oq6", LaunchingUser: "u@ds"})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if len(revIDs) == 0 {
		t.Fatal("expected at least one native per-block revocation id")
	}
	for i, id := range revIDs {
		hexID := RevocationBlockID(id)
		if len(hexID) != biscuitRevocationIDHexLen {
			t.Fatalf("revid[%d] hex length = %d, want %d (64-byte block signature → 128 hex)", i, len(hexID), biscuitRevocationIDHexLen)
		}
		if len(hexID)%2 != 0 {
			t.Fatalf("revid[%d] hex is odd length %d", i, len(hexID))
		}
		if strings.ToLower(hexID) != hexID {
			t.Fatalf("revid[%d] hex must be lower-case: %q", i, hexID)
		}
		for j := 0; j < len(hexID); j++ {
			c := hexID[j]
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				t.Fatalf("revid[%d] not lower-hex at byte %d", i, j)
			}
		}
	}

	// An attenuation hop yields a fresh native id per block — each also keys a
	// block-id directly (the chain-lineage revocation surface, doc 19 §7/§9).
	child, childIDs, err := s.Attenuate(mustMint(t, s), SessionTokenAttenuation{ChildSessionUUID: "child-oq6"})
	if err != nil {
		t.Fatalf("Attenuate: %v", err)
	}
	if len(child) == 0 || len(childIDs) < 2 {
		t.Fatalf("attenuated token should carry >=2 per-block revocation ids, got %d", len(childIDs))
	}
	for i, id := range childIDs {
		if len(RevocationBlockID(id)) != biscuitRevocationIDHexLen {
			t.Fatalf("attenuated revid[%d] hex length = %d, want %d", i, len(RevocationBlockID(id)), biscuitRevocationIDHexLen)
		}
	}

	// RevocationBlockID must never leak token bytes: it encodes ONLY the public
	// revocation id it is handed.
	if RevocationBlockID(nil) != "" {
		t.Fatal("empty revocation id must encode to empty hex")
	}
}

func mustMint(t *testing.T, s *biscuitSigner) []byte {
	t.Helper()
	tok, _, err := s.Mint(SessionTokenClaims{SessionUUID: "sess-oq6", LaunchingUser: "u@ds"})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	return tok
}
