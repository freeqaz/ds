// SPDX-License-Identifier: Apache-2.0

// Lineage store for agent sub-token revocation tracking (D126).
//
// ListDerivedTokens and cascade revocation are the two operations the
// TokenAttenuationService surfaces: a parent JWT revocation cascades to all
// derived sub-tokens by marking them revoked in the lineage store, and
// ListDerivedTokens surfaces the audit trail for a given parent jti.
//
// The store is in-memory and suitable for a single-instance service; persistent
// backends (e.g. the D39 KV store) attach by replacing the lineage store at
// the service layer.
package attenuation

import "sync"

// DerivedRecord tracks one derived sub-token in the lineage store.
type DerivedRecord struct {
	// DerivedJTI is the unique identifier of the derived sub-token (the lineage
	// store key for point-revocation and ListDerivedTokens).
	DerivedJTI string
	// ParentJTI is the jti of the parent user auth JWT (revocation lineage, D126).
	ParentJTI string
	// HostSessionIndex is the agent VM index the sub-token scopes to (D18).
	HostSessionIndex int32
	// Scopes is the narrowed scope set carried in the sub-token.
	Scopes []string
	// IssuedAt is the Unix-second timestamp when the sub-token was derived.
	IssuedAt int64
	// ExpiresAt is the Unix-second timestamp of the sub-token horizon.
	ExpiresAt int64
	// Revoked is true if the sub-token has been explicitly revoked or cascade-
	// revoked through its parent JWT (CascadeRevoke).
	Revoked bool
}

// LineageStore tracks parent_jti → []DerivedRecord for revocation cascade
// (D126). It is safe for concurrent use.
type LineageStore struct {
	mu        sync.RWMutex
	byParent  map[string][]*DerivedRecord
	byDerived map[string]*DerivedRecord
}

// NewLineageStore allocates and returns an empty LineageStore.
func NewLineageStore() *LineageStore {
	return &LineageStore{
		byParent:  make(map[string][]*DerivedRecord),
		byDerived: make(map[string]*DerivedRecord),
	}
}

// Record adds a derived token to the lineage store. The record is indexed both
// by ParentJTI (for ListByParent / CascadeRevoke) and by DerivedJTI (for
// point-revocation lookups). Duplicate DerivedJTIs replace the existing record.
func (s *LineageStore) Record(rec DerivedRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := rec // copy so the caller cannot mutate through the original struct
	// Replace any existing record with the same DerivedJTI (idempotent
	// re-derive, e.g. on retry).
	if old, ok := s.byDerived[rec.DerivedJTI]; ok {
		// Remove the old pointer from byParent to keep the slice consistent.
		list := s.byParent[old.ParentJTI]
		for i, p := range list {
			if p == old {
				s.byParent[old.ParentJTI] = append(list[:i], list[i+1:]...)
				break
			}
		}
	}
	s.byParent[rec.ParentJTI] = append(s.byParent[rec.ParentJTI], &r)
	s.byDerived[rec.DerivedJTI] = &r
}

// ListByParent returns all DerivedRecords whose ParentJTI matches parentJTI.
// If includeRevoked is false, revoked records are omitted. The returned slice
// is a snapshot (value copy) — mutations do not affect the store.
func (s *LineageStore) ListByParent(parentJTI string, includeRevoked bool) []DerivedRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	recs := s.byParent[parentJTI]
	out := make([]DerivedRecord, 0, len(recs))
	for _, r := range recs {
		if !includeRevoked && r.Revoked {
			continue
		}
		out = append(out, *r)
	}
	return out
}

// ListDerivedTokens returns the live (non-revoked) sub-tokens derived from
// parentJTI — the TokenAttenuationService.ListDerivedTokens surface (doc 23 §9.2,
// D126), consumed by the revocation sweep and the audit trail. It is a thin,
// self-documenting alias for ListByParent(parentJTI, false): "live" means
// not-yet-revoked. Expiry is a clock predicate the caller applies against the
// returned ExpiresAt values (the store holds no clock); the gRPC ListDerivedTokens
// handler layers that status on top. The returned slice is a snapshot (value
// copies) — mutations do not affect the store.
func (s *LineageStore) ListDerivedTokens(parentJTI string) []DerivedRecord {
	return s.ListByParent(parentJTI, false)
}

// CascadeRevoke marks all derived tokens of parentJTI as revoked (D126
// revocation cascade: revoking a parent JWT immediately invalidates every
// sub-token derived from it). Returns the number of previously-live records
// that were revoked.
func (s *LineageStore) CascadeRevoke(parentJTI string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, r := range s.byParent[parentJTI] {
		if !r.Revoked {
			r.Revoked = true
			n++
		}
	}
	return n
}

// Revoke marks a single derived token as revoked by DerivedJTI. Returns true if
// the record existed and was not already revoked.
func (s *LineageStore) Revoke(derivedJTI string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.byDerived[derivedJTI]
	if !ok || r.Revoked {
		return false
	}
	r.Revoked = true
	return true
}
