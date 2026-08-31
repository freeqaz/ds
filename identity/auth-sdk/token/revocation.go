// SPDX-License-Identifier: Apache-2.0
package token

import "sync"

// RevocationSet is a thread-safe in-memory jti revocation store.
// Entries never expire (production would use a persistent store with TTL sweep).
type RevocationSet struct {
	mu      sync.RWMutex
	revoked map[string]struct{}
}

func NewRevocationSet() *RevocationSet {
	return &RevocationSet{revoked: make(map[string]struct{})}
}

func (r *RevocationSet) Add(jti string) {
	r.mu.Lock()
	r.revoked[jti] = struct{}{}
	r.mu.Unlock()
}

func (r *RevocationSet) IsRevoked(jti string) bool {
	r.mu.RLock()
	_, ok := r.revoked[jti]
	r.mu.RUnlock()
	return ok
}
