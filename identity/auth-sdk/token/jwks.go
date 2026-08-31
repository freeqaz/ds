// SPDX-License-Identifier: Apache-2.0

package token

import (
	"net/http"
)

// JWKSHandler returns an http.Handler that serves the JWKS document for the
// provided signing keys. Suitable for mounting at /.well-known/jwks.json.
// The document is re-generated on every request so key rotation takes effect
// immediately without a restart (production: cache with short TTL).
func JWKSHandler(keys ...*KeyPair) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		data, err := JWKSDocument(keys...)
		if err != nil {
			http.Error(w, "failed to build JWKS", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "max-age=300")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	})
}
