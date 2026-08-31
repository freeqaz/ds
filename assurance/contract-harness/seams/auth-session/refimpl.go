// SPDX-License-Identifier: Apache-2.0

package authsession

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/auth/v1"
)

// RefImpl is a minimal honest reference implementation of the D126/D129
// TokenAttenuationService — the "real implementation" side of the dual-run.
//
// It implements the monotonic-narrowing and cascade-revocation invariants from
// doc 23 §5–§6 and D126:
//   - derived scopes ⊆ parent scopes (DeriveAgentToken returns INVALID_ARGUMENT otherwise)
//   - derived lifetime ≤ parent remaining lifetime
//   - RevokeParentForTest cascades: ListDerivedTokens with include_expired=false
//     must exclude records whose parent has been revoked
//   - derived_jti is always distinct from the parent_jti
//
// State is held in-memory under a mutex so the in-process gRPC server is safe
// under concurrent calls.  Synthetic fixtures only (D50).
type RefImpl struct {
	authv1.UnimplementedTokenAttenuationServiceServer

	mu      sync.Mutex
	parents map[string]*parentRecord    // keyed by parentJTI
	derived map[string][]*derivedRecord // keyed by parentJTI
}

// parentRecord holds the test-seeded state for a parent user auth token.
type parentRecord struct {
	jti     string
	expUnix int64
	scopes  []string
	revoked bool
}

// derivedRecord is one derived agent token stored for a given parent.
type derivedRecord struct {
	derivedJTI string
	parentJTI  string
	hostIndex  int32
	expUnix    int64
	scopes     []string
	tokenBytes []byte
	revoked    bool
}

// NewRefImpl returns an empty reference implementation ready for seeding.
func NewRefImpl() *RefImpl {
	return &RefImpl{
		parents: make(map[string]*parentRecord),
		derived: make(map[string][]*derivedRecord),
	}
}

// SeedParentToken is a test affordance to register a parent user auth token
// directly, without going through an actual auth flow.  Synthetic fixtures only (D50).
func (r *RefImpl) SeedParentToken(jti string, scopes []string, expUnix int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	sorted := make([]string, len(scopes))
	copy(sorted, scopes)
	sort.Strings(sorted)
	r.parents[jti] = &parentRecord{
		jti:     jti,
		expUnix: expUnix,
		scopes:  sorted,
	}
}

// RevokeParentForTest is a test affordance that marks a parent token as revoked,
// cascading revocation to all its derived tokens.  Synthetic fixtures only (D50).
func (r *RefImpl) RevokeParentForTest(parentJTI string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if p, ok := r.parents[parentJTI]; ok {
		p.revoked = true
	}
	for _, rec := range r.derived[parentJTI] {
		rec.revoked = true
	}
}

// nowLocked returns the synthetic monotonic clock used for expiry decisions.
// Fixed at synthNow so the dual-run is deterministic across calls.  The caller
// holds r.mu.  Synthetic fixtures only (D50).
func (r *RefImpl) nowLocked() int64 {
	return synthNow
}

// DeriveAgentToken validates scope monotonicity and lifetime, then mints a
// synthetic derived agent token.  Returns INVALID_ARGUMENT if:
//   - the parent token is not seeded or is revoked
//   - any requested scope is not present in the parent's scopes
//   - lifetime_seconds > 0 and nowUnix+lifetime > parent expiry
func (r *RefImpl) DeriveAgentToken(_ context.Context, req *authv1.DeriveAgentTokenRequest) (*authv1.DeriveAgentTokenResponse, error) {
	if req.GetParentUserAuthToken() == "" {
		return nil, status.Error(codes.InvalidArgument, "parent_user_auth_token is required")
	}

	// Parse the format-opaque synthetic parent token.
	parentJTI, parentExp, parentScopes, ok := parseUserAuthToken(req.GetParentUserAuthToken())
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "parent_user_auth_token is malformed")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	now := r.nowLocked()

	// The parent must be known and not revoked.
	p, known := r.parents[parentJTI]
	if !known {
		return nil, status.Error(codes.InvalidArgument, "parent token not found")
	}
	if p.revoked {
		return nil, status.Error(codes.InvalidArgument, "parent token has been revoked")
	}

	// Validate scope monotonicity (D126): requested ⊆ parent.
	requested := req.GetRequestedScopes()
	if err := checkScopeMonotonicity(parentScopes, requested); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	// Validate lifetime.
	var expUnix int64
	if req.GetLifetimeSeconds() > 0 {
		expUnix = now + int64(req.GetLifetimeSeconds())
		if expUnix > parentExp {
			return nil, status.Error(codes.InvalidArgument,
				"lifetime_seconds would exceed parent token expiry (monotonic narrowing violated)")
		}
	} else {
		expUnix = parentExp
	}

	// Mint the derived token.
	derivedJTI := "derived-synthetic-" + parentJTI
	grantedScopes := make([]string, len(requested))
	copy(grantedScopes, requested)
	sort.Strings(grantedScopes)

	agentToken := MintAgentToken(derivedJTI, parentJTI, req.GetHostSessionIndex(), expUnix, grantedScopes...)

	rec := &derivedRecord{
		derivedJTI: derivedJTI,
		parentJTI:  parentJTI,
		hostIndex:  req.GetHostSessionIndex(),
		expUnix:    expUnix,
		scopes:     grantedScopes,
		tokenBytes: agentToken,
	}
	r.derived[parentJTI] = append(r.derived[parentJTI], rec)

	return &authv1.DeriveAgentTokenResponse{
		AgentToken:    agentToken,
		DerivedJti:    derivedJTI,
		ExpiresAtUnix: expUnix,
		GrantedScopes: grantedScopes,
	}, nil
}

// ListDerivedTokens returns the derived token records for a parent JTI.
// When IncludeExpired is false, revoked records are excluded.
func (r *RefImpl) ListDerivedTokens(_ context.Context, req *authv1.ListDerivedTokensRequest) (*authv1.ListDerivedTokensResponse, error) {
	if req.GetParentJti() == "" {
		return nil, status.Error(codes.InvalidArgument, "parent_jti is required")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	recs := r.derived[req.GetParentJti()]
	var tokens []*authv1.DerivedTokenRecord
	for _, rec := range recs {
		if !req.GetIncludeExpired() && rec.revoked {
			continue
		}
		st := authv1.DerivedTokenStatus_DERIVED_TOKEN_STATUS_ACTIVE
		if rec.revoked {
			st = authv1.DerivedTokenStatus_DERIVED_TOKEN_STATUS_REVOKED
		}
		tokens = append(tokens, &authv1.DerivedTokenRecord{
			DerivedJti:       rec.derivedJTI,
			HostSessionIndex: rec.hostIndex,
			Scopes:           rec.scopes,
			IssuedAtUnix:     synthNow,
			ExpiresAtUnix:    rec.expUnix,
			Status:           st,
		})
	}
	return &authv1.ListDerivedTokensResponse{Tokens: tokens}, nil
}

// Register registers the reference implementation on a grpc.ServiceRegistrar.
func (r *RefImpl) Register(reg grpc.ServiceRegistrar) {
	authv1.RegisterTokenAttenuationServiceServer(reg, r)
}

// checkScopeMonotonicity returns an error if any scope in requested is not
// present in parentScopes (D126: derived scopes ⊆ parent scopes).
func checkScopeMonotonicity(parentScopes, requested []string) error {
	parentSet := make(map[string]struct{}, len(parentScopes))
	for _, s := range parentScopes {
		parentSet[s] = struct{}{}
	}
	var missing []string
	for _, s := range requested {
		if _, ok := parentSet[s]; !ok {
			missing = append(missing, s)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("requested scopes not in parent: %s", strings.Join(missing, ", "))
	}
	return nil
}

// --- format-opaque synthetic token helpers (D50) ----------------------------
//
// Parent user auth token (string):
//   "user-auth-synthetic|<jti>|<exp_unix>|<scope1,scope2,...>"
//
// Derived agent token (bytes):
//   "agent-token-synthetic|<derived_jti>|<parent_jti>|<host_index>|<exp_unix>|<scope1,...>"

const (
	userAuthPrefix   = "user-auth-synthetic"
	agentTokenPrefix = "agent-token-synthetic"
)

// MintUserAuthToken builds the obvious-synthetic parent user auth token string.
// Scopes are sorted for determinism.  Synthetic fixtures only (D50).
func MintUserAuthToken(jti string, expUnix int64, scopes ...string) string {
	sorted := make([]string, len(scopes))
	copy(sorted, scopes)
	sort.Strings(sorted)
	return userAuthPrefix + "|" + jti + "|" + decimalSigned(expUnix) + "|" + strings.Join(sorted, ",")
}

// MintAgentToken builds the obvious-synthetic derived agent token bytes.
// Scopes are sorted for determinism.  Synthetic fixtures only (D50).
func MintAgentToken(derivedJTI, parentJTI string, hostIndex int32, expUnix int64, scopes ...string) []byte {
	sorted := make([]string, len(scopes))
	copy(sorted, scopes)
	sort.Strings(sorted)
	return []byte(agentTokenPrefix + "|" + derivedJTI + "|" + parentJTI + "|" +
		decimalSigned(int64(hostIndex)) + "|" + decimalSigned(expUnix) + "|" + strings.Join(sorted, ","))
}

// parseUserAuthToken parses the synthetic user auth token format.
// Returns (jti, expUnix, scopes, ok).
func parseUserAuthToken(s string) (jti string, expUnix int64, scopes []string, ok bool) {
	parts := strings.Split(s, "|")
	if len(parts) != 4 || parts[0] != userAuthPrefix {
		return "", 0, nil, false
	}
	jti = parts[1]
	if jti == "" {
		return "", 0, nil, false
	}
	exp, parsed := atoiSigned(parts[2])
	if !parsed {
		return "", 0, nil, false
	}
	var sc []string
	if parts[3] != "" {
		sc = strings.Split(parts[3], ",")
		sort.Strings(sc)
	}
	return jti, exp, sc, true
}

// parseAgentToken parses the synthetic agent token bytes.
func parseAgentToken(b []byte) (derivedJTI, parentJTI string, hostIndex int32, expUnix int64, scopes []string, ok bool) {
	parts := strings.Split(string(b), "|")
	if len(parts) != 6 || parts[0] != agentTokenPrefix {
		return "", "", 0, 0, nil, false
	}
	derivedJTI = parts[1]
	parentJTI = parts[2]
	hi, hiOK := atoiSigned(parts[3])
	if !hiOK {
		return "", "", 0, 0, nil, false
	}
	exp, expOK := atoiSigned(parts[4])
	if !expOK {
		return "", "", 0, 0, nil, false
	}
	var sc []string
	if parts[5] != "" {
		sc = strings.Split(parts[5], ",")
		sort.Strings(sc)
	}
	return derivedJTI, parentJTI, int32(hi), exp, sc, true
}

// --- tiny stdlib-free integer codecs ----------------------------------------

func decimalSigned(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func atoiSigned(s string) (int64, bool) {
	if s == "" {
		return 0, false
	}
	neg := false
	i := 0
	if s[0] == '-' {
		neg = true
		i = 1
		if len(s) == 1 {
			return 0, false
		}
	}
	var n int64
	for ; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int64(c-'0')
	}
	if neg {
		n = -n
	}
	return n, true
}
