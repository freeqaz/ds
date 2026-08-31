// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/dream-serpent/dream-serpent/identity/auth-sdk/attenuation"
	"github.com/dream-serpent/dream-serpent/identity/auth-sdk/token"
	authv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/auth/v1"
)

// AttenuationServer implements dreamserpent.auth.v1.TokenAttenuationService (D126/D129).
// Called exclusively by the orchestrator fan-out path (D18). Validates the parent
// user auth JWT, derives an attenuated Biscuit sub-token, and records it for the
// revocation cascade (D126 lineage chain).
type AttenuationServer struct {
	authv1.UnimplementedTokenAttenuationServiceServer

	keyPair    *token.KeyPair
	attenuator *attenuation.Attenuator
	lineage    *attenuation.LineageStore
	sink       EventSink
	now        func() time.Time
}

// AttenuationServerOption tunes an AttenuationServer.
type AttenuationServerOption func(*AttenuationServer)

func WithAttenuationSink(sink EventSink) AttenuationServerOption {
	return func(a *AttenuationServer) { a.sink = sink }
}

func WithAttenuationNow(f func() time.Time) AttenuationServerOption {
	return func(a *AttenuationServer) { a.now = f }
}

// NewAttenuationServer constructs an AttenuationServer.
func NewAttenuationServer(kp *token.KeyPair, att *attenuation.Attenuator, lin *attenuation.LineageStore, opts ...AttenuationServerOption) *AttenuationServer {
	s := &AttenuationServer{
		keyPair:    kp,
		attenuator: att,
		lineage:    lin,
		sink:       DiscardEventSink{},
		now:        time.Now,
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// DeriveAgentToken derives an attenuated Biscuit sub-token from a parent user auth JWT.
func (s *AttenuationServer) DeriveAgentToken(ctx context.Context, req *authv1.DeriveAgentTokenRequest) (*authv1.DeriveAgentTokenResponse, error) {
	now := s.now()

	// 1. Validate parent JWT (signature + exp + aud).
	parentClaims, err := token.ValidateToken(
		req.GetParentUserAuthToken(),
		s.keyPair.PublicKey(),
		"dreamserpent.platform",
		now.Unix(),
	)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "DeriveAgentToken: invalid parent token: %v", err)
	}

	// 2. Check v1:identity:mint scope — caller must have minting authority.
	if !hasScope(parentClaims.DSScopes, token.ScopeIdentMint) {
		return nil, status.Errorf(codes.PermissionDenied,
			"DeriveAgentToken: parent token missing %q scope", token.ScopeIdentMint)
	}

	// 3. Generate derived_jti.
	derivedJTI, err := generateDerivedJTI()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "DeriveAgentToken: generate jti: %v", err)
	}

	// 4. Derive the Biscuit sub-token with monotonic scope narrowing (D126).
	reqScopes := req.GetRequestedScopes()
	if len(reqScopes) == 0 {
		reqScopes = parentClaims.DSScopes // default to parent scopes
	}
	agentBytes, agentClaims, err := s.attenuator.DeriveAgentToken(
		parentClaims.JWTID,
		parentClaims.DSScopes,
		parentClaims.Expiry,
		attenuation.DeriveRequest{
			HostSessionIndex: req.GetHostSessionIndex(),
			RequestedScopes:  reqScopes,
			LifetimeSeconds:  req.GetLifetimeSeconds(),
			DerivedJTI:       derivedJTI,
		},
		now.Unix(),
	)
	if err != nil {
		switch err {
		case attenuation.ErrScopeWidening:
			return nil, status.Errorf(codes.InvalidArgument,
				"DeriveAgentToken: requested scopes exceed parent scopes (D126 monotonicity)")
		case attenuation.ErrLifetimeWidening:
			return nil, status.Errorf(codes.InvalidArgument,
				"DeriveAgentToken: lifetime exceeds parent token remaining lifetime (D126)")
		default:
			return nil, status.Errorf(codes.Internal, "DeriveAgentToken: derive: %v", err)
		}
	}

	// 5. Record in lineage store for revocation cascade (D126).
	s.lineage.Record(attenuation.DerivedRecord{
		DerivedJTI:       agentClaims.DerivedJTI,
		ParentJTI:        agentClaims.ParentJTI,
		HostSessionIndex: agentClaims.HostSessionIndex,
		Scopes:           agentClaims.Scopes,
		IssuedAt:         now.Unix(),
		ExpiresAt:        agentClaims.ExpiresAt,
	})

	// 6. Emit EventTokenIssued (D128).
	_ = s.sink.EmitTokenEvent(ctx, TokenEvent{
		Kind:      EventTokenIssued,
		JTI:       agentClaims.DerivedJTI,
		SessionID: req.GetSessionRef().GetSessionUuid(),
		At:        now,
		Fields: map[string]string{
			"parent_jti":         agentClaims.ParentJTI,
			"host_session_index": fmt.Sprintf("%d", req.GetHostSessionIndex()),
		},
	})

	return &authv1.DeriveAgentTokenResponse{
		AgentToken:    agentBytes,
		DerivedJti:    agentClaims.DerivedJTI,
		ExpiresAtUnix: agentClaims.ExpiresAt,
		GrantedScopes: agentClaims.Scopes,
	}, nil
}

// ListDerivedTokens returns all derived sub-tokens for a parent jti.
func (s *AttenuationServer) ListDerivedTokens(ctx context.Context, req *authv1.ListDerivedTokensRequest) (*authv1.ListDerivedTokensResponse, error) {
	if req.GetParentJti() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "ListDerivedTokens: parent_jti required")
	}
	records := s.lineage.ListByParent(req.GetParentJti(), req.GetIncludeExpired())

	out := make([]*authv1.DerivedTokenRecord, 0, len(records))
	for _, r := range records {
		st := authv1.DerivedTokenStatus_DERIVED_TOKEN_STATUS_ACTIVE
		if r.Revoked {
			st = authv1.DerivedTokenStatus_DERIVED_TOKEN_STATUS_REVOKED
		} else if r.ExpiresAt <= s.now().Unix() {
			st = authv1.DerivedTokenStatus_DERIVED_TOKEN_STATUS_EXPIRED
		}
		out = append(out, &authv1.DerivedTokenRecord{
			DerivedJti:       r.DerivedJTI,
			HostSessionIndex: r.HostSessionIndex,
			Scopes:           r.Scopes,
			IssuedAtUnix:     r.IssuedAt,
			ExpiresAtUnix:    r.ExpiresAt,
			Status:           st,
		})
	}
	return &authv1.ListDerivedTokensResponse{Tokens: out}, nil
}

// hasScope reports whether scope is present in scopes.
func hasScope(scopes []string, scope string) bool {
	for _, s := range scopes {
		if s == scope {
			return true
		}
	}
	return false
}

func generateDerivedJTI() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "d-" + base64.RawURLEncoding.EncodeToString(b), nil
}
