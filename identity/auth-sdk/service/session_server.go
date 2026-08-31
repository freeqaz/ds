// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/dream-serpent/dream-serpent/identity/auth-sdk/attenuation"
	"github.com/dream-serpent/dream-serpent/identity/auth-sdk/oidc"
	"github.com/dream-serpent/dream-serpent/identity/auth-sdk/saml"
	"github.com/dream-serpent/dream-serpent/identity/auth-sdk/token"
	authv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/auth/v1"
)

// maxStateAge is the TTL for server-side PKCE pending state.
const maxStateAge = 10 * time.Minute

// envExpiryWarnLive presence-arms the D128 expiry-warn daemon goroutine — the
// loud-skip-by-default live gate (mirrors DS_SEVER_LIVE in severing.go). With it
// UNSET (the default) StartExpiryWarnDaemon starts nothing and the process
// behaves exactly as before; only an operator that arms it launches the sweep
// loop. Presence-only (any non-empty value arms it).
const envExpiryWarnLive = "DS_AUTHSDK_LIVE"

// defaultExpiryWarnInterval is the production Sweep cadence for the daemon — the
// resolution at which the (exp-300s) window is checked. Chosen well under the
// 300s lead so a warning fires with time to spare. A caller may override it.
const defaultExpiryWarnInterval = 30 * time.Second

// pendingOIDCFlow holds the server-side PKCE state for an in-flight authz-code flow.
type pendingOIDCFlow struct {
	orgID        string
	codeVerifier string
	redirectURI  string
	issuedAt     time.Time
}

// SessionServer implements dreamserpent.auth.v1.AuthSessionService (D129, doc 23 §9).
// It orchestrates the oidc/, saml/, and token/ packages to produce short-lived
// user auth tokens (D125) regardless of which IdP protocol the org uses.
type SessionServer struct {
	authv1.UnimplementedAuthSessionServiceServer

	registry      *Registry
	keyPair       *token.KeyPair
	revocationSet *token.RevocationSet
	lineage       *attenuation.LineageStore
	sweep         *RevocationSweep
	expiryWarn    *ExpiryWarnScheduler
	sink          EventSink
	now           func() time.Time
	httpClient    oidc.HTTPClient

	pendingMu     sync.Mutex
	pendingStates map[string]*pendingOIDCFlow // keyed by state token

	// daemon lifecycle for the D128 expiry-warn Sweep loop (StartExpiryWarnDaemon).
	daemonMu      sync.Mutex
	daemonStarted bool
	daemonWG      sync.WaitGroup
}

// SessionServerOption tunes a SessionServer (clock injection, HTTP client, sink).
type SessionServerOption func(*SessionServer)

func WithNow(f func() time.Time) SessionServerOption {
	return func(s *SessionServer) { s.now = f }
}

func WithHTTPClient(c oidc.HTTPClient) SessionServerOption {
	return func(s *SessionServer) { s.httpClient = c }
}

func WithEventSink(sink EventSink) SessionServerOption {
	return func(s *SessionServer) { s.sink = sink }
}

// WithLineageStore wires the D126 lineage store so RevokeToken can collect and
// cascade-revoke every sub-token derived from the revoked parent.
func WithLineageStore(l *attenuation.LineageStore) SessionServerOption {
	return func(s *SessionServer) { s.lineage = l }
}

// WithExpiryWarnScheduler wires the D128 expiry-warning scheduler so every minted
// user auth token is registered for an auth.token.expiry_warn at (exp-300s) and
// deregistered on revocation. Without it, tokens are minted and revoked exactly
// as before but emit no pre-expiry warning (no wired scheduler).
func WithExpiryWarnScheduler(s *ExpiryWarnScheduler) SessionServerOption {
	return func(srv *SessionServer) { srv.expiryWarn = s }
}

// WithSeveringRegistry wires the D53/D76 SeveringRegistry seam so RevokeToken
// severs in-flight upstream connections bound to any jti in the lineage chain
// (doc 23 §8). Without it, revocation still marks tokens revoked but severs
// nothing (no wired datapath).
func WithSeveringRegistry(r SeveringRegistry) SessionServerOption {
	return func(s *SessionServer) { s.sweep = NewRevocationSweep(r) }
}

// NewSessionServer constructs a SessionServer ready to serve.
func NewSessionServer(reg *Registry, kp *token.KeyPair, rev *token.RevocationSet, opts ...SessionServerOption) *SessionServer {
	s := &SessionServer{
		registry:      reg,
		keyPair:       kp,
		revocationSet: rev,
		sweep:         NewRevocationSweep(nil),
		sink:          DiscardEventSink{},
		now:           time.Now,
		httpClient:    http.DefaultClient,
		pendingStates: make(map[string]*pendingOIDCFlow),
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// StartExpiryWarnDaemon launches the D128 expiry-warn scheduler's Sweep loop as a
// background goroutine joined to the server lifecycle — the production daemon leg
// that makes live deployments actually emit auth.token.expiry_warn. Without it a
// wired scheduler registers minted tokens but nothing ever sweeps them, so no
// pre-expiry warning fires.
//
// LOUD-SKIP-BY-DEFAULT (mirrors DS_SEVER_LIVE): with envExpiryWarnLive
// (DS_AUTHSDK_LIVE) UNSET — the default — this starts NOTHING and the gate-off
// path is byte-identical to before (tokens are still minted, registered, and
// revoked exactly as before). Only when the gate is armed AND a scheduler is
// wired (WithExpiryWarnScheduler) does it spawn exactly one goroutine running
// scheduler.Run(ctx, interval).
//
// The goroutine is joined to the server's WaitGroup: it stops cleanly when ctx is
// cancelled (Run returns on ctx.Done) and ShutdownDaemons blocks until it has
// returned, so it never leaks. A non-positive interval defaults to
// defaultExpiryWarnInterval. Idempotent: at most one daemon goroutine is ever
// started (a second call, a nil scheduler, or the gate unset is a safe no-op).
// It returns true iff a daemon goroutine was started.
func (s *SessionServer) StartExpiryWarnDaemon(ctx context.Context, interval time.Duration) bool {
	if os.Getenv(envExpiryWarnLive) == "" {
		return false // loud-skip: the default build launches no daemon
	}
	if s.expiryWarn == nil {
		return false // no scheduler wired: nothing to sweep
	}
	if interval <= 0 {
		interval = defaultExpiryWarnInterval
	}

	s.daemonMu.Lock()
	defer s.daemonMu.Unlock()
	if s.daemonStarted {
		return false // idempotent: at most one daemon goroutine
	}
	s.daemonStarted = true

	sched := s.expiryWarn
	s.daemonWG.Add(1)
	go func() {
		defer s.daemonWG.Done()
		sched.Run(ctx, interval)
	}()
	return true
}

// ShutdownDaemons blocks until every background daemon goroutine started by
// StartExpiryWarnDaemon has returned. The caller signals shutdown by cancelling
// the context it passed to StartExpiryWarnDaemon; ShutdownDaemons then joins the
// WaitGroup. It is safe to call when no daemon was started (returns immediately),
// so a gate-off deployment pays nothing.
func (s *SessionServer) ShutdownDaemons() {
	s.daemonWG.Wait()
}

// InitiateOIDC starts an OIDC/OAuth2 flow for the org.
func (s *SessionServer) InitiateOIDC(ctx context.Context, req *authv1.InitiateOIDCRequest) (*authv1.InitiateOIDCResponse, error) {
	orgCfg, err := s.registry.Lookup(req.GetOrgId())
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "InitiateOIDC: %v", err)
	}
	if orgCfg.Protocol != ProtocolOIDC {
		return nil, status.Errorf(codes.InvalidArgument, "InitiateOIDC: org %q uses SAML, not OIDC", req.GetOrgId())
	}

	provider, err := oidc.NewProvider(*orgCfg.OIDCConfig, oidc.WithHTTPClient(s.httpClient))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "InitiateOIDC: build provider: %v", err)
	}

	switch req.GetFlowType() {
	case authv1.OIDCFlowType_OIDC_FLOW_TYPE_AUTHORIZATION_CODE:
		authzURL, pending, err := oidc.StartAuthzCode(ctx, provider, req.GetRedirectUri())
		if err != nil {
			return nil, status.Errorf(codes.Internal, "InitiateOIDC: start authz-code: %v", err)
		}
		// Store server-side PKCE state keyed by the state token.
		s.pendingMu.Lock()
		s.pendingStates[pending.State] = &pendingOIDCFlow{
			orgID:        req.GetOrgId(),
			codeVerifier: pending.CodeVerifier,
			redirectURI:  req.GetRedirectUri(),
			issuedAt:     pending.IssuedAt,
		}
		s.pendingMu.Unlock()
		return &authv1.InitiateOIDCResponse{
			Response: &authv1.InitiateOIDCResponse_AuthorizationCode{
				AuthorizationCode: &authv1.AuthorizationCodeChallenge{
					AuthorizationUrl: authzURL,
					State:            pending.State,
				},
			},
		}, nil

	case authv1.OIDCFlowType_OIDC_FLOW_TYPE_DEVICE_CODE:
		dar, err := oidc.StartDeviceCode(ctx, provider)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "InitiateOIDC: start device-code: %v", err)
		}
		return &authv1.InitiateOIDCResponse{
			Response: &authv1.InitiateOIDCResponse_DeviceCode{
				DeviceCode: &authv1.DeviceCodeChallenge{
					DeviceCode:      dar.DeviceCode,
					UserCode:        dar.UserCode,
					VerificationUri: dar.VerificationURI,
					ExpiresIn:       int32(dar.ExpiresIn),
					Interval:        int32(dar.Interval),
				},
			},
		}, nil

	default:
		return nil, status.Errorf(codes.InvalidArgument, "InitiateOIDC: unknown flow type %v", req.GetFlowType())
	}
}

// CompleteOIDC exchanges an OIDC authorization code or polls a device code.
func (s *SessionServer) CompleteOIDC(ctx context.Context, req *authv1.CompleteOIDCRequest) (*authv1.AuthTokenResponse, error) {
	orgCfg, err := s.registry.Lookup(req.GetOrgId())
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "CompleteOIDC: %v", err)
	}
	if orgCfg.Protocol != ProtocolOIDC {
		return nil, status.Errorf(codes.InvalidArgument, "CompleteOIDC: org %q uses SAML, not OIDC", req.GetOrgId())
	}

	provider, err := oidc.NewProvider(*orgCfg.OIDCConfig, oidc.WithHTTPClient(s.httpClient))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "CompleteOIDC: build provider: %v", err)
	}

	var idToken string
	switch c := req.GetCompletion().(type) {
	case *authv1.CompleteOIDCRequest_AuthorizationCode:
		ac := c.AuthorizationCode
		// Recover server-side PKCE state.
		s.pendingMu.Lock()
		pending := s.pendingStates[ac.GetState()]
		if pending != nil {
			delete(s.pendingStates, ac.GetState())
		}
		s.pendingMu.Unlock()

		verifier := ac.GetCodeVerifier()
		if verifier == "" && pending != nil {
			verifier = pending.codeVerifier
		}
		if verifier == "" {
			return nil, status.Errorf(codes.InvalidArgument, "CompleteOIDC: code_verifier required")
		}
		redirectURI := ac.GetRedirectUri()
		if redirectURI == "" && pending != nil {
			redirectURI = pending.redirectURI
		}

		tok, err := oidc.ExchangeCode(ctx, provider, ac.GetCode(), verifier, redirectURI)
		if err != nil {
			return nil, status.Errorf(codes.Unauthenticated, "CompleteOIDC: exchange code: %v", err)
		}
		idToken = tok.IDToken

	case *authv1.CompleteOIDCRequest_DeviceCode:
		tok, err := oidc.PollDeviceToken(ctx, provider, c.DeviceCode)
		if err != nil {
			return nil, status.Errorf(codes.Unauthenticated, "CompleteOIDC: poll device token: %v", err)
		}
		idToken = tok.IDToken

	default:
		return nil, status.Errorf(codes.InvalidArgument, "CompleteOIDC: completion required")
	}

	claims, err := provider.ValidateIDToken(ctx, idToken, "")
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "CompleteOIDC: validate id_token: %v", err)
	}

	return s.mintUserAuthToken(ctx, req.GetOrgId(), claims.Subject, claims.Groups,
		req.GetSessionRef().GetSessionUuid())
}

// InitiateSAML builds a signed SAML 2.0 AuthnRequest for the org.
func (s *SessionServer) InitiateSAML(ctx context.Context, req *authv1.InitiateSAMLRequest) (*authv1.InitiateSAMLResponse, error) {
	orgCfg, err := s.registry.Lookup(req.GetOrgId())
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "InitiateSAML: %v", err)
	}
	if orgCfg.Protocol != ProtocolSAML {
		return nil, status.Errorf(codes.InvalidArgument, "InitiateSAML: org %q uses OIDC, not SAML", req.GetOrgId())
	}

	cfg := *orgCfg.SAMLConfig
	if req.GetAcsUrl() != "" {
		cfg.ACSURL = req.GetAcsUrl()
	}

	authnReq, err := saml.NewAuthnRequest(cfg)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "InitiateSAML: build AuthnRequest: %v", err)
	}
	xmlBytes, err := saml.BuildXML(authnReq)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "InitiateSAML: build XML: %v", err)
	}
	if cfg.SigningKey != nil {
		xmlBytes, err = saml.SignXML(xmlBytes, cfg.SigningKey, cfg.SigningCert)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "InitiateSAML: sign XML: %v", err)
		}
	}

	return &authv1.InitiateSAMLResponse{
		AuthnRequestB64: xmlBytes,
		IdpSsoUrl:       cfg.IDPMetadata.SSOURL,
		RelayState:      authnReq.RelayState,
	}, nil
}

// CompleteSAML validates a SAMLResponse and issues a user auth token.
func (s *SessionServer) CompleteSAML(ctx context.Context, req *authv1.CompleteSAMLRequest) (*authv1.AuthTokenResponse, error) {
	orgCfg, err := s.registry.Lookup("")
	// SAML completion doesn't carry org_id directly — it's carried in the relay_state
	// or inferred from the ACS endpoint. For M0: scan all SAML orgs, or require the
	// caller to embed org_id in the relay_state. Use a synthetic lookup by relay_state prefix.
	// Simplified: attempt to look up "saml-default" or accept the first SAML org.
	// Production: relay_state = "<orgID>:<nonce>"; parse orgID from relay_state.
	_ = err
	orgID, nonce, parseErr := parseRelayState(req.GetRelayState())
	if parseErr != nil {
		return nil, status.Errorf(codes.InvalidArgument, "CompleteSAML: invalid relay_state: %v", parseErr)
	}
	_ = nonce
	orgCfg, err = s.registry.Lookup(orgID)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "CompleteSAML: %v", err)
	}
	if orgCfg.Protocol != ProtocolSAML {
		return nil, status.Errorf(codes.InvalidArgument, "CompleteSAML: org %q uses OIDC, not SAML", orgID)
	}

	claims, err := saml.ValidateResponse(*orgCfg.SAMLConfig,
		string(req.GetSamlResponseB64()), req.GetRelayState(), s.now().Unix())
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "CompleteSAML: %v", err)
	}

	return s.mintUserAuthToken(ctx, orgID, claims.Subject, claims.Groups,
		req.GetSessionRef().GetSessionUuid())
}

// RevokeToken revokes a user auth token, cascades to every derived sub-token
// (D126), and severs any in-flight upstream connections bound to a jti in the
// lineage chain across the D53/D76 SeveringRegistry seam (doc 23 §8). It returns
// the real cascade count and emits the D128 auth.token.revoked event.
func (s *SessionServer) RevokeToken(ctx context.Context, req *authv1.RevokeTokenRequest) (*authv1.RevokeTokenResponse, error) {
	if req.GetJti() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "RevokeToken: jti required")
	}
	parentJTI := req.GetJti()

	// 1. Mark the parent token revoked in the local admission set.
	s.revocationSet.Add(parentJTI)

	// 2. Collect the full lineage jti set — the parent plus every derived
	//    sub-token. Snapshot the chain (includeRevoked=true) BEFORE flipping the
	//    cascade bits so a re-revoke still severs the whole chain, then
	//    CascadeRevoke marks the derived tokens revoked and returns the count of
	//    previously-live records (the D126 CascadeRevokedCount).
	lineage := []string{parentJTI}
	cascadeCount := 0
	if s.lineage != nil {
		for _, rec := range s.lineage.ListByParent(parentJTI, true) {
			lineage = append(lineage, rec.DerivedJTI)
		}
		cascadeCount = s.lineage.CascadeRevoke(parentJTI)
	}

	// D128: a revoked token must never later emit an expiry warning, so drop the
	// whole lineage chain from the expiry-warn scheduler. This is independent of
	// push routing — the sever below still tears the connections down regardless
	// of whether any jti carried v1:notify:receive.
	if s.expiryWarn != nil {
		for _, jti := range lineage {
			s.expiryWarn.Remove(jti)
		}
	}

	// 3. Sever in-flight connections bound to any revoked jti across the seam
	//    (doc 23 §8: RevocationSweep.apply on ds-tlsproxy's SeveringRegistry).
	//    AUDIT-COMPLETENESS POSTURE (secfu): the token is already revoked in the
	//    admission set (step 1) and the derived chain is cascade-revoked (step 2),
	//    so the revocation is a fact the moment we reach here — the D128 event MUST
	//    record it whether or not the datapath sever succeeds. A Sever failure that
	//    aborted BEFORE emission (the prior ordering) left a revoked-but-unobserved
	//    state: the token was denied at admission yet no auth.token.revoked event
	//    was ever emitted, blinding every D128 subscriber to a live revocation. So
	//    the sever runs best-effort here; its outcome is captured and the event is
	//    emitted UNCONDITIONALLY at step 4, then the failure is surfaced at step 5.
	_, severErr := s.sweep.apply(ctx, lineage)

	// 4. Emit the D128 auth.token.revoked event UNCONDITIONALLY — even when the
	//    sever failed — so the audit trail is complete (cascade count and sever
	//    outcome in Fields; the "sever" field is "ok" or "error", never token bytes).
	severStatus := "ok"
	if severErr != nil {
		severStatus = "error"
	}
	_ = s.sink.EmitTokenEvent(ctx, TokenEvent{
		Kind: EventTokenRevoked,
		JTI:  parentJTI,
		Fields: map[string]string{
			"reason":  req.GetReason(),
			"cascade": strconv.Itoa(cascadeCount),
			"sever":   severStatus,
		},
		At: s.now(),
	})

	// 5. Surface a sever failure to the caller AFTER the audit event is out, so the
	//    revocation stays observable while the datapath fault is still reported.
	if severErr != nil {
		return nil, status.Errorf(codes.Internal, "RevokeToken: sever lineage: %v", severErr)
	}

	return &authv1.RevokeTokenResponse{CascadeRevokedCount: int32(cascadeCount)}, nil
}

// mintUserAuthToken is the shared token-issuance path (OIDC + SAML converge here).
// It mints a D125 JWT and emits EventTokenIssued.
func (s *SessionServer) mintUserAuthToken(ctx context.Context, orgID, subject string, groups []string, sessionUUID string) (*authv1.AuthTokenResponse, error) {
	now := s.now()
	expUnix := now.Unix() + 900 // D125: 15 minutes
	jti, err := generateJTI()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "mint: generate jti: %v", err)
	}

	role := mapRole(groups)
	scopes := scopesForRole(role)

	claims := token.Claims{
		Issuer:    "dreamserpent.auth.v1",
		Subject:   subject,
		Audience:  "dreamserpent.platform",
		IssuedAt:  now.Unix(),
		Expiry:    expUnix,
		JWTID:     jti,
		DSRole:    role,
		DSScopes:  scopes,
		DSSession: sessionUUID,
	}
	jwt, err := token.MintToken(s.keyPair, claims)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "mint: mint JWT: %v", err)
	}

	_ = s.sink.EmitTokenEvent(ctx, TokenEvent{
		Kind:      EventTokenIssued,
		JTI:       jti,
		OrgID:     orgID,
		SessionID: sessionUUID,
		At:        now,
	})

	// D128: register the freshly minted token for its (exp-300s) expiry warning.
	if s.expiryWarn != nil {
		s.expiryWarn.Register(ExpiryWarnEntry{
			JTI:        jti,
			Subject:    subject,
			SessionRef: sessionUUID,
			OrgID:      orgID,
			ExpiresAt:  expUnix,
		})
	}

	return &authv1.AuthTokenResponse{
		UserAuthToken: jwt,
		ExpiresAtUnix: expUnix,
		Scopes:        scopes,
	}, nil
}

// parseRelayState parses a relay_state of the form "<orgID>:<nonce>".
// GenerateRelayState in saml/authn_request.go generates a random nonce only;
// for M0 the relay_state is used as-is for correlation. Production embeds
// "<orgID>:" prefix. If no colon is present, the whole value is treated as orgID.
func parseRelayState(rs string) (orgID, nonce string, err error) {
	if rs == "" {
		return "", "", fmt.Errorf("relay_state is empty")
	}
	for i, c := range rs {
		if c == ':' {
			return rs[:i], rs[i+1:], nil
		}
	}
	return rs, "", nil
}

// generateJTI returns a cryptographically random 22-character base64url string.
func generateJTI() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// mapRole maps IdP group membership to a platform role string.
// M0: first group wins; no groups → "member".
func mapRole(groups []string) string {
	if len(groups) > 0 {
		return groups[0]
	}
	return "member"
}

// scopesForRole returns the D127 scope set for a role.
// M0: every authenticated user gets the full scope set.
// Production: role → scope mapping from the roles catalog (dreamserpent.roles.v1).
func scopesForRole(_ string) []string {
	return token.AllScopes
}
