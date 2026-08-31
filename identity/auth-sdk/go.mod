// SPDX-License-Identifier: Apache-2.0

// The auth SDK — unified human-principal authentication for the Dream Serpent
// platform (doc 23; D123–D129). Handles SAML 2.0 SP-initiated SSO (D124) and
// OIDC/OAuth2 (D55/D123), mints a short-lived user auth token (D125), and
// derives attenuated sub-tokens at D18 fan-out (D126, Biscuit primary, D98).
//
// Deliberately OUTSIDE go.work — same standalone-module pattern as
// identity/mint and identity/idp: a substrate swap must not perturb the
// workspace. Standalone module; built/vetted/tested under GOWORK=off.
// Deps: biscuit-go (sub-token attenuation), proto/gen/go (gRPC contract types),
// grpc (service wiring). STDLIB for OIDC JWS + SAML XML-DSig (same judgment
// as identity/idp and identity/mint: no JWT/SAML library needed).
module github.com/dream-serpent/dream-serpent/identity/auth-sdk

go 1.25.11

require (
	github.com/biscuit-auth/biscuit-go/v2 v2.2.0
	github.com/dream-serpent/dream-serpent/proto/gen/go v0.0.0
	google.golang.org/grpc v1.81.1
)

require (
	golang.org/x/net v0.51.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
	golang.org/x/text v0.34.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260226221140-a57be14db171 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

replace github.com/dream-serpent/dream-serpent/proto/gen/go => ../../proto/gen/go
