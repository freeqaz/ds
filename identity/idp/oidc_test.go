// SPDX-License-Identifier: Apache-2.0

package idp

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// oidc_test.go drives ID-token validation against the fake OIDC server for both
// signature families (RS256, ES256) and the full failure matrix of doc 16 §11.2
// step 4 (signature, iss, aud, exp, nonce) — synthetic keys only (D50).

func TestValidateIDToken_RS256_Valid(t *testing.T) {
	f := newFakeOIDC(t, "RS256", "ds-client")
	cfg := f.config("acme", nil)
	p := providerForFake(t, f, cfg, time.Now())

	token := f.signToken(map[string]any{
		"sub": "okta|ada", "email": "ada@acme.example", "name": "Ada",
	})
	claims, err := p.ValidateIDToken(context.Background(), token, "")
	if err != nil {
		t.Fatalf("ValidateIDToken: %v", err)
	}
	if claims.Subject != "okta|ada" {
		t.Errorf("Subject = %q, want okta|ada", claims.Subject)
	}
	if claims.Email != "ada@acme.example" {
		t.Errorf("Email = %q (display metadata), want ada@acme.example", claims.Email)
	}
}

func TestValidateIDToken_ES256_Valid(t *testing.T) {
	f := newFakeOIDC(t, "ES256", "ds-client")
	p := providerForFake(t, f, f.config("acme", nil), time.Now())

	token := f.signToken(map[string]any{"sub": "okta|grace"})
	claims, err := p.ValidateIDToken(context.Background(), token, "")
	if err != nil {
		t.Fatalf("ValidateIDToken ES256: %v", err)
	}
	if claims.Subject != "okta|grace" {
		t.Errorf("Subject = %q, want okta|grace", claims.Subject)
	}
}

func TestValidateIDToken_NonceChecked(t *testing.T) {
	f := newFakeOIDC(t, "RS256", "ds-client")
	p := providerForFake(t, f, f.config("acme", nil), time.Now())

	token := f.signToken(map[string]any{"sub": "okta|ada", "nonce": "n-correct"})
	if _, err := p.ValidateIDToken(context.Background(), token, "n-correct"); err != nil {
		t.Fatalf("matching nonce should validate: %v", err)
	}
	if _, err := p.ValidateIDToken(context.Background(), token, "n-wrong"); !errors.Is(err, ErrToken) {
		t.Fatalf("nonce mismatch should be ErrToken, got %v", err)
	}
}

func TestValidateIDToken_WrongIssuer(t *testing.T) {
	f := newFakeOIDC(t, "RS256", "ds-client")
	p := providerForFake(t, f, f.config("acme", nil), time.Now())

	token := f.signToken(map[string]any{"sub": "okta|ada", "iss": "https://evil.example"})
	if _, err := p.ValidateIDToken(context.Background(), token, ""); !errors.Is(err, ErrToken) {
		t.Fatalf("wrong issuer should be ErrToken, got %v", err)
	}
}

func TestValidateIDToken_WrongAudience(t *testing.T) {
	f := newFakeOIDC(t, "RS256", "ds-client")
	p := providerForFake(t, f, f.config("acme", nil), time.Now())

	token := f.signToken(map[string]any{"sub": "okta|ada", "aud": "some-other-client"})
	if _, err := p.ValidateIDToken(context.Background(), token, ""); !errors.Is(err, ErrToken) {
		t.Fatalf("wrong audience should be ErrToken, got %v", err)
	}
}

func TestValidateIDToken_Expired(t *testing.T) {
	f := newFakeOIDC(t, "RS256", "ds-client")
	// Clock far in the future relative to the token's exp.
	future := time.Now().Add(48 * time.Hour)
	p := providerForFake(t, f, f.config("acme", nil), future)

	token := f.signToken(map[string]any{
		"sub": "okta|ada", "exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := p.ValidateIDToken(context.Background(), token, ""); !errors.Is(err, ErrToken) {
		t.Fatalf("expired token should be ErrToken, got %v", err)
	}
}

func TestValidateIDToken_TamperedSignature(t *testing.T) {
	f := newFakeOIDC(t, "RS256", "ds-client")
	p := providerForFake(t, f, f.config("acme", nil), time.Now())

	token := f.signToken(map[string]any{"sub": "okta|ada"})
	// Flip a character in the MIDDLE of the signature segment (a full-byte
	// position, so the decoded signature genuinely differs).
	dot := strings.LastIndex(token, ".")
	sigStart := dot + 1
	mid := sigStart + (len(token)-sigStart)/2
	b := []byte(token)
	if b[mid] == 'A' {
		b[mid] = 'B'
	} else {
		b[mid] = 'A'
	}
	tampered := string(b)
	if _, err := p.ValidateIDToken(context.Background(), tampered, ""); !errors.Is(err, ErrToken) {
		t.Fatalf("tampered signature should be ErrToken, got %v", err)
	}
}

func TestValidateIDToken_MissingSubject(t *testing.T) {
	f := newFakeOIDC(t, "RS256", "ds-client")
	p := providerForFake(t, f, f.config("acme", nil), time.Now())

	// No sub claim: the §3.2 identity key is absent → reject (never self-declare).
	token := f.signToken(map[string]any{"email": "ada@acme.example"})
	if _, err := p.ValidateIDToken(context.Background(), token, ""); !errors.Is(err, ErrToken) {
		t.Fatalf("missing sub should be ErrToken, got %v", err)
	}
}

func TestValidateIDToken_Malformed(t *testing.T) {
	f := newFakeOIDC(t, "RS256", "ds-client")
	p := providerForFake(t, f, f.config("acme", nil), time.Now())

	if _, err := p.ValidateIDToken(context.Background(), "not-a-jws", ""); !errors.Is(err, ErrToken) {
		t.Fatalf("malformed token should be ErrToken, got %v", err)
	}
	// A two-segment token (signature segment dropped) is not a compact JWS.
	token := f.signToken(map[string]any{"sub": "okta|ada"})
	twoSeg := token[:strings.LastIndex(token, ".")]
	if _, err := p.ValidateIDToken(context.Background(), twoSeg, ""); !errors.Is(err, ErrToken) {
		t.Fatalf("truncated token should be ErrToken")
	}
}

// TestDeviceFlow_HeaderMemberRefusedE2E proves the §11.2 header-member / typ
// contract holds on the INTEGRATED device-code path — not only in the unit-level
// confuser. The fake IdP completes a genuine RFC 8628 device-code grant (the human
// "approves" in the browser) and mints a real, correctly-signed ID token, but with a
// HOSTILE protected header: a wrong JOSE typ ("at+jwt", an access token replayed as
// an ID token), or a self-declared cert reference (x5t / x5t#S256 / x5c). The flow
// therefore reaches ValidateIDToken with an otherwise-valid token, so if the contract
// did NOT hold the flow would converge on an AuthResult; instead each must fail as
// ErrToken (surfaced unwrapped by resultFromToken — the single convergence point both
// flows share). This is the end-to-end proof that the parse-stage refusals gate the
// real mint-time auth path, not just a hand-built token handed straight to the verifier.
func TestDeviceFlow_HeaderMemberRefusedE2E(t *testing.T) {
	cases := []struct {
		name   string
		header map[string]any
	}{
		{"typ_at_jwt", map[string]any{"alg": "RS256", "kid": "test-kid-1", "typ": "at+jwt"}},
		{"typ_logout_jwt", map[string]any{"alg": "RS256", "kid": "test-kid-1", "typ": "logout+jwt"}},
		{"x5t_thumbprint", map[string]any{"alg": "RS256", "kid": "test-kid-1", "typ": "JWT", "x5t": "AAAAAAAAAAAAAAAAAAAAAAAAAAA"}},
		{"x5t_s256_thumbprint", map[string]any{"alg": "RS256", "kid": "test-kid-1", "typ": "JWT", "x5t#S256": "AAAAAAAAAAAAAAAAAAAAAAAAAAA"}},
		{"x5c_self_declared", map[string]any{"alg": "RS256", "kid": "test-kid-1", "typ": "JWT", "x5c": []string{"AAAA"}}},
		{"jku_redirect", map[string]any{"alg": "RS256", "kid": "test-kid-1", "typ": "JWT", "jku": "https://attacker.example/jwks"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeOIDC(t, "RS256", "ds-client")
			p := providerForFake(t, f, f.config("acme", nil), time.Now())

			// A genuine, otherwise-valid device-code grant — the ONLY defect is the header.
			f.scriptDeviceWithHeader("dev-hostile", tc.header, map[string]any{
				"sub": "okta|ada", "email": "ada@acme.example",
			})

			flow := NewDeviceFlow(p).withSleep(func(time.Duration) {})
			polls := 0
			flow.sleep = func(time.Duration) {
				polls++
				if polls == 2 {
					f.approveDevice("dev-hostile") // the human completes auth in the browser
				}
			}

			res, err := flow.Authenticate(context.Background(), nil)
			if err == nil {
				t.Fatalf("device flow converged on %+v, but the hostile header must be refused end-to-end", res)
			}
			// The header-member / typ refusal is an ErrToken (validation), surfaced
			// unwrapped through the device flow's resultFromToken convergence point.
			if !errors.Is(err, ErrToken) {
				t.Fatalf("want ErrToken on the integrated device-code path, got %v", err)
			}
		})
	}

	// Control: the SAME flow with the LEGITIMATE header (typ:"JWT", no cert refs)
	// converges on a validated AuthResult — proving the refusals above are the header
	// member, not a broken device-code harness.
	t.Run("legit_header_validates", func(t *testing.T) {
		f := newFakeOIDC(t, "RS256", "ds-client")
		p := providerForFake(t, f, f.config("acme", nil), time.Now())
		f.scriptDeviceWithHeader("dev-ok", map[string]any{"alg": "RS256", "kid": "test-kid-1", "typ": "JWT"}, map[string]any{
			"sub": "okta|ada",
		})
		flow := NewDeviceFlow(p).withSleep(func(time.Duration) {})
		polls := 0
		flow.sleep = func(time.Duration) {
			polls++
			if polls == 2 {
				f.approveDevice("dev-ok")
			}
		}
		res, err := flow.Authenticate(context.Background(), nil)
		if err != nil {
			t.Fatalf("control: legit-header device flow must validate, got %v", err)
		}
		if res.Subject != "okta|ada" {
			t.Fatalf("control: Subject = %q, want okta|ada", res.Subject)
		}
	})
}

func TestConfig_Validate(t *testing.T) {
	bad := []struct {
		name string
		cfg  Config
	}{
		{"no org", Config{Issuer: "https://i", ClientID: "c"}},
		{"no issuer", Config{Org: "acme", ClientID: "c"}},
		{"no client id", Config{Org: "acme", Issuer: "https://i"}},
		{"bad role", Config{Org: "acme", Issuer: "https://i", ClientID: "c",
			GroupRoleMap: map[string]PlatformRole{"g": "superuser"}}},
	}
	for _, tc := range bad {
		if err := tc.cfg.Validate(); !errors.Is(err, ErrConfig) {
			t.Errorf("%s: want ErrConfig, got %v", tc.name, err)
		}
	}
	ok := Config{Org: "acme", Issuer: "https://i", ClientID: "c",
		GroupRoleMap: map[string]PlatformRole{"eng-admins": RoleOrgAdmin}}
	if err := ok.Validate(); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}
}
