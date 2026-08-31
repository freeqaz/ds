// SPDX-License-Identifier: Apache-2.0

package credttl

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
)

// Tag is the single-sourced guardrail tag for this row (doc.go REGISTRATION).
// The guardrail-map.yaml glob for this package points at this exact string, and
// TestTagStable pins it, so the §3c table, this package, and the map name the
// SAME row.
const Tag = "identity-inject-class-ttl-bound"

// ── The validation fence (doc 16 §5.4 "TTL-as-revocation") ───────────────────
//
// The minimal CA ships no CRL/OCSP: an inject-class credential is bounded by TTL,
// so freshness is a ttl-vs-now comparison. We model the fence as DATA carried in
// each fixture (Policy.NowUnixSeconds) so a presentation pins the exact fence it
// asserts against; the check never reads a wall clock (D50).

// Policy is the validation policy a presentation is diffed against: the single
// knob is the validation fence (now, in unix seconds). A credential horizon at or
// before the fence is expired.
type Policy struct {
	// NowUnixSeconds is the validation fence: a token/grant TTL ≤ this is expired,
	// one > this is fresh (the inclusive-lapse boundary refimpl.go uses). A
	// non-positive fence is invalid (the policy must name a real instant).
	NowUnixSeconds int64 `json:"now_unix"`
}

// ── The presentation (synthetic fixture) ────────────────────────────────────

// Presentation is one synthetic inject-class credential presentation: the two
// independent freshness horizons the validator enforces (doc 16 §5.1, doc 19 §8)
// — the presented TOKEN's own TTL and the matched GRANT's own TTL, both as
// absolute unix seconds. A conforming presentation has BOTH strictly in the
// future; the ALLOW horizon it earns is the tighter of the two (AllowHorizon).
type Presentation struct {
	// Name labels the presentation for violation messages (filled from the
	// filename when loaded via Load).
	Name string `json:"-"`
	// TokenTTLUnixSeconds is the presented token's own expiry horizon. At or
	// before the fence → TOKEN-EXPIRED (the token-TTL leg, refimpl.go
	// HonestDecision step 3). Non-positive → UNDECIDABLE.
	TokenTTLUnixSeconds int64 `json:"token_ttl_unix"`
	// GrantTTLUnixSeconds is the matched grant's own expiry horizon. At or before
	// the fence → GRANT-EXPIRED (the grant-TTL leg, HonestDecision step 4), an
	// INDEPENDENT leg from the token's. Non-positive → UNDECIDABLE.
	GrantTTLUnixSeconds int64 `json:"grant_ttl_unix"`
}

// label names the presentation for violation messages, with a fallback when
// blank.
func (p Presentation) label() string {
	if p.Name != "" {
		return p.Name
	}
	return "(unnamed presentation)"
}

// ── Violation taxonomy ──────────────────────────────────────────────────────

// ViolationClass names the TTL-bound failure modes this row enumerates, so each
// violation reports WHICH leg it tripped (the "fails NAMED" bar). The two expiry
// classes are DELIBERATELY distinct — token vs grant — so a diff that reports one
// cannot be mistaken for the other, mirroring the two independent legs the
// production validator turns on (refimpl.go HonestDecision steps 3 and 4).
type ViolationClass string

const (
	// ViolationTokenExpired — (a) the presented token's own TTL is at or before
	// the fence (the token-TTL leg).
	ViolationTokenExpired ViolationClass = "inject-class-token-ttl-expired"
	// ViolationGrantExpired — (b) the matched grant's own TTL is at or before the
	// fence (the grant-TTL leg), independent of the token's.
	ViolationGrantExpired ViolationClass = "inject-class-grant-ttl-expired"
	// ViolationUndecidableTTL — (c) a horizon that is non-positive (≤ 0) names no
	// real instant; the ttl-vs-now verdict is undecidable and is treated as a
	// breach, never a silent pass.
	ViolationUndecidableTTL ViolationClass = "inject-class-ttl-horizon-undecidable"
)

// Violation is a single TTL-bound failure: which rule, which leg, and a
// human-readable reason citing the TTL-bound anchor.
type Violation struct {
	Class  ViolationClass
	Leg    string // "token" or "grant" — which horizon tripped
	Reason string
}

func (v Violation) String() string {
	return fmt.Sprintf("[%s] %s: %s", v.Class, v.Leg, v.Reason)
}

// ── The mechanical diff ─────────────────────────────────────────────────────

// Check diffs a presentation's two freshness horizons against the validation
// fence and returns every TTL-bound violation, in a stable order (rule class,
// then leg). An empty result means the presentation conforms: BOTH the token TTL
// and the grant TTL are strictly in the future.
//
// Per-leg verdict (applied independently to the token and the grant horizon):
//
//   - ttl ≤ 0        → UNDECIDABLE (c): no real horizon; a breach, never a pass.
//   - ttl ≤ now      → EXPIRED (a token → TokenExpired, a grant → GrantExpired):
//     the credential (or its grant) has lapsed as of the fence.
//   - ttl > now      → FRESH (no violation).
//
// A horizon EXACTLY at the fence (ttl == now) is EXPIRED — the inclusive-lapse
// boundary refimpl.go's `expiry <= now` comparison uses, so `now` is the first
// lapsed instant, not the last fresh one. The two legs are checked
// independently, so a presentation whose token AND grant are both stale reports
// BOTH — the diff never short-circuits after the first failing leg.
func Check(p Presentation, policy Policy) []Violation {
	now := policy.NowUnixSeconds
	var vs []Violation
	vs = appendLeg(vs, "token", ViolationTokenExpired, p.TokenTTLUnixSeconds, now, p.label())
	vs = appendLeg(vs, "grant", ViolationGrantExpired, p.GrantTTLUnixSeconds, now, p.label())
	sort.Slice(vs, func(i, j int) bool {
		if vs[i].Class != vs[j].Class {
			return vs[i].Class < vs[j].Class
		}
		return vs[i].Leg < vs[j].Leg
	})
	return vs
}

// appendLeg classifies ONE horizon (token or grant) against the fence and
// appends its violation, if any. The undecidable guard (ttl ≤ 0) runs FIRST so a
// zero/negative horizon is reported as undecidable, not masked as a routine
// expiry — a non-positive value would otherwise satisfy `ttl <= now` and read as
// merely lapsed.
func appendLeg(vs []Violation, leg string, expiredClass ViolationClass, ttl, now int64, name string) []Violation {
	if ttl <= 0 {
		return append(vs, Violation{
			Class: ViolationUndecidableTTL,
			Leg:   leg,
			Reason: fmt.Sprintf("presentation %s carries a %s TTL of %d (≤ 0) — it names no real "+
				"horizon, so the ttl-vs-now verdict is undecidable; an undecidable TTL is a breach, "+
				"never a silent pass (doc 16 §5.4)", name, leg, ttl),
		})
	}
	if ttl <= now {
		return append(vs, Violation{
			Class: expiredClass,
			Leg:   leg,
			Reason: fmt.Sprintf("presentation %s has a %s TTL of %d at or before the validation "+
				"fence now=%d; the inject-class %s credential has lapsed and the swap is denied "+
				"credential_expired (doc 06 §3c inject-class twin; doc 16 §5.1/§5.4 — the %s-TTL "+
				"freshness leg)", name, leg, ttl, now, leg, leg),
		})
	}
	return vs
}

// ── The intersection horizon (grant-wins / token-wins the min) ──────────────

// AllowHorizon returns the ALLOW horizon a conforming presentation earns: the
// TIGHTER of the token TTL and the grant TTL (min), the intersection-narrowing
// property (doc 16 §5.1, doc 19 §8). A token narrower than its grant is bounded
// by the token (token wins the min); a grant narrower than its token is bounded
// by the grant (grant wins the min). It is meaningful only for a conforming
// presentation (Check returns empty); on a stale/undecidable presentation the
// returned value has no contract meaning (the swap is denied, not allowed).
func AllowHorizon(p Presentation) int64 {
	if p.GrantTTLUnixSeconds < p.TokenTTLUnixSeconds {
		return p.GrantTTLUnixSeconds
	}
	return p.TokenTTLUnixSeconds
}

// HorizonWinner names which leg supplies the ALLOW horizon (the tighter one):
// "grant" when the grant TTL is strictly tighter, "token" when the token TTL is
// strictly tighter, and "equal" when the two horizons coincide (neither strictly
// wins). It is the readable companion to AllowHorizon for asserting the
// grant-wins-the-min and token-wins-the-min corners.
func HorizonWinner(p Presentation) string {
	switch {
	case p.GrantTTLUnixSeconds < p.TokenTTLUnixSeconds:
		return "grant"
	case p.TokenTTLUnixSeconds < p.GrantTTLUnixSeconds:
		return "token"
	default:
		return "equal"
	}
}

// ── Loading fixtures (cwd-independent) ──────────────────────────────────────

// thisDir returns the directory of THIS source file (runtime.Caller-anchored),
// so fixture lookups work under `go test` from any cwd — the same technique the
// sibling guardrail-conformance packages use.
func thisDir() string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return "."
	}
	return filepath.Dir(thisFile)
}

// FixturesDir is the synthetic-fixture directory, anchored off this file.
func FixturesDir() string { return filepath.Join(thisDir(), "fixtures") }

// validate accepts any presentation: a token/grant TTL of any value is a legal
// INPUT — a non-positive or already-lapsed horizon is a Check-time VIOLATION
// (undecidable / expired), never a load error, so the corpus can carry the
// breach fixtures the coverage gate requires.
func (p Presentation) validate() error {
	return nil
}

// validate rejects a policy that cannot anchor a TTL verdict: a non-positive
// validation fence names no real instant.
func (policy Policy) validate() error {
	if policy.NowUnixSeconds <= 0 {
		return fmt.Errorf("policy declares now_unix=%d — the validation fence must name a "+
			"positive unix instant", policy.NowUnixSeconds)
	}
	return nil
}

// Fixture is a loaded synthetic fixture's full TTL picture: the validation policy
// in force plus the single presentation it covers.
type Fixture struct {
	// Name labels the fixture for violation messages (filled from the filename
	// when loaded via Load).
	Name string `json:"-"`
	// Policy is the validation policy this fixture asserts against.
	Policy Policy `json:"policy"`
	// Presentation is the inject-class credential presentation the fixture covers.
	Presentation Presentation `json:"presentation"`
}

// Load reads a synthetic TTL fixture from a JSON file and labels both it and its
// presentation with the file's base name for violation messages.
func Load(path string) (Fixture, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Fixture{}, fmt.Errorf("reading credttl fixture %s: %w", path, err)
	}
	var f Fixture
	if err := json.Unmarshal(data, &f); err != nil {
		return Fixture{}, fmt.Errorf("parsing credttl fixture %s: %w", path, err)
	}
	f.Name = filepath.Base(path)
	f.Presentation.Name = filepath.Base(path)
	if err := f.Policy.validate(); err != nil {
		return Fixture{}, err
	}
	if err := f.Presentation.validate(); err != nil {
		return Fixture{}, err
	}
	return f, nil
}
