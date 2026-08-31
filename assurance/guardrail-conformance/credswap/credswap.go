// SPDX-License-Identifier: Apache-2.0

package credswap

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
)

// Tag is the single-sourced guardrail tag for this row, so the package's claim
// metadata and any future guardrail-map.yaml row name the SAME row (doc.go
// REGISTRATION). It is NOT written into the map here (the map is Boundary-owned;
// an unmapped subdir is fail-closed to the full matrix, D47).
const Tag = "cred-swap-never-leaks"

// ── Credential classes (doc 16 §13, doc 20 §7.3) ────────────────────────────
//
// The D8 never-enters-the-VM promise covers swap-class IN FULL; inject-class is
// a deliberately weaker, distinct claim the doc 06 (c) wording keeps split
// (doc 20 §7.3). We model exactly that split: a swap-class long-lived secret is
// judged on its ABSENCE from every in-VM/host surface; an inject-class secret
// is in the environment BY DESIGN and judged only on its TTL bound + the
// presence of its ISSUED{service_id} digest.

// CredClass names a credential's class.
type CredClass string

const (
	// ClassSwap — swap-class: never enters the VM, header-substitutable at TLS-5
	// outside the VM (D8 covers these in full; doc 16 §13).
	ClassSwap CredClass = "swap"
	// ClassInject — inject-class: STS-style short-lived creds passed into the
	// environment by design (doc 02 §6's AWS sketch); bounded by TTL + the
	// ISSUED{service_id} digest, not by in-VM absence (doc 20 §7.3).
	ClassInject CredClass = "inject"
)

// ── The enumerated surfaces (doc 06 §3c) ────────────────────────────────────
//
// The claim names exactly these surfaces. A swap-class long-lived credential
// observed on ANY of them is a breach.

// Surface names one place the claim asserts a swap-class long-lived credential
// must NOT appear.
type Surface string

const (
	// SurfaceDisk — a file inside the VM's filesystem.
	SurfaceDisk Surface = "disk"
	// SurfaceEnv — a process environment variable inside the VM.
	SurfaceEnv Surface = "env"
	// SurfaceCoWDelta — the per-session copy-on-write overlay.
	SurfaceCoWDelta Surface = "cow_delta"
	// SurfaceAgentResponse — any response byte the agent can read.
	SurfaceAgentResponse Surface = "agent_response"
	// SurfaceMetalHost — the bare-metal host (the D39 "never on the metal host"
	// extension).
	SurfaceMetalHost Surface = "metal_host"
)

// inVMHostSurfaces is the full enumerated surface set, in claim order. The
// conforming control proves a swap-class secret is absent from EVERY one.
var inVMHostSurfaces = []Surface{
	SurfaceDisk, SurfaceEnv, SurfaceCoWDelta, SurfaceAgentResponse, SurfaceMetalHost,
}

// ── The synthetic credential picture ────────────────────────────────────────

// Credential is one credential in the synthetic fixture: its class, and — for a
// swap-class credential — which enumerated surfaces its LONG-LIVED secret value
// was observed on (the empty/absent set is conforming). For an inject-class
// credential the surface set is irrelevant (in-VM presence is by design); it is
// judged on TTLSeconds and IssuedDigest instead.
type Credential struct {
	// Name labels the credential for violation messages (e.g. "github-pat").
	Name string `json:"name"`
	// Class is swap | inject.
	Class CredClass `json:"class"`
	// LongLivedOnSurfaces lists the surfaces on which this credential's
	// LONG-LIVED secret value was observed. For a swap-class credential this MUST
	// be empty; any entry is a breach. Ignored for inject-class.
	LongLivedOnSurfaces []Surface `json:"long_lived_on_surfaces"`
	// TTLSeconds is the inject-class credential's TTL bound (doc 16 §13). It must
	// be positive for an inject-class credential; ignored for swap-class.
	TTLSeconds int `json:"ttl_seconds"`
	// IssuedDigest is the inject-class credential's ISSUED{service_id} digest tag
	// (doc 16 §5.1/§13: a digest's intended service is a grant fact). It must be
	// present (non-empty) for an inject-class credential; ignored for swap-class.
	IssuedDigest string `json:"issued_digest"`
}

// Picture is a synthetic fixture's full credential picture.
type Picture struct {
	// Name labels the fixture (filled from the filename when loaded via Load).
	Name string `json:"-"`
	// Credentials is the set of credentials this picture covers.
	Credentials []Credential `json:"credentials"`
}

// ── Violation taxonomy ──────────────────────────────────────────────────────

// ViolationClass names the failure modes this row enumerates, so each violation
// reports WHICH rule it tripped (the "fails NAMED" bar).
type ViolationClass string

const (
	// ViolationSwapLeakOnSurface — a swap-class long-lived credential observed on
	// an enumerated in-VM/host surface. The surface name is carried in the
	// violation's Surface field.
	ViolationSwapLeakOnSurface ViolationClass = "swap-class-long-lived-credential-on-surface"
	// ViolationInjectTTLUnbounded — an inject-class credential with a missing or
	// non-positive TTL (the inject-class twin's TTL-bound half).
	ViolationInjectTTLUnbounded ViolationClass = "inject-class-credential-ttl-unbounded"
	// ViolationInjectDigestMissing — an inject-class credential with no
	// ISSUED{service_id} digest (the inject-class twin's digest half).
	ViolationInjectDigestMissing ViolationClass = "inject-class-credential-issued-digest-missing"
)

// Violation is a single failure: which rule, which credential, the surface (for
// a swap leak), and a human-readable reason citing the anchor.
type Violation struct {
	Class      ViolationClass
	Credential string
	Surface    Surface // set only for ViolationSwapLeakOnSurface
	Reason     string
}

func (v Violation) String() string {
	if v.Surface != "" {
		return fmt.Sprintf("[%s] %s @ %s: %s", v.Class, v.Credential, v.Surface, v.Reason)
	}
	return fmt.Sprintf("[%s] %s: %s", v.Class, v.Credential, v.Reason)
}

// ── The mechanical check ────────────────────────────────────────────────────

// Check scans a synthetic credential picture and returns every violation, in a
// stable order (rule class, credential, surface). An empty result means the
// picture conforms: every swap-class long-lived secret is absent from all five
// surfaces, and every inject-class credential carries a positive TTL and an
// ISSUED digest.
//
// Per-credential verdict:
//
//   - swap-class: each surface in LongLivedOnSurfaces → SwapLeakOnSurface. The
//     long-lived secret must never appear inside the VM (disk/env/CoW/response)
//     nor on the metal host (D8/D39).
//   - inject-class: TTLSeconds ≤ 0 → InjectTTLUnbounded; empty IssuedDigest →
//     InjectDigestMissing. In-VM presence is BY DESIGN and never a violation
//     (doc 20 §7.3, the weaker split claim).
func Check(p Picture) []Violation {
	var vs []Violation
	for _, c := range p.Credentials {
		switch c.Class {
		case ClassSwap:
			for _, s := range c.LongLivedOnSurfaces {
				vs = append(vs, Violation{
					Class:      ViolationSwapLeakOnSurface,
					Credential: c.label(),
					Surface:    s,
					Reason: fmt.Sprintf("swap-class credential %s's long-lived secret was observed on "+
						"surface %q; a swap-class credential must never appear inside the VM "+
						"(disk/env/CoW delta/agent-readable response) nor on the metal host — the swap "+
						"happens OUTSIDE the VM at the egress gateway (D8, doc 02 §6; D39, doc 16 §13)",
						c.label(), s),
				})
			}
		case ClassInject:
			if c.TTLSeconds <= 0 {
				vs = append(vs, Violation{
					Class:      ViolationInjectTTLUnbounded,
					Credential: c.label(),
					Reason: fmt.Sprintf("inject-class credential %s reports ttl_seconds=%d (≤0); the "+
						"inject-class claim is bounded by a TTL — an unbounded inject-class credential "+
						"defeats the weaker split claim (doc 16 §13, doc 20 §7.3)", c.label(), c.TTLSeconds),
				})
			}
			if c.IssuedDigest == "" {
				vs = append(vs, Violation{
					Class:      ViolationInjectDigestMissing,
					Credential: c.label(),
					Reason: fmt.Sprintf("inject-class credential %s carries no ISSUED{service_id} digest; "+
						"the digest is what makes a wrong-destination egress block (a digest's intended "+
						"service is a grant fact, doc 16 §5.1/§13, doc 20 §7.3)", c.label()),
				})
			}
		}
	}
	sort.Slice(vs, func(i, j int) bool {
		if vs[i].Class != vs[j].Class {
			return vs[i].Class < vs[j].Class
		}
		if vs[i].Credential != vs[j].Credential {
			return vs[i].Credential < vs[j].Credential
		}
		return vs[i].Surface < vs[j].Surface
	})
	return vs
}

// EnumeratedSurfaces returns the full claim surface set (copy), so a test can
// assert the conforming control proves absence on EVERY surface the claim names.
func EnumeratedSurfaces() []Surface {
	out := make([]Surface, len(inVMHostSurfaces))
	copy(out, inVMHostSurfaces)
	return out
}

// label names the credential for messages, with a fallback when blank.
func (c Credential) label() string {
	if c.Name != "" {
		return c.Name
	}
	return "(unnamed credential)"
}

// ── Loading fixtures (cwd-independent) ──────────────────────────────────────

// thisDir returns the directory of THIS source file (runtime.Caller-anchored),
// so fixture lookups work under `go test` from any cwd.
func thisDir() string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return "."
	}
	return filepath.Dir(thisFile)
}

// FixturesDir is the synthetic-fixture directory, anchored off this file.
func FixturesDir() string { return filepath.Join(thisDir(), "fixtures") }

// validate rejects a picture that cannot anchor a verdict: no credentials, an
// unknown class, or a surface name outside the enumerated set.
func (p Picture) validate() error {
	if len(p.Credentials) == 0 {
		return fmt.Errorf("picture %s declares no credentials — a credential picture must cover at "+
			"least one credential", p.Name)
	}
	known := map[Surface]bool{}
	for _, s := range inVMHostSurfaces {
		known[s] = true
	}
	for _, c := range p.Credentials {
		switch c.Class {
		case ClassSwap, ClassInject:
		default:
			return fmt.Errorf("picture %s credential %s declares unknown class %q (want %q or %q)",
				p.Name, c.label(), c.Class, ClassSwap, ClassInject)
		}
		for _, s := range c.LongLivedOnSurfaces {
			if !known[s] {
				return fmt.Errorf("picture %s credential %s names unknown surface %q (the claim "+
					"enumerates exactly %v)", p.Name, c.label(), s, inVMHostSurfaces)
			}
		}
	}
	return nil
}

// Load reads a synthetic credential picture from a JSON file and labels it with
// the file's base name for violation messages.
func Load(path string) (Picture, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Picture{}, fmt.Errorf("reading credential-picture fixture %s: %w", path, err)
	}
	var p Picture
	if err := json.Unmarshal(data, &p); err != nil {
		return Picture{}, fmt.Errorf("parsing credential-picture fixture %s: %w", path, err)
	}
	p.Name = filepath.Base(path)
	if err := p.validate(); err != nil {
		return Picture{}, err
	}
	return p, nil
}
