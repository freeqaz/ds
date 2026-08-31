package sessions

// envconfig.go is the doc 15 §9 RecordEnvConfig SURFACE — the create-time stage
// that turns a RecordEnvConfig request (repo ref + hash, or an inline body) into
// the stored env-config reference shape (store.EnvConfig), recording the image's
// COUPLED INVARIANTS as one unsplittable unit so the CC-pin ↔ pack-exclusion
// coupling cannot silently split (D74/D49). It is the D7 env/build-config recorder
// the §4.1 step-1 two-key check (twokey.go) reads the "checked-in env spec" key from.
//
// WHAT THIS STAGE OWNS AND WHAT IT DOES NOT:
//   - OWNS: the REFERENCE shape stored (doc 15 §9: "this doc freezes only the
//     reference shape stored") — the env-spec source (repo ref + hash, or inline),
//     the resolved content-addressed image ID, and the coupled invariants (CC pin
//     ≥ 2.1.116 + auto-update off ↔ downloads.claude.ai excluded-from-pack, pack
//     version). It validates and persists that shape through the EXISTING store
//     seam (store.PutEnvConfig), never widening the store record.
//   - DOES NOT OWN: the env-spec document FORMAT itself (doc 15 OQ10 — "owned
//     elsewhere", the Image & cache builder workstream jointly with Onboarding). The
//     env_spec body is OPAQUE here: this stage hashes it and stores it, never parses
//     it. It also does not RESOLVE the image (the (repo, ref, env_spec_hash) → image
//     ID resolution is the Image-workstream's content-address; the caller supplies
//     the resolved image ID, this stage records the lineage). The mirror_source
//     clone-delivery selector (doc 15 §9) is excluded from env_spec_hash and is not
//     recorded here — it is a clone-time delivery selector, not a content-address
//     input.
//
// WHY THE COUPLING IS A STRUCTURAL UNIT (the gap this closes, D74/D49). D74 couples
// "CC pinned ≥ 2.1.116, auto-update disabled" to "downloads.claude.ai excluded from
// the session pack" — recorded together so a future edit cannot pin the CC version
// while silently re-admitting downloads.claude.ai into the pack (or vice versa),
// which would let unreviewed CC protocol drift reach production behind a pin that no
// longer matches the pack (the D49 hazard). This stage records the three coupled
// facts as ONE CoupledInvariants value and REFUSES (ErrCouplingSplit) to record a
// partial coupling — a half-set coupling is the silent split D74/D49 forbids, so it
// fails-closed at record time rather than persisting a record that reads as coupled
// but is not.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// minCCPin is the D74 minimum Claude Code pin recorded with the image — "CC pinned
// ≥ 2.1.116" — the floor below which a coupled invariant set is refused. It is the
// documented decision constant, not a parsed semver: the recorded pin string must be
// present and the caller asserts it meets the floor; this stage records the floor it
// was checked against so the audit trail carries the contract the record satisfies.
const minCCPin = "2.1.116"

// packExclusionHost is the D74 host that MUST be excluded from the session pack and
// instead joins the image-build-time allowlist (coupled to D49). It is the host the
// CoupledInvariants pack-exclusion fact names; recording any other value (or an
// empty one) alongside a CC pin is the silent split this stage refuses.
const packExclusionHost = "downloads.claude.ai"

// ErrCouplingSplit is the structural refusal of a SPLIT coupled-invariant set: a
// record that pins the CC version (or names the pack version) WITHOUT also recording
// the downloads.claude.ai pack-exclusion (or vice versa) is the silent split D74/D49
// forbids. It is refused fail-closed at record time — the same fail-closed posture
// as the D56 two-key check and the steps-1–2 role refusal — so a half-coupled record
// never reaches the store and reads later as "coupled" when it is not.
var ErrCouplingSplit = errors.New("sessions: coupled invariants split (D74/D49: CC pin ↔ downloads.claude.ai pack-exclusion must be recorded together)")

// ErrEnvSpecInvalid is the structural refusal of an env-config record that carries
// NEITHER a repo ref NOR an inline spec body — there is nothing to content-address,
// so there is no "checked-in env spec" key for the §4.1 two-key check to read. It is
// distinct from ErrCouplingSplit (a bad coupling, not a missing spec).
var ErrEnvSpecInvalid = errors.New("sessions: env spec invalid (neither a repo ref nor an inline spec body)")

// CoupledInvariants is the doc 15 §9 image-coupled-invariant UNIT (D74/D49),
// recorded as ONE value so the coupling cannot silently split. It is the in-package
// projection of exactly the three store.EnvConfig coupling fields (CoupledPin,
// PackVersion, PackExclusion) — carried together, validated together, persisted
// together. A caller builds it once and hands it to RecordEnvConfig; the validator
// refuses any half-set (ErrCouplingSplit).
//
// THE COUPLING (D74, "coupled to D49"): "CC pinned ≥ 2.1.116, auto-update disabled"
// ↔ "downloads.claude.ai excluded from the session pack (joins the image-build-time
// allowlist)". The three fields below are the three facts of that one coupling; all
// three are present together or the set is refused.
type CoupledInvariants struct {
	// CCPin is the recorded Claude Code version pin (D74: "CC pinned ≥ 2.1.116").
	// The recorded value must be non-empty and meet the minCCPin floor — auto-update
	// is the OTHER half of this fact (auto-update disabled), asserted by AutoUpdateOff
	// so the two never read apart.
	CCPin string
	// AutoUpdateOff records the D74 "auto-update disabled" fact paired with the pin.
	// A pinned CC with auto-update STILL ON is not the D74 coupling — the pin would
	// drift on the next launch — so this MUST be true for a valid coupled set.
	AutoUpdateOff bool
	// PackVersion is the D74 session-pack (baseline endpoint pack v2) version this
	// image's pack-exclusion is recorded against. Non-empty for a valid coupled set:
	// the pack-exclusion fact is only meaningful against a known pack version.
	PackVersion string
	// PackExclusion is the host excluded from the session pack (D74: downloads.claude.ai
	// joins the image-build-time allowlist, NOT the session pack). It MUST equal
	// packExclusionHost for a valid coupled set — recording the pin without this host
	// (or with a different host) is the silent split ErrCouplingSplit refuses.
	PackExclusion string
}

// Validate enforces the D74/D49 coupling as an UNSPLITTABLE unit: all three coupled
// facts are present and consistent, or the set is refused fail-closed
// (ErrCouplingSplit). This is what makes "the coupling cannot silently split" a
// structural property of the record rather than a comment — a half-set never
// validates, so it never reaches the store.
//
// The checks, all fail-closed (the D56-posture refusal):
//   - CCPin present AND ≥ minCCPin (the D74 floor; an empty or below-floor pin is a
//     split — the pack-exclusion below would then be recorded against no pin).
//   - AutoUpdateOff true (the D74 "auto-update disabled" half of the pin fact — a
//     pin with auto-update still on would drift, defeating the pin).
//   - PackVersion present (the pack-exclusion fact is meaningless against no pack).
//   - PackExclusion == packExclusionHost (D74: downloads.claude.ai, exactly — a
//     different or empty host re-admits it to the pack, the silent split).
func (c CoupledInvariants) Validate() error {
	pin := strings.TrimSpace(c.CCPin)
	if pin == "" {
		return fmt.Errorf("%w: no CC pin recorded (D74 requires CC pinned ≥ %s)", ErrCouplingSplit, minCCPin)
	}
	if !ccPinMeetsFloor(pin) {
		return fmt.Errorf("%w: CC pin %q below the D74 floor %s", ErrCouplingSplit, pin, minCCPin)
	}
	if !c.AutoUpdateOff {
		return fmt.Errorf("%w: CC pin %q recorded with auto-update STILL ON (D74 couples the pin to auto-update disabled)", ErrCouplingSplit, pin)
	}
	if strings.TrimSpace(c.PackVersion) == "" {
		return fmt.Errorf("%w: no session-pack version recorded (the %s pack-exclusion has no pack to exclude from)", ErrCouplingSplit, packExclusionHost)
	}
	if strings.TrimSpace(c.PackExclusion) != packExclusionHost {
		return fmt.Errorf("%w: pack-exclusion is %q, want %q (D74: %s is excluded from the session pack, joins the image-build-time allowlist)",
			ErrCouplingSplit, c.PackExclusion, packExclusionHost, packExclusionHost)
	}
	return nil
}

// ccPinMeetsFloor reports whether a recorded CC pin meets the D74 minCCPin floor. It
// is a small dotted-numeric compare (major.minor.patch), tolerant of a leading "v"
// and of extra dotted components (a 4th component compares as the tiebreaker). It is
// NOT a full semver parser (pre-release/build metadata are not part of the recorded
// pin contract); an unparseable component is treated as below-floor (fail-closed),
// so a malformed pin is refused rather than silently passed.
func ccPinMeetsFloor(pin string) bool {
	return compareDotted(strings.TrimPrefix(pin, "v"), minCCPin) >= 0
}

// compareDotted compares two dotted-numeric version strings component-by-component,
// returning -1/0/+1. A missing trailing component is treated as 0 (so "2.1" < "2.1.1"
// is false only at the shared prefix; the shorter is the lower when the longer has a
// non-zero tail). A non-numeric component makes that side compare LOW (fail-closed:
// a malformed pin must not pass the floor).
func compareDotted(a, b string) int {
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		av, aok := atoiComponent(as, i)
		bv, bok := atoiComponent(bs, i)
		// A malformed component compares LOW (fail-closed) — a parse failure on the
		// candidate must not let it meet the floor.
		switch {
		case !aok && !bok:
			// both malformed at this position: treat as equal, keep scanning.
		case !aok:
			return -1
		case !bok:
			return 1
		case av < bv:
			return -1
		case av > bv:
			return 1
		}
	}
	return 0
}

// atoiComponent returns the i-th dotted component as an int, or ok=false if the
// component is absent (treated as 0, ok=true) or non-numeric (ok=false). An absent
// component is a legitimate 0; only a present-but-non-numeric component is malformed.
func atoiComponent(parts []string, i int) (int, bool) {
	if i >= len(parts) {
		return 0, true // absent trailing component = 0
	}
	s := strings.TrimSpace(parts[i])
	if s == "" {
		return 0, true
	}
	v := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, false // non-numeric: malformed, compares low
		}
		v = v*10 + int(r-'0')
	}
	return v, true
}

// RecordEnvConfigInput is the input to the doc 15 §9 RecordEnvConfig surface: the
// env-spec source (a repo ref + its hash, OR an inline spec body), the resolved
// content-addressed image ID, and the image's coupled invariants. It is the
// in-package projection of the proto RecordEnvConfigRequest PLUS the resolved image
// lineage and coupling the orchestrator records alongside the opaque spec body — the
// proto carries `repo_id` + opaque `env_spec`; the resolved image ID and the coupled
// invariants are control-plane facts the recorder attaches, not request fields.
type RecordEnvConfigInput struct {
	// RepoRef is the repo ref the env spec is checked into (D56 second key's "how"),
	// empty when the spec is request-carried inline. Recorded as lineage.
	RepoRef string
	// SpecHash is the caller-supplied env-spec hash, when the spec is repo-referenced
	// and already content-addressed upstream. Empty = this stage computes the hash
	// from InlineSpec (the inline case). When BOTH are supplied the caller's SpecHash
	// is authoritative (it is the upstream content-address) and InlineSpec is recorded
	// verbatim as the body.
	SpecHash string
	// InlineSpec is the OPAQUE env-spec body (schema UNOWNED, doc 15 OQ10) when the
	// spec is request-carried rather than repo-referenced. Hashed (never parsed) to
	// derive SpecHash when SpecHash is empty.
	InlineSpec []byte
	// ImageID is the resolved content-addressed image ID — the
	// (repo, ref, env_spec_hash) → image ID the Image workstream resolved. This stage
	// records the lineage; it does NOT resolve the image (that content-address is the
	// Image workstream's, doc 15 §9). Required: an env config with no resolved image
	// has nothing to couple the invariants to.
	ImageID string
	// Coupled is the image's coupled-invariant unit (D74/D49). Validated as an
	// unsplittable set (CoupledInvariants.Validate) before anything is stored.
	Coupled CoupledInvariants
}

// RecordEnvConfig is the doc 15 §9 RecordEnvConfig surface: it validates the request
// (a present spec source, a resolved image, an unsplit coupling), derives the
// content-addressed env-config reference, and PERSISTS the store.EnvConfig through
// the existing store seam — returning the stored reference the §4.1 two-key check and
// CreateSession's env_config_ref resolve against.
//
// Order (all checks fail-closed, the D56 posture):
//  1. SPEC SOURCE present — a repo ref OR an inline body, else ErrEnvSpecInvalid
//     (there is no "checked-in env spec" key without one).
//  2. IMAGE resolved — a non-empty ImageID, else an error (nothing to couple to).
//  3. COUPLING unsplit — CoupledInvariants.Validate, else ErrCouplingSplit. This is
//     the D74/D49 structural guard: a half-coupled record never reaches the store.
//  4. SPEC HASH derived — the caller's upstream hash, or the SHA-256 of the inline
//     body (the env spec is OPAQUE; hashing is the only operation on the body).
//  5. REF derived — a content-addressed handle over (repo ref, spec hash, image ID)
//     so the same env config records to the same ref (idempotent re-record), then
//     stored via store.PutEnvConfig.
//
// The store seam (PutEnvConfig) is the EXISTING reference-shape store — this stage
// fills the surface logic over it, never widening the store record.
func RecordEnvConfig(ctx context.Context, s envConfigStore, in RecordEnvConfigInput) (store.EnvConfig, error) {
	if s == nil {
		return store.EnvConfig{}, fmt.Errorf("sessions: RecordEnvConfig: no env-config store configured")
	}

	repoRef := strings.TrimSpace(in.RepoRef)
	specHash := strings.TrimSpace(in.SpecHash)

	// (1) SPEC SOURCE present.
	if repoRef == "" && len(in.InlineSpec) == 0 && specHash == "" {
		return store.EnvConfig{}, ErrEnvSpecInvalid
	}

	// (2) IMAGE resolved.
	imageID := strings.TrimSpace(in.ImageID)
	if imageID == "" {
		return store.EnvConfig{}, fmt.Errorf("sessions: RecordEnvConfig: no resolved image ID (the coupled invariants have no image to couple to)")
	}

	// (3) COUPLING unsplit — the D74/D49 structural guard, before anything is stored.
	if err := in.Coupled.Validate(); err != nil {
		return store.EnvConfig{}, err
	}

	// (4) SPEC HASH derived. The caller's upstream hash wins (it is the upstream
	// content-address); otherwise hash the OPAQUE inline body (the env spec is never
	// parsed — doc 15 OQ10).
	if specHash == "" {
		if len(in.InlineSpec) == 0 {
			// A repo ref with no upstream hash and no inline body: nothing to
			// content-address. Refuse rather than store a ref-less record.
			return store.EnvConfig{}, fmt.Errorf("%w: repo-referenced spec %q carries no upstream hash and no inline body", ErrEnvSpecInvalid, repoRef)
		}
		sum := sha256.Sum256(in.InlineSpec)
		specHash = hex.EncodeToString(sum[:])
	}

	// (5) REF derived — content-addressed over the lineage so re-recording the same
	// env config is idempotent (same ref). The image ID is in the key so a re-resolve
	// to a new image is a distinct record.
	ref := deriveEnvConfigRef(repoRef, specHash, imageID)

	rec := store.EnvConfig{
		Ref:           ref,
		RepoRef:       repoRef,
		SpecHash:      specHash,
		InlineSpec:    in.InlineSpec,
		ImageID:       imageID,
		CoupledPin:    strings.TrimSpace(in.Coupled.CCPin),
		PackVersion:   strings.TrimSpace(in.Coupled.PackVersion),
		PackExclusion: strings.TrimSpace(in.Coupled.PackExclusion),
	}
	stored, err := s.PutEnvConfig(ctx, rec)
	if err != nil {
		return store.EnvConfig{}, fmt.Errorf("sessions: RecordEnvConfig: persist env config: %w", err)
	}
	return stored, nil
}

// deriveEnvConfigRef computes the content-addressed env-config reference over the
// recorded lineage (repo ref, spec hash, image ID). Recording the same lineage twice
// yields the same ref — RecordEnvConfig is idempotent on the env config it records,
// matching the §4.1 "every create verb is idempotent on session UUID" discipline at
// the env-config-record layer.
func deriveEnvConfigRef(repoRef, specHash, imageID string) string {
	h := sha256.New()
	// Length-prefix each component so distinct splits cannot collide (a classic
	// concatenation ambiguity); the field separator is the component length.
	for _, part := range []string{repoRef, specHash, imageID} {
		fmt.Fprintf(h, "%d:%s", len(part), part)
	}
	return "env-" + hex.EncodeToString(h.Sum(nil))[:32]
}

// envConfigStore is the narrow store seam the RecordEnvConfig surface writes through:
// the EXISTING store.PutEnvConfig reference-shape recorder (store stays frozen — this
// stage only calls it). It is the env-config analog of the launch gate's sessionLinker
// seam: a method subset of the real store, taken as data so this stage depends on the
// verb, not the whole repository.
type envConfigStore interface {
	PutEnvConfig(ctx context.Context, c store.EnvConfig) (store.EnvConfig, error)
}
