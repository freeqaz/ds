// SPDX-License-Identifier: Apache-2.0

package appinstall

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// ── Access levels ──────────────────────────────────────────────────────────
//
// The doc 16 §5.2 inventory records an Access level per row. We model only the
// distinctions the read-level-subset claim turns on: read, write, and a
// "not-derivable" positioning level used by the §5.2 rows whose owning flow has
// not landed its exact permission yet (recorded positioning, not a grant).

// AccessLevel is the access tier a permission is requested or inventoried at.
type AccessLevel string

const (
	// LevelRead is the read tier — the only tier the onboarding CI-read path may
	// request, and the tier the ratified triplet lives at.
	LevelRead AccessLevel = "read"
	// LevelWrite is any write tier. A write scope on the onboarding read path is
	// violation (b); a write-level permission requested by an onboarding-path
	// fixture is violation (a)/(b) per its phrasing.
	LevelWrite AccessLevel = "write"
	// LevelNotDerivable marks a §5.2 positioning row whose exact permission/level
	// is not yet derivable from doc prose (CI dispatch, status checks, the D56
	// enrollment flow). These rows are recorded positioning, never grants, and the
	// onboarding read path never requests them.
	LevelNotDerivable AccessLevel = "not-derivable"
)

// isReadOnly reports whether a level is strictly the read tier.
func (l AccessLevel) isReadOnly() bool { return l == LevelRead }

// isWrite reports whether a level is a write tier.
func (l AccessLevel) isWrite() bool { return l == LevelWrite }

// ── The onboarding read path ───────────────────────────────────────────────

// RatifiedOnboardingReadScope is the ratified onboarding CI-read scope set
// (doc 16 §5.2, ratified 2026-06-12; closes doc 07 §2b-spec OQ3). It MUST
// stay a strict read-only subset of the §5.2 inventory. This is the only set the
// onboarding agent's optional CI-run-metadata read may request.
//
// It is declared here as the ratified constant the guard test pins the parsed
// §5.2 read level against — so a doc edit that added a fourth read scope, or
// promoted one of these off read level, is caught by the guard rather than
// silently widening the onboarding posture.
var RatifiedOnboardingReadScope = []string{
	"contents:read",
	"actions:read",
	"metadata:read",
}

// OnboardingFlowMarker is the substring that identifies a manifest row as
// belonging to the onboarding CI-read path. The fixture manifest tags each
// requested permission with its consuming flow; a row whose flow carries this
// marker is on the read path and is held to the read-only-subset invariant.
const OnboardingFlowMarker = "onboarding"

// ── The inventory (doc 16 §5.2) ────────────────────────────────────────────

// InventoryRow is one row of the §5.2 D83 App-install permission inventory:
// {GitHub App permission, access level, consuming flow}. Positioning rows
// (CI dispatch, status checks, the D56 enrollment flow) carry LevelWrite or
// LevelNotDerivable and a non-canonical permission key; only the three read rows
// carry a concrete `*:read` permission at LevelRead.
type InventoryRow struct {
	Permission string      // e.g. "contents:read"; positioning rows use a descriptive key
	Level      AccessLevel // read | write | not-derivable
	Flow       string      // the consuming-flow derivation text
	// Positioning marks a §5.2 row whose exact permission/level is recorded
	// positioning pending the owning flow's spec (not a grant). Concrete `*:read`
	// onboarding rows are not positioning.
	Positioning bool
}

// Inventory is the parsed §5.2 table. It carries the concrete read-level
// permission set the onboarding subset is diffed against, plus the positioning
// rows (kept so "absent from the inventory" is judged against the WHOLE table,
// not just the read rows — a requested permission that matches a positioning row
// is "in the inventory" even though it is not a grant).
type Inventory struct {
	Rows []InventoryRow
}

// readPermissions returns the set of concrete read-level permissions (the
// `*:read` rows). These are the strict-subset anchor.
func (inv Inventory) readPermissions() map[string]bool {
	out := map[string]bool{}
	for _, r := range inv.Rows {
		if r.Level.isReadOnly() {
			out[r.Permission] = true
		}
	}
	return out
}

// has reports whether a permission key appears anywhere in the inventory
// (read rows by exact `*:read` key; positioning rows by their recorded key).
func (inv Inventory) has(permission string) (InventoryRow, bool) {
	for _, r := range inv.Rows {
		if r.Permission == permission {
			return r, true
		}
	}
	return InventoryRow{}, false
}

// ── The requested manifest (synthetic fixture) ─────────────────────────────

// RequestedPermission is one entry of a fixture manifest of requested GitHub App
// permissions: the permission key, the access level it is requested at, and the
// consuming flow that requests it.
type RequestedPermission struct {
	Permission string      `json:"permission"`
	Level      AccessLevel `json:"level"`
	Flow       string      `json:"flow"`
}

// isOnboardingPath reports whether this requested permission is on the
// onboarding CI-read path (judged by the OnboardingFlowMarker substring in its
// flow text, case-insensitive).
func (r RequestedPermission) isOnboardingPath() bool {
	return strings.Contains(strings.ToLower(r.Flow), OnboardingFlowMarker)
}

// Manifest is a synthetic fixture's full set of requested App permissions.
type Manifest struct {
	// Name labels the fixture for violation messages (filled from the filename
	// when loaded via LoadManifest).
	Name string `json:"-"`
	// Requested is the list of requested permissions.
	Requested []RequestedPermission `json:"requested"`
}

// ── Violation taxonomy ─────────────────────────────────────────────────────

// ViolationClass names the three failure modes the §13 row enumerates, so each
// violation reports WHICH rule it tripped (the "fails NAMED" acceptance bar).
type ViolationClass string

const (
	// ViolationAboveReadLevel — (a) an onboarding-path permission requested above
	// read level.
	ViolationAboveReadLevel ViolationClass = "onboarding-path-above-read-level"
	// ViolationWriteOnReadPath — (b) a write scope on the onboarding read path.
	ViolationWriteOnReadPath ViolationClass = "write-scope-on-onboarding-read-path"
	// ViolationAbsentFromInventory — (c) a requested permission absent from the
	// §5.2 inventory.
	ViolationAbsentFromInventory ViolationClass = "permission-absent-from-inventory"
)

// Violation is a single failure: which rule, which permission, and a
// human-readable reason citing the §5.2 anchor.
type Violation struct {
	Class      ViolationClass
	Permission string
	Flow       string
	Reason     string
}

func (v Violation) String() string {
	return fmt.Sprintf("[%s] %s (flow %q): %s", v.Class, v.Permission, v.Flow, v.Reason)
}

// ── The mechanical diff ────────────────────────────────────────────────────

// Diff diffs a requested manifest against the §5.2 inventory and returns every
// violation, in a stable order (rule class, then permission). An empty result
// means the manifest conforms: every onboarding-path permission is at read level
// with no write scope, and every requested permission is present in the
// inventory.
//
// Rule precedence per requested permission:
//
//   - ONBOARDING READ PATH (flow carries OnboardingFlowMarker). The level
//     invariant is the strongest claim on this path, so it is checked FIRST,
//     ahead of inventory presence: a write scope on the read path is (b)
//     write-on-read-path and an above-read level is (a) above-read-level —
//     EVEN IF the offending `*:write` permission is itself absent from the
//     inventory (it usually is: §5.2 records no `*:write` key). Naming the
//     read-path breach is more precise than reporting it as a generic absence,
//     and matches the row phrasing "widens the read level OR adds write scope to
//     the onboarding read path fails." A read-level onboarding permission then
//     still falls through to the presence/concrete-read checks below.
//
//   - (c) absent-from-inventory binds the rest: a NON-onboarding-path permission
//     (CI dispatch, status checks, the D56 enrollment flow) is legitimate iff it
//     names an inventory row; a read-level onboarding permission must name a
//     concrete `*:read` row. The level invariant does not bind the non-onboarding
//     flows — they may request the inventory's write/positioning rows.
func Diff(m Manifest, inv Inventory) []Violation {
	var vs []Violation
	for _, req := range m.Requested {
		// ── Onboarding read path: the level invariant first (binds this path only).
		if req.isOnboardingPath() {
			if req.Level.isWrite() {
				vs = append(vs, Violation{
					Class:      ViolationWriteOnReadPath,
					Permission: req.Permission,
					Flow:       req.Flow,
					Reason: fmt.Sprintf("the onboarding read path requested %q at WRITE "+
						"level; no write scope may exist on the onboarding read path (§5.2: "+
						"no contents:write, no actions:write, no enrollment-flow write "+
						"authority)", req.Permission),
				})
				continue
			}
			if !req.Level.isReadOnly() {
				vs = append(vs, Violation{
					Class:      ViolationAboveReadLevel,
					Permission: req.Permission,
					Flow:       req.Flow,
					Reason: fmt.Sprintf("the onboarding read path requested %q at level "+
						"%q, which is above read level; the onboarding CI-read scope must "+
						"stay a strict read-only subset of the §5.2 inventory",
						req.Permission, req.Level),
				})
				continue
			}
			// Read-level onboarding permission: it must name a CONCRETE `*:read` row
			// (not a positioning row, not an unknown key).
			if !inv.readPermissions()[req.Permission] {
				vs = append(vs, Violation{
					Class:      ViolationAbsentFromInventory,
					Permission: req.Permission,
					Flow:       req.Flow,
					Reason: fmt.Sprintf("onboarding-path %q claims read level but matches "+
						"no concrete `*:read` row of the §5.2 inventory; the onboarding read "+
						"path may only request the ratified read triplet", req.Permission),
				})
			}
			continue
		}

		// ── Non-onboarding flow: it must name an inventory row (read or positioning),
		//    but the read-only invariant does not bind it.
		if _, present := inv.has(req.Permission); !present {
			vs = append(vs, Violation{
				Class:      ViolationAbsentFromInventory,
				Permission: req.Permission,
				Flow:       req.Flow,
				Reason: fmt.Sprintf("requested permission %q is in no row of the §5.2 "+
					"D83 App-install permission inventory (the single anchor); a request "+
					"may only name a permission the inventory records", req.Permission),
			})
		}
	}
	sort.Slice(vs, func(i, j int) bool {
		if vs[i].Class != vs[j].Class {
			return vs[i].Class < vs[j].Class
		}
		return vs[i].Permission < vs[j].Permission
	})
	return vs
}

// ── Loading fixtures and the doc anchor (cwd-independent) ───────────────────

// thisDir returns the directory of THIS source file (runtime.Caller-anchored),
// so fixture and doc lookups work under `go test` from any cwd — the same
// technique the resolverlock corpus uses.
func thisDir() string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return "."
	}
	return filepath.Dir(thisFile)
}

// FixturesDir is the synthetic-fixture directory, anchored off this file.
func FixturesDir() string { return filepath.Join(thisDir(), "fixtures") }

// Doc16Path resolves the doc 16 source the §5.2 inventory is parsed from. It is
// anchored off this file via the known repo-relative offset (this package lives
// at assurance/guardrail-conformance/appinstall/, four levels under the repo
// root), so the parse works from any cwd.
func Doc16Path() string {
	return filepath.Clean(filepath.Join(thisDir(), "..", "..", "..",
		"docs", "16-identity-and-credentials-design.md"))
}

// LoadManifest reads a synthetic fixture manifest from a JSON file and labels it
// with the file's base name for violation messages.
func LoadManifest(path string) (Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("reading manifest fixture %s: %w", path, err)
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return Manifest{}, fmt.Errorf("parsing manifest fixture %s: %w", path, err)
	}
	m.Name = filepath.Base(path)
	if len(m.Requested) == 0 {
		return Manifest{}, fmt.Errorf("manifest fixture %s declares no requested "+
			"permissions — a manifest must request at least one", path)
	}
	return m, nil
}
