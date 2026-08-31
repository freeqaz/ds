package store

// session.go carries the doc 18 §7 PINNED-ROLE persistence the migration-0009
// store unfreeze adds to the never-recycled session record (D66/D89–D96). The
// single field that joins it to the frozen-shared Session struct (records.go) is
// `Session.RolePin`; everything ELSE about the pin — its type, its zero-value
// semantics, its update payload, and its deep-copy — lives HERE so the frozen
// records.go carries only the one-line registration the unfreeze sanctions.
//
// WHY A PIN ON THE RECORD (doc 18 §7, §11 pin-and-audit row). The create
// choreography's steps-1–2 stage (sessions/roleref.go: ResolveAndPinRole) resolves
// the requested role_ref against the org catalog and pins the immutable
// (role_name, role_version, role_content_hash) triple for the session lifetime.
// Before this unfreeze that pin rode only in-package; the §11 row "every session
// record carries role fields" and "a catalog update mid-flight does not change a
// pinned session" require it to PERSIST on the D66 row. RunCreateSpine now writes
// the pin through this seam (WriteRolePin), so the persisted record is the pin's
// system of record — re-readable through GetSession on either backend.
//
// THE CONTENT HASH IS THE CANONICAL ONE (roles/SCHEMA.md rule 5). RolePin.ContentHash
// is the role's `role_content_hash`: SHA-256 (hex) over the produce-once JCS
// canonical payload of the role document — the SAME canonical-serialization
// machinery the PolicySnapshot content_hash uses (one spec, not two). The store
// is hash-agnostic: it persists the hex string the resolver computed (via the
// nftbridge canonical path) verbatim and never re-hashes — the store is not the
// trust boundary for the canonicalization, the resolver is.

// RolePin is the doc 18 §7 immutable role identity persisted onto the
// never-recycled session record (the store-side counterpart of
// sessions.PinnedRole, carried as DATA across the package boundary — the sessions
// package never imports store for this, the create driver copies the triple in).
// It is value-typed (strings + a bool), so a RolePin is trivially copyable and the
// store hands out copies without an alias-cloning helper.
//
// ZERO VALUE (the pre-pin posture). A zero RolePin (every field empty/false) is
// the "no pin written yet" state a row carries before the create choreography
// writes the resolved triple — distinct from the RECORDED DEFAULT pin
// (`default@<current>` with its content hash), which is an explicit, non-empty
// triple (doc 18 §7: "Default is recorded, not null"). Pinned() reports the
// difference.
type RolePin struct {
	// Name is the role's catalog name (doc 18 §7 role_name); `default` for the
	// recorded de-risking default. Empty only in the pre-pin zero value.
	Name string
	// Version is the role's content identifier (doc 18 §7 role_version,
	// roles/SCHEMA.md rule 5: a content identifier, NEVER a second version
	// namespace). E.g. `2026.06.11-v1`.
	Version string
	// ContentHash is the role's role_content_hash: SHA-256 (hex) over the
	// produce-once JCS canonical payload of the role document (roles/SCHEMA.md
	// rule 5 — the shared canonical-serialization machinery, one spec not two).
	// Persisted verbatim; the store never re-hashes. Pins the EXACT role bytes, so
	// a catalog update to the same (name, version) is still a distinct pin.
	ContentHash string
	// WideningsInert records the doc 18 §9 widening-gate posture: true when the
	// pinned role version carried UNRATIFIED widenings that rode INERT at create
	// (logged warning, admitting nothing — the doc 13 §1 rule-7 pattern, D91). The
	// widening SET itself is the catalog's (the actor-recorded ratification event),
	// never duplicated onto every session row; the record carries only this
	// boolean for the §11 widening-gate audit row.
	WideningsInert bool
}

// Pinned reports whether a role has actually been pinned onto the record — true
// once the create choreography writes the resolved triple (the recorded default
// or a named role), false for the pre-pin zero value. The triple is complete by
// construction when Pinned is true: ResolveAndPinRole refuses fail-closed on an
// incomplete pin, so the persistence path never writes a partial triple. We key
// on Name because the recorded default and every named role have a non-empty name
// while the pre-pin zero value does not.
func (p RolePin) Pinned() bool { return p.Name != "" }

// Ref returns the canonical recorded `<name>@<version>` form of the pin (doc 18
// §7's recorded ref) — `default@<current>` for the recorded default, the empty
// string for the pre-pin zero value. It mirrors sessions.PinnedRole.Ref so the
// in-package pin and its persisted form read the same.
func (p RolePin) Ref() string {
	if p.Name == "" {
		return ""
	}
	if p.Version == "" {
		return p.Name
	}
	return p.Name + "@" + p.Version
}

// --- minted-credential expiry persistence (migration 0010) ---
//
// session.go also carries the doc 15 §5.6 / doc 16 §5.4 MINTED-CREDENTIAL EXPIRY
// persistence the migration-0010 store unfreeze adds to the never-recycled session
// record (D22/D82) — the credential-TTL counterpart of the RolePin block above. The
// single field that joins it to the frozen-shared Session struct (records.go) is
// `Session.MintExpiry` (a time.Time, value-typed, so cloneSession copies it with the
// struct — no clone helper needed); the SessionUpdate apply for it lives HERE so the
// frozen records.go carries only the one-line registration the unfreeze sanctions.
//
// WHY A HORIZON ON THE RECORD (doc 16 §5.4). The §4.1 step-5 mint surfaces the
// per-session credential / interception-CA TTL (MintResult.Expiry → the create-local
// st.mintExpiry). Before this unfreeze that expiry rode only create-local coordinator
// state, so after an orchestrator restart the §4.2 teardown/resume path had no DURABLE
// horizon to read and an expired credential never actually re-minted. RunCreate now
// writes the horizon through this seam (UpdateSession{MintExpiry:...}) alongside
// IdentityRef/CARef, so the persisted record is the horizon's system of record — the
// §4.2 resume re-mint reads it (expired creds re-mint on resume) rather than
// reconstructing it.
//
// ZERO VALUE = NULL (the not-set posture). A zero MintExpiry (MintExpiry.IsZero()) is
// the "no TTL tracked" state — a mint that surfaced no expiry (a bare MintClient or a
// TTL-less proto), persisted as SQL NULL, exactly the way ready_at / attached_at map
// their not-set timestamps. It is NEVER read as "expires at the epoch".

// applyMintExpiry copies the SessionUpdate's minted-credential expiry horizon onto s
// when set (migration 0010). It mirrors the value-set semantics of the RolePin apply in
// helpers.go's applyUpdate but lives in the MintExpiry-owning file: a NIL u.MintExpiry
// leaves the persisted horizon unchanged; a NON-NIL pointer sets it to the value it
// carries (INCLUDING the zero time, which persists as the NULL not-set posture). The
// memory + postgres UpdateSession paths call this right after applyUpdate so the apply
// is identical on both backends (the D33 conformance parity). It is a plain value copy —
// time.Time is value-typed, so the record holds its own horizon with no caller alias.
func applyMintExpiry(s *Session, u SessionUpdate) {
	if u.MintExpiry != nil {
		s.MintExpiry = *u.MintExpiry
	}
}
