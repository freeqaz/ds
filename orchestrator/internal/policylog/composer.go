package policylog

// This file is the DEFAULT SnapshotComposer (doc 13 §5, D120): it folds the
// policy_log rows up to a seq into the deny-overrides composed snapshot the
// WatchPolicies stream carries. It is the control-plane half of composition — the
// deny-overrides STRUCTURE (doc 13 §1 rule 2) over allow/deny rule sets and live
// ask-grants — written against the LayerDecoder seam, which is the ONLY place the
// opaque POL-1 layer-document body (ds-contracts, doc 13 §3) is interpreted.
//
// The split is deliberate: the deny-wins fold, the per-session sectioning, the
// produce-once hash, and the grant-liveness gate are control-plane invariants
// that live here; the bytes→{scope, allow, deny} parse of an append row's payload
// is ds-contracts' POL-1 schema, injected as LayerDecoder so this package never
// re-declares that schema (doc 13 §1 rule 1, the one-evaluator rule).

import (
	"context"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// LayerDecoder interprets an append row's opaque payload as the layer it
// contributes (doc 13 §3 — the POL-1 v0 field inventory lives in ds-contracts).
// It is the ONE seam that touches the layer-document body: given an append row,
// it returns the Layer (scope + allow/deny rule keys) and the session_id the
// layer is scoped to (empty for host-wide system/org layers). A row it cannot
// decode (a kind it does not own) returns ok=false and is skipped — a decoder
// never guesses, and an undecodable append contributes nothing rather than
// fabricating an admit (fail-closed, doc 13 §1 rule 2).
type LayerDecoder interface {
	DecodeLayer(row store.PolicyLogRow) (layer Layer, sessionID string, ok bool)
}

// LayerDecoderFunc adapts a function to LayerDecoder.
type LayerDecoderFunc func(row store.PolicyLogRow) (Layer, string, bool)

// DecodeLayer calls the function.
func (f LayerDecoderFunc) DecodeLayer(row store.PolicyLogRow) (Layer, string, bool) {
	return f(row)
}

// GrantDecoder interprets an ask-grant row's payload as the rule key it admits
// (doc 15 §4.3). The grant body is opaque (the ask path composes it); the
// decoder extracts the matched rule key so the grant folds into its session
// section. A row it cannot decode returns ok=false and the grant is skipped (a
// grant that cannot be read admits nothing — fail-closed). The grant's session
// scope and expiry ride the row fields directly (SessionUUID / ExpiresAt), so the
// decoder needs only the rule key.
type GrantDecoder interface {
	DecodeGrant(row store.PolicyLogRow) (rule string, ok bool)
}

// GrantDecoderFunc adapts a function to GrantDecoder.
type GrantDecoderFunc func(row store.PolicyLogRow) (string, bool)

// DecodeGrant calls the function.
func (f GrantDecoderFunc) DecodeGrant(row store.PolicyLogRow) (string, bool) { return f(row) }

// DefaultComposer is the control-plane SnapshotComposer: it folds the rows up to
// a seq into the deny-overrides composite host document (doc 13 §5). It holds the
// two decoders that interpret the opaque POL-1 / grant bodies (ds-contracts'
// schema); the deny-wins fold, the sectioning, the produce-once hash, and the
// grant-liveness gate are this composer's, all reusing compose.go's primitives.
type DefaultComposer struct {
	Layers LayerDecoder
	Grants GrantDecoder
}

// NewDefaultComposer constructs a DefaultComposer over a layer decoder and a
// grant decoder (the ds-contracts POL-1 / grant-body parse seams).
func NewDefaultComposer(layers LayerDecoder, grants GrantDecoder) *DefaultComposer {
	return &DefaultComposer{Layers: layers, Grants: grants}
}

// ComposeAt folds rows (ascending, up to and including seq) into the snapshot for
// seq (doc 13 §5). Shared (host-wide) append layers — system-baseline + org, plus
// any append with an empty session scope — compose into the shared deny-overrides
// material; session-scoped append layers compose per session_id; live ask-grants
// (non-expired as of now) fold into their session sections. The composed document
// is the produce-once hashed composite host document; deny-wins applies uniformly
// (doc 13 §1 rule 2). now gates grant liveness (doc 13 §1 rule 8 — expiry gates
// new flows).
func (c *DefaultComposer) ComposeAt(_ context.Context, seq int64, rows []store.PolicyLogRow, now time.Time) (Snapshot, error) {
	var sharedLayers []Layer
	sessionLayers := map[string][]Layer{}
	sessionGrants := map[string][]LiveGrant{}
	sessionOrder := []string{}
	seenSession := map[string]struct{}{}

	noteSession := func(id string) {
		if id == "" {
			return
		}
		if _, ok := seenSession[id]; !ok {
			seenSession[id] = struct{}{}
			sessionOrder = append(sessionOrder, id)
		}
	}

	// POL-4 enforcement clock (doc 16 §6.2; D68/D72): fold the FleetDigestKind rows
	// in this run through the revocation sweep so the live fleet-scope forbidden
	// digests (and the retire effect of a revoke) reach the composed host snapshot.
	// SweepFleetDigests classifies purely on the FleetDigestKind tag, so the
	// fleet-digest rows are handled here and are NOT decodable layers — the layer
	// switch below skips them (an undecodable append contributes nothing), leaving
	// the sweep the single fold for fleet-digest state.
	fleetSweep := SweepFleetDigests(rows)

	for _, r := range rows {
		switch r.Kind {
		case FleetDigestKind:
			continue // folded by the POL-4 sweep above, never as a deny-overrides layer
		case store.PolicyKindAskGrant:
			// Live-grant fold: only non-expired grants gate new flows (doc 13 §1
			// rule 8). Expiry rides the row field; the decoder yields the rule key.
			if r.ExpiresAt != nil && !r.ExpiresAt.After(now) {
				continue // expired
			}
			rule, ok := c.decodeGrant(r)
			if !ok {
				continue // undecodable grant admits nothing (fail-closed)
			}
			g := LiveGrant{Rule: rule}
			if r.ExpiresAt != nil {
				g.ExpiresUnix = r.ExpiresAt.Unix()
			}
			sessionGrants[r.SessionUUID] = append(sessionGrants[r.SessionUUID], g)
			noteSession(r.SessionUUID)
		default: // PolicyKindAppend (and any future authored-edit kind)
			layer, sessionID, ok := c.decodeLayer(r)
			if !ok {
				continue // undecodable layer contributes nothing (fail-closed)
			}
			if sessionID == "" {
				sharedLayers = append(sharedLayers, layer)
				continue
			}
			sessionLayers[sessionID] = append(sessionLayers[sessionID], layer)
			noteSession(sessionID)
		}
	}

	shared := ComposeLayers(sharedLayers)

	composites := make([]SessionComposite, 0, len(sessionOrder))
	for _, id := range sessionOrder {
		// Session policy = shared layers + this session's repo/session layers,
		// composed deny-overrides (a session inherits the host-wide deny set, doc 13
		// §1 rule 2 — a session can never re-admit what the baseline/org denies).
		layers := make([]Layer, 0, len(sharedLayers)+len(sessionLayers[id]))
		layers = append(layers, sharedLayers...)
		layers = append(layers, sessionLayers[id]...)
		composites = append(composites, SessionComposite{
			SessionID: id,
			Composed:  ComposeLayers(layers),
			Grants:    liveGrantsFrom(sessionGrants[id], now),
		})
	}

	return ComposeSnapshotWithSweep(seq, shared, composites, fleetSweep), nil
}

func (c *DefaultComposer) decodeLayer(row store.PolicyLogRow) (Layer, string, bool) {
	if c.Layers == nil {
		return Layer{}, "", false
	}
	return c.Layers.DecodeLayer(row)
}

func (c *DefaultComposer) decodeGrant(row store.PolicyLogRow) (string, bool) {
	if c.Grants == nil {
		return "", false
	}
	return c.Grants.DecodeGrant(row)
}
