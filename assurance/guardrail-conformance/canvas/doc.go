// SPDX-License-Identifier: Apache-2.0

// Package canvas holds the executable form of the collaborative-canvas
// (c)-tier guardrail-conformance rows: the four doc 17 §13(c) canvas claims
// plus the re-filed "a read-only spectator provably cannot inject input into a
// session" claim from doc 06 §3c. It is part of the D51 public claims package
// (README.md): every guardrail the docs promise becomes a test that tries to
// make the guardrail FAIL and asserts it doesn't.
//
// The doc 06 §3c language note is binding here: NOTHING in this package is named
// attack / redteam / intrusion. Every row is phrased as "the guardrail HOLDS,
// and this is the NAMED way a regression would let it slip." A fixture that
// models a defeat path is named for the property it probes (a canvas op that
// reached a VM, a projection edge pointing into a session), never for an
// attacker.
//
// SHAPE (the goldenfreshness/orchctl sibling pattern, extended to a multi-row
// package). Each row is a small, deterministic Check over a typed SYNTHETIC
// fixture (D50) built as Go literals or loaded from synthetic JSON under
// fixtures/ — never a live web client, Yjs provider, projection pipeline,
// session VM, host-agent, KVM, or podman run. A typed ViolationClass taxonomy
// names every failure mode so each violation reports WHICH rule it tripped (the
// "fails NAMED" bar). The five rows' guardrail tags are single-sourced in Tags
// and pinned by TestTagsStable.
//
// canvas.v1 IS FROZEN. The rows assert canvas.v1's DOCUMENTED no-input-message
// posture — the projection seam carries platform→board reads only, and there is
// no canvas.v1 message that delivers canvas/board state back INTO a session as
// input (doc 17 §3.1/§13(c)(2)). This package asserts that documented shape; it
// adds no stub message bodies and imports no proto, paid/, dataplane/, identity,
// or canvas product code.
//
// ── THE FIVE ROWS ────────────────────────────────────────────────────────────
//
// ROW 1 — canvas edits never reach a session VM (doc 17 §13(c)(1)).
//
//	THE CLAIM: a board edit never reaches a session VM — no canvas operation
//	produces any observable effect inside any session. Canvas-truth objects
//	(§3.2 free-form shapes/stickies/connectors) live in the Yjs document; they
//	are NOT a channel into a guest. The synthetic fixture records, per canvas
//	operation, whether it produced an effect observable inside a session VM
//	(a guest-visible filesystem/env/stdin/socket write). A conforming op set
//	produces NONE; any op with a VM-observable effect FAILS NAMED.
//
// ROW 2 — canvas is not an input channel (doc 17 §3.1/§13(c)(2)).
//
//	THE CLAIM: canvas state cannot become an input channel into any session —
//	the projection pipeline is provably READ-ONLY. The §3.1 projection
//	references are read-only by construction (D61): every projection edge runs
//	platform→board, never board→session. The synthetic fixture records the
//	projection graph's edges (each tagged with its direction) and whether any
//	canvas.v1 message is declared input-bearing into a session. A conforming
//	graph has every edge platform→board and NO input-bearing canvas→session
//	message; a board→session edge or an input-bearing message FAILS NAMED.
//
// ROW 3 — canvas control actions carry attribution (doc 17 §7/§13(c)(3); D8/D61).
//
//	THE CLAIM: a canvas-originated control-plane RPC carries D8 attribution and
//	respects single-driver arbitration — a board is never a second writer
//	(doc 17 §7). The synthetic fixture records, per canvas-originated
//	control-plane RPC, whether it carries a D8 actor identity and whether it was
//	admitted while another principal holds the single writer seat. A conforming
//	RPC carries attribution AND is admitted only when it holds (or the seat is
//	free) the writer seat; a missing actor identity or a second-writer admission
//	FAILS NAMED.
//
// ROW 4 — boards respect directory rights (doc 17 §8/§13(c)(4)).
//
//	THE CLAIM: a board never leaks the content or platform metadata of a session
//	the viewer lacks directory rights to — including the §3.1/§8
//	existence-disclosure posture as shipped: a dangling/unauthorized reference
//	resolves to a TOMBSTONE (dangling) or an ACCESS PLACEHOLDER (access-denied),
//	both non-load-blocking, and NEITHER leaks the underlying session's content
//	or platform metadata (doc 17 §3.3(c)). The synthetic fixture records, per
//	projected reference, the viewer's directory right, the resolved render state
//	(live | tombstone | access_placeholder), and whether the rendered tile
//	carried session content or platform metadata. A conforming board renders an
//	unauthorized reference as a placeholder/tombstone with no leaked
//	content/metadata; leaked content/metadata, or a live render the viewer has
//	no right to, FAILS NAMED.
//
// ROW 5 — read-only spectate cannot inject (doc 06 §3c, re-filed; D61).
//
//	THE CLAIM (quoted exactly from sessions/06 via doc 06 §3c): "a read-only
//	spectator provably cannot inject input into a session." Canvas live-views
//	inherit this console/attach claim. The synthetic fixture records, per
//	viewer, the held role (spectator | driver) and whether any input event the
//	viewer emitted was accepted into the session. A conforming picture accepts
//	input ONLY from a driver-role seat; an input event accepted from a
//	spectator-role seat FAILS NAMED.
//
// SYNTHETIC ONLY (D50). Every fixture is a hand-authored picture against the
// DOCUMENTED canvas/projection/attach contracts (doc 17 §3.1/§3.3(c)/§7/§8/§13,
// doc 06 §3c). Fixtures loaded from fixtures/*.json carry a `.provenance`
// sidecar. Nothing here renders a real board, opens a Yjs provider, runs a
// projection pipeline, emits an input event into a real session, reads a guest
// surface, or touches a VM/host. The observations are DATA, never produced by
// touching any filesystem, process, network, or live service. There is NO live
// claude / qemu(VM-run) / podman / KVM invocation anywhere in this package, and
// no DS_*_LIVE token is read or set.
//
// RUNNABILITY (README.md "OSS-runnable vs paid-dependent"; doc 17 §13). D51
// ships the COMPLETE §3c table, but canvas rows "must be runnable without
// paid-layer scale machinery or be split accordingly." Each row therefore
// carries a typed Runnability marker (RunnabilityOSS | RunnabilityPaidDependent)
// so an OSS run reports a paid-dependent row as NOT-APPLICABLE rather than
// FAILED. As modeled here, ALL FIVE rows are oss-runnable: each is a static
// data-shape diff (canvas-op effect set, projection-edge directionality +
// no-input-message posture, RPC attribution/arbitration, directory-right
// existence-disclosure, spectator-vs-driver input acceptance) with no web-client
// or paid-layer dependency. The split mechanism (RunnabilityPaidDependent +
// CheckRunnable's not-applicable short-circuit) is present and exercised so a
// future row that genuinely needs the web-client render surface can be marked
// paid-dependent without a structural change.
//
// REGISTRATION (claim metadata). The five rows' guardrail tags are
// single-sourced in Tags (TagCanvasEditsNeverReachVM, TagCanvasNotInputChannel,
// TagCanvasControlAttribution, TagCanvasDirectoryRights, TagSpectatorNoInject)
// so the package's claim metadata and any future guardrail-map.yaml canvas row
// name the SAME rows. The repo-root guardrail-map.yaml is NOT edited here (it is
// Boundary-owned via CODEOWNERS); a new unmapped subdir is fail-closed to the
// full matrix (D47), so the rows self-gate without a map edit — a map edit buys
// only a CI-scope narrowing.
//
//	guardrail tags:
//	  canvas-edits-never-reach-vm        — doc 17 §13(c)(1)
//	  canvas-not-an-input-channel        — doc 17 §3.1/§13(c)(2)
//	  canvas-control-rpc-attribution     — doc 17 §7/§13(c)(3); D8/D61
//	  canvas-respects-directory-rights   — doc 17 §8/§13(c)(4)
//	  spectator-cannot-inject            — doc 06 §3c re-file; D61
//	runnability: oss-runnable (all five; see RUNNABILITY above)
//	anchor:      doc 17 §13 (canvas (c) rows), doc 06 §3c (the (c) claims table)
package canvas
