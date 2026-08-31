# Canvas conformance fixtures — provenance (D50)

**Rule: if it is in git, it is synthetic.** No exceptions. The canonical
contract, tag format, and consent-class table live in
[`client/fixtures/PROVENANCE.md`](../../../../client/fixtures/PROVENANCE.md);
this file applies that contract to this directory.

Every fixture here is an **authored** picture exercising one disposition of a
collaborative-canvas (c)-tier guardrail row
(doc 06 §3c,
doc 17 §13). The JSON
fixtures in this directory back the **re-filed spectator no-inject** row
("a read-only spectator provably cannot inject input into a session", doc 06 §3c;
D61): a conforming live-view participant picture (input accepted only from the
driver seat) and a violation picture (a spectator-role seat whose input was
accepted into the session).

The other four canvas rows (canvas-edits-never-reach-vm,
canvas-not-an-input-channel, canvas-control-rpc-attribution,
canvas-respects-directory-rights) use **in-code Go-literal** fixtures built by
`canvas_test.go` — there is no file I/O and no working-directory dependency for
those; "synthetic only" is structural.

Each fixture records its observations as DATA; the conformance test mechanically
scans them, but no real board is rendered, no Yjs provider is opened, no
projection pipeline is run, no input event is emitted into a real session, and no
real VM disk/env/stdin/socket or metal host is touched. No `DS_*_LIVE` token is
read or set; no live claude / qemu / podman / KVM is invoked (D50).

Each JSON fixture carries its D50 tag in a `<name>.provenance` sidecar committed
beside it (the non-NDJSON convention from the canonical contract). The only legal
`provenance` value in this directory is `synthetic`. Recorded session material
never enters this repository — re-author it as synthetic placeholder strings
first, per the canonical contract.
