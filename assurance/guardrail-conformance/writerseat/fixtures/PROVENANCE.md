# Writer-seat conformance fixtures — provenance (D50)

**Rule: if it is in git, it is synthetic.** No exceptions. The canonical
contract, tag format, and consent-class table live in
[`client/fixtures/PROVENANCE.md`](../../../../client/fixtures/PROVENANCE.md);
this file applies that contract to this directory.

Every fixture here is an **authored** picture exercising one disposition of a
browser-writer-seat guardrail-conformance row
(sessions/10 §5,
doc 06 §3c).
The JSON fixtures in this directory back the **reader-cannot-reach-WriterRelay**
row — the **D137 re-green** of the `01KTWJ64M0` no-inject barrier
(sessions/10 §5 claim 4): with the `attach.v1` `WriterRelayService` write leg
present, a `ROLE_READER` (no grant) provably cannot reach the WriterRelay RPCs
(`RequestWriterSeat` / `YieldWriterSeat` / `DriveSession`) or stdin. The corpus
is a conforming picture (a granted `ROLE_WRITER` driving plus read-only spectators
reaching no write surface) and two violation pictures (a reader that reached a
WriterRelay RPC; a reader whose input reached stdin).

The other four writer-seat rows (`writerseat-exactly-one-live-seat`,
`writerseat-no-drive-without-live-grant`,
`writerseat-handoff-attributed-and-observable`,
`writerseat-attendedness-honest-when-detached`) use **in-code Go-literal**
fixtures built by `writerseat_test.go` — there is no file I/O and no
working-directory dependency for those; "synthetic only" is structural.

Each fixture records its observations as DATA; the conformance test mechanically
scans them, but no real orchestrator is stood up, no `DriveSession` stream is
opened, no live seat is arbitrated, no byte reaches any stdin, and no real VM
disk/env/stdin/socket or metal host is touched. No `DS_*_LIVE` token is read or
set; no live claude / qemu / podman / KVM is invoked (D50).

Each JSON fixture carries its D50 tag in a `<name>.provenance` sidecar committed
beside it (the non-NDJSON convention from the canonical contract). The only legal
`provenance` value in this directory is `synthetic`. Recorded session material
never enters this repository — re-author it as synthetic placeholder strings
first, per the canonical contract.
