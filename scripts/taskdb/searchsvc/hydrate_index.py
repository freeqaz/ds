#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Bulk-hydrate a dedicated searchsvc index DB with live BGE-M3 dense+sparse
# embeddings over the WHOLE taskdb corpus (docs + tasks + notes).
#
# Writes chunk_embeddings rows in the exact byte encoding the Go side uses
# (encodeVector: LE float32; encodeSparse: sorted (uint32 token_id, float32
# weight) pairs) so searchsvc's index_store/sparse modules read them directly.
# Operates on a COPY of taskdb.sqlite (never the shared live DB).

import hashlib
import os
import sqlite3
import struct
import sys
import time

import serve_live  # imported from the searchsvc dir on sys.path

DB = os.environ["HYDRATE_DB"]
BATCH = int(os.environ.get("HYDRATE_BATCH", "32"))
MODEL = "BAAI/bge-m3"
DIMS = 1024


def enc_dense(vec):
    return struct.pack("<%df" % len(vec), *vec)


def enc_sparse(smap):
    if not smap:
        return b""
    out = bytearray()
    for tid in sorted(smap):
        out += struct.pack("<If", int(tid), float(smap[tid]))
    return bytes(out)


def chash(text):
    return hashlib.sha1(text.encode("utf-8")).hexdigest()


def ensure_corpus_rows(conn):
    """Add task + note bodies into doc_chunks (idempotent by hash) so they join
    into the search index alongside the doc chunks already present."""
    cur = conn.cursor()
    existing = {r[0] for r in cur.execute("SELECT hash FROM doc_chunks")}
    added = 0
    # tasks: title + body, path 'task:<id>'
    for tid, title, body in cur.execute("SELECT id, title, body FROM tasks").fetchall():
        text = (title or "") + ("\n\n" + body if body else "")
        h = chash("task:" + tid + ":" + text)
        if h in existing:
            continue
        cur.execute(
            "INSERT INTO doc_chunks(doc_id, path, heading, seq, body, hash) VALUES (?,?,?,?,?,?)",
            (-1, "task:" + tid, (title or "")[:120], 0, text, h),
        )
        existing.add(h)
        added += 1
    # notes: body, path 'note:<id>'
    for nid, task_id, body in cur.execute("SELECT id, task_id, body FROM notes").fetchall():
        if not body:
            continue
        h = chash("note:" + nid + ":" + body)
        if h in existing:
            continue
        cur.execute(
            "INSERT INTO doc_chunks(doc_id, path, heading, seq, body, hash) VALUES (?,?,?,?,?,?)",
            (-2, "note:" + nid, "note on " + (task_id or "?"), 0, body, h),
        )
        existing.add(h)
        added += 1
    conn.commit()
    return added


def main():
    conn = sqlite3.connect(DB)
    conn.execute("PRAGMA journal_mode=WAL")
    added = ensure_corpus_rows(conn)
    print(f"[corpus] added {added} task/note rows to doc_chunks", flush=True)

    cur = conn.cursor()
    rows = cur.execute(
        """SELECT dc.hash, dc.body FROM doc_chunks dc
           LEFT JOIN chunk_embeddings ce ON ce.chunk_hash = dc.hash
           WHERE ce.chunk_hash IS NULL AND LENGTH(dc.body) > 0"""
    ).fetchall()
    total = len(rows)
    print(f"[embed] {total} chunks to embed with BGE-M3 (model load on first batch)...", flush=True)

    t0 = time.time()
    done = 0
    for i in range(0, total, BATCH):
        batch = rows[i : i + BATCH]
        embs = serve_live.embed_batch([b for _h, b in batch])
        payload = []
        for (h, _b), e in zip(batch, embs):
            payload.append((h, MODEL, DIMS, enc_dense(e["dense"]), enc_sparse(e["sparse"]), MODEL))
        conn.executemany(
            """INSERT OR REPLACE INTO chunk_embeddings
               (chunk_hash, model, dims, vector, sparse_vector, sparse_model)
               VALUES (?,?,?,?,?,?)""",
            payload,
        )
        conn.commit()
        done += len(batch)
        rate = done / max(time.time() - t0, 1e-6)
        eta = (total - done) / max(rate, 1e-6)
        print(f"[embed] {done}/{total}  ({rate:.1f}/s, eta {eta/60:.1f}m)", flush=True)

    n = cur.execute("SELECT COUNT(*) FROM chunk_embeddings").fetchone()[0]
    print(f"[done] chunk_embeddings now holds {n} rows in {(time.time()-t0)/60:.1f}m", flush=True)
    conn.close()


if __name__ == "__main__":
    main()
