/* ds_nft.h — the C-ABI surface of the ds-nft staticlib (the one nft/netlink
 * writing API; dataplane/crates/ds-nft). The Go host agent #includes this from
 * orchestrator/internal/nftbridge/ — the single Go<->Rust write edge (doc 14
 * §6). Keep these declarations in lockstep with the #[no_mangle] extern "C"
 * functions in src/ffi.rs; a content_hash contract test guards the edge
 * (doc 13 OQ2 / doc 15 OQ3).
 *
 * This surface creates/deletes the per-session tap netdev, runs the NFT-6
 * teardown flush, and — under the ratified Model A (D1/D3/D4) —
 * instantiates/tears down the per-session admit SURFACE: the empty
 * allow4_<idx>/allow6_<idx> sets in `inet ds_filter` (which instantiate
 * idempotently ensures first, since no host bootstrap artifact owns that table).
 * It does NOT program any floor enforcement (default-deny, redirect, ct-mark verdict,
 * session enforcement chains) — the host-wide `dstap-*` glob floor owns all of
 * those, and the NFT-3b OUTPUT chain that reads the allow-sets is Stage-3
 * (out of scope here).
 *
 * Return convention: 0 (DS_NFT_OK) on success; a negative code on error, after
 * which ds_nft_last_error() yields the message.
 *
 * Prototype-drift contract (guarded by ffi.rs `header_pins_extern_c_param_types_
 * and_arity`): each `int32_t ds_nft_*(...)` prototype below is kept on a SINGLE
 * canonical line — `<ret> ds_nft_<name>(<type> <name>, ...);` with an explicit
 * `(void)` for the zero-arg form — so the Rust-side pure-text guard can parse
 * each parameter's C TYPE and ARITY out of this header (it splits the paren body
 * on `,` and strips parameter names). That guard asserts the parsed types/arity
 * equal the known-good table, single-sourced with the Rust extern-fn pointer
 * types, catching a dropped/added param or a flipped `uint32_t`/`int32_t`/`int`
 * — the cgo edge links against THIS prototype, not the Rust signature. When you
 * add or change a symbol, keep its prototype a single canonical line and update
 * that table; do NOT wrap a prototype across lines.
 */
#ifndef DS_NFT_H
#define DS_NFT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Return codes (mirror of src/ffi.rs DS_NFT_OK / DS_NFT_ERR_*). */
#define DS_NFT_OK 0          /* success */
#define DS_NFT_ERR_ARG (-1)  /* NULL / non-UTF-8 / interior-NUL argument */
#define DS_NFT_ERR_BACKEND (-2) /* nft/conntrack/ip backend failure */

/* Create the per-session tap netdev `name` (e.g. "dstap-7") AND program its
 * routed addressing (D2, doc 11 §2.4): the host-side gateway
 * 10.77.<host_session_index>.0/31, the on-link /32 route to the guest .1, and —
 * when `guest_mac` is non-NULL — a static `ip neigh replace 10.77.<idx>.1 lladdr
 * <guest_mac>`. When `has_uid` is non-zero, the tap is created owned by
 * `owner_uid` (ip tuntap add ... user <uid>); when zero, `owner_uid` is ignored.
 * `host_session_index` is the routed /31 authority (it lands in the third octet
 * of 10.77.<idx>.0/31). `guest_mac` is the OPTIONAL static-neigh lladdr: NULL
 * means the guest MAC is unknown, so the `ip neigh` leg is SKIPPED (a recoverable
 * gap, never a failure — it can be programmed later); a malformed non-NULL MAC
 * surfaces as a backend error straight from `ip neigh`. Mechanism only in the
 * nft sense: this programs the netdev + routed addressing but still writes NO
 * nft rules (no default-deny/redirect/ct-mark/session chain — those are the glob
 * floor / Stage-3). Idempotent (re-create of a present tap is success).
 * `name` must be a valid NUL-terminated C string (NULL is a handled arg error);
 * `guest_mac` is a valid NUL-terminated C string OR NULL.
 * Returns DS_NFT_OK, DS_NFT_ERR_ARG, or DS_NFT_ERR_BACKEND. */
int32_t ds_nft_create_tap(const char *name, uint32_t owner_uid, int has_uid, uint32_t host_session_index, const char *guest_mac);

/* Delete the tap netdev `name`. Idempotent (delete of an absent tap is success).
 * Returns DS_NFT_OK, DS_NFT_ERR_ARG, or DS_NFT_ERR_BACKEND. */
int32_t ds_nft_delete_tap(const char *name);

/* Flush the whole session identified by `tap_name` / `host_session_index`:
 * flush_session(dst=all, legs=all) — the unconditional NFT-6 teardown flush
 * (doc 15 §4.2). Returns DS_NFT_OK, DS_NFT_ERR_ARG, or DS_NFT_ERR_BACKEND. */
int32_t ds_nft_flush_session(const char *tap_name, uint32_t host_session_index);

/* InstantiateSessionNFT (Model A, D1/D3/D4): idempotently ensure `inet ds_filter`
 * exists (a leading `add table`, a no-op that never clears existing sets — no host
 * bootstrap artifact owns this shared table), then create the EMPTY per-session
 * allow4_<host_session_index>/allow6_<host_session_index> sets in it — the
 * per-session admit SURFACE ONLY. Writes NO
 * default-deny, NO redirect, NO ct-mark verdict, NO session chain (the
 * `dstap-*` glob floor owns those; the NFT-3b OUTPUT chain is Stage-3). The set
 * NAME is single-sourced in ds-contracts (allow_set_name) so this side and the
 * ds-dnsgate fill side cannot diverge. Idempotent. `tap_name` must be a valid
 * NUL-terminated C string (NULL is a handled arg error).
 * Returns DS_NFT_OK, DS_NFT_ERR_ARG, or DS_NFT_ERR_BACKEND. */
int32_t ds_nft_instantiate_session(const char *tap_name, uint32_t host_session_index);

/* Remove the per-session allow-sets created by ds_nft_instantiate_session:
 * delete set both allow{4,6}_<host_session_index> in `inet ds_filter` — the
 * named-set half of the NFT-6 teardown. The conntrack-by-mark half is
 * ds_nft_flush_session; a full teardown calls flush THEN this. Idempotent.
 * Returns DS_NFT_OK, DS_NFT_ERR_ARG, or DS_NFT_ERR_BACKEND. */
int32_t ds_nft_teardown_session(const char *tap_name, uint32_t host_session_index);

/* The message of the LAST error produced on the calling thread, as a borrowed,
 * NUL-terminated C string (empty after a successful call). Never returns NULL.
 * The pointer is valid only until this thread's next ds-nft call — copy it
 * (e.g. C.GoString) immediately; never free it (ds-nft owns the storage). */
const char *ds_nft_last_error(void);

/* STILL DEFERRED (Stage-3, off the M1 gate): the NFT-3b out_<session> OUTPUT
 * containment chain + @session_out mark-vmap element (the per-session layer that
 * READS the allow-sets), the NFT-5 ct-mark verdict, and the NFT-2b 80/443 ->
 * ds-tlsproxy cutover. Model A here instantiates the admit SURFACE only. */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DS_NFT_H */
