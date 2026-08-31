#!/bin/sh
# check-service-readme.sh — dataplane/services/* README token anti-drift guard.
#
# PURPOSE
#   The dataplane service READMEs quote load-bearing literals that must track a
#   crate-side source of truth (version pins, ports, frozen-stack choices).  When
#   the source is bumped but the README prose is not (or vice versa), the doc
#   lies.  This lint is the repo-level home for that class of README-vs-source
#   token guard for the dataplane/services/* trees — the analog of the per-image
#   README-token guards baked into images/*/lint-*.sh --self-test, but reached
#   READ-ONLY (it never edits the README or any crate file).
#
#   It is built on the shared scripts/lint-readme-tokens.sh helper (sourcing API:
#   lrt_set_readme + lrt_register + lrt_check_all, exit codes 0=match / 1=drift /
#   2=structural, structural overrides drift; unique-match anchoring required).
#
# ANCHOR — ds-dnsgate (readme-survey P1)
#   The first service tree wired here is ds-dnsgate.  Its frozen-stack note pins
#   the hickory + tokio versions in a single unique README line:
#
#     `[workspace.dependencies]` (hickory-server / hickory-resolver `0.26`, tokio `1.48`),
#
#   The source of truth is the workspace manifest dataplane/Cargo.toml, whose
#   [workspace.dependencies] block carries the canonical version = "<ver>" pins.
#   A pin bump in Cargo.toml that does not update this README line (or a README
#   edit that drifts from the manifest) now fails the gate.  Both sides are
#   recomputed every run (never literal-frozen here), so a coordinated bump of
#   both stays green while a one-sided edit fails immediately.
#
#   The hickory pin is guarded as TWO independent arms — hickory-server AND
#   hickory-resolver — even though the README quotes a single shared `0.26`
#   backtick token.  The manifest carries the two pins on separate lines, and
#   D67 keeps them lock-stepped; guarding each manifest pin against the one
#   README token means a one-sided manifest bump (e.g. hickory-resolver -> 0.27
#   while hickory-server stays 0.26) fails the gate, instead of the README's
#   single token silently agreeing with only one of the two pins.
#
# ANCHOR — ds-tlsproxy (D40)
#   The second service tree wired here is ds-tlsproxy.  Its governing-decisions
#   line documents the pinned pingora-core MINOR series:
#
#     - **Governing decisions:** D40 (pingora-core 0.8.x, pinned + vendored, ...
#
#   The README documents the SERIES (`0.8.x`) while the manifest pins the exact
#   patch (`pingora-core = { version = "0.8.1", ... }`); the guard compares the
#   README's documented major.minor (`0.8`) against the manifest pin's
#   major.minor (the patch stripped from `0.8.1`).  A D40 re-evaluation that
#   bumps the manifest across the minor series (e.g. to `0.9.x`) without
#   updating the README governing-decisions line now fails the gate.
#
#   ds-tlsproxy also documents the two transparent-listener PORTS in a single
#   line (``binds `:18080`/`:18443```).  The source of truth is the crate's own
#   `add_tcp("0.0.0.0:<port>")` binding calls in src/main.rs (http_svc /
#   https_svc).  Two arms — HTTP and HTTPS — reconcile each documented port
#   against its main.rs binding, so a main.rs<->README port skew (e.g. add_tcp
#   bumped to :28443 while the README stays :18443) now fails the gate, instead
#   of the README literal being pinned against a hard-coded constant.
#
# ANCHOR — ds-flowlog (D66/D76)
#   The third service tree wired here is ds-flowlog.  Its crate is a skeleton
#   with no version/port literals of its own, but its frozen-contract table
#   quotes the session-index field width — ``mark_session_index` is index mod
#   2^14`.  The source of truth is the ds-contracts mark-decode constant
#   `pub const INDEX_BITS: u32 = 14` in dataplane/crates/ds-contracts/src/mark.rs
#   (the same field width SESSION_INDEX_MODULUS = 1 << INDEX_BITS derives from).
#   An INDEX_BITS change that does not update this README line (or vice versa)
#   now fails the gate.
#
#
# ANCHOR — ds-nft (D68/D76)
#   The fourth tree wired here is ds-nft.  Unlike the trees above it is a CRATE
#   under dataplane/crates/ (not a dataplane/services/* service), and its own
#   Cargo.toml is workspace-inherited (`version.workspace = true`, a single
#   path-only dependency on ds-contracts) — there is no version/port literal to
#   guard there.  The three guarded pairs instead reconcile the crate's OWN
#   README against ITS OWN source:
#
#     - the D68 in-place refresh kernel boundary, stated TWICE in the README and
#       guarded as TWO independent arms against the SAME truth
#       (`pub const INPLACE_MIN_KERNEL: (u32, u32) = (6, 12);` in
#       dataplane/crates/ds-nft/src/refresh.rs): the frozen-invariants row
#       "≥6.12 in-place element-timeout update (commit 4201f3938914)" and the
#       module-map `refresh` row "the ≥6.12 in-place element-timeout update and
#       the pre-6.12 delete+add-in-one-batch fallback".  Guarding BOTH means a
#       one-sided README edit (bump one row, leave the other) fails the gate
#       instead of drifting silently.  Both arms key on the same LOCAL
#       ">=<ver> in-place" token (see _NFT_KERNEL_EXTRACT), so a benign reword
#       of the surrounding sentence is not drift;
#     - the doc 14 §4 wrap/exhaustion alarm index-space exponent: the module-map
#       row "approaching 2^14 -> page" versus the SAME `INDEX_BITS` constant the
#       ds-flowlog guard above reads from ds-contracts mark.rs (a different
#       README line, reconciled independently so each tree's --self-test drives
#       on its own).
#
#   An INPLACE_MIN_KERNEL or INDEX_BITS change that does not update the
#   corresponding ds-nft README line (or vice versa) now fails the gate.
#
#   READ-ONLY: this lint greps the README, Cargo.toml, main.rs, refresh.rs, and
#   mark.rs and edits NONE of them.  No crate source is touched.  Adding a new
#   service tree's guards is a matter of another _register_<tree>_guards block
#   below; no Makefile edit is required beyond the existing repo-lints wiring.
#
# Usage:
#   sh scripts/check-service-readme.sh
#   sh scripts/check-service-readme.sh --self-test
#
# Exit codes (mirroring the shared helper):
#   0  — every guarded token matches its source of truth
#   1  — a token drifted (README literal != source value)
#   2  — structural failure (anchor matched 0 or >1 lines, file missing,
#         truth command empty), OR a required input file is absent
#
# --self-test: internal regression harness.  Builds a self-contained sandbox
#   (synthetic README + synthetic Cargo.toml + a copy of the shared helper),
#   verifies the clean copy passes (rc=0), then injects a one-sided drift on the
#   README side and on the source side and confirms each is caught (rc=1), plus a
#   reworded-anchor structural case (rc=2).  Never reads the real tree for its own
#   pass/fail; the sandbox is cleaned up via an EXIT trap.
#
# SPDX-License-Identifier: Apache-2.0

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
HELPER="$SCRIPT_DIR/lint-readme-tokens.sh"

# ---------------------------------------------------------------------------
# Source-value extractors (READ-ONLY greps over the workspace manifest).
# ---------------------------------------------------------------------------

# _manifest_dep_version MANIFEST KEY — print the version = "<ver>" pin on the
# [workspace.dependencies] line whose key is KEY (e.g. hickory-server, tokio).
# The pin is the first double-quoted token after `version`.  Empty if absent.
_manifest_dep_version() {
    awk -v key="$1" '
        $0 ~ ("^" key "[[:space:]]*=") && $0 ~ /version[[:space:]]*=[[:space:]]*"/ {
            s = $0
            sub(/.*version[[:space:]]*=[[:space:]]*"/, "", s)
            sub(/".*/, "", s)
            print s
            exit
        }
    ' "$2"
}

# _manifest_dep_version_minor MANIFEST KEY — like _manifest_dep_version, but
# strip the trailing patch component so a `version = "0.8.1"` pin yields its
# major.minor series `0.8`.  Used by the ds-tlsproxy arm, whose README documents
# the pinned MINOR series (`0.8.x`) rather than the exact patch.  Empty if the
# pin is absent (the trailing-component strip is a no-op on empty input).
_manifest_dep_version_minor() {
    _mdvm_full="$(_manifest_dep_version "$1" "$2")"
    printf '%s' "$_mdvm_full" | sed 's/\.[0-9][0-9]*$//'
}

# _rs_add_tcp_port SOURCE SVC — print the TCP port the `<SVC>` pingora listener
# binds, from the given Rust SOURCE file.  SVC is the service-binding variable
# (e.g. http_svc, https_svc).  Two source shapes are accepted, tried in order:
#   (1) LEGACY LITERAL: `<SVC>.add_tcp("0.0.0.0:<port>")` — the port inline in the
#       add_tcp call (the shape the --self-test fixture still emits).
#   (2) CURRENT (resolve_listen_addr): the bind was hoisted to an env-overridable
#       address — `<SVC>.add_tcp(&<addr>)` where `<addr> = resolve_listen_addr(
#       "DS_TLSPROXY_<HTTP|HTTPS>_ADDR", "0.0.0.0:<port>")`.  The DEFAULT (2nd) arg
#       is the source of truth; the env key is derived from SVC (http_svc ->
#       DS_TLSPROXY_HTTP_ADDR).  This tracks the tlsproxy main.rs listener refactor.
#       Arm (2) is FLOW-CHECKED: it captures the `let <var> =` LHS of the resolve
#       assignment and reports the default port ONLY when that same `<var>` is
#       consumed by `<SVC>.add_tcp(&<var>)`.  A resolve_listen_addr whose result
#       is never bound (or is bound to a different listener) is treated as no truth
#       (empty -> STRUCTURAL), closing the unlinked-resolve false-pass where a
#       stale default masquerades as the live listener port.
# The leading `<SVC>\.add_tcp` anchor in arm (1) is exact, so `http_svc` never
# matches `https_svc` (the latter has no `.` after `http`).  Prints the FIRST such
# port and stops.  Empty only if NEITHER shape is present (then STRUCTURAL).
_rs_add_tcp_port() {
    _rsatp_port="$(awk -v svc="$1" '
        $0 ~ (svc "\\.add_tcp\\(\"0\\.0\\.0\\.0:") {
            s = $0
            sub(/.*\.add_tcp\("0\.0\.0\.0:/, "", s)
            sub(/".*/, "", s)
            print s
            exit
        }
    ' "$2")"
    if [ -n "$_rsatp_port" ]; then printf '%s' "$_rsatp_port"; return 0; fi
    # Arm (2): the bind was hoisted to `let <var> = resolve_listen_addr("<key>",
    # "0.0.0.0:<port>")` consumed by `<svc>.add_tcp(&<var>)`.  Derive the env key
    # from the svc name (http_svc -> DS_TLSPROXY_HTTP_ADDR); the default (2nd) arg
    # is the truth port.  But the default is only the LIVE bind when the resolved
    # address VARIABLE actually FLOWS into this svc's add_tcp(&<var>) call — a
    # dangling `resolve_listen_addr(...)` whose result is never bound (or is bound
    # to a different listener) would otherwise let a stale default masquerade as
    # the live port (the unlinked-resolve false-pass).  So: capture the LHS var,
    # ASSERT `<svc>.add_tcp(&<var>)`, and only THEN read the port; if the resolve
    # result is unlinked, return empty (STRUCTURAL upstream), never the stale port.
    _rsatp_key="DS_TLSPROXY_$(printf '%s' "${1%_svc}" | tr '[:lower:]' '[:upper:]')_ADDR"
    _rsatp_var="$(awk -v key="$_rsatp_key" '
        $0 ~ ("let[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]*=[[:space:]]*resolve_listen_addr\\(\"" key "\",[[:space:]]*\"0\\.0\\.0\\.0:") {
            s = $0
            sub(/.*let[[:space:]]+/, "", s)
            sub(/[[:space:]]*=.*/, "", s)
            print s
            exit
        }
    ' "$2")"
    [ -n "$_rsatp_var" ] || return 0   # no resolve_listen_addr assignment for this key -> empty (STRUCTURAL upstream)
    # FLOW ASSERTION: the captured var must be consumed by THIS svc's
    # add_tcp(&<var>).  A literal substring match (index) sidesteps regex-escaping
    # the parens/ampersand; the trailing `;`/`?` after `)` is irrelevant.
    if ! awk -v svc="$1" -v var="$_rsatp_var" '
            index($0, svc ".add_tcp(&" var ")") > 0 { found = 1; exit }
            END { exit(found ? 0 : 1) }
        ' "$2"; then
        # resolve_listen_addr default computed but never wired into
        # <svc>.add_tcp(&<var>): the resolve result is unlinked from the live bind,
        # so there is no trustworthy truth port here — return empty (STRUCTURAL
        # upstream), closing the unlinked-resolve false-pass.
        return 0
    fi
    awk -v key="$_rsatp_key" '
        $0 ~ ("resolve_listen_addr\\(\"" key "\", \"0\\.0\\.0\\.0:") {
            s = $0
            sub(/.*resolve_listen_addr\("[^"]*", "0\.0\.0\.0:/, "", s)
            sub(/".*/, "", s)
            print s
            exit
        }
    ' "$2"
}

# _rs_const_rhs SOURCE NAME — print the right-hand-side integer literal of a
# `pub const <NAME>: <ty> = <literal>;` definition in the given Rust SOURCE file
# (e.g. INDEX_BITS in ds-contracts mark.rs).  The trailing `;` and any
# end-of-line `// comment` are stripped; surrounding whitespace removed.  Empty
# if the const is absent (then STRUCTURAL via the truth-empty path).
_rs_const_rhs() {
    awk -v name="$1" '
        $0 ~ ("^pub const " name "[[:space:]]*:") {
            s = $0
            sub(/.*=[[:space:]]*/, "", s)
            sub(/;.*/, "", s)
            gsub(/[[:space:]]/, "", s)
            print s
            exit
        }
    ' "$2"
}

# _rs_kernel_pair NAME SOURCE — turn the `(major,minor)` tuple RHS that
# _rs_const_rhs extracts from `pub const <NAME>: (u32, u32) = (6, 12);` into the
# dotted "6.12" form the ds-nft README documents (drop the parens, swap the
# comma for a dot).  Empty stays empty, so an absent const still falls through
# _rs_const_rhs's truth-empty path to a STRUCTURAL (rc=2) result upstream.
_rs_kernel_pair() {
    _rkp_raw="$(_rs_const_rhs "$1" "$2")"
    printf '%s' "$_rkp_raw" | sed 's/[()]//g; s/,/./'
}

# ---------------------------------------------------------------------------
# _register_dnsgate_guards README MANIFEST
#   Register the ds-dnsgate (readme-survey P1) token guards against the given
#   README and workspace manifest.  Factored out so --self-test can register the
#   SAME guards against its synthetic sandbox copies.
# ---------------------------------------------------------------------------
_register_dnsgate_guards() {
    _rg_readme="$1"
    _rg_manifest="$2"

    lrt_set_readme "$_rg_readme"

    # The hickory pin is guarded as TWO independent arms.  The README quotes a
    # single shared `0.26` backtick token covering both hickory crates
    # (`hickory-server / hickory-resolver `0.26``), but the manifest carries the
    # two pins on separate [workspace.dependencies] lines.  Guarding EACH
    # manifest pin against the one README token means a one-sided manifest bump
    # (e.g. hickory-resolver -> 0.27 while hickory-server stays 0.26) fails the
    # gate, instead of the README's single token silently agreeing with only one
    # of the two pins.  Both arms anchor on the same unique frozen-stack line and
    # extract the `0.26` backtick token that follows "hickory-resolver".

    # (i) hickory-server version pin.  Truth: hickory-server's manifest version.
    _hickory_server_ver="$(_manifest_dep_version hickory-server "$_rg_manifest")"
    lrt_register "ds-dnsgate-hickory-server-version" \
        "printf '%s' \"$_hickory_server_ver\"" \
        'hickory-server / hickory-resolver `[0-9][0-9.]*`, tokio' \
        's/.*hickory-resolver `\([0-9][0-9.]*\)`.*/\1/'

    # (ii) hickory-resolver version pin (the split arm).  Truth: hickory-resolver's
    # OWN manifest version, independent of hickory-server.
    _hickory_resolver_ver="$(_manifest_dep_version hickory-resolver "$_rg_manifest")"
    lrt_register "ds-dnsgate-hickory-resolver-version" \
        "printf '%s' \"$_hickory_resolver_ver\"" \
        'hickory-server / hickory-resolver `[0-9][0-9.]*`, tokio' \
        's/.*hickory-resolver `\([0-9][0-9.]*\)`.*/\1/'

    # (iii) tokio version pin.  Truth: tokio's version in the same manifest block.
    # README anchor: the same unique line; extract the `1.48` backtick token that
    # follows "tokio".
    _tokio_ver="$(_manifest_dep_version tokio "$_rg_manifest")"
    lrt_register "ds-dnsgate-tokio-version" \
        "printf '%s' \"$_tokio_ver\"" \
        'hickory-server / hickory-resolver `[0-9][0-9.]*`, tokio `[0-9][0-9.]*`' \
        's/.*tokio `\([0-9][0-9.]*\)`.*/\1/'
}

# ---------------------------------------------------------------------------
# _register_tlsproxy_guards README MANIFEST MAINRS
#   Register the ds-tlsproxy (D40) token guards against the given README,
#   workspace manifest, and crate main.rs.  Factored out so --self-test can
#   register the SAME guards against its synthetic sandbox copies.
# ---------------------------------------------------------------------------
_register_tlsproxy_guards() {
    _rt_readme="$1"
    _rt_manifest="$2"
    _rt_mainrs="$3"

    lrt_set_readme "$_rt_readme"

    # pingora-core MINOR-series pin.  Truth: pingora-core's manifest version with
    # the patch component stripped (`0.8.1` -> `0.8`).  README anchor: the unique
    # governing-decisions line documenting `pingora-core 0.8.x`; extract the
    # major.minor that precedes the `.x` series suffix.  D40 keeps the manifest on
    # the 0.8.x series; a minor/major re-evaluation that bumps the manifest pin
    # without updating the README governing-decisions line fails the gate.
    _pingora_minor="$(_manifest_dep_version_minor pingora-core "$_rt_manifest")"
    lrt_register "ds-tlsproxy-pingora-core-minor" \
        "printf '%s' \"$_pingora_minor\"" \
        'pingora-core [0-9][0-9.]*\.x' \
        's/.*pingora-core \([0-9][0-9.]*\)\.x.*/\1/'

    # Listener-port reconcile.  The README documents the two transparent-listener
    # ports in a single unique line (`binds `:18080`/`:18443``), but the truth is
    # the crate's own `add_tcp("0.0.0.0:<port>")` binding calls in main.rs.  This
    # was a port LITERAL pinned against a constant in wave-1 (main.rs was out of
    # that unit's read scope); reading main.rs as the source makes it a genuine
    # source-vs-README reconcile.  A main.rs<->README skew (e.g. add_tcp bumped to
    # :28443 while the README stays :18443) now fails the gate.  Two arms — HTTP
    # and HTTPS — both anchor on the same unique `binds` line and extract their
    # respective port from the `:<http>`/`:<https>` pair, mirroring the split
    # hickory arms whose single README token covers two independent sources.

    # (i) HTTP transparent-listener port.  Truth: http_svc.add_tcp port in main.rs.
    _tlsproxy_http_port="$(_rs_add_tcp_port http_svc "$_rt_mainrs")"
    lrt_register "ds-tlsproxy-http-listener-port" \
        "printf '%s' \"$_tlsproxy_http_port\"" \
        'binds `:[0-9][0-9]*`/`:[0-9][0-9]*`' \
        's/.*binds `:\([0-9][0-9]*\)`\/`:[0-9][0-9]*`.*/\1/'

    # (ii) HTTPS transparent-listener port.  Truth: https_svc.add_tcp port.
    _tlsproxy_https_port="$(_rs_add_tcp_port https_svc "$_rt_mainrs")"
    lrt_register "ds-tlsproxy-https-listener-port" \
        "printf '%s' \"$_tlsproxy_https_port\"" \
        'binds `:[0-9][0-9]*`/`:[0-9][0-9]*`' \
        's/.*binds `:[0-9][0-9]*`\/`:\([0-9][0-9]*\)`.*/\1/'
}

# ---------------------------------------------------------------------------
# _register_flowlog_guards README MARKRS
#   Register the ds-flowlog token guards against the given README and the
#   ds-contracts mark.rs (the canonical mark-decode source).  ds-flowlog's own
#   crate is a skeleton (no version/port literals of its own), so the one
#   load-bearing literal its README quotes against a NON-doc source of truth is
#   the session-index modulus exponent: the README says `mark_session_index` is
#   `index mod 2^14`, and `dataplane/crates/ds-contracts/src/mark.rs` defines the
#   field width as `pub const INDEX_BITS: u32 = 14`.  A change to INDEX_BITS that
#   does not update this README line (or vice versa) now fails the gate.
#   Factored out so --self-test can register the SAME guard against synthetic
#   sandbox copies.
# ---------------------------------------------------------------------------
_register_flowlog_guards() {
    _rf_readme="$1"
    _rf_markrs="$2"

    lrt_set_readme "$_rf_readme"

    # session-index modulus exponent.  Truth: INDEX_BITS in ds-contracts mark.rs.
    # README anchor: the unique frozen-contract row documenting `index mod 2^14`;
    # extract the exponent that follows `mod 2^`.
    _flowlog_index_bits="$(_rs_const_rhs INDEX_BITS "$_rf_markrs")"
    lrt_register "ds-flowlog-session-index-bits" \
        "printf '%s' \"$_flowlog_index_bits\"" \
        'mark_session_index` is index mod 2\^[0-9][0-9]*' \
        's/.*index mod 2\^\([0-9][0-9]*\).*/\1/'
}

# ---------------------------------------------------------------------------
# _register_nft_guards README REFRESHRS MARKRS
#   Register the ds-nft (D68/D76) token guards.  ds-nft is a CRATE under
#   dataplane/crates/ (not a dataplane/services/* tree) whose own Cargo.toml is
#   workspace-inherited (`version.workspace = true`, one path-only dependency) —
#   there is no version/port literal there to guard.  All THREE guarded pairs
#   instead reconcile the crate's own README against its own (or a shared
#   ds-contracts) source.  Factored out so --self-test can register the SAME
#   guards against synthetic sandbox copies.
# ---------------------------------------------------------------------------

# The shared ds-nft kernel-boundary EXTRACT expression, single-sourced so the two
# kernel arms (frozen-invariants row + module-map refresh row) can never key on
# different tokens.
#
#   s/≥/>=/g   — normalise the README's typographic U+2265 to the ASCII digraph,
#                so ONE expression serves both the real README (which writes
#                "≥6.12") and the --self-test fixture (which writes ">=6.12"),
#                and a future ASCII rewrite of the README stays green.
#   then       — key on the LOCAL ">=<ver> in-place" token.  The previous
#                expression keyed on "in CI:[^0-9]*<ver> in-place", i.e. on the
#                coincidental co-location of an "in CI:" phrase EARLIER in the
#                same sentence; a benign reword of that clause ("both exercised
#                on every kernel:") presented as a structural break even though
#                the guarded literal never moved.  The ">=<ver> in-place" token
#                is local to the boundary itself, so only a real edit to the
#                boundary trips the guard.
_NFT_KERNEL_EXTRACT='s/≥/>=/g; s/.*>=\([0-9][0-9.]*\) in-place.*/\1/'

_register_nft_guards() {
    _rn_readme="$1"
    _rn_refreshrs="$2"
    _rn_markrs="$3"

    lrt_set_readme "$_rn_readme"

    # (i) D68 in-place refresh kernel boundary, FROZEN-INVARIANTS row.  Truth:
    # INPLACE_MIN_KERNEL in the crate's own refresh.rs, dotted via
    # _rs_kernel_pair.  README anchor: the frozen-invariants row's "in-place
    # element-timeout update (commit" phrase — the `\(commit` suffix
    # disambiguates it from the module-map row's matching-but-suffix-less
    # "in-place element-timeout update" phrase (two occurrences in the real
    # README; only the frozen-invariants row carries the commit-hash suffix).
    # The anchor carries no version digits, so a kernel boundary bump stays a
    # drift (rc=1), never a structural break (rc=2).
    _nft_inplace_kernel="$(_rs_kernel_pair INPLACE_MIN_KERNEL "$_rn_refreshrs")"
    lrt_register "ds-nft-inplace-min-kernel" \
        "printf '%s' \"$_nft_inplace_kernel\"" \
        'in-place element-timeout update \(commit' \
        "$_NFT_KERNEL_EXTRACT"

    # (i-b) The SAME D68 boundary, MODULE-MAP `refresh` row.  The README states
    # the ≥6.12 boundary in TWO places; arm (i) deliberately disambiguates AWAY
    # from this second row (via the `\(commit` suffix), which left that
    # statement unguarded — a one-sided edit to the module-map row, or a
    # boundary bump applied to only one of the two rows, drifted silently.  This
    # arm targets that second row EXPLICITLY rather than defeating (i)'s
    # disambiguation: its anchor keys on the module-map row's OWN unique suffix,
    # "in-place element-timeout update and the pre-" (the frozen-invariants row
    # continues "(commit ...", never "and the pre-"), so the two anchors stay
    # mutually exclusive and each remains a UNIQUE single-line match.  Same
    # truth (INPLACE_MIN_KERNEL), same single-sourced extract expression: both
    # rows are now pinned to one source of truth, and thereby to each other.
    lrt_register "ds-nft-inplace-min-kernel-modmap" \
        "printf '%s' \"$_nft_inplace_kernel\"" \
        'in-place element-timeout update and the pre-' \
        "$_NFT_KERNEL_EXTRACT"

    # (ii) doc 14 §4 wrap/exhaustion alarm index-space exponent.  Truth:
    # INDEX_BITS in ds-contracts mark.rs — the SAME constant the ds-flowlog
    # guard above reads, but reconciled against a DIFFERENT README line here,
    # so the two trees keep checking independently (a bump now correctly fails
    # both --self-test suites at once; neither dedupes the truth read across
    # trees).  README anchor: the module-map "alarm" row's unique
    # "approaching 2^<bits>" phrase.
    _nft_index_bits="$(_rs_const_rhs INDEX_BITS "$_rn_markrs")"
    lrt_register "ds-nft-alarm-index-bits" \
        "printf '%s' \"$_nft_index_bits\"" \
        'approaching 2\^[0-9][0-9]*' \
        's/.*approaching 2\^\([0-9][0-9]*\).*/\1/'
}

# ---------------------------------------------------------------------------
# --self-test mode: dispatched BEFORE any real-tree access.
# ---------------------------------------------------------------------------
if [ "${1:-}" = "--self-test" ]; then
    if [ ! -f "$HELPER" ]; then
        printf 'check-service-readme: ABORT — helper not found: %s\n' "$HELPER" >&2
        exit 2
    fi

    _ST_ROOT="$(mktemp -d)"
    _st_cleanup() { rm -rf "$_ST_ROOT"; }
    trap _st_cleanup EXIT

    _ST_README="$_ST_ROOT/README.md"
    _ST_TLSPROXY_README="$_ST_ROOT/tlsproxy-README.md"
    _ST_FLOWLOG_README="$_ST_ROOT/flowlog-README.md"
    _ST_MANIFEST="$_ST_ROOT/Cargo.toml"
    _ST_MAINRS="$_ST_ROOT/main.rs"
    _ST_MARKRS="$_ST_ROOT/mark.rs"
    _ST_NFT_README="$_ST_ROOT/nft-README.md"
    _ST_REFRESHRS="$_ST_ROOT/refresh.rs"

    # Synthetic ds-dnsgate README carrying the same unique anchor line shape the
    # real ds-dnsgate README uses.  The single `%s` backtick token covers both
    # hickory crates (as the real README does).
    _st_write_readme() {
        _w_hver="$1"
        _w_tver="$2"
        {
            printf '# ds-dnsgate (synthetic self-test fixture)\n\n'
            printf 'Pins recorded at\n'
            printf '`[workspace.dependencies]` (hickory-server / hickory-resolver `%s`, tokio `%s`),\n' \
                "$_w_hver" "$_w_tver"
            printf 'and vendored offline.\n'
        } > "$_ST_README"
    }

    # Synthetic ds-tlsproxy README carrying the same unique governing-decisions
    # anchor line shape the real ds-tlsproxy README uses (the documented
    # pingora-core MINOR series `<minor>.x`) AND the unique listener-`binds` line
    # documenting the two transparent-listener ports `:<http>`/`:<https>`.
    _st_write_tlsproxy_readme() {
        _wt_pminor="$1"
        _wt_http="${2:-18080}"
        _wt_https="${3:-18443}"
        {
            printf '# ds-tlsproxy (synthetic self-test fixture)\n\n'
            # Leading literal "- " passed as an argument: a format string that
            # begins with "-" is parsed as a printf option by some shells.
            printf '%s**Governing decisions:** D40 (pingora-core %s.x, pinned + vendored, with a written\n' \
                '- ' "$_wt_pminor"
            printf '  re-evaluation trigger), and so on.\n'
            printf 'The `pingora-core` listener that binds `:%s`/`:%s` and attaches the per-tap session.\n' \
                "$_wt_http" "$_wt_https"
        } > "$_ST_TLSPROXY_README"
    }

    # Synthetic ds-tlsproxy main.rs carrying the LEGACY add_tcp("0.0.0.0:<port>")
    # binding-call shape (arm 1 of _rs_add_tcp_port), distinguished by the http_svc /
    # https_svc binding variable (the same anchors _rs_add_tcp_port keys on).
    _st_write_mainrs() {
        _wm_http="$1"
        _wm_https="$2"
        {
            printf '// synthetic ds-tlsproxy main.rs self-test fixture\n'
            printf '    let mut http_svc = Service::new("ds-tlsproxy-http".to_string(), http_proxy);\n'
            printf '    http_svc.add_tcp("0.0.0.0:%s");\n' "$_wm_http"
            printf '    let mut https_svc = Service::new("ds-tlsproxy-https".to_string(), https_proxy);\n'
            printf '    https_svc.add_tcp("0.0.0.0:%s");\n' "$_wm_https"
        } > "$_ST_MAINRS"
    }

    # Synthetic ds-tlsproxy main.rs carrying the CURRENT resolve_listen_addr +
    # `add_tcp(&<addr>)` binding shape the real crate uses since the
    # DS_TLSPROXY_<HTTP|HTTPS>_ADDR listener refactor (tlsproxytail, landq #6583;
    # extractor arm (2) added in fb5b2a80) — the port moved OUT
    # of the add_tcp() call into a `resolve_listen_addr("DS_TLSPROXY_<H>_ADDR",
    # "0.0.0.0:<port>")` default that add_tcp then consumes by reference.  This
    # fixture emits ONLY that shape (NO legacy `add_tcp("0.0.0.0:...")` literal), so
    # it exercises arm (2) of _rs_add_tcp_port in isolation: with only the legacy
    # literal arm (the pre-fb5b2a80 extractor) the truth grep returns empty and BOTH
    # ports go STRUCTURAL (rc=2); with the resolve_listen_addr fallback arm the
    # defaults are recovered and the guard passes.  This is the regression guard that
    # keeps arm (2) from silently re-drifting if the real main.rs shape is touched.
    _st_write_mainrs_resolve() {
        _wmr_http="$1"
        _wmr_https="$2"
        {
            printf '// synthetic ds-tlsproxy main.rs self-test fixture (resolve_listen_addr shape)\n'
            printf '    let mut http_svc = Service::new("ds-tlsproxy-http".to_string(), http_proxy);\n'
            printf '    let http_addr = resolve_listen_addr("DS_TLSPROXY_HTTP_ADDR", "0.0.0.0:%s");\n' "$_wmr_http"
            printf '    http_svc.add_tcp(&http_addr);\n'
            printf '    let mut https_svc = Service::new("ds-tlsproxy-https".to_string(), https_proxy);\n'
            printf '    let https_addr = resolve_listen_addr("DS_TLSPROXY_HTTPS_ADDR", "0.0.0.0:%s");\n' "$_wmr_https"
            printf '    https_svc.add_tcp(&https_addr);\n'
        } > "$_ST_MAINRS"
    }

    # Synthetic ds-tlsproxy main.rs carrying an UNLINKED resolve_listen_addr for the
    # HTTP listener: the `let http_addr = resolve_listen_addr("DS_TLSPROXY_HTTP_ADDR",
    # "0.0.0.0:<port>")` default is computed but http_svc.add_tcp binds a DIFFERENT
    # variable (stale_addr), so the resolve result never reaches the live listener.
    # HTTPS stays correctly wired.  Under the pre-flow-assertion arm (2) this fixture
    # false-PASSED (the extractor happily returned the dangling default port); with
    # the flow assertion the http truth goes empty and the guard fails STRUCTURAL
    # (rc=2).  This is the regression guard for the unlinked-resolve false-pass close.
    _st_write_mainrs_resolve_unlinked() {
        _wmu_http="$1"
        _wmu_https="$2"
        {
            printf '// synthetic ds-tlsproxy main.rs self-test fixture (unlinked resolve_listen_addr)\n'
            printf '    let mut http_svc = Service::new("ds-tlsproxy-http".to_string(), http_proxy);\n'
            printf '    let http_addr = resolve_listen_addr("DS_TLSPROXY_HTTP_ADDR", "0.0.0.0:%s");\n' "$_wmu_http"
            printf '    let stale_addr = String::from("0.0.0.0:0");\n'
            printf '    http_svc.add_tcp(&stale_addr);\n'
            printf '    let mut https_svc = Service::new("ds-tlsproxy-https".to_string(), https_proxy);\n'
            printf '    let https_addr = resolve_listen_addr("DS_TLSPROXY_HTTPS_ADDR", "0.0.0.0:%s");\n' "$_wmu_https"
            printf '    https_svc.add_tcp(&https_addr);\n'
        } > "$_ST_MAINRS"
    }

    # Synthetic ds-flowlog README carrying the same unique frozen-contract row
    # shape the real README uses (the `mark_session_index` is `index mod 2^<bits>`
    # disambiguator note).
    _st_write_flowlog_readme() {
        _wf_bits="$1"
        {
            printf '# ds-flowlog (synthetic self-test fixture)\n\n'
            printf '| The tap name is the join key; the FlowRecord`s '
            printf '`mark_session_index` is index mod 2^%s — a disambiguator, never the primary key | doc 14 |\n' \
                "$_wf_bits"
        } > "$_ST_FLOWLOG_README"
    }

    # Synthetic ds-contracts mark.rs carrying the same `pub const INDEX_BITS`
    # definition shape _rs_const_rhs keys on (trailing `;` + `// comment`).
    _st_write_markrs() {
        _wk_bits="$1"
        {
            printf '// synthetic ds-contracts mark.rs self-test fixture\n'
            printf 'pub const INDEX_SHIFT: u32 = 0;\n'
            printf 'pub const INDEX_BITS: u32 = %s; // 14-bit session-index field\n' "$_wk_bits"
        } > "$_ST_MARKRS"
    }

    # Synthetic ds-nft README carrying the same unique frozen-invariants row
    # shape ("in-place element-timeout update (commit ...)"), the same unique
    # module-map `refresh` row shape ("... in-place element-timeout update and
    # the pre-<ver> ... fallback"), AND the same unique module-map alarm row
    # shape ("approaching 2^<bits>") the real ds-nft README uses.
    #
    # $3 (module-map kernel version) defaults to $1 so every existing call site
    # writes a CONSISTENT pair; passing a different $3 plants the one-sided
    # README edit the (i-b) arm exists to catch.  $4 optionally rewords the
    # frozen-invariants row's leading clause, proving the re-keyed extractor no
    # longer depends on the coincidental "in CI:" co-location.
    _st_write_nft_readme() {  # $1=kernel ver, $2=alarm bits, $3=modmap ver, $4=lead clause
        _wn_kver="$1"
        _wn_bits="${2:-14}"
        _wn_mapkver="${3:-$1}"
        _wn_lead="${4:-Both kernel refresh paths behind the same API, both in CI:}"
        {
            printf '# ds-nft (synthetic self-test fixture)\n\n'
            printf '| %s >=%s in-place element-timeout update (commit 4201f3938914) and the delete+add fallback | D68 |\n' \
                "$_wn_lead" "$_wn_kver"
            printf '| `refresh` | BOTH kernel refresh paths behind one API (D68): the >=%s in-place element-timeout update and the pre-%s delete+add-in-one-batch fallback. |\n' \
                "$_wn_mapkver" "$_wn_mapkver"
            printf '| `alarm` | wrap alarm (live retention-window indices per host approaching 2^%s -> page), threshold parameterized. |\n' \
                "$_wn_bits"
        } > "$_ST_NFT_README"
    }

    # Synthetic ds-nft refresh.rs carrying the same tuple-const shape
    # _rs_kernel_pair (via _rs_const_rhs) keys on.
    _st_write_refreshrs() {  # $1=major $2=minor
        {
            printf '// synthetic ds-nft refresh.rs self-test fixture\n'
            printf 'pub const INPLACE_MIN_KERNEL: (u32, u32) = (%s, %s);\n' "$1" "$2"
        } > "$_ST_REFRESHRS"
    }

    # Synthetic workspace manifest [workspace.dependencies] block.  hickory-server
    # and hickory-resolver are written from SEPARATE args so a one-sided bump can
    # be exercised against the split arms; pingora-core carries a full
    # major.minor.patch pin so the minor-series strip is exercised.
    _st_write_manifest() {
        _m_hsver="$1"
        _m_hrver="$2"
        _m_tver="$3"
        _m_pver="$4"
        {
            printf '[workspace.dependencies]\n'
            printf 'tokio = { version = "%s", default-features = false }\n' "$_m_tver"
            printf 'hickory-server = { version = "%s", default-features = false }\n' "$_m_hsver"
            printf 'hickory-resolver = { version = "%s", default-features = false }\n' "$_m_hrver"
            printf 'pingora-core = { version = "%s", default-features = false }\n' "$_m_pver"
        } > "$_ST_MANIFEST"
    }

    . "$HELPER"

    _st_reset() { _LRT_COUNT=0; _LRT_README=""; }

    _fail=0

    # --- baseline: matched README + manifest -> rc 0 ---
    # manifest args: hickory-server, hickory-resolver, tokio, pingora-core
    _st_write_readme "0.26" "1.48"
    _st_write_manifest "0.26" "0.26" "1.48" "0.8.1"
    _st_reset
    _register_dnsgate_guards "$_ST_README" "$_ST_MANIFEST"
    _rc=0
    lrt_check_all >/dev/null 2>&1 || _rc=$?
    if [ "$_rc" -ne 0 ]; then
        printf 'self-test: FAIL — clean fixture expected rc=0, got rc=%d\n' "$_rc" >&2
        _fail=1
    else
        printf 'self-test: clean fixture passed (rc=0)\n'
    fi

    # --- drift 1: README hickory version bumped, manifest unchanged -> rc 1 ---
    _st_write_readme "0.27" "1.48"
    _st_write_manifest "0.26" "0.26" "1.48" "0.8.1"
    _st_reset
    _register_dnsgate_guards "$_ST_README" "$_ST_MANIFEST"
    _rc=0
    lrt_check_all >/dev/null 2>&1 || _rc=$?
    if [ "$_rc" -ne 1 ]; then
        printf 'self-test: FAIL — README-side hickory drift expected rc=1, got rc=%d\n' "$_rc" >&2
        _fail=1
    else
        printf 'self-test: README-side hickory drift caught (rc=1)\n'
    fi

    # --- split arm: manifest hickory-RESOLVER bumped alone, hickory-server and
    # the README's single token unchanged -> rc 1.  The split arm is what catches
    # this: with the pre-split single hickory guard (truth = hickory-server only)
    # this one-sided resolver bump would have passed silently. ---
    _st_write_readme "0.26" "1.48"
    _st_write_manifest "0.26" "0.27" "1.48" "0.8.1"
    _st_reset
    _register_dnsgate_guards "$_ST_README" "$_ST_MANIFEST"
    _rc=0
    lrt_check_all >/dev/null 2>&1 || _rc=$?
    if [ "$_rc" -ne 1 ]; then
        printf 'self-test: FAIL — one-sided hickory-resolver manifest drift expected rc=1, got rc=%d\n' "$_rc" >&2
        _fail=1
    else
        printf 'self-test: one-sided hickory-resolver manifest drift caught by split arm (rc=1)\n'
    fi

    # --- drift 2: manifest tokio version bumped, README unchanged -> rc 1 ---
    _st_write_readme "0.26" "1.48"
    _st_write_manifest "0.26" "0.26" "1.50" "0.8.1"
    _st_reset
    _register_dnsgate_guards "$_ST_README" "$_ST_MANIFEST"
    _rc=0
    lrt_check_all >/dev/null 2>&1 || _rc=$?
    if [ "$_rc" -ne 1 ]; then
        printf 'self-test: FAIL — source-side tokio drift expected rc=1, got rc=%d\n' "$_rc" >&2
        _fail=1
    else
        printf 'self-test: source-side tokio drift caught (rc=1)\n'
    fi

    # --- structural: reworded ds-dnsgate README anchor (phrase gone) -> rc 2 ---
    {
        printf '# ds-dnsgate (synthetic self-test fixture)\n\n'
        printf 'The framework versions are now described in entirely new prose.\n'
    } > "$_ST_README"
    _st_write_manifest "0.26" "0.26" "1.48" "0.8.1"
    _st_reset
    _register_dnsgate_guards "$_ST_README" "$_ST_MANIFEST"
    _rc=0
    lrt_check_all >/dev/null 2>&1 || _rc=$?
    if [ "$_rc" -ne 2 ]; then
        printf 'self-test: FAIL — reworded anchor expected rc=2 (structural), got rc=%d\n' "$_rc" >&2
        _fail=1
    else
        printf 'self-test: reworded-anchor structural failure caught (rc=2)\n'
    fi

    # --- ds-tlsproxy clean: README 0.8.x matches manifest 0.8.1 minor AND the
    # README `:18080`/`:18443` ports match the main.rs add_tcp bindings -> rc 0 ---
    _st_write_tlsproxy_readme "0.8"
    _st_write_manifest "0.26" "0.26" "1.48" "0.8.1"
    _st_write_mainrs "18080" "18443"
    _st_reset
    _register_tlsproxy_guards "$_ST_TLSPROXY_README" "$_ST_MANIFEST" "$_ST_MAINRS"
    _rc=0
    lrt_check_all >/dev/null 2>&1 || _rc=$?
    if [ "$_rc" -ne 0 ]; then
        printf 'self-test: FAIL — tlsproxy clean fixture expected rc=0, got rc=%d\n' "$_rc" >&2
        _fail=1
    else
        printf 'self-test: tlsproxy clean fixture passed (rc=0)\n'
    fi

    # --- ds-tlsproxy drift (source side): manifest pingora minor-series bumped
    # (0.8.1 -> 0.9.0) while the README still documents 0.8.x -> rc 1 ---
    _st_write_tlsproxy_readme "0.8"
    _st_write_manifest "0.26" "0.26" "1.48" "0.9.0"
    _st_write_mainrs "18080" "18443"
    _st_reset
    _register_tlsproxy_guards "$_ST_TLSPROXY_README" "$_ST_MANIFEST" "$_ST_MAINRS"
    _rc=0
    lrt_check_all >/dev/null 2>&1 || _rc=$?
    if [ "$_rc" -ne 1 ]; then
        printf 'self-test: FAIL — tlsproxy source-side pingora drift expected rc=1, got rc=%d\n' "$_rc" >&2
        _fail=1
    else
        printf 'self-test: tlsproxy source-side pingora minor-series drift caught (rc=1)\n'
    fi

    # --- ds-tlsproxy drift (README side): README documents 0.9.x while the
    # manifest still pins 0.8.1 -> rc 1 ---
    _st_write_tlsproxy_readme "0.9"
    _st_write_manifest "0.26" "0.26" "1.48" "0.8.1"
    _st_write_mainrs "18080" "18443"
    _st_reset
    _register_tlsproxy_guards "$_ST_TLSPROXY_README" "$_ST_MANIFEST" "$_ST_MAINRS"
    _rc=0
    lrt_check_all >/dev/null 2>&1 || _rc=$?
    if [ "$_rc" -ne 1 ]; then
        printf 'self-test: FAIL — tlsproxy README-side pingora drift expected rc=1, got rc=%d\n' "$_rc" >&2
        _fail=1
    else
        printf 'self-test: tlsproxy README-side pingora drift caught (rc=1)\n'
    fi

    # --- ds-tlsproxy structural: reworded README anchor (pingora line gone) -> rc 2 ---
    {
        printf '# ds-tlsproxy (synthetic self-test fixture)\n\n'
        printf '%s**Governing decisions:** the framework choice is now described in new prose.\n' '- '
    } > "$_ST_TLSPROXY_README"
    _st_write_manifest "0.26" "0.26" "1.48" "0.8.1"
    _st_write_mainrs "18080" "18443"
    _st_reset
    _register_tlsproxy_guards "$_ST_TLSPROXY_README" "$_ST_MANIFEST" "$_ST_MAINRS"
    _rc=0
    lrt_check_all >/dev/null 2>&1 || _rc=$?
    if [ "$_rc" -ne 2 ]; then
        printf 'self-test: FAIL — tlsproxy reworded anchor expected rc=2 (structural), got rc=%d\n' "$_rc" >&2
        _fail=1
    else
        printf 'self-test: tlsproxy reworded-anchor structural failure caught (rc=2)\n'
    fi

    # --- ds-tlsproxy PORT skew (source side): main.rs https listener bumped to
    # :28443 while the README still documents `:18443` -> rc 1.  This is the new
    # main.rs<->README port reconcile arm; without it the README literal would
    # have agreed with nothing and the skew would go undetected. ---
    _st_write_tlsproxy_readme "0.8"
    _st_write_manifest "0.26" "0.26" "1.48" "0.8.1"
    _st_write_mainrs "18080" "28443"
    _st_reset
    _register_tlsproxy_guards "$_ST_TLSPROXY_README" "$_ST_MANIFEST" "$_ST_MAINRS"
    _rc=0
    lrt_check_all >/dev/null 2>&1 || _rc=$?
    if [ "$_rc" -ne 1 ]; then
        printf 'self-test: FAIL — tlsproxy main.rs<->README port skew expected rc=1, got rc=%d\n' "$_rc" >&2
        _fail=1
    else
        printf 'self-test: tlsproxy main.rs<->README https-port skew caught (rc=1)\n'
    fi

    # --- ds-tlsproxy PORT skew (README side): README documents `:18444` for the
    # HTTPS listener while main.rs still binds :18443 -> rc 1 ---
    _st_write_tlsproxy_readme "0.8" "18080" "18444"
    _st_write_manifest "0.26" "0.26" "1.48" "0.8.1"
    _st_write_mainrs "18080" "18443"
    _st_reset
    _register_tlsproxy_guards "$_ST_TLSPROXY_README" "$_ST_MANIFEST" "$_ST_MAINRS"
    _rc=0
    lrt_check_all >/dev/null 2>&1 || _rc=$?
    if [ "$_rc" -ne 1 ]; then
        printf 'self-test: FAIL — tlsproxy README-side port skew expected rc=1, got rc=%d\n' "$_rc" >&2
        _fail=1
    else
        printf 'self-test: tlsproxy README-side https-port skew caught (rc=1)\n'
    fi

    # --- ds-tlsproxy resolve_listen_addr CLEAN: main.rs binds via the CURRENT
    # `let <addr> = resolve_listen_addr("DS_TLSPROXY_<H>_ADDR", "0.0.0.0:<port>")`
    # + `add_tcp(&<addr>)` shape (NO legacy add_tcp literal) and the README still
    # documents `:18080`/`:18443` -> rc 0.  This is the &var-binding regression
    # guard for arm (2) of _rs_add_tcp_port: run against the PRE-fb5b2a80 extractor
    # (legacy-literal arm only) this SAME fixture returns an empty truth for both
    # ports and goes STRUCTURAL (rc=2) — it passes ONLY because the
    # resolve_listen_addr fallback arm recovers the port defaults, so a future edit
    # that breaks arm (2) can no longer silently re-drift while the real main.rs
    # uses this shape. ---
    _st_write_tlsproxy_readme "0.8"
    _st_write_manifest "0.26" "0.26" "1.48" "0.8.1"
    _st_write_mainrs_resolve "18080" "18443"
    _st_reset
    _register_tlsproxy_guards "$_ST_TLSPROXY_README" "$_ST_MANIFEST" "$_ST_MAINRS"
    _rc=0
    lrt_check_all >/dev/null 2>&1 || _rc=$?
    if [ "$_rc" -ne 0 ]; then
        printf 'self-test: FAIL — tlsproxy resolve_listen_addr(&var) clean fixture expected rc=0, got rc=%d\n' "$_rc" >&2
        _fail=1
    else
        printf 'self-test: tlsproxy resolve_listen_addr(&var) binding shape extracted (rc=0)\n'
    fi

    # --- ds-tlsproxy resolve_listen_addr PORT skew (source side): main.rs binds via
    # the resolve_listen_addr(&var) shape but its HTTPS default was bumped to
    # :28443 while the README still documents `:18443` -> rc 1.  Proves arm (2) does
    # not merely find SOME port but extracts the RIGHT one, so a real main.rs<->README
    # skew is still caught under the current binding shape (not just the legacy one). ---
    _st_write_tlsproxy_readme "0.8"
    _st_write_manifest "0.26" "0.26" "1.48" "0.8.1"
    _st_write_mainrs_resolve "18080" "28443"
    _st_reset
    _register_tlsproxy_guards "$_ST_TLSPROXY_README" "$_ST_MANIFEST" "$_ST_MAINRS"
    _rc=0
    lrt_check_all >/dev/null 2>&1 || _rc=$?
    if [ "$_rc" -ne 1 ]; then
        printf 'self-test: FAIL — tlsproxy resolve_listen_addr(&var) source-side port skew expected rc=1, got rc=%d\n' "$_rc" >&2
        _fail=1
    else
        printf 'self-test: tlsproxy resolve_listen_addr(&var) source-side https-port skew caught (rc=1)\n'
    fi

    # --- ds-tlsproxy resolve_listen_addr UNLINKED (false-pass close): main.rs computes
    # `let http_addr = resolve_listen_addr("DS_TLSPROXY_HTTP_ADDR", "0.0.0.0:18080")`
    # but http_svc.add_tcp binds a DIFFERENT variable (stale_addr), so the resolve
    # result never flows into the live HTTP listener.  The README still documents
    # `:18080`.  Pre-flow-assertion this false-PASSED (arm (2) returned the dangling
    # default); with the FLOW ASSERTION the http truth goes empty -> STRUCTURAL rc=2.
    # This proves the unlinked-resolve false-pass is closed: a stale resolve default
    # can no longer masquerade as the live listener port. ---
    _st_write_tlsproxy_readme "0.8"
    _st_write_manifest "0.26" "0.26" "1.48" "0.8.1"
    _st_write_mainrs_resolve_unlinked "18080" "18443"
    _st_reset
    _register_tlsproxy_guards "$_ST_TLSPROXY_README" "$_ST_MANIFEST" "$_ST_MAINRS"
    _rc=0
    lrt_check_all >/dev/null 2>&1 || _rc=$?
    if [ "$_rc" -ne 2 ]; then
        printf 'self-test: FAIL — tlsproxy unlinked resolve_listen_addr expected rc=2 (structural), got rc=%d\n' "$_rc" >&2
        _fail=1
    else
        printf 'self-test: tlsproxy unlinked-resolve false-pass caught (flow assertion, rc=2)\n'
    fi

    # --- ds-flowlog clean: README `mod 2^14` matches mark.rs INDEX_BITS=14 -> rc 0 ---
    _st_write_flowlog_readme "14"
    _st_write_markrs "14"
    _st_reset
    _register_flowlog_guards "$_ST_FLOWLOG_README" "$_ST_MARKRS"
    _rc=0
    lrt_check_all >/dev/null 2>&1 || _rc=$?
    if [ "$_rc" -ne 0 ]; then
        printf 'self-test: FAIL — flowlog clean fixture expected rc=0, got rc=%d\n' "$_rc" >&2
        _fail=1
    else
        printf 'self-test: flowlog clean fixture passed (rc=0)\n'
    fi

    # --- ds-flowlog drift (README side): README documents `mod 2^16` while
    # mark.rs still defines INDEX_BITS = 14 -> rc 1 ---
    _st_write_flowlog_readme "16"
    _st_write_markrs "14"
    _st_reset
    _register_flowlog_guards "$_ST_FLOWLOG_README" "$_ST_MARKRS"
    _rc=0
    lrt_check_all >/dev/null 2>&1 || _rc=$?
    if [ "$_rc" -ne 1 ]; then
        printf 'self-test: FAIL — flowlog README-side modulus drift expected rc=1, got rc=%d\n' "$_rc" >&2
        _fail=1
    else
        printf 'self-test: flowlog README-side modulus drift caught (rc=1)\n'
    fi

    # --- ds-flowlog drift (source side): mark.rs INDEX_BITS bumped to 13 while
    # the README still documents `mod 2^14` -> rc 1 ---
    _st_write_flowlog_readme "14"
    _st_write_markrs "13"
    _st_reset
    _register_flowlog_guards "$_ST_FLOWLOG_README" "$_ST_MARKRS"
    _rc=0
    lrt_check_all >/dev/null 2>&1 || _rc=$?
    if [ "$_rc" -ne 1 ]; then
        printf 'self-test: FAIL — flowlog source-side INDEX_BITS drift expected rc=1, got rc=%d\n' "$_rc" >&2
        _fail=1
    else
        printf 'self-test: flowlog source-side INDEX_BITS drift caught (rc=1)\n'
    fi

    # --- ds-flowlog structural: reworded README anchor (mark_session_index row
    # gone) -> rc 2 ---
    {
        printf '# ds-flowlog (synthetic self-test fixture)\n\n'
        printf 'The session-index field width is now described in entirely new prose.\n'
    } > "$_ST_FLOWLOG_README"
    _st_write_markrs "14"
    _st_reset
    _register_flowlog_guards "$_ST_FLOWLOG_README" "$_ST_MARKRS"
    _rc=0
    lrt_check_all >/dev/null 2>&1 || _rc=$?
    if [ "$_rc" -ne 2 ]; then
        printf 'self-test: FAIL — flowlog reworded anchor expected rc=2 (structural), got rc=%d\n' "$_rc" >&2
        _fail=1
    else
        printf 'self-test: flowlog reworded-anchor structural failure caught (rc=2)\n'
    fi

    # --- ds-nft clean: README "6.12"/"14" matches refresh.rs (6,12) AND
    # mark.rs INDEX_BITS=14 -> rc 0 ---
    _st_write_nft_readme "6.12" "14"
    _st_write_refreshrs 6 12
    _st_write_markrs "14"
    _st_reset
    _register_nft_guards "$_ST_NFT_README" "$_ST_REFRESHRS" "$_ST_MARKRS"
    _rc=0
    lrt_check_all >/dev/null 2>&1 || _rc=$?
    if [ "$_rc" -ne 0 ]; then
        printf 'self-test: FAIL — ds-nft clean fixture expected rc=0, got rc=%d\n' "$_rc" >&2
        _fail=1
    else
        printf 'self-test: ds-nft clean fixture passed (rc=0)\n'
    fi

    # --- ds-nft drift (source side): refresh.rs INPLACE_MIN_KERNEL bumped to
    # (6,13) while the README still documents "6.12" -> rc 1 ---
    _st_write_nft_readme "6.12" "14"
    _st_write_refreshrs 6 13
    _st_write_markrs "14"
    _st_reset
    _register_nft_guards "$_ST_NFT_README" "$_ST_REFRESHRS" "$_ST_MARKRS"
    _rc=0
    lrt_check_all >/dev/null 2>&1 || _rc=$?
    if [ "$_rc" -ne 1 ]; then
        printf 'self-test: FAIL — ds-nft source-side kernel drift expected rc=1, got rc=%d\n' "$_rc" >&2
        _fail=1
    else
        printf 'self-test: ds-nft source-side kernel drift caught (rc=1)\n'
    fi

    # --- ds-nft drift (README side): README documents "6.13" while
    # refresh.rs still defines (6,12) -> rc 1 ---
    _st_write_nft_readme "6.13" "14"
    _st_write_refreshrs 6 12
    _st_write_markrs "14"
    _st_reset
    _register_nft_guards "$_ST_NFT_README" "$_ST_REFRESHRS" "$_ST_MARKRS"
    _rc=0
    lrt_check_all >/dev/null 2>&1 || _rc=$?
    if [ "$_rc" -ne 1 ]; then
        printf 'self-test: FAIL — ds-nft README-side kernel drift expected rc=1, got rc=%d\n' "$_rc" >&2
        _fail=1
    else
        printf 'self-test: ds-nft README-side kernel drift caught (rc=1)\n'
    fi

    # --- ds-nft ONE-SIDED README drift (module-map row only): the
    # frozen-invariants row still says 6.12 (matching refresh.rs) while the
    # module-map `refresh` row was bumped to 6.13 -> rc 1.  This is the exact
    # silent drift the (i-b) arm exists to catch: WITHOUT it arm (i) passes and
    # the whole check returns 0. ---
    _st_write_nft_readme "6.12" "14" "6.13"
    _st_write_refreshrs 6 12
    _st_write_markrs "14"
    _st_reset
    _register_nft_guards "$_ST_NFT_README" "$_ST_REFRESHRS" "$_ST_MARKRS"
    _rc=0
    lrt_check_all >/dev/null 2>&1 || _rc=$?
    if [ "$_rc" -ne 1 ]; then
        printf 'self-test: FAIL — ds-nft one-sided module-map kernel drift expected rc=1, got rc=%d\n' "$_rc" >&2
        _fail=1
    else
        printf 'self-test: ds-nft one-sided module-map kernel drift caught (rc=1)\n'
    fi

    # --- ds-nft BENIGN REWORD of the frozen-invariants row's leading clause:
    # the "in CI:" phrase the OLD extractor keyed on is gone, but the guarded
    # ">=6.12 in-place" token is untouched -> rc 0.  Pins the re-key: prose
    # churn around the boundary must not present as drift. ---
    _st_write_nft_readme "6.12" "14" "6.12" \
        "Both kernel refresh paths behind the same API, exercised on every kernel:"
    _st_write_refreshrs 6 12
    _st_write_markrs "14"
    _st_reset
    _register_nft_guards "$_ST_NFT_README" "$_ST_REFRESHRS" "$_ST_MARKRS"
    _rc=0
    lrt_check_all >/dev/null 2>&1 || _rc=$?
    if [ "$_rc" -ne 0 ]; then
        printf 'self-test: FAIL — ds-nft benign reword expected rc=0 (no false drift), got rc=%d\n' "$_rc" >&2
        _fail=1
    else
        printf 'self-test: ds-nft benign reword did not trip the re-keyed extractor (rc=0)\n'
    fi

    # --- ds-nft drift (source side, alarm bits): mark.rs INDEX_BITS bumped to
    # 13 while the README still documents "approaching 2^14" -> rc 1 (mirrors
    # the ds-flowlog source-side arm; independent registration proves the two
    # trees' guards over the SAME constant do not share state) ---
    _st_write_nft_readme "6.12" "14"
    _st_write_refreshrs 6 12
    _st_write_markrs "13"
    _st_reset
    _register_nft_guards "$_ST_NFT_README" "$_ST_REFRESHRS" "$_ST_MARKRS"
    _rc=0
    lrt_check_all >/dev/null 2>&1 || _rc=$?
    if [ "$_rc" -ne 1 ]; then
        printf 'self-test: FAIL — ds-nft source-side alarm-bits drift expected rc=1, got rc=%d\n' "$_rc" >&2
        _fail=1
    else
        printf 'self-test: ds-nft source-side alarm-bits drift caught (rc=1)\n'
    fi

    # --- ds-nft structural: reworded README anchors (both rows gone) -> rc 2 ---
    {
        printf '# ds-nft (synthetic self-test fixture)\n\n'
        printf 'The kernel refresh boundary and alarm space are now described in entirely new prose.\n'
    } > "$_ST_NFT_README"
    _st_write_refreshrs 6 12
    _st_write_markrs "14"
    _st_reset
    _register_nft_guards "$_ST_NFT_README" "$_ST_REFRESHRS" "$_ST_MARKRS"
    _rc=0
    lrt_check_all >/dev/null 2>&1 || _rc=$?
    if [ "$_rc" -ne 2 ]; then
        printf 'self-test: FAIL — ds-nft reworded-anchor structural failure expected rc=2, got rc=%d\n' "$_rc" >&2
        _fail=1
    else
        printf 'self-test: ds-nft reworded-anchor structural failure caught (rc=2)\n'
    fi

    if [ "$_fail" -ne 0 ]; then
        printf 'self-test: FAIL — one or more sub-tests failed\n' >&2
        exit 1
    fi
    printf 'self-test: ALL CHECKS PASSED — check-service-readme.sh OK\n'
    exit 0
fi

# ---------------------------------------------------------------------------
# Production path: guard the real dataplane/services/* READMEs.
# ---------------------------------------------------------------------------
if [ ! -f "$HELPER" ]; then
    printf 'check-service-readme: ERROR: helper not found: %s\n' "$HELPER" >&2
    exit 2
fi

DNSGATE_README="$REPO_ROOT/dataplane/services/ds-dnsgate/README.md"
TLSPROXY_README="$REPO_ROOT/dataplane/services/ds-tlsproxy/README.md"
TLSPROXY_MAINRS="$REPO_ROOT/dataplane/services/ds-tlsproxy/src/main.rs"
FLOWLOG_README="$REPO_ROOT/dataplane/services/ds-flowlog/README.md"
MARK_RS="$REPO_ROOT/dataplane/crates/ds-contracts/src/mark.rs"
WORKSPACE_MANIFEST="$REPO_ROOT/dataplane/Cargo.toml"
NFT_README="$REPO_ROOT/dataplane/crates/ds-nft/README.md"
NFT_REFRESH_RS="$REPO_ROOT/dataplane/crates/ds-nft/src/refresh.rs"

for _f in "$DNSGATE_README" "$TLSPROXY_README" "$TLSPROXY_MAINRS" \
          "$FLOWLOG_README" "$MARK_RS" "$WORKSPACE_MANIFEST" \
          "$NFT_README" "$NFT_REFRESH_RS"; do
    if [ ! -f "$_f" ]; then
        printf 'check-service-readme: ERROR: not found: %s\n' "$_f" >&2
        exit 2
    fi
done

. "$HELPER"

# lrt_check_all checks every registered token against ONE README path, so each
# service tree gets its OWN registration+check pass (the registry is reset
# between passes via _LRT_COUNT=0); the worst exit code across passes is
# returned (structural 2 overrides drift 1 overrides clean 0).
#
# NOTE the accumulator is named _csr_overall, NOT _overall: lrt_check_all in the
# helper uses a NON-local `_overall` of its own (sh functions have no default
# local scope), so each per-tree call CLOBBERS a shared `_overall` to its own
# tree's rc.  A clean tree run AFTER a drifting one would reset a shared
# `_overall` back to 0 and silently swallow the earlier drift; keeping this
# accumulator under a distinct name that the helper never writes makes the
# worst-across-trees fold correct regardless of tree order.
_csr_overall=0

_run_tree_guards() {
    # $1 = greppable tree label, $2 = register-fn, $3.. = register-fn args
    # (README + whichever source-of-truth files that tree's guards reconcile).
    _rtg_label="$1"
    _rtg_fn="$2"
    shift 2
    _LRT_COUNT=0
    _LRT_README=""
    "$_rtg_fn" "$@"
    _rtg_out="$(mktemp)"
    _rtg_rc=0
    lrt_check_all > "$_rtg_out" 2>&1 || _rtg_rc=$?
    sed "s/^/check-service-readme [$_rtg_label]: /" < "$_rtg_out"
    rm -f "$_rtg_out"
    if [ "$_rtg_rc" -gt "$_csr_overall" ]; then
        _csr_overall="$_rtg_rc"
    fi
}

_run_tree_guards "ds-dnsgate"  _register_dnsgate_guards  "$DNSGATE_README"  "$WORKSPACE_MANIFEST"
_run_tree_guards "ds-tlsproxy" _register_tlsproxy_guards "$TLSPROXY_README" "$WORKSPACE_MANIFEST" "$TLSPROXY_MAINRS"
_run_tree_guards "ds-flowlog"  _register_flowlog_guards  "$FLOWLOG_README"  "$MARK_RS"
_run_tree_guards "ds-nft"      _register_nft_guards      "$NFT_README"      "$NFT_REFRESH_RS" "$MARK_RS"

if [ "$_csr_overall" -ne 0 ]; then
    printf 'check-service-readme: FAIL — a guarded dataplane README token drifted from its source (rc=%d)\n' "$_csr_overall" >&2
    exit "$_csr_overall"
fi

printf 'check-service-readme: OK — all guarded dataplane README tokens match their source\n'
