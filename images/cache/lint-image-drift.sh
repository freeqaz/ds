#!/bin/sh
# lint-image-drift.sh — assert that the stock Nexus image literal is byte-
# identical across the two deploy paths in this tree, AND that the site-local
# OCI pull-through cache's :5000 connector port agrees three ways across the
# files that independently encode it.
#
# images/cache/ ships TWO deploy definitions for the same desired state
# (D41 buy-not-build): the podman-quadlet unit deploy/nexus.container and the
# podman-compose / docker-compose file deploy/compose.yaml.  Pick ONE per host,
# never both — but both must name the SAME stock Nexus Repository CE image,
# pinned identically, or the two paths drift to different versions.
#
# The image reference lives as a hand-synced LITERAL in each file:
#   - nexus.container: the [Container] section's "Image=<ref>" line
#   - compose.yaml:    the ds-cache-nexus service's "image: <ref>" line
# Neither file can interpolate the other, so the two literals are kept in
# lockstep by hand; this lint catches divergence before it reaches a deploy.
# (It does not validate the ref's syntax or that it is digest-pinned — only
# that the two files agree; production pins to a digest, see nexus.container.)
#
# OCI :5000 PORT THREE-WAY RECONCILE
# The Docker-Hub pull-through connector port (:5000) is encoded by HAND in three
# independent files that nothing else cross-checks:
#   - wiring/registries.conf:  the docker.io [[registry.mirror]] location
#       `cache.ds.local:5000` (the in-VM mirror hop the golden images bake);
#   - deploy/nexus.container:   the [Container] `PublishPort=5000:5000` host port
#       (the port Nexus actually publishes on the cache host);
#   - deploy/repos.yaml:        the `docker-proxy` connector's `httpPort: 5000`
#       AND its bare `endpoint: cache.ds.local:5000` (the Nexus REST desired
#       state — two independent encodings within the one file, both checked).
# registries.conf's header and repos.yaml both ASSERT these must agree, but the
# existing README-token arms (ix)/(x) only reconcile each one against the README
# cell — a one-sided edit of the mirror port OR the repos.yaml connector slips
# through with no direct file-to-file guard.  The reconcile below fails closed
# unless registries.conf, nexus.container, and BOTH repos.yaml encodings equal
# the canonical :5000 (a "three-way" file reconcile, four port reads).  Like the
# PublishPort/registries.conf reads elsewhere, the three deploy/wiring files are
# READ-ONLY truth sources here — this script owns none of them.
#
# The docker.io mirror extraction is ANCHORED to the `prefix = "docker.io"`
# [[registry]] block (capture the NEXT [[registry.mirror]] location), not
# positional-first, so an enabled ghcr.io / quay.io mirror ordered BEFORE
# docker.io cannot mis-reconcile as docker.io's port.
#
# PER-UPSTREAM OCI GUARDS (ghcr.io :5001 / quay.io :5002)
# The two further OCI upstreams pre-declared disabled-by-default in
# wiring/registries.conf each get their own clean-mode guard, GATED on the
# stanza being ACTIVE (uncommented): a commented stanza yields a loud clean SKIP
# (rc=0 — the shipped default keeps the gate green), while an active stanza
# reconciles that upstream's README endpoint cell against its now-active mirror
# location (rc=1 value drift, rc=2 structural: no following mirror / README
# missing / anchor count != 1 / empty cell).  README.md is a truth source for
# these guards and so joins the --self-test sandbox copy set.
#
# An ACTIVATED upstream additionally gets the SAME three-way connector-:PORT
# reconcile docker.io :5000 enforces above: its mirror location's :PORT must
# equal the `<name>-proxy` entry's httpPort AND bare endpoint in
# deploy/repos.yaml, the marker-anchored PublishPort pair in
# deploy/nexus.container, and the httpPort in its create_proxy invocation in
# deploy/bootstrap.sh.  Before this, activating ghcr.io/quay.io reconciled only
# the mirror LOCATION, so a one-sided connector-port bump slipped through to
# runtime.  Those three deploy files ship the optional entries as COMMENTED
# templates (the connector stays defined-but-unopened), so the per-upstream
# readers are comment-tolerant by design — uncommenting the registries.conf
# stanza alone is enough to arm the reconcile.  deploy/bootstrap.sh therefore
# joins CONTAINER_FILE / REPOS_FILE / REGISTRIES_FILE as a READ-ONLY truth
# source; this script owns none of them.
#
# Usage:
#   sh images/cache/lint-image-drift.sh
# (or run from anywhere; paths are resolved relative to this script's directory)
#
# Exit codes:
#   0  — the two image literals match AND the OCI :5000 port agrees three ways
#        (plus, for each ACTIVATED optional upstream, its own three-way port
#        agreement; a commented upstream is a clean SKIP)
#   1  — they diverge, OR the OCI :5000 port drifts across the three files, OR
#        an activated upstream's connector port drifts across its three deploy
#        files (both/all values printed to stderr)
#   2  — a required file or the image/port key is missing
#
# --self-test: internal regression harness; copies deploy/ AND wiring/ to a temp
# dir, verifies the clean copy passes (rc=0), then injects each recognised drift
# one at a time and verifies the lint catches it with the expected non-zero rc:
#   - a diverging Image= literal must drive rc=1 (the two paths disagree);
#   - a one-sided OCI :5000 port edit in EITHER registries.conf (mirror
#     location), nexus.container (PublishPort), or repos.yaml (docker-proxy
#     httpPort/endpoint) must drive rc=1 (the three encodings disagree);
#   - a dropped image key, or a removed deploy file, must drive rc=2;
#   - a SECOND active mirror ordered BEFORE docker.io must NOT steal docker.io's
#     reconcile (rc=0 — the block anchoring holds);
#   - activating a ghcr.io / quay.io stanza with a clean README cell must stay
#     rc=0 (guard reconciles), a drifted cell must drive rc=1, and a dropped
#     README row must drive rc=2 (structural);
#   - with a ghcr.io / quay.io stanza ACTIVATED, a one-sided connector-port edit
#     in EACH of the three deploy files in turn — repos.yaml (httpPort and the
#     bare endpoint), nexus.container (the marker-anchored PublishPort), and
#     bootstrap.sh (the create_proxy httpPort) — must drive rc=1, and dropping
#     any of those keys must drive rc=2, while the all-commented default tree
#     stays rc=0.
# Exits 0 on success, non-zero if any injection is not caught (or is caught with
# the wrong rc).  Dispatched BEFORE any file-existence checks so it never reads
# the real deploy/ for its own pass/fail.  The temp dir is cleaned up via a trap
# on EXIT.
# Injections are anchored to image-key PATTERNS (not byte-exact whole lines) —
# the harness aborts immediately (rc=1) if an anchor is gone, so an upstream
# line reformat can never silently turn an injection into a no-op.
#
# GATE WIRING: this lint runs under the standing gate two ways — `make
# check-image-drift` (clean mode) validates the real tree, and `make
# check-image-drift-selftest` re-runs it under --self-test so the injection arms
# and README-token guards fire in CI; both are repo-lints prerequisites. The
# Makefile owns that wiring (this script is only invoked, never edited by it).
# smoke.sh (live-verification owner) is not touched here.
#
# SPDX-License-Identifier: Apache-2.0

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ---------------------------------------------------------------------------
# Shared anchored mirror-location extractor.
# Usage: _mirror_location_for_prefix PREFIX FILE
# Prints the `location` value of the [[registry.mirror]] that immediately
# follows the ACTIVE (non-commented) [[registry]] block whose prefix == PREFIX;
# prints nothing if that block, or its following mirror, is absent.  This is the
# block-ANCHORED replacement for the old positional "first active mirror
# location" reads: an enabled ghcr.io / quay.io mirror ordered BEFORE docker.io
# can no longer be mis-attributed to docker.io.  Defined before the --self-test
# block because the self-test path (arm (x)) uses it and exits before the later
# clean-mode function definitions are ever read.
#
# awk state machine (rule order is load-bearing): the two exact-header rules for
# [[registry.mirror]] and [[registry]] fire BEFORE the generic `[[` reset; a new
# [[registry]] header before the mirror clears `want`, so "docker.io block with
# no following mirror" still yields empty.  PREFIX is passed as a plain string
# (-v) and compared with string equality, so no regex escaping is needed.
# ---------------------------------------------------------------------------
_mirror_location_for_prefix() {
    awk -v pfx="$1" '
        /^[[:space:]]*#/ { next }
        { s = $0; gsub(/[[:space:]]/, "", s) }
        s == "[[registry.mirror]]" { if (want) armed = 1; want = 0; in_reg = 0; next }
        s == "[[registry]]"        { in_reg = 1; want = 0; armed = 0; next }
        in_reg && s == ("prefix=\"" pfx "\"") { want = 1; next }
        armed && /^[[:space:]]*location[[:space:]]*=/ {
            val = $0
            sub(/^[[:space:]]*location[[:space:]]*=[[:space:]]*/, "", val)
            gsub(/"/, "", val); gsub(/[[:space:]]*$/, "", val)
            print val; exit
        }
        s ~ /^\[\[/ { want = 0; armed = 0; in_reg = 0 }
    ' "$2"
}

# ---------------------------------------------------------------------------
# --self-test mode: must be dispatched before any file-existence checks so the
# harness exercises only its own temp-dir copy, never the real deploy/ tree.
# ---------------------------------------------------------------------------
if [ "${1:-}" = "--self-test" ]; then
    # The production lint resolves deploy/ relative to its OWN SCRIPT_DIR with no
    # override hook.  So the harness builds a self-contained sandbox root holding
    # a copy of this script PLUS a deploy/ subdir copied from the real one, then
    # invokes the copied lint — whose SCRIPT_DIR resolves to the sandbox, never
    # the real tree.  Injections mutate only the sandbox's deploy/ files.
    _ST_ROOT="$(mktemp -d)"
    _st_cleanup() { rm -rf "$_ST_ROOT"; }
    trap _st_cleanup EXIT

    cp "$SCRIPT_DIR/lint-image-drift.sh" "$_ST_ROOT/lint-image-drift.sh"
    mkdir -p "$_ST_ROOT/deploy"
    cp -r "$SCRIPT_DIR/deploy/." "$_ST_ROOT/deploy/"
    # wiring/ holds registries.conf — the third truth source for the OCI :5000
    # three-way port reconcile; copy it into the sandbox so port injections
    # mutate only the sandbox copy, never the real wiring/ tree.
    mkdir -p "$_ST_ROOT/wiring"
    cp -r "$SCRIPT_DIR/wiring/." "$_ST_ROOT/wiring/"
    # README.md is a truth source for the clean-mode per-upstream ghcr/quay
    # guards (they read $SCRIPT_DIR/README.md); copy it in so the activation
    # self-test arms drive the sandbox lint against a sandbox README, never the
    # real one.
    cp "$SCRIPT_DIR/README.md" "$_ST_ROOT/README.md"

    _ST_LINT="$_ST_ROOT/lint-image-drift.sh"
    _ST_CTR="$_ST_ROOT/deploy/nexus.container"
    _ST_COMPOSE="$_ST_ROOT/deploy/compose.yaml"
    _ST_REGCONF="$_ST_ROOT/wiring/registries.conf"
    _ST_REPOS="$_ST_ROOT/deploy/repos.yaml"
    _ST_README="$_ST_ROOT/README.md"
    # deploy/bootstrap.sh is the third deploy-side truth source for an ACTIVATED
    # optional upstream's connector port; it rides in via the deploy/ copy above.
    _ST_BOOTSTRAP="$_ST_ROOT/deploy/bootstrap.sh"

    # Helper: replace the first line matching ANCHOR_PAT in FILE with NEW_LINE.
    # Fails (rc=1) if no line matched (anchor gone — no silent no-op).
    # Usage: _replace_line FILE ANCHOR_PAT NEW_LINE LABEL
    _replace_line() {
        _rl_file="$1"
        _rl_pat="$2"
        _rl_new="$3"
        _rl_label="$4"
        _rl_matched="$(awk -v pat="$_rl_pat" '$0 ~ pat { print NR; exit }' "$_rl_file")"
        if [ -z "$_rl_matched" ]; then
            printf 'self-test: ABORT — injection anchor gone: %s (pattern: %s)\n' \
                "$_rl_label" "$_rl_pat" >&2
            exit 1
        fi
        awk -v pat="$_rl_pat" -v new="$_rl_new" -v done=0 '
            !done && $0 ~ pat { print new; done=1; next }
            { print }
        ' "$_rl_file" > "$_rl_file.tmp" && mv "$_rl_file.tmp" "$_rl_file"
    }

    # Helper: delete lines matching ANCHOR_PAT from FILE.
    # Fails (rc=1) if no line matched (anchor gone — no silent no-op).
    # Usage: _delete_line FILE ANCHOR_PAT LABEL
    _delete_line() {
        _dl_file="$1"
        _dl_pat="$2"
        _dl_label="$3"
        _dl_matched="$(awk -v pat="$_dl_pat" '$0 ~ pat { print NR; exit }' "$_dl_file")"
        if [ -z "$_dl_matched" ]; then
            printf 'self-test: ABORT — injection anchor gone: %s (pattern: %s)\n' \
                "$_dl_label" "$_dl_pat" >&2
            exit 1
        fi
        awk -v pat="$_dl_pat" '$0 ~ pat { next } { print }' \
            "$_dl_file" > "$_dl_file.tmp" && mv "$_dl_file.tmp" "$_dl_file"
    }

    # Helper: in the FIRST line matching ANCHOR_PAT in FILE, replace the literal
    # substring OLD with NEW.  Used for the per-upstream port injections, where
    # the surrounding line carries backslash-escaped JSON that a whole-line
    # rewrite would mangle.  ANCHOR_PAT MUST encode the old value, so the
    # post-check ("the anchor must no longer match anywhere") turns both a gone
    # anchor and a silent no-op substitution into an immediate ABORT.
    # Usage: _sub_in_line FILE ANCHOR_PAT OLD NEW LABEL
    _sub_in_line() {
        _sil_file="$1"
        _sil_pat="$2"
        _sil_old="$3"
        _sil_new="$4"
        _sil_label="$5"
        _sil_matched="$(awk -v pat="$_sil_pat" '$0 ~ pat { print NR; exit }' "$_sil_file")"
        if [ -z "$_sil_matched" ]; then
            printf 'self-test: ABORT — injection anchor gone: %s (pattern: %s)\n' \
                "$_sil_label" "$_sil_pat" >&2
            exit 1
        fi
        awk -v ln="$_sil_matched" -v old="$_sil_old" -v new="$_sil_new" '
            NR == ln {
                i = index($0, old)
                if (i > 0) { $0 = substr($0, 1, i - 1) new substr($0, i + length(old)) }
            }
            { print }
        ' "$_sil_file" > "$_sil_file.tmp" && mv "$_sil_file.tmp" "$_sil_file"
        if awk -v pat="$_sil_pat" '$0 ~ pat { f = 1 } END { exit f ? 0 : 1 }' "$_sil_file"; then
            printf 'self-test: ABORT — injection was a no-op: %s (pattern still matches: %s)\n' \
                "$_sil_label" "$_sil_pat" >&2
            exit 1
        fi
    }

    # Helper: uncomment (ACTIVATE) the registries.conf stanza between BEGIN_PAT
    # and END_PAT (END_PAT empty = to EOF), then verify the activation actually
    # took (the anchor-gone discipline — a silent no-op would turn arms 2–6 into
    # false greens/reds).  Only the stanza's `# [[`, `# prefix`, `# location`,
    # `# insecure` lines are uncommented; prose (`# DISABLED …`) and the blank
    # `#` separators stay commented (harmless).  The quay range has no end marker
    # (runs to EOF), so the END rule is guarded with `e != ""`.
    # Usage: _activate_stanza FILE BEGIN_PAT END_PAT PFX LABEL
    _activate_stanza() {
        awk -v b="$2" -v e="$3" '
            e != "" && $0 ~ e { act = 0 }
            $0 ~ b            { act = 1 }
            act && /^# (\[\[|prefix|location|insecure)/ { sub(/^# /, ""); print; next }
            { print }
        ' "$1" > "$1.tmp" && mv "$1.tmp" "$1"
        if ! grep -q "^prefix = \"$4\"" "$1"; then
            printf 'self-test: ABORT — stanza activation no-op: %s\n' "$5" >&2
            exit 1
        fi
    }

    # Helper: restore the sandbox deploy/ AND wiring/ to the clean (canonical)
    # copy — covers both the image-drift injections (deploy/) and the OCI :5000
    # three-way port injections (deploy/ + wiring/).
    _restore() {
        rm -rf "$_ST_ROOT/deploy" "$_ST_ROOT/wiring"
        mkdir -p "$_ST_ROOT/deploy" "$_ST_ROOT/wiring"
        cp -r "$SCRIPT_DIR/deploy/." "$_ST_ROOT/deploy/"
        cp -r "$SCRIPT_DIR/wiring/." "$_ST_ROOT/wiring/"
        # README.md too — the upstream-injection arms (3/5/6) mutate the sandbox
        # README, so restore it between arms or drift leaks into later arms.
        rm -f "$_ST_ROOT/README.md"
        cp "$SCRIPT_DIR/README.md" "$_ST_ROOT/README.md"
    }

    # Run the copied lint against the sandbox deploy/; print its rc on stdout.
    _lint_rc() {
        _lr_rc=0
        sh "$_ST_LINT" >/dev/null 2>&1 || _lr_rc=$?
        printf '%s' "$_lr_rc"
    }

    # --- baseline: the clean copy must pass (rc=0). ---
    _restore
    _clean_rc="$(_lint_rc)"
    if [ "$_clean_rc" -ne 0 ]; then
        printf 'self-test: FAIL — clean copy did not exit 0 (rc=%d)\n' "$_clean_rc" >&2
        exit 1
    fi
    printf 'self-test: clean copy passed (rc=0)\n'

    # --- injection 1: diverging Image= literal → rc=1 (the two paths disagree) ---
    # Mutate ONLY the quadlet Image= digest; compose.yaml keeps the canonical
    # ref, so the byte-identity assertion must fail with rc=1.
    _restore
    _replace_line "$_ST_CTR" \
        '^Image=docker[.]io/sonatype/nexus3:' \
        'Image=docker.io/sonatype/nexus3:3.70.1@sha256:0000000000000000000000000000000000000000000000000000000000000bad' \
        'Image= digest diverged'
    _rc="$(_lint_rc)"
    if [ "$_rc" -ne 1 ]; then
        printf 'self-test: FAIL — injection [Image= digest diverged] expected rc=1, got rc=%d\n' "$_rc" >&2
        exit 1
    fi
    printf 'self-test: injection [Image= digest diverged] caught (rc=%d)\n' "$_rc"

    # --- injection 2: diverging compose image: tag → rc=1 (mirror of injection 1) ---
    # Mutate ONLY the compose image: tag; the quadlet keeps the canonical ref.
    _restore
    _replace_line "$_ST_COMPOSE" \
        '^[[:space:]]*image:[[:space:]]*docker[.]io/sonatype/nexus3:' \
        '    image: docker.io/sonatype/nexus3:3.69.0@sha256:00ecf29c4a3a43d677aec9ff07966e942c4356d9c16a275d94110f6e1e5aca94' \
        'compose image: tag diverged'
    _rc="$(_lint_rc)"
    if [ "$_rc" -ne 1 ]; then
        printf 'self-test: FAIL — injection [compose image: tag diverged] expected rc=1, got rc=%d\n' "$_rc" >&2
        exit 1
    fi
    printf 'self-test: injection [compose image: tag diverged] caught (rc=%d)\n' "$_rc"

    # --- injection 3: dropped Image= key in nexus.container → rc=2 (key missing) ---
    # Delete the [Container] Image= line entirely; the lint cannot extract a
    # container image and must exit 2 (missing key), not 1 (divergence).
    _restore
    _delete_line "$_ST_CTR" \
        '^Image=docker[.]io/sonatype/nexus3:' \
        'Image= key dropped'
    _rc="$(_lint_rc)"
    if [ "$_rc" -ne 2 ]; then
        printf 'self-test: FAIL — injection [Image= key dropped] expected rc=2, got rc=%d\n' "$_rc" >&2
        exit 1
    fi
    printf 'self-test: injection [Image= key dropped] caught (rc=%d)\n' "$_rc"

    # --- injection 4: dropped compose image: key → rc=2 (key missing) ---
    _restore
    _delete_line "$_ST_COMPOSE" \
        '^[[:space:]]*image:[[:space:]]*docker[.]io/sonatype/nexus3:' \
        'compose image: key dropped'
    _rc="$(_lint_rc)"
    if [ "$_rc" -ne 2 ]; then
        printf 'self-test: FAIL — injection [compose image: key dropped] expected rc=2, got rc=%d\n' "$_rc" >&2
        exit 1
    fi
    printf 'self-test: injection [compose image: key dropped] caught (rc=%d)\n' "$_rc"

    # --- injection 5: missing nexus.container file → rc=2 (required file gone) ---
    _restore
    rm -f "$_ST_CTR"
    _rc="$(_lint_rc)"
    if [ "$_rc" -ne 2 ]; then
        printf 'self-test: FAIL — injection [nexus.container removed] expected rc=2, got rc=%d\n' "$_rc" >&2
        exit 1
    fi
    printf 'self-test: injection [nexus.container removed] caught (rc=%d)\n' "$_rc"

    # --- injection 6: missing compose.yaml file → rc=2 (required file gone) ---
    _restore
    rm -f "$_ST_COMPOSE"
    _rc="$(_lint_rc)"
    if [ "$_rc" -ne 2 ]; then
        printf 'self-test: FAIL — injection [compose.yaml removed] expected rc=2, got rc=%d\n' "$_rc" >&2
        exit 1
    fi
    printf 'self-test: injection [compose.yaml removed] caught (rc=%d)\n' "$_rc"

    # -----------------------------------------------------------------------
    # OCI :5000 three-way port reconcile injections (this unit).
    #
    # The production lint reconciles the docker.io mirror port (registries.conf),
    # the PublishPort host port (nexus.container), and the docker-proxy connector
    # port (repos.yaml) and fails closed (rc=1) unless all three == :5000.  A
    # one-sided edit of ANY of the three must be caught.  The clean baseline
    # (covered by the rc=0 baseline above and re-asserted per injection via
    # _restore) keeps the arm honest: it fires only on real drift.
    # -----------------------------------------------------------------------

    # --- port-injection 1: one-sided registries.conf mirror port edit → rc=1 ---
    # Bump ONLY the active docker.io [[registry.mirror]] location to :5001; the
    # PublishPort and repos.yaml connector stay :5000, so the three-way reconcile
    # must fail with rc=1.  The disabled-by-default ghcr.io/quay.io mirror
    # stanzas are fully commented, so this edit targets the one live mirror.
    _restore
    _replace_line "$_ST_REGCONF" \
        '^location = "cache[.]ds[.]local:5000"$' \
        'location = "cache.ds.local:5001"' \
        'registries.conf mirror port diverged'
    _rc="$(_lint_rc)"
    if [ "$_rc" -ne 1 ]; then
        printf 'self-test: FAIL — injection [registries.conf mirror port diverged] expected rc=1, got rc=%d\n' "$_rc" >&2
        exit 1
    fi
    printf 'self-test: injection [registries.conf mirror port diverged] caught (rc=%d)\n' "$_rc"

    # --- port-injection 2: one-sided repos.yaml connector port edit → rc=1 ---
    # Bump ONLY the docker-proxy `httpPort:` to :5001; registries.conf and
    # PublishPort stay :5000, so the three-way reconcile must fail with rc=1.
    # The ghcr/quay sibling proxy entries are fully commented, so the active
    # docker-proxy httpPort is the one this anchor hits.
    _restore
    _replace_line "$_ST_REPOS" \
        '^[[:space:]]*httpPort:[[:space:]]*5000[[:space:]]*$' \
        '  httpPort: 5001' \
        'repos.yaml connector httpPort diverged'
    _rc="$(_lint_rc)"
    if [ "$_rc" -ne 1 ]; then
        printf 'self-test: FAIL — injection [repos.yaml connector httpPort diverged] expected rc=1, got rc=%d\n' "$_rc" >&2
        exit 1
    fi
    printf 'self-test: injection [repos.yaml connector httpPort diverged] caught (rc=%d)\n' "$_rc"

    # --- port-injection 3: one-sided nexus.container PublishPort edit → rc=1 ---
    # Bump ONLY the OCI PublishPort host port to :5001; registries.conf and
    # repos.yaml stay :5000, so the three-way reconcile must fail with rc=1.
    # (Mirror of port-injections 1/2 on the third truth source, closing the
    # third side.)
    _restore
    _replace_line "$_ST_CTR" \
        '^PublishPort=5000:5000$' \
        'PublishPort=5001:5000' \
        'nexus.container OCI PublishPort diverged'
    _rc="$(_lint_rc)"
    if [ "$_rc" -ne 1 ]; then
        printf 'self-test: FAIL — injection [nexus.container OCI PublishPort diverged] expected rc=1, got rc=%d\n' "$_rc" >&2
        exit 1
    fi
    printf 'self-test: injection [nexus.container OCI PublishPort diverged] caught (rc=%d)\n' "$_rc"

    # --- port-injection 4: dropped repos.yaml docker-proxy httpPort key → rc=2 ---
    # Delete the docker-proxy `httpPort:` line entirely; the lint cannot extract
    # the connector port and must exit 2 (missing key), not 1 (drift).
    _restore
    _delete_line "$_ST_REPOS" \
        '^[[:space:]]*httpPort:[[:space:]]*5000[[:space:]]*$' \
        'repos.yaml httpPort key dropped'
    _rc="$(_lint_rc)"
    if [ "$_rc" -ne 2 ]; then
        printf 'self-test: FAIL — injection [repos.yaml httpPort key dropped] expected rc=2, got rc=%d\n' "$_rc" >&2
        exit 1
    fi
    printf 'self-test: injection [repos.yaml httpPort key dropped] caught (rc=%d)\n' "$_rc"

    # --- port-injection 5: dropped registries.conf active mirror location → rc=2 ---
    # Delete the active docker.io mirror location line; the lint cannot extract
    # the mirror port and must exit 2 (missing key), not 1 (drift).  Only the
    # live (non-commented) location matches this anchor.
    _restore
    _delete_line "$_ST_REGCONF" \
        '^location = "cache[.]ds[.]local:5000"$' \
        'registries.conf mirror location dropped'
    _rc="$(_lint_rc)"
    if [ "$_rc" -ne 2 ]; then
        printf 'self-test: FAIL — injection [registries.conf mirror location dropped] expected rc=2, got rc=%d\n' "$_rc" >&2
        exit 1
    fi
    printf 'self-test: injection [registries.conf mirror location dropped] caught (rc=%d)\n' "$_rc"

    # --- port-injection 6: one-sided repos.yaml endpoint port edit → rc=1 ---
    # Bump ONLY the docker-proxy bare `endpoint: cache.ds.local:5000` to :5001,
    # leaving httpPort (and the other two files) at :5000.  endpoint is a SECOND
    # independent encoding of the connector port within repos.yaml; the reconcile
    # checks it too, so this one-sided edit must fail with rc=1.  The anchor is
    # the bare host:port endpoint (no scheme/path), so the npm/PyPI/Go :8081 URL
    # rows are never matched.
    _restore
    _replace_line "$_ST_REPOS" \
        '^[[:space:]]*endpoint:[[:space:]]*cache[.]ds[.]local:5000[[:space:]]*$' \
        '  endpoint: cache.ds.local:5001' \
        'repos.yaml endpoint port diverged'
    _rc="$(_lint_rc)"
    if [ "$_rc" -ne 1 ]; then
        printf 'self-test: FAIL — injection [repos.yaml endpoint port diverged] expected rc=1, got rc=%d\n' "$_rc" >&2
        exit 1
    fi
    printf 'self-test: injection [repos.yaml endpoint port diverged] caught (rc=%d)\n' "$_rc"

    # --- port-injection 7: dropped repos.yaml docker-proxy endpoint → rc=2 ---
    # Delete the bare docker-proxy `endpoint:` line; the lint cannot extract the
    # endpoint port and must exit 2 (missing key), not 1 (drift).
    _restore
    _delete_line "$_ST_REPOS" \
        '^[[:space:]]*endpoint:[[:space:]]*cache[.]ds[.]local:5000[[:space:]]*$' \
        'repos.yaml endpoint key dropped'
    _rc="$(_lint_rc)"
    if [ "$_rc" -ne 2 ]; then
        printf 'self-test: FAIL — injection [repos.yaml endpoint key dropped] expected rc=2, got rc=%d\n' "$_rc" >&2
        exit 1
    fi
    printf 'self-test: injection [repos.yaml endpoint key dropped] caught (rc=%d)\n' "$_rc"

    # -----------------------------------------------------------------------
    # Per-upstream gated-guard + docker.io anchoring injections (this unit).
    #
    # These arms exercise the clean-mode ghcr.io/quay.io per-upstream guards and
    # the docker.io block-anchored mirror extraction, all through _lint_rc (a
    # sandbox CLEAN-mode run — the guards live in the clean-mode path, not the
    # lrt README-token path, precisely so these arms can drive rc=1/rc=2).  Named
    # `# --- upstream-injection N` (NOT `# --- injection N`) so they do not bump
    # the (ii) IMAGE-DRIFT recognized-drifts count the README prose pins.
    # -----------------------------------------------------------------------

    # --- upstream-injection 1: a SECOND active mirror ordered BEFORE docker.io
    # must NOT steal docker.io's reconcile → rc=0.  Prepend an ACTIVE ghcr pair
    # ahead of the docker.io block; the docker.io extraction must still anchor to
    # its own block and return :5000 (the OLD positional-first read would have
    # grabbed :5001 → false rc=1), AND the now-active ghcr guard must reconcile
    # the README `cache.ds.local:5001` cell — so the inserted location MUST be
    # cache.ds.local:5001 to match the README ghcr row.
    _restore
    { printf '%s\n' '[[registry]]' 'prefix = "ghcr.io"' 'location = "ghcr.io"' '' \
        '[[registry.mirror]]' 'location = "cache.ds.local:5001"' ''; \
        cat "$_ST_REGCONF"; } > "$_ST_REGCONF.tmp" && mv "$_ST_REGCONF.tmp" "$_ST_REGCONF"
    _rc="$(_lint_rc)"
    if [ "$_rc" -ne 0 ]; then
        printf 'self-test: FAIL — upstream-injection [second mirror ordered before docker.io] expected rc=0, got rc=%d\n' "$_rc" >&2
        exit 1
    fi
    printf 'self-test: upstream-injection [second mirror ordered before docker.io] docker.io still reconciles + ghcr guard active (rc=%d)\n' "$_rc"

    # --- upstream-injection 2: ghcr stanza activated, README untouched → rc=0.
    # The lockstep baseline: activating the ghcr stanza turns its guard ON, and
    # the untouched real README row must reconcile.  This is what keeps the real
    # README row and the commented stanza in lockstep — a one-sided edit of
    # EITHER real file fails this arm in CI.
    _restore
    _activate_stanza "$_ST_REGCONF" '^# --- ghcr[.]io ' '^# --- quay[.]io ' 'ghcr.io' 'ghcr stanza activation'
    _rc="$(_lint_rc)"
    if [ "$_rc" -ne 0 ]; then
        printf 'self-test: FAIL — upstream-injection [ghcr activated, README clean] expected rc=0, got rc=%d\n' "$_rc" >&2
        exit 1
    fi
    printf 'self-test: upstream-injection [ghcr activated, README clean] guard reconciles (rc=%d)\n' "$_rc"

    # --- upstream-injection 3: ghcr active + drifted README cell → rc=1.
    # Keep the row-anchor prefix so the guard finds the row and reports DRIFT
    # (rc=1), not a structural miss (rc=2).
    _restore
    _activate_stanza "$_ST_REGCONF" '^# --- ghcr[.]io ' '^# --- quay[.]io ' 'ghcr.io' 'ghcr stanza activation'
    _replace_line "$_ST_README" \
        '^[|] [*][*]OCI / ghcr[.]io[*][*] [|]' \
        '| **OCI / ghcr.io** | `ghcr.io` | `cache.ds.local:5999` | `wiring/registries.conf` (commented stanza) |' \
        'ghcr README endpoint cell drifted'
    _rc="$(_lint_rc)"
    if [ "$_rc" -ne 1 ]; then
        printf 'self-test: FAIL — upstream-injection [ghcr active + drifted README cell] expected rc=1, got rc=%d\n' "$_rc" >&2
        exit 1
    fi
    printf 'self-test: upstream-injection [ghcr active + drifted README cell] caught (rc=%d)\n' "$_rc"

    # --- upstream-injection 4: quay stanza activated, README untouched → rc=0.
    # (quay range runs to EOF — END_PAT empty.)
    _restore
    _activate_stanza "$_ST_REGCONF" '^# --- quay[.]io ' '' 'quay.io' 'quay stanza activation'
    _rc="$(_lint_rc)"
    if [ "$_rc" -ne 0 ]; then
        printf 'self-test: FAIL — upstream-injection [quay activated, README clean] expected rc=0, got rc=%d\n' "$_rc" >&2
        exit 1
    fi
    printf 'self-test: upstream-injection [quay activated, README clean] guard reconciles (rc=%d)\n' "$_rc"

    # --- upstream-injection 5: quay active + drifted README cell → rc=1. ---
    _restore
    _activate_stanza "$_ST_REGCONF" '^# --- quay[.]io ' '' 'quay.io' 'quay stanza activation'
    _replace_line "$_ST_README" \
        '^[|] [*][*]OCI / quay[.]io[*][*] [|]' \
        '| **OCI / quay.io** | `quay.io` | `cache.ds.local:5999` | `wiring/registries.conf` (commented stanza) |' \
        'quay README endpoint cell drifted'
    _rc="$(_lint_rc)"
    if [ "$_rc" -ne 1 ]; then
        printf 'self-test: FAIL — upstream-injection [quay active + drifted README cell] expected rc=1, got rc=%d\n' "$_rc" >&2
        exit 1
    fi
    printf 'self-test: upstream-injection [quay active + drifted README cell] caught (rc=%d)\n' "$_rc"

    # --- upstream-injection 6: fail-closed pin — ghcr active + README row
    # DELETED → rc=2 (structural: the anchor no longer matches exactly one row).
    _restore
    _activate_stanza "$_ST_REGCONF" '^# --- ghcr[.]io ' '^# --- quay[.]io ' 'ghcr.io' 'ghcr stanza activation'
    _delete_line "$_ST_README" \
        '^[|] [*][*]OCI / ghcr[.]io[*][*] [|]' \
        'ghcr README row dropped'
    _rc="$(_lint_rc)"
    if [ "$_rc" -ne 2 ]; then
        printf 'self-test: FAIL — upstream-injection [ghcr active + README row dropped] expected rc=2, got rc=%d\n' "$_rc" >&2
        exit 1
    fi
    printf 'self-test: upstream-injection [ghcr active + README row dropped] caught (rc=%d)\n' "$_rc"

    # -----------------------------------------------------------------------
    # ACTIVATED-upstream three-way connector-port injections (this unit).
    #
    # The arms above prove the activated ghcr/quay guards reconcile the README
    # cell.  These prove the SECOND half: once a stanza is uncommented, that
    # upstream's connector :PORT must agree across all three deploy files, the
    # same reconcile docker.io :5000 already gets.  Every arm activates ONLY the
    # registries.conf stanza (the deploy entries stay commented templates — the
    # exact shape an operator hits mid-activation, and the window the old guard
    # let a one-sided port bump through) and then plants a single one-sided edit.
    #
    # Named `# --- upstream-port-injection N` (NOT `# --- injection N`) so they
    # do not bump the (ii) IMAGE-DRIFT recognized-drifts count the README prose
    # pins.  Run for BOTH upstreams through one parameterised helper, so the two
    # can never drift apart in coverage.
    # -----------------------------------------------------------------------

    # _expect_rc EXPECTED LABEL — run the sandbox lint, require EXPECTED.
    _expect_rc() {
        _er_rc="$(_lint_rc)"
        if [ "$_er_rc" -ne "$1" ]; then
            printf 'self-test: FAIL — upstream-port-injection [%s] expected rc=%d, got rc=%d\n' \
                "$2" "$1" "$_er_rc" >&2
            exit 1
        fi
        printf 'self-test: upstream-port-injection [%s] caught (rc=%d)\n' "$2" "$_er_rc"
    }

    # _upstream_port_arms LABEL REPO PORT BADPORT BEGIN_PAT END_PAT PREFIX
    # 7 arms per upstream: 4 x one-sided drift (rc=1) + 3 x dropped key (rc=2).
    _upstream_port_arms() {
        _upa_label="$1"
        _upa_repo="$2"
        _upa_port="$3"
        _upa_bad="$4"
        _upa_begin="$5"
        _upa_end="$6"
        _upa_pfx="$7"

        _upa_http_pat="^#[[:space:]]+httpPort:[[:space:]]*${_upa_port}$"
        _upa_ep_pat="^#[[:space:]]+endpoint:[[:space:]]*cache[.]ds[.]local:${_upa_port}$"
        _upa_pub_pat="^# PublishPort=${_upa_port}:${_upa_port}$"
        _upa_boot_pat="httpPort[^0-9]*${_upa_port}"

        # --- upstream-port-injection 1: repos.yaml httpPort one-sided → rc=1 ---
        _restore
        _activate_stanza "$_ST_REGCONF" "$_upa_begin" "$_upa_end" "$_upa_pfx" "$_upa_label activation"
        _sub_in_line "$_ST_REPOS" "$_upa_http_pat" "$_upa_port" "$_upa_bad" \
            "$_upa_label repos.yaml httpPort diverged"
        _expect_rc 1 "$_upa_label active + repos.yaml httpPort diverged"

        # --- upstream-port-injection 2: repos.yaml endpoint one-sided → rc=1 ---
        _restore
        _activate_stanza "$_ST_REGCONF" "$_upa_begin" "$_upa_end" "$_upa_pfx" "$_upa_label activation"
        _sub_in_line "$_ST_REPOS" "$_upa_ep_pat" ":${_upa_port}" ":${_upa_bad}" \
            "$_upa_label repos.yaml endpoint diverged"
        _expect_rc 1 "$_upa_label active + repos.yaml endpoint diverged"

        # --- upstream-port-injection 3: nexus.container PublishPort → rc=1 ---
        _restore
        _activate_stanza "$_ST_REGCONF" "$_upa_begin" "$_upa_end" "$_upa_pfx" "$_upa_label activation"
        _sub_in_line "$_ST_CTR" "$_upa_pub_pat" "=${_upa_port}:" "=${_upa_bad}:" \
            "$_upa_label nexus.container PublishPort diverged"
        _expect_rc 1 "$_upa_label active + nexus.container PublishPort diverged"

        # --- upstream-port-injection 4: bootstrap.sh create_proxy port → rc=1 ---
        _restore
        _activate_stanza "$_ST_REGCONF" "$_upa_begin" "$_upa_end" "$_upa_pfx" "$_upa_label activation"
        _sub_in_line "$_ST_BOOTSTRAP" "$_upa_boot_pat" ":${_upa_port}" ":${_upa_bad}" \
            "$_upa_label bootstrap.sh create_proxy port diverged"
        _expect_rc 1 "$_upa_label active + bootstrap.sh create_proxy port diverged"

        # --- upstream-port-injection 5: repos.yaml httpPort key dropped → rc=2 -
        _restore
        _activate_stanza "$_ST_REGCONF" "$_upa_begin" "$_upa_end" "$_upa_pfx" "$_upa_label activation"
        _delete_line "$_ST_REPOS" "$_upa_http_pat" "$_upa_label repos.yaml httpPort dropped"
        _expect_rc 2 "$_upa_label active + repos.yaml httpPort dropped"

        # --- upstream-port-injection 6: nexus.container PublishPort dropped → 2 -
        _restore
        _activate_stanza "$_ST_REGCONF" "$_upa_begin" "$_upa_end" "$_upa_pfx" "$_upa_label activation"
        _delete_line "$_ST_CTR" "$_upa_pub_pat" "$_upa_label nexus.container PublishPort dropped"
        _expect_rc 2 "$_upa_label active + nexus.container PublishPort dropped"

        # --- upstream-port-injection 7: bootstrap.sh httpPort dropped → rc=2 ---
        # The reader is STOPPED by the next create_proxy, so the sibling
        # upstream's port can never back-fill this one into a false green.
        _restore
        _activate_stanza "$_ST_REGCONF" "$_upa_begin" "$_upa_end" "$_upa_pfx" "$_upa_label activation"
        _delete_line "$_ST_BOOTSTRAP" "$_upa_boot_pat" "$_upa_label bootstrap.sh httpPort dropped"
        _expect_rc 2 "$_upa_label active + bootstrap.sh httpPort dropped"
    }

    _upstream_port_arms "ghcr" "ghcr-proxy" "5001" "5999" \
        '^# --- ghcr[.]io ' '^# --- quay[.]io ' 'ghcr.io'
    _upstream_port_arms "quay" "quay-proxy" "5002" "5998" \
        '^# --- quay[.]io ' '' 'quay.io'

    # --- upstream-port-injection 8: BOTH upstreams activated, nothing planted
    # → rc=0.  The positive direction with both guards armed at once: the real
    # tree's commented ghcr/quay port literals in all three deploy files already
    # agree with their mirror locations, so a future one-sided edit of ANY of
    # them fails this arm in CI even though the shipped tree never activates.
    _restore
    _activate_stanza "$_ST_REGCONF" '^# --- ghcr[.]io ' '^# --- quay[.]io ' 'ghcr.io' 'ghcr activation'
    _activate_stanza "$_ST_REGCONF" '^# --- quay[.]io ' '' 'quay.io' 'quay activation'
    _rc="$(_lint_rc)"
    if [ "$_rc" -ne 0 ]; then
        printf 'self-test: FAIL — upstream-port-injection [both upstreams activated, clean] expected rc=0, got rc=%d\n' "$_rc" >&2
        exit 1
    fi
    printf 'self-test: upstream-port-injection [both upstreams activated, clean] all four encodings agree (rc=%d)\n' "$_rc"

    # Leave the sandbox in its canonical state for the README-token block below.
    _restore

    # -----------------------------------------------------------------------
    # README token guard — via scripts/lint-readme-tokens.sh (shared helper).
    #
    # Unique-match anchoring: zero or multiple anchor hits is itself a failure,
    # retiring the wave-1 first-match residual risk.
    #
    # Several load-bearing tokens in README.md must stay in sync with their
    # ground truth.  Every side is recomputed here (never literal-frozen), so
    # a future unit that updates both sides stays green while a one-sided edit
    # fails immediately.
    #
    # (i)   Pinned Nexus image ref — anchored to the unique phrase "pinned image:"
    #       in the component table row for deploy/nexus.container; value extracted
    #       from the first backtick-quoted token on that line.  Ground truth is
    #       the Image= line in deploy/nexus.container's [Container] section.
    # (ii)  Injected-drift count — anchored to the unique bold-backtick phrase
    #       **`N recognized drifts`**; value is the leading number.  This counts
    #       only the IMAGE-DRIFT injection blocks (`# --- injection N`) the README
    #       prose describes (Image=/image: divergence + dropped key/file); the
    #       OCI :5000 three-way port arm has its own `# --- port-injection N`
    #       blocks (a distinct guard category) and is not folded into this count.
    # (iii)–(v) Pull-through endpoint URLs (npm / PyPI / Go) — each anchored to
    #       the unique ecosystem label at the start of its row in the
    #       "Ecosystem → endpoint → wiring" registry table; value extracted from
    #       the backtick-quoted host-local endpoint URL on that row.  Ground
    #       truth is the wiring/ client config the golden images bake:
    #       wiring/npmrc (registry=), wiring/pip.conf (index-url =),
    #       wiring/go.env (GOPROXY=) — a one-sided rename or :8081 bump desyncs
    #       the doc from the config and fails the self-test.
    # (vi)–(ix) Per-row endpoint PORT literals (readme-survey P7/P8) — each
    #       registry-table row's :PORT (npm/PyPI/Go front :8081; OCI fronts
    #       :5000) reconciled against the deploy source of truth, the
    #       PublishPort= host ports in deploy/nexus.container.  Narrower than the
    #       whole-URL guards above: a one-sided port bump on EITHER side (README
    #       row or quadlet PublishPort=) fails the self-test per-row.
    # (x)   OCI / containers row FULL endpoint (host+port) — reconciled against
    #       the mirror location ANCHORED to the `prefix = "docker.io"` [[registry]]
    #       block in wiring/registries.conf (capture the NEXT [[registry.mirror]]
    #       location, canonical cache.ds.local:5000), not the positional-first
    #       active mirror — so an enabled ghcr.io/quay.io mirror ordered before
    #       docker.io cannot mis-reconcile.  The OCI analogue of the (iii)–(v)
    #       whole-endpoint guards, whose truth lives split across a
    #       [[registry.mirror]] pair rather than one URL line; a one-sided edit of
    #       either the README OCI cell or the mirror location fails the self-test.
    # -----------------------------------------------------------------------

    _README="$SCRIPT_DIR/README.md"
    _SELF="$SCRIPT_DIR/lint-image-drift.sh"
    _HELPER="$(cd "$SCRIPT_DIR/../.." && pwd)/scripts/lint-readme-tokens.sh"

    if [ ! -f "$_README" ]; then
        printf 'self-test: ABORT — README.md not found at %s\n' "$_README" >&2
        exit 1
    fi
    if [ ! -f "$_HELPER" ]; then
        printf 'self-test: ABORT — lint-readme-tokens.sh helper not found at %s\n' "$_HELPER" >&2
        exit 1
    fi
    . "$_HELPER"

    lrt_set_readme "$_README"

    # (i) Pinned Nexus image ref — source: Image= line in [Container] section of
    # deploy/nexus.container.  The awk extracts the value after "Image=", strips
    # trailing whitespace.
    _nexus_image_ref="$(awk '
        /^\[/ { in_c=0 }
        /^\[Container\]/ { in_c=1; next }
        in_c && /^Image=/ { val=substr($0,7); gsub(/[[:space:]]*$/,"",val); print val; exit }
    ' "$SCRIPT_DIR/deploy/nexus.container")"
    # README anchor: the unique component-table line "pinned image: `<ref>`".
    # Extract: content of the first backtick pair after "pinned image: ".
    lrt_register "nexus-image-ref" \
        "printf '%s' \"$_nexus_image_ref\"" \
        'pinned image:' \
        's/.*pinned image: `\([^`]*\)`.*/\1/'

    # (ii) Injected-drift count — source: count of IMAGE-DRIFT injection blocks
    # in this script.  Anchored on "# --- injection " (trailing space) so the
    # distinct "# --- port-injection N" blocks of the OCI :5000 three-way port
    # arm are NOT counted — they are a separate guard category the README prose
    # does not fold into "recognized drifts".
    _script_injection_count="$(grep -c '^    # --- injection [0-9]' "$_SELF")"
    # README anchor: the unique bold-backtick phrase **`N recognized drifts`**.
    # Extract: the leading number before " recognized drifts".
    lrt_register "drift-count" \
        "printf '%s' \"$_script_injection_count\"" \
        '\*\*`[0-9][0-9]* recognized drifts`\*\*' \
        's/.*[^0-9]\([0-9][0-9]*\) recognized drifts.*/\1/'

    # (iii)–(v) Pull-through endpoint URLs — source: the wiring/ client config
    # the golden images bake.  Each value is recomputed here from its wiring file
    # (never literal-frozen), so a one-sided edit — rename a proxy repo, bump the
    # :8081 port on only one side — desyncs the README registry-table row from
    # the config and fails the self-test.  Each README anchor is the unique
    # ecosystem label at the start of its registry-table row; the extract pulls
    # the backtick-quoted host-local endpoint URL from that row.

    # (iii) npm — truth: the `registry=` line in wiring/npmrc.
    _npm_endpoint="$(grep '^registry=' "$SCRIPT_DIR/wiring/npmrc" \
        | sed 's/^registry=//; s/[[:space:]]*$//')"
    lrt_register "npm-endpoint" \
        "printf '%s' \"$_npm_endpoint\"" \
        '^\| \*\*npm\*\* \|' \
        's|.*`\(http://cache\.ds\.local:8081/repository/[^`]*\)`.*|\1|'

    # (iv) PyPI — truth: the `index-url =` line in wiring/pip.conf.
    _pypi_endpoint="$(grep '^index-url' "$SCRIPT_DIR/wiring/pip.conf" \
        | sed 's/^index-url[[:space:]]*=[[:space:]]*//; s/[[:space:]]*$//')"
    lrt_register "pypi-endpoint" \
        "printf '%s' \"$_pypi_endpoint\"" \
        '^\| \*\*PyPI\*\* \|' \
        's|.*`\(http://cache\.ds\.local:8081/repository/[^`]*\)`.*|\1|'

    # (v) Go modules — truth: the `GOPROXY=` line in wiring/go.env.
    _go_endpoint="$(grep '^GOPROXY=' "$SCRIPT_DIR/wiring/go.env" \
        | sed 's/^GOPROXY=//; s/[[:space:]]*$//')"
    lrt_register "go-endpoint" \
        "printf '%s' \"$_go_endpoint\"" \
        '^\| \*\*Go modules\*\* \|' \
        's|.*`\(http://cache\.ds\.local:8081/repository/[^`]*\)`.*|\1|'

    # -----------------------------------------------------------------------
    # (vi)–(ix) Per-row cache endpoint PORT-literal guards (readme-survey P7/P8).
    #
    # The (iii)–(v) endpoint guards above pin each npm/PyPI/Go row's WHOLE
    # endpoint URL against its wiring/ source.  This block adds a narrower,
    # per-row guard on just the PORT literal embedded in each registry-table
    # endpoint cell, reconciled against the deploy source of truth — the
    # PublishPort= lines in deploy/nexus.container.  A row's port and the
    # quadlet PublishPort= that publishes it are hand-kept in two files; a
    # one-sided bump (e.g. the README OCI row to :5001 while PublishPort stays
    # :5000, or the reverse) now fails the self-test per-row instead of slipping
    # through.  npm/PyPI/Go all front the :8081 core port; OCI fronts :5000.
    #
    # Truth ports are extracted from the quadlet's PublishPort=<host>:<ctr>
    # lines (host port == published endpoint port): 8081 (core) and 5000 (OCI).
    # Each README anchor is the unique ecosystem label at the start of its
    # registry-table row; the extract pulls the :PORT that immediately follows
    # `cache.ds.local` in that row's backtick-quoted endpoint.
    # -----------------------------------------------------------------------

    # Truth: the :8081 core-HTTP host port — the PublishPort= line whose
    # host:container pair is 8081:8081 in deploy/nexus.container.
    _core_port="$(awk '
        /^\[/ { in_c=0 }
        /^\[Container\]/ { in_c=1; next }
        in_c && /^PublishPort=8081:/ {
            n=split(substr($0,13), p, ":"); if (n>=1) { print p[1]; exit }
        }
    ' "$SCRIPT_DIR/deploy/nexus.container")"
    # Truth: the :5000 OCI connector host port — PublishPort=5000:5000.
    _oci_port="$(awk '
        /^\[/ { in_c=0 }
        /^\[Container\]/ { in_c=1; next }
        in_c && /^PublishPort=5000:/ {
            n=split(substr($0,13), p, ":"); if (n>=1) { print p[1]; exit }
        }
    ' "$SCRIPT_DIR/deploy/nexus.container")"

    # (vi) npm row port — extract the :PORT after cache.ds.local in the npm row.
    lrt_register "npm-port" \
        "printf '%s' \"$_core_port\"" \
        '^\| \*\*npm\*\* \|' \
        's|.*cache\.ds\.local:\([0-9][0-9]*\)/.*|\1|'

    # (vii) PyPI row port.
    lrt_register "pypi-port" \
        "printf '%s' \"$_core_port\"" \
        '^\| \*\*PyPI\*\* \|' \
        's|.*cache\.ds\.local:\([0-9][0-9]*\)/.*|\1|'

    # (viii) Go modules row port.
    lrt_register "go-port" \
        "printf '%s' \"$_core_port\"" \
        '^\| \*\*Go modules\*\* \|' \
        's|.*cache\.ds\.local:\([0-9][0-9]*\)/.*|\1|'

    # (ix) OCI / containers row port — anchored on the OCI label; the endpoint
    # cell is `cache.ds.local:5000` (no path component), so the extract pulls
    # the trailing :PORT inside the backtick pair.
    lrt_register "oci-port" \
        "printf '%s' \"$_oci_port\"" \
        '^\| \*\*OCI / containers\*\* \|' \
        's|.*`cache\.ds\.local:\([0-9][0-9]*\)`.*|\1|'

    # -----------------------------------------------------------------------
    # (x) OCI / containers row FULL endpoint (host+port) — source: the ACTIVE
    # (non-commented) [[registry.mirror]] location in wiring/registries.conf.
    #
    # The (iii)–(v) endpoint guards above pin each npm/PyPI/Go row's whole
    # endpoint URL against its single-line wiring/ source (registry= /
    # index-url = / GOPROXY=).  The OCI row had no such whole-endpoint guard
    # because its truth does not live on one URL line: it is the location value
    # of the docker.io [[registry.mirror]] pair in wiring/registries.conf
    # (canonical `cache.ds.local:5000`).  This arm closes that last cell.
    #
    # Truth extraction is ANCHORED to the docker.io [[registry]] block (via the
    # shared _mirror_location_for_prefix): it enters on the active (non-commented)
    # `prefix = "docker.io"` [[registry]] and captures the NEXT [[registry.mirror]]
    # location (canonical cache.ds.local:5000).  This retires the old
    # positional-first read, so an enabled ghcr.io / quay.io mirror ordered BEFORE
    # docker.io can no longer be mis-attributed to docker.io.  The README anchor
    # is the unique OCI ecosystem label; the extract pulls the backtick-quoted
    # `cache.ds.local:PORT` endpoint cell.  A one-sided edit of EITHER side — the
    # README OCI endpoint cell or the docker.io mirror location in
    # registries.conf — now fails the self-test.
    # -----------------------------------------------------------------------
    _oci_endpoint="$(_mirror_location_for_prefix "docker.io" "$SCRIPT_DIR/wiring/registries.conf")"
    lrt_register "oci-endpoint" \
        "printf '%s' \"$_oci_endpoint\"" \
        '^\| \*\*OCI / containers\*\* \|' \
        's|.*`\(cache\.ds\.local:[0-9][0-9]*\)`.*|\1|'

    # Capture lrt_check_all exit code before routing output through sed.
    _readme_out="$(mktemp)"
    _readme_rc=0
    lrt_check_all > "$_readme_out" 2>&1 || _readme_rc=$?
    sed 's/^/self-test: /' < "$_readme_out"
    rm -f "$_readme_out"
    if [ "$_readme_rc" -ne 0 ]; then
        printf 'self-test: FAIL — README token guard failed (rc=%d)\n' "$_readme_rc" >&2
        exit 1
    fi

    printf 'self-test: ALL INJECTIONS CAUGHT — lint-image-drift.sh OK\n'
    exit 0
fi

CONTAINER_FILE="$SCRIPT_DIR/deploy/nexus.container"
COMPOSE_FILE="$SCRIPT_DIR/deploy/compose.yaml"
REGISTRIES_FILE="$SCRIPT_DIR/wiring/registries.conf"
REPOS_FILE="$SCRIPT_DIR/deploy/repos.yaml"

if [ ! -f "$CONTAINER_FILE" ]; then
    printf 'lint-image-drift: ERROR: not found: %s\n' "$CONTAINER_FILE" >&2
    exit 2
fi
if [ ! -f "$COMPOSE_FILE" ]; then
    printf 'lint-image-drift: ERROR: not found: %s\n' "$COMPOSE_FILE" >&2
    exit 2
fi
if [ ! -f "$REGISTRIES_FILE" ]; then
    printf 'lint-image-drift: ERROR: not found: %s\n' "$REGISTRIES_FILE" >&2
    exit 2
fi
if [ ! -f "$REPOS_FILE" ]; then
    printf 'lint-image-drift: ERROR: not found: %s\n' "$REPOS_FILE" >&2
    exit 2
fi

# ---------------------------------------------------------------------------
# nexus.container — the [Container] section's "Image=<ref>" line.
# Only the [Container] section is considered, so a stray Image= elsewhere
# cannot be mistaken for it.
# ---------------------------------------------------------------------------
_container_image() {
    awk '
        /^\[/ { in_container = 0 }
        /^\[Container\]/ { in_container = 1; next }
        in_container && /^Image=/ {
            val = substr($0, 7)
            gsub(/^[[:space:]]*/, "", val)
            gsub(/[[:space:]]*$/, "", val)
            print val
            exit
        }
    ' "$CONTAINER_FILE"
}

# ---------------------------------------------------------------------------
# compose.yaml — the "image: <ref>" line under the services map.  We match the
# first "image:" key (the single service in this file) and strip an optional
# surrounding quote pair plus any trailing inline comment.
# ---------------------------------------------------------------------------
_compose_image() {
    awk '
        {
            line = $0
            sub(/^[[:space:]]*/, "", line)
            if (index(line, "image:") == 1) {
                val = substr(line, 7)
                # strip trailing inline comment (first unquoted #)
                gsub(/[[:space:]]+#.*/, "", val)
                # strip leading/trailing whitespace
                gsub(/^[[:space:]]*/, "", val)
                gsub(/[[:space:]]*$/, "", val)
                # strip a surrounding matched quote pair, if present
                if (val ~ /^".*"$/ || val ~ /^'\''.*'\''$/) {
                    val = substr(val, 2, length(val) - 2)
                }
                print val
                exit
            }
        }
    ' "$COMPOSE_FILE"
}

# ---------------------------------------------------------------------------
# wiring/registries.conf — the host port of the docker.io mirror, ANCHORED to
# the `prefix = "docker.io"` [[registry]] block (capture the NEXT
# [[registry.mirror]] location, canonical cache.ds.local:5000) via the shared
# _mirror_location_for_prefix — NOT positional-first.  So an enabled ghcr.io
# (:5001) / quay.io (:5002) mirror ordered BEFORE the docker.io block can no
# longer be mis-reconciled as docker.io's.  Empty output → rc=2 upstream; the
# `case *:*` guard preserves that empty→rc=2 contract even for a colon-less
# location (${loc##*:} on such a value would otherwise return the whole string).
# ---------------------------------------------------------------------------
_registries_mirror_port() {
    _rmp_loc="$(_mirror_location_for_prefix "docker.io" "$REGISTRIES_FILE")"
    case "$_rmp_loc" in *:*) printf '%s\n' "${_rmp_loc##*:}" ;; esac
}

# ---------------------------------------------------------------------------
# deploy/nexus.container — the OCI connector HOST port from the [Container]
# section's "PublishPort=<host>:5000" line.  The OCI connector is identified by
# its CONTAINER-side port (:5000, Nexus's fixed docker-proxy connector); the
# HOST port is the published endpoint that must reconcile with the mirror /
# repos.yaml.  Anchoring on the container side (not the host side) means a
# one-sided HOST-port edit (e.g. 5001:5000) is still found and reported as a
# DRIFT (rc=1), not a missing key (rc=2).  Only the [Container] section is
# considered.  (The :8081 core-HTTP PublishPort is unaffected.)
# ---------------------------------------------------------------------------
_publish_oci_port() {
    awk '
        /^\[/ { in_c=0 }
        /^\[Container\]/ { in_c=1; next }
        in_c && /^PublishPort=[0-9]+:5000([[:space:]]|$)/ {
            n=split(substr($0,13), p, ":"); if (n>=1) { print p[1]; exit }
        }
    ' "$CONTAINER_FILE"
}

# ---------------------------------------------------------------------------
# deploy/repos.yaml — the docker-proxy connector port from the ACTIVE
# (non-commented) `httpPort:` entry.  repos.yaml is a flat list of proxy-repo
# maps; the disabled-by-default ghcr-proxy (:5001) / quay-proxy (:5002) entries
# are fully commented (`# ` prefix), so skipping comment lines leaves only the
# live docker-proxy httpPort.  We read httpPort as the canonical connector port;
# a dropped key yields empty → exit 2 upstream.
# ---------------------------------------------------------------------------
_repos_connector_port() {
    awk '
        /^[[:space:]]*#/ { next }
        /^[[:space:]]*httpPort[[:space:]]*:/ {
            val=$0
            sub(/^[[:space:]]*httpPort[[:space:]]*:[[:space:]]*/, "", val)
            gsub(/[[:space:]]*$/, "", val)
            print val
            exit
        }
    ' "$REPOS_FILE"
}

# ---------------------------------------------------------------------------
# deploy/repos.yaml — the docker-proxy connector port from the ACTIVE
# (non-commented) BARE `endpoint: cache.ds.local:<port>` entry.  The OCI
# connector's endpoint is a bare host:port with no URL scheme and no trailing
# path; the npm/PyPI/Go rows instead use full `http://cache.ds.local:8081/...`
# URLs, so requiring `cache.ds.local:<port>` at end-of-value (no `/` after the
# port) selects ONLY the docker-proxy endpoint and never the :8081 rows.  This
# is a SECOND independent encoding of the connector port WITHIN repos.yaml; the
# reconcile checks it too, so a one-sided edit of EITHER httpPort OR endpoint is
# caught.  A dropped/renamed endpoint yields empty → exit 2 upstream.
# ---------------------------------------------------------------------------
_repos_endpoint_port() {
    awk '
        /^[[:space:]]*#/ { next }
        /^[[:space:]]*endpoint[[:space:]]*:[[:space:]]*cache\.ds\.local:[0-9]+[[:space:]]*$/ {
            val=$0
            sub(/^.*cache\.ds\.local:/, "", val)
            gsub(/[[:space:]]*$/, "", val)
            print val
            exit
        }
    ' "$REPOS_FILE"
}

README_FILE="$SCRIPT_DIR/README.md"
BOOTSTRAP_FILE="$SCRIPT_DIR/deploy/bootstrap.sh"

# ---------------------------------------------------------------------------
# COMMENT-TOLERANT per-upstream connector-port readers (ghcr.io / quay.io).
#
# The docker.io :5000 reconcile reads only ACTIVE (non-commented) lines, because
# docker.io is the live upstream.  The optional upstreams are the opposite case:
# their registries.conf stanza may be uncommented (ACTIVATED) while the three
# deploy files still carry their entries as commented TEMPLATES — that is the
# shipped shape, and it is exactly the window in which a one-sided port bump
# used to slip through to runtime.  So these readers strip one leading `# `
# before matching: the port literals are reconciled whether the deploy entry is
# commented or live, and activating the mirror alone is enough to arm the guard.
#
# Each reader is NAME-ANCHORED to the Nexus repo name (ghcr-proxy / quay-proxy)
# rather than to the port it is looking for, so a consistent four-file rename to
# a different port stays green while any one-sided edit fails closed.  Empty
# output always means "key not found" → rc=2 (structural) upstream, never a
# silent pass.
# ---------------------------------------------------------------------------

# deploy/repos.yaml — the named proxy entry's `httpPort:` or its bare
# `endpoint: cache.ds.local:<port>` (the two independent encodings within the
# one file, both reconciled).  `cur` tracks the entry the parser is inside,
# switched by each `- name:` line, so prose between entries can never be read as
# a key of the wrong entry.  KEY is "httpPort" or "endpoint".
# Usage: _optional_repos_field REPO_NAME KEY
_optional_repos_field() {
    awk -v want="$1" -v key="$2" '
        { line = $0; sub(/^[[:space:]]*#[[:space:]]?/, "", line) }
        line ~ /^[[:space:]]*-[[:space:]]*name[[:space:]]*:/ {
            n = line
            sub(/^[[:space:]]*-[[:space:]]*name[[:space:]]*:[[:space:]]*/, "", n)
            gsub(/[[:space:]]*$/, "", n)
            cur = n
            next
        }
        cur != want { next }
        key == "httpPort" && line ~ /^[[:space:]]*httpPort[[:space:]]*:[[:space:]]*[0-9]+[[:space:]]*$/ {
            v = line
            sub(/^[[:space:]]*httpPort[[:space:]]*:[[:space:]]*/, "", v)
            gsub(/[[:space:]]*$/, "", v)
            print v
            exit
        }
        key == "endpoint" && line ~ /^[[:space:]]*endpoint[[:space:]]*:[[:space:]]*cache\.ds\.local:[0-9]+[[:space:]]*$/ {
            v = line
            sub(/^.*cache\.ds\.local:/, "", v)
            gsub(/[[:space:]]*$/, "", v)
            print v
            exit
        }
    ' "$REPOS_FILE"
}

# deploy/nexus.container — the `PublishPort=<host>:<ctr>` pair belonging to the
# named connector, anchored to the `ds-oci-connector: <name>` marker line that
# precedes it (the quadlet has no per-port name field of its own).  Prints the
# whole `host:ctr` pair so a one-sided edit of EITHER side is a DRIFT (rc=1),
# not a missing key.  The scan STOPS at the next `ds-oci-connector:` marker, so
# a dropped PublishPort can never be back-filled from the sibling connector
# (that must stay rc=2, structural).
# Usage: _optional_publish_pair REPO_NAME
_optional_publish_pair() {
    awk -v marker="ds-oci-connector: $1" '
        {
            line = $0
            sub(/^[[:space:]]*#[[:space:]]?/, "", line)
            sub(/^[[:space:]]*/, "", line)
            sub(/[[:space:]]*$/, "", line)
        }
        !armed && line == marker { armed = 1; next }
        armed && line ~ /^ds-oci-connector:/ { exit }
        armed && line ~ /^PublishPort=[0-9]+:[0-9]+$/ {
            sub(/^PublishPort=/, "", line)
            print line
            exit
        }
    ' "$CONTAINER_FILE"
}

# deploy/bootstrap.sh — the connector port carried by the named repo's
# create_proxy invocation (`"httpPort":<port>` inside its JSON body).  Armed by
# the `create_proxy "docker/proxy" "<name>"` line and STOPPED by the next
# create_proxy, so a dropped httpPort in this block can never be back-filled
# from the following block (that must stay rc=2).
# Usage: _optional_bootstrap_port REPO_NAME
_optional_bootstrap_port() {
    awk -v want="$1" '
        {
            line = $0
            sub(/^[[:space:]]*#[[:space:]]?/, "", line)
            sub(/^[[:space:]]*/, "", line)
        }
        index(line, "create_proxy \"docker/proxy\" \"" want "\"") == 1 { armed = 1; next }
        armed && index(line, "create_proxy ") == 1 { exit }
        armed && line ~ /httpPort/ {
            v = line
            sub(/^.*httpPort[^0-9]*/, "", v)
            sub(/[^0-9].*$/, "", v)
            if (v != "") { print v; exit }
        }
    ' "$BOOTSTRAP_FILE"
}

# ---------------------------------------------------------------------------
# Per-upstream OCI guard for a disabled-by-default upstream (ghcr.io / quay.io),
# GATED on its registries.conf stanza being ACTIVE (uncommented).
# Usage: _check_optional_upstream PREFIX README_ANCHOR_ERE REPO_NAME
#
# - Commented (disabled) stanza → clean SKIP, rc/exit 0, LOUD stdout line: the
#   real tree ships these stanzas commented, so the standing gate stays green.
# - Active stanza → TWO reconciles against the mirror location anchored to that
#   upstream's [[registry]] block:
#     (a) the README endpoint cell for that upstream, and
#     (b) the SAME three-way connector-:PORT agreement docker.io :5000 already
#         enforces — repos.yaml (its `<name>` entry's httpPort AND bare
#         endpoint), nexus.container (its marker-anchored PublishPort pair), and
#         bootstrap.sh (its create_proxy httpPort).
#   rc=1 on any value drift, rc=2 structural (no following mirror / port-less
#   mirror location / README or bootstrap.sh missing / anchor count != 1 / empty
#   cell / any of the four deploy-side keys absent).
#   The activity gate tests for an UNCOMMENTED `prefix = "…"` line (NOT for a
#   non-empty mirror location — that would conflate "active but mirror missing"
#   [rc=2] with "commented" [skip]).
# ---------------------------------------------------------------------------
_check_optional_upstream() {
    if ! awk -v pfx="$1" '
        /^[[:space:]]*#/ { next }
        { s = $0; gsub(/[[:space:]]/, "", s) }
        s == ("prefix=\"" pfx "\"") { found = 1; exit }
        END { exit found ? 0 : 1 }
    ' "$REGISTRIES_FILE"; then
        printf 'lint-image-drift: OK — %s upstream disabled (commented) in registries.conf; guard skipped\n' "$1"
        return 0
    fi

    _ou_loc="$(_mirror_location_for_prefix "$1" "$REGISTRIES_FILE")"
    if [ -z "$_ou_loc" ]; then
        printf 'lint-image-drift: ERROR: active %s [[registry]] block has no following [[registry.mirror]] location in %s\n' "$1" "$REGISTRIES_FILE" >&2
        exit 2
    fi
    if [ ! -f "$README_FILE" ]; then
        printf 'lint-image-drift: ERROR: not found: %s\n' "$README_FILE" >&2
        exit 2
    fi
    _ou_cnt="$(grep -cE "$2" "$README_FILE" || true)"
    if [ "$_ou_cnt" -ne 1 ]; then
        printf 'lint-image-drift: ERROR: %s README endpoint anchor matched %s lines (expected exactly 1) in %s\n' "$1" "$_ou_cnt" "$README_FILE" >&2
        exit 2
    fi
    _ou_cell="$(grep -E "$2" "$README_FILE" | sed -n 's|.*`\(cache[.]ds[.]local:[0-9][0-9]*\)`.*|\1|p')"
    if [ -z "$_ou_cell" ]; then
        printf 'lint-image-drift: ERROR: %s README endpoint row has no `cache.ds.local:PORT` cell in %s\n' "$1" "$README_FILE" >&2
        exit 2
    fi
    if [ "$_ou_loc" != "$_ou_cell" ]; then
        printf 'lint-image-drift: MISMATCH: %s registries.conf mirror=%s  README cell=%s\n' "$1" "$_ou_loc" "$_ou_cell" >&2
        printf 'lint-image-drift: FAIL — the %s active mirror location diverged from its README endpoint cell\n' "$1" >&2
        exit 1
    fi
    printf 'lint-image-drift: OK — %s README endpoint cell matches active mirror location (%s)\n' "$1" "$_ou_loc"

    # --- three-way connector-:PORT reconcile (the docker.io :5000 discipline) ---
    # Canonical port for this upstream is the mirror location's :PORT (never a
    # frozen literal), so a deliberate four-file renumber stays green.  A
    # colon-less location is structural (rc=2), matching the `case *:*` guard the
    # docker.io reader uses.
    _ou_port=""
    case "$_ou_loc" in *:*) _ou_port="${_ou_loc##*:}" ;; esac
    if [ -z "$_ou_port" ]; then
        printf 'lint-image-drift: ERROR: active %s mirror location %s carries no :PORT in %s\n' "$1" "$_ou_loc" "$REGISTRIES_FILE" >&2
        exit 2
    fi
    if [ ! -f "$BOOTSTRAP_FILE" ]; then
        printf 'lint-image-drift: ERROR: not found: %s\n' "$BOOTSTRAP_FILE" >&2
        exit 2
    fi

    _ou_repo="$3"
    _ou_http="$(_optional_repos_field "$_ou_repo" httpPort)"
    _ou_ep="$(_optional_repos_field "$_ou_repo" endpoint)"
    _ou_pub="$(_optional_publish_pair "$_ou_repo")"
    _ou_boot="$(_optional_bootstrap_port "$_ou_repo")"

    if [ -z "$_ou_http" ]; then
        printf 'lint-image-drift: ERROR: no %s httpPort: entry (commented or live) in %s\n' "$_ou_repo" "$REPOS_FILE" >&2
        exit 2
    fi
    if [ -z "$_ou_ep" ]; then
        printf 'lint-image-drift: ERROR: no %s bare endpoint: cache.ds.local:<port> entry (commented or live) in %s\n' "$_ou_repo" "$REPOS_FILE" >&2
        exit 2
    fi
    if [ -z "$_ou_pub" ]; then
        printf 'lint-image-drift: ERROR: no PublishPort= after the `ds-oci-connector: %s` marker in %s\n' "$_ou_repo" "$CONTAINER_FILE" >&2
        exit 2
    fi
    if [ -z "$_ou_boot" ]; then
        printf 'lint-image-drift: ERROR: no httpPort in the %s create_proxy invocation in %s\n' "$_ou_repo" "$BOOTSTRAP_FILE" >&2
        exit 2
    fi

    if [ "$_ou_http" != "$_ou_port" ] || \
       [ "$_ou_ep" != "$_ou_port" ] || \
       [ "$_ou_pub" != "$_ou_port:$_ou_port" ] || \
       [ "$_ou_boot" != "$_ou_port" ]; then
        printf 'lint-image-drift: MISMATCH: %s connector port drift — registries.conf mirror=%s  repos.yaml httpPort=%s  repos.yaml endpoint=%s  nexus.container PublishPort=%s  bootstrap.sh create_proxy=%s\n' \
            "$1" "$_ou_port" "$_ou_http" "$_ou_ep" "$_ou_pub" "$_ou_boot" >&2
        printf 'lint-image-drift: FAIL — the active %s connector port diverged across the files that encode it\n' "$1" >&2
        exit 1
    fi
    printf 'lint-image-drift: OK — %s connector port agrees (registries.conf mirror / repos.yaml httpPort+endpoint / nexus.container PublishPort / bootstrap.sh create_proxy all :%s)\n' "$1" "$_ou_port"
}

CTR_IMAGE="$(_container_image)"
COMPOSE_IMAGE="$(_compose_image)"

if [ -z "$CTR_IMAGE" ]; then
    printf 'lint-image-drift: ERROR: no [Container] Image= line in %s\n' "$CONTAINER_FILE" >&2
    exit 2
fi
if [ -z "$COMPOSE_IMAGE" ]; then
    printf 'lint-image-drift: ERROR: no image: line in %s\n' "$COMPOSE_FILE" >&2
    exit 2
fi

if [ "$CTR_IMAGE" != "$COMPOSE_IMAGE" ]; then
    printf 'lint-image-drift: MISMATCH: nexus.container Image=%s  compose.yaml image:%s\n' \
        "$CTR_IMAGE" "$COMPOSE_IMAGE" >&2
    printf 'lint-image-drift: FAIL — the hand-synced Nexus image literal diverged between the two deploy paths\n' >&2
    exit 1
fi

printf 'lint-image-drift: OK — nexus.container and compose.yaml name the same Nexus image (%s)\n' "$CTR_IMAGE"

# ---------------------------------------------------------------------------
# OCI :5000 connector port — three-way reconcile across the files that each
# encode it independently (registries.conf mirror, nexus.container PublishPort,
# repos.yaml docker-proxy connector).  Fail closed (rc=2) on a missing key, and
# (rc=1) unless all three agree on the canonical port.
# ---------------------------------------------------------------------------
CANONICAL_OCI_PORT="5000"

REG_MIRROR_PORT="$(_registries_mirror_port)"
PUBLISH_OCI_PORT="$(_publish_oci_port)"
REPOS_HTTP_PORT="$(_repos_connector_port)"
REPOS_ENDPOINT_PORT="$(_repos_endpoint_port)"

if [ -z "$REG_MIRROR_PORT" ]; then
    printf 'lint-image-drift: ERROR: no active docker.io [[registry.mirror]] location port in %s\n' "$REGISTRIES_FILE" >&2
    exit 2
fi
if [ -z "$PUBLISH_OCI_PORT" ]; then
    printf 'lint-image-drift: ERROR: no [Container] PublishPort=<host>:5000 (OCI connector) line in %s\n' "$CONTAINER_FILE" >&2
    exit 2
fi
if [ -z "$REPOS_HTTP_PORT" ]; then
    printf 'lint-image-drift: ERROR: no active docker-proxy httpPort: in %s\n' "$REPOS_FILE" >&2
    exit 2
fi
if [ -z "$REPOS_ENDPOINT_PORT" ]; then
    printf 'lint-image-drift: ERROR: no active docker-proxy bare endpoint: cache.ds.local:<port> in %s\n' "$REPOS_FILE" >&2
    exit 2
fi

if [ "$REG_MIRROR_PORT" != "$CANONICAL_OCI_PORT" ] || \
   [ "$PUBLISH_OCI_PORT" != "$CANONICAL_OCI_PORT" ] || \
   [ "$REPOS_HTTP_PORT" != "$CANONICAL_OCI_PORT" ] || \
   [ "$REPOS_ENDPOINT_PORT" != "$CANONICAL_OCI_PORT" ]; then
    printf 'lint-image-drift: MISMATCH: OCI connector port drift — registries.conf mirror=%s  nexus.container PublishPort=%s  repos.yaml httpPort=%s  repos.yaml endpoint=%s  (canonical %s)\n' \
        "$REG_MIRROR_PORT" "$PUBLISH_OCI_PORT" "$REPOS_HTTP_PORT" "$REPOS_ENDPOINT_PORT" "$CANONICAL_OCI_PORT" >&2
    printf 'lint-image-drift: FAIL — the OCI :5000 connector port diverged across the files that encode it\n' >&2
    exit 1
fi

printf 'lint-image-drift: OK — OCI connector port agrees (registries.conf mirror / nexus.container PublishPort / repos.yaml httpPort+endpoint all :%s)\n' "$CANONICAL_OCI_PORT"

# ---------------------------------------------------------------------------
# Per-upstream OCI guards for the disabled-by-default upstreams (ghcr.io :5001,
# quay.io :5002).  Each is GATED on its registries.conf stanza being ACTIVE:
# while commented (the shipped default) the guard prints a clean SKIP and the
# gate stays green; once a follow-up uncomments a stanza, the guard reconciles
# that upstream's README endpoint cell against its now-active mirror location so
# doc and wiring cannot drift out of lockstep, AND holds that upstream's
# connector :PORT to the same three-way deploy-file agreement docker.io :5000
# gets (repos.yaml httpPort+endpoint / nexus.container PublishPort /
# bootstrap.sh create_proxy) — the deploy entries stay commented templates until
# the operator enables them, so the reads there are comment-tolerant.
# ---------------------------------------------------------------------------
_check_optional_upstream "ghcr.io" '^\| \*\*OCI / ghcr\.io\*\* \|' "ghcr-proxy"
_check_optional_upstream "quay.io" '^\| \*\*OCI / quay\.io\*\* \|' "quay-proxy"
