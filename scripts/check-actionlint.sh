#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# check-actionlint.sh — run actionlint(1) over the tracked GitHub-workflow YAML
# surface (.github/workflows/*.yml|*.yaml), failing closed on a real finding.
#
# WHY: repo-lints already mechanizes doc links, SPDX headers, golden byte-
# identity, NFTables grammar, shell-script lint, and vendor tracking — but it
# lints NO GitHub-workflow YAML.  The .github/workflows/ tree ships ~two dozen
# workflow files unlinted (check-nightly-workflow-shape only shape-greps ONE
# file, golden-image-nightly.yml, and only for three specific invariants), so a
# malformed step, an unknown `uses:` shape, a bad `runs-on:`, or a broken
# expression ships uncaught.  This adds the missing class: a static actionlint
# pass that fails closed on a genuine workflow finding.
#
# RUNNER-LABEL RECONCILE (tool-INDEPENDENT, always non-vacuous)
# The self-hosted runner label allowlist lives in the TRACKED .github/
# actionlint.yaml (SPDX'd), not inline here.  actionlint reads that path
# automatically when invoked inside the repo, so a bare `actionlint` run and
# this gate now agree by construction; the script passes it explicitly with
# -config-file so an absolute-glob/sandbox invocation resolves the same list.
#
# Before (and independently of) the actionlint pass, this script reconciles every
# `runs-on:` label in the discovered workflow surface against that allowlist plus
# the GitHub-hosted built-ins, and FAILS CLOSED on an unknown label.  That
# reconcile is pure grep/awk over committed text — it runs on hosts WITHOUT
# actionlint, so the "remember to extend the allowlist" maintenance note that
# used to sit inline here is now an enforced gate rather than a comment nobody
# reads.  ACTIONLINT_CONFIG overrides the config path (used by --self-test to
# prove the missing-config arm fails closed).
#
# Fail-open on a MISSING tool: actionlint is not guaranteed to be installed on
# every developer machine or CI gate host.  When the tool is absent this is a
# LOUD clean SKIP — the skip reason is printed to stderr (so it appears in CI
# logs) and the script exits 0.  This is the exact fail-open-on-missing-tool
# discipline scripts/check-shellcheck.sh / scripts/check-runbook-nft.sh already
# use ("LOUD SKIP (stderr, exit 0) when no ..."): never block work because an
# optional static-analysis tool is unavailable, but fail closed on a real
# finding when the tool IS present.
#
# DS_REQUIRE_ACTIONLINT=1: when this environment variable is set to "1", the
# actionlint-absent SKIP path becomes a FAIL instead (exit 1, loud reason on
# stderr).  This lets a CI gate leg that provisions actionlint(1) assert the
# lint is actually exercised — converting the soft skip into a hard CI-enforced
# requirement, mirroring check-shellcheck.sh's DS_REQUIRE_SHELLCHECK=1 and
# check-runbook-nft.sh's DS_REQUIRE_NFT=1 contract.  Default behaviour (unset or
# any value other than "1") is unchanged: LOUD clean SKIP with exit 0 when
# actionlint is absent.
#
# DS_ACTIONLINT_SHELLCHECK=1: OPT-IN widening of the gate to the shell embedded
# in workflow `run:` blocks.  actionlint can hand every inline `run:` script to
# the shellcheck(1) binary; that integration is disabled BY DEFAULT here (see
# the -shellcheck= rationale at the invocation below).  Setting this to "1"
# drops ONLY that suppression — `-pyflakes=` and `-config-file` are unaffected —
# so a quoting bug inside a workflow `run:` block fails the gate closed.  Default
# (unset, or any value other than "1") is byte-for-byte the pre-existing
# behaviour: the integration stays off and `make repo-lints` is unchanged.
#   * Tool-absent degradation: when the toggle is ON but no shellcheck binary is
#     resolvable, the shellcheck integration is a LOUD clean SKIP (reason on
#     stderr, exit 0) and the actionlint YAML pass still runs — the same
#     optional-tool discipline as the actionlint-absent path above.  Setting
#     DS_REQUIRE_ACTIONLINT=1 turns that skip into a hard FAIL, so a CI leg that
#     provisions shellcheck asserts the widening is actually exercised.
# DS_ACTIONLINT_SHELLCHECK_BIN: command name OR absolute path of the shellcheck
#   binary the integration should use (default "shellcheck", i.e. PATH lookup).
#   The CI gate points this at a PINNED shellcheck release binary rather than the
#   runner image's floating apt package: runner-image-dependent findings are the
#   exact drift the suppression was protecting against, so a shellcheck minor
#   bump must not be able to turn CI red with no repo change.  This mirrors the
#   pinned actionlint release binary the same gate leg provisions, and it
#   deliberately does NOT shadow the apt shellcheck that check-shellcheck.sh
#   lints the standalone *.sh surface with.
# DS_ACTIONLINT_SHELLCHECK_SEVERITY: shellcheck severity floor for the embedded
#   surface (default "error", passed through SHELLCHECK_OPTS).  The embedded
#   `run:` surface was NEVER linted before this toggle, so it enters at the same
#   additive error tier check-shellcheck.sh uses for its own newly-added
#   scripts/check-*.sh surface — catching the parse-breaking class (unbalanced
#   quotes, unterminated heredocs) without importing a wall of pre-existing
#   info/style debt into a gate that must stay green.  Ratchet it down locally
#   (e.g. =style) to see the full backlog; an inherited SHELLCHECK_OPTS wins.
#
# ACTIONLINT_GLOBS: space-separated list of globs to lint.  Defaults to
# ".github/workflows/*.yml .github/workflows/*.yaml" (repo-root-relative; the
# tree carries only *.yml today, and the empty *.yaml glob contributes nothing).
# Overridable so the surface can be extended without editing this script, and so
# the hermetic --self-test can point it at a throwaway directory (absolute globs
# are supported — see the discovery loop below).  Globs that match nothing
# contribute no files; if NO glob matches any file at all the check is a LOUD
# clean SKIP (exit 0) — an empty workflow surface is not a failure.
#
# --self-test: stands up a throwaway sandbox and retargets ACTIONLINT_GLOBS at it
# via recursive `bash "$0"` calls.  Two groups of arms:
#   (A) label-reconcile arms — ALWAYS run, on every host, because they need no
#       external tool: an allowed self-hosted label PASSES (rc=0), an UNKNOWN
#       self-hosted label FAILS (rc=1), a GitHub-hosted label passes, and an
#       absent/label-less config FAILS (rc=1).
#   (B) actionlint arms — a planted-bad workflow (a step carrying BOTH `uses:`
#       and `run:`) must FAIL (rc=1) and a clean workflow must PASS (rc=0).
#       These are a LOUD clean SKIP when actionlint is absent, so tool-less
#       hosts stay green while group (A) still asserts.
#   (C) DS_ACTIONLINT_SHELLCHECK arms — a workflow whose `run:` block carries a
#       quoting bug an ordinary shellcheck run detects (an unterminated double
#       quote) is exercised three ways against a PATH-stubbed FAKE, so the arm is
#       hermetic on hosts with no real shellcheck: toggle ON + fake present must
#       FAIL (rc=1); the SAME fixture with the toggle OFF must PASS (rc=0);
#       and toggle ON with shellcheck ABSENT from PATH must PASS (rc=0) via the
#       loud SKIP.  A fourth arm proves DS_REQUIRE_ACTIONLINT=1 converts that
#       skip into a FAIL.  Both directions are asserted, so neither the toggle
#       nor its default-off path can rot into a no-op.
#       The self-test pins the DS_ACTIONLINT_SHELLCHECK_* knobs to their default
#       posture up front and each arm re-states the ones it needs, so an
#       INHERITED value cannot change a verdict — the CI gate leg exports
#       DS_ACTIONLINT_SHELLCHECK=1 plus an ABSOLUTE _BIN path into the job env
#       before `make repo-lints` runs this self-test, and an absolute path
#       resolves regardless of PATH, which would otherwise defeat the very
#       PATH manipulation the fake-present / tool-absent arms rely on.
# Network-free; mutates only its mktemp sandbox.
#
# Requires: bash, git; actionlint (optional — drives the SKIP path when absent).
# Network-free.  Idempotent: reads only; mutates nothing outside the --self-test
# sandbox.
#
# Exit codes: 0 = every discovered `runs-on:` label is allowlisted AND actionlint
#               reported no findings over the discovered workflows; or the labels
#               reconciled and actionlint is absent with DS_REQUIRE_ACTIONLINT≠1
#               (loud skip); or no workflow matched the globs (loud skip).
#             1 = a `runs-on:` label is not in .github/actionlint.yaml (or that
#               config is missing/empty); or actionlint reported at least one
#               finding over a discovered workflow (including a shellcheck
#               finding in an embedded `run:` block when
#               DS_ACTIONLINT_SHELLCHECK=1); or actionlint is absent and
#               DS_REQUIRE_ACTIONLINT=1; or DS_ACTIONLINT_SHELLCHECK=1 requested
#               the widening, no shellcheck binary is resolvable, and
#               DS_REQUIRE_ACTIONLINT=1.

set -euo pipefail

# --- locate repo root (git-anchored; fall back to script-relative) ----------
if ROOT=$(git rev-parse --show-toplevel 2>/dev/null); then
    :
else
    ROOT=$(cd "$(dirname "$0")/.." && pwd)
fi

# Default surface: the tracked GitHub-workflow YAML.  The tree carries only
# *.yml today; the *.yaml glob is included for forward-compatibility and simply
# contributes nothing while it matches no file.  Overridable via env so the
# surface can grow (or the hermetic --self-test can retarget it) without an edit
# here.
ACTIONLINT_GLOBS="${ACTIONLINT_GLOBS:-.github/workflows/*.yml .github/workflows/*.yaml}"

# The TRACKED single-source allowlist.  Overridable so --self-test can prove the
# missing-config arm fails closed; never overridden in the production path.
ACTIONLINT_CONFIG="${ACTIONLINT_CONFIG:-${ROOT}/.github/actionlint.yaml}"

# Opt-in embedded-`run:` shell lint (OFF by default — see the header block and
# the invocation rationale at the bottom of this file).
DS_ACTIONLINT_SHELLCHECK="${DS_ACTIONLINT_SHELLCHECK:-}"
DS_ACTIONLINT_SHELLCHECK_BIN="${DS_ACTIONLINT_SHELLCHECK_BIN:-shellcheck}"
DS_ACTIONLINT_SHELLCHECK_SEVERITY="${DS_ACTIONLINT_SHELLCHECK_SEVERITY:-error}"

# --- allowlist + label reconcile (tool-independent) --------------------------

# allowlist_labels — emit one allowlisted self-hosted label per line, read from
# the `self-hosted-runner: labels:` block of ACTIONLINT_CONFIG.  Deliberately a
# focused awk over the documented, fixed-shape config (the same stdlib-only
# posture the other repo-lints YAML readers take) — not a general YAML parser.
allowlist_labels() {
    awk '
        # column-0 key: enter/leave the self-hosted-runner block
        /^[[:space:]]*#/          { next }
        /^[^[:space:]]/           { inblk = ($0 ~ /^self-hosted-runner:([[:space:]]|$)/); inlbl = 0; next }
        inblk && /^[[:space:]]*labels:[[:space:]]*$/ { inlbl = 1; next }
        inblk && inlbl && /^[[:space:]]*-[[:space:]]*/ {
            line = $0
            sub(/^[[:space:]]*-[[:space:]]*/, "", line)
            sub(/[[:space:]]*#.*$/, "", line)
            gsub(/^"|"$/, "", line)
            gsub(/[[:space:]]+$/, "", line)
            if (line != "") print line
            next
        }
        inblk && inlbl && /^[[:space:]]*[^[:space:]-]/ { inlbl = 0 }
    ' "$1"
}

# is_builtin_label LABEL — 0 when the label is a GitHub-hosted/built-in runner
# label that needs no allowlist entry.  Case-insensitive (GHA labels are).
is_builtin_label() {
    local l
    l=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
    case "$l" in
        self-hosted|linux|windows|macos|x64|x86|arm|arm32|arm64) return 0 ;;
        ubuntu-*|windows-*|macos-*) return 0 ;;
        *) return 1 ;;
    esac
}

# runs_on_labels FILE — emit one `runs-on:` label per line for a workflow file.
# Handles the two shapes this tree uses: an inline array (`runs-on: [a, b]`) and
# a bare scalar (`runs-on: ubuntu-latest`).  Comment lines never match because
# the `#` precedes `runs-on:`.  A `runs-on:` whose value is EMPTY (the
# block-sequence shape this reader does not understand) yields the sentinel
# `<unsupported-shape>` so the caller fails closed rather than silently passing.
runs_on_labels() {
    grep -E '^[[:space:]]*runs-on:' "$1" 2>/dev/null | while IFS= read -r line; do
        local val
        val=${line#*runs-on:}
        val=$(printf '%s' "$val" | sed -e 's/[[:space:]]*#.*$//' \
                                       -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' \
                                       -e 's/^\[//' -e 's/\]$//')
        if [ -z "$val" ]; then
            echo '<unsupported-shape>'
            continue
        fi
        printf '%s' "$val" | tr ',' '\n' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' \
                                               -e 's/^"//' -e 's/"$//' \
                                               -e "s/^'//" -e "s/'\$//" \
            | grep -v '^$' || true
    done
}

# reconcile_labels FILE... — fail closed (rc 1) on any `runs-on:` label that is
# neither a GitHub-hosted built-in nor present in ACTIONLINT_CONFIG's allowlist.
# Runs on EVERY host, actionlint installed or not: this is the arm that keeps the
# gate non-vacuous where the optional binary is absent.
reconcile_labels() {
    local allowed bad=0 f label
    if [ ! -f "$ACTIONLINT_CONFIG" ]; then
        echo "check-actionlint: ERROR: runner-label allowlist not found: ${ACTIONLINT_CONFIG} — the tracked .github/actionlint.yaml is the single source for the self-hosted labels; failing closed rather than linting without it" >&2
        return 1
    fi
    allowed=$(allowlist_labels "$ACTIONLINT_CONFIG")
    if [ -z "$allowed" ]; then
        echo "check-actionlint: ERROR: ${ACTIONLINT_CONFIG} declares no self-hosted-runner labels — expected a 'self-hosted-runner: labels:' list; failing closed" >&2
        return 1
    fi
    for f in "$@"; do
        while IFS= read -r label; do
            [ -n "$label" ] || continue
            if [ "$label" = '<unsupported-shape>' ]; then
                echo "check-actionlint: ERROR: ${f#"${ROOT}"/}: a 'runs-on:' uses a YAML shape this reconcile does not parse (block sequence / empty value). Rewrite it as an inline array or extend runs_on_labels(); failing closed rather than skipping the label check" >&2
                bad=1
                continue
            fi
            # An unresolvable expression (matrix/env) cannot be checked statically.
            case "$label" in *'${{'*) continue ;; esac
            is_builtin_label "$label" && continue
            if ! printf '%s\n' "$allowed" | grep -Fxq "$label"; then
                echo "check-actionlint: ERROR: ${f#"${ROOT}"/}: unknown runner label \"${label}\" — add it to ${ACTIONLINT_CONFIG#"${ROOT}"/} (self-hosted-runner.labels) or fix the runs-on; failing closed" >&2
                bad=1
            fi
        done <<EOF
$(runs_on_labels "$f")
EOF
    done
    return "$bad"
}

# --- --self-test: hermetic, non-vacuous; label arms run on EVERY host ---------
# Defined and dispatched BEFORE the production tool-absent gate so each process
# owns exactly one EXIT trap.
self_test() {
    local TMP
    TMP=$(mktemp -d)
    # shellcheck disable=SC2064  # expand TMP now: it must survive into the trap
    trap "rm -rf \"$TMP\"" EXIT
    mkdir -p "$TMP/bad" "$TMP/clean" "$TMP/label-ok" "$TMP/label-bad" "$TMP/label-hosted"

    # ---- env hygiene: pin the DS_ACTIONLINT_SHELLCHECK knobs to their DEFAULT
    # posture for every arm below, then let each group-(C) arm opt in explicitly.
    # This is load-bearing, not tidiness: the CI gate leg exports
    # DS_ACTIONLINT_SHELLCHECK=1 and DS_ACTIONLINT_SHELLCHECK_BIN=<ABSOLUTE path
    # to the pinned binary> into the job env BEFORE `make repo-lints` runs this
    # self-test.  An absolute BIN resolves no matter what PATH says, so an
    # inherited one would defeat both the PATH-stubbed FAKE (arms a/a2) and the
    # tool-ABSENT symlink farm (arms c/d) — those arms would see
    # a real shellcheck, lint the bad fixture for real, and fail the self-test in
    # exactly the posture the gate runs in.  Forcing the bare command name keeps
    # PATH the only resolution channel, which is what those arms manipulate.
    export DS_ACTIONLINT_SHELLCHECK=''
    export DS_ACTIONLINT_SHELLCHECK_BIN='shellcheck'
    export DS_ACTIONLINT_SHELLCHECK_SEVERITY='error'
    export SHELLCHECK_OPTS=''

    # ---- group (A): runner-label reconcile.  No external tool required, so
    # these assert on tool-less hosts too (the whole point of single-sourcing
    # the allowlist into a tracked config).
    cat > "$TMP/label-ok/ok.yml" <<'LOKYML'
name: label-ok
on: push
jobs:
  ok:
    runs-on: [self-hosted, debian]
    steps:
      - run: echo ok
LOKYML
    cat > "$TMP/label-bad/bad.yml" <<'LBADYML'
name: label-bad
on: push
jobs:
  bad:
    runs-on: [self-hosted, moon-base]
    steps:
      - run: echo nope
LBADYML
    cat > "$TMP/label-hosted/hosted.yml" <<'LHOSTYML'
name: label-hosted
on: push
jobs:
  hosted:
    runs-on: ubuntu-latest
    steps:
      - run: echo ok
LHOSTYML

    # UNKNOWN self-hosted label must FAIL CLOSED (rc=1).  Run FIRST: an
    # empty-match SKIP or a dead reconcile would return 0 and fail this arm, so
    # a plumbing regression is caught before any clean arm can pass falsely.
    if ACTIONLINT_GLOBS="$TMP/label-bad/*.yml" bash "$0"; then
        echo "check-actionlint: self-test FAIL: unknown runner label 'moon-base' was NOT rejected (expected rc=1)" >&2
        exit 1
    fi
    # An ALLOWLISTED self-hosted label must pass.
    if ! ACTIONLINT_GLOBS="$TMP/label-ok/*.yml" bash "$0"; then
        echo "check-actionlint: self-test FAIL: allowlisted label [self-hosted, debian] was rejected (expected rc=0)" >&2
        exit 1
    fi
    # A GitHub-hosted label needs no allowlist entry.
    if ! ACTIONLINT_GLOBS="$TMP/label-hosted/*.yml" bash "$0"; then
        echo "check-actionlint: self-test FAIL: GitHub-hosted label ubuntu-latest was rejected (expected rc=0)" >&2
        exit 1
    fi
    # A MISSING allowlist config must fail closed, never silently lint without it.
    if ACTIONLINT_CONFIG="$TMP/no-such-actionlint.yaml" \
       ACTIONLINT_GLOBS="$TMP/label-ok/*.yml" bash "$0"; then
        echo "check-actionlint: self-test FAIL: missing ${ACTIONLINT_CONFIG##*/} did not fail closed (expected rc=1)" >&2
        exit 1
    fi
    # A config with no labels at all must fail closed too.
    printf 'self-hosted-runner:\n  labels:\n' > "$TMP/empty-config.yaml"
    if ACTIONLINT_CONFIG="$TMP/empty-config.yaml" \
       ACTIONLINT_GLOBS="$TMP/label-ok/*.yml" bash "$0"; then
        echo "check-actionlint: self-test FAIL: label-less config did not fail closed (expected rc=1)" >&2
        exit 1
    fi
    echo "check-actionlint: self-test OK (runner-label allowlist arms)"

    # ---- group (B): the actionlint pass itself.  LOUD clean SKIP when the
    # optional binary is absent; DS_REQUIRE_ACTIONLINT=1 turns that into a FAIL.
    if ! command -v actionlint >/dev/null 2>&1; then
        if [ "${DS_REQUIRE_ACTIONLINT:-}" = "1" ]; then
            echo "check-actionlint: ERROR: actionlint(1) not found on PATH and DS_REQUIRE_ACTIONLINT=1 — the actionlint --self-test arms cannot run and are failing closed (install actionlint on this gate host)" >&2
            exit 1
        fi
        echo "check-actionlint: SKIP — actionlint(1) not found on PATH; the actionlint --self-test arms are SKIPPED on this host (the runner-label arms above still ran; install actionlint to exercise the rest, or set DS_REQUIRE_ACTIONLINT=1 to turn this skip into a failure)" >&2
        exit 0
    fi

    # Planted-bad workflow: a single step carrying BOTH `uses:` and `run:` — a
    # deterministic, version-stable actionlint error ("this step is for running
    # action ... but ... run" / both uses and run).
    cat > "$TMP/bad/bad.yml" <<'BADYML'
name: bad
on: push
jobs:
  bad:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        run: echo both
BADYML

    # Clean workflow: valid, minimal, must pass.
    cat > "$TMP/clean/ok.yml" <<'OKYML'
name: ok
on: push
jobs:
  ok:
    runs-on: ubuntu-latest
    steps:
      - run: echo ok
OKYML

    # Run the BAD arm FIRST.  It proves the absolute-glob plumbing is live: an
    # empty-match SKIP would return 0 and correctly FAIL this arm, so a plumbing
    # regression is caught non-vacuously before the clean arm can pass falsely.
    # Expected: rc=1 from the recursion (safe under set -e inside the `if`).
    if ACTIONLINT_GLOBS="$TMP/bad/*.yml" bash "$0"; then
        echo "check-actionlint: self-test FAIL: planted-bad workflow was NOT flagged (expected rc=1)" >&2
        exit 1
    fi

    # Clean arm: expected rc=0.
    if ! ACTIONLINT_GLOBS="$TMP/clean/*.yml" bash "$0"; then
        echo "check-actionlint: self-test FAIL: clean fixture failed (expected rc=0)" >&2
        exit 1
    fi

    # ---- group (C): the DS_ACTIONLINT_SHELLCHECK widening.  Hermetic: the
    # linter side is a PATH-stubbed FAKE, so these arms assert identically on a
    # host with no real shellcheck and can never reach the network.
    mkdir -p "$TMP/scbin" "$TMP/quote-bug" "$TMP/quote-clean"

    # FAKE shellcheck.  actionlint invokes it as
    #   <bin> --norc -f json -x --shell bash -e <codes> -
    # with the embedded `run:` script on stdin, and parses the JSON array on
    # stdout.  This stub implements a deliberately crude but REAL quoting-bug
    # detector — an odd number of double quotes — so the bad and clean fixtures
    # are distinguished by their content, not by a magic marker: a stub that
    # always reported a finding would make the clean arm vacuous.  It emits an
    # `error`-level finding so the arm exercises the production severity floor.
    cat > "$TMP/scbin/shellcheck" <<'FAKESC'
#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# FAKE shellcheck for check-actionlint.sh --self-test.  Not a linter: it reports
# one error-level finding when the script on stdin has unbalanced double quotes.
set -u
src=$(cat)
q=$(printf '%s' "$src" | tr -cd '"' | wc -c | tr -d '[:space:]')
if [ $((q % 2)) -ne 0 ]; then
    printf '%s\n' '[{"file":"-","line":1,"endLine":1,"column":1,"endColumn":2,"level":"error","code":1073,"message":"FAKE-SHELLCHECK: unbalanced double quote in this run: block","fix":null}]'
    exit 1
fi
printf '%s\n' '[]'
exit 0
FAKESC
    chmod +x "$TMP/scbin/shellcheck"

    cat > "$TMP/quote-bug/qbug.yml" <<'QBUGYML'
name: quote-bug
on: push
jobs:
  q:
    runs-on: ubuntu-latest
    steps:
      - name: unterminated double quote inside an embedded run block
        run: |
          MSG="oops
          echo "$MSG"
QBUGYML
    cat > "$TMP/quote-clean/qok.yml" <<'QOKYML'
name: quote-clean
on: push
jobs:
  q:
    runs-on: ubuntu-latest
    steps:
      - name: correctly quoted embedded run block
        run: |
          MSG="ok"
          echo "$MSG"
QOKYML

    # (a) toggle ON + fake shellcheck on PATH: the quoting bug must FAIL CLOSED.
    # Run FIRST — a dead toggle would return 0 here, so the widening cannot rot
    # into a no-op unnoticed.
    if PATH="$TMP/scbin:$PATH" DS_ACTIONLINT_SHELLCHECK=1 DS_ACTIONLINT_SHELLCHECK_BIN=shellcheck \
       DS_REQUIRE_ACTIONLINT='' \
       ACTIONLINT_GLOBS="$TMP/quote-bug/*.yml" bash "$0"; then
        echo "check-actionlint: self-test FAIL: DS_ACTIONLINT_SHELLCHECK=1 did NOT flag the quoting bug in the embedded run: block (expected rc=1)" >&2
        exit 1
    fi

    # (a2) same posture, correctly quoted fixture: must PASS.  Without this the
    # stub could be a blanket failer and arm (a) would prove nothing.
    if ! PATH="$TMP/scbin:$PATH" DS_ACTIONLINT_SHELLCHECK=1 DS_ACTIONLINT_SHELLCHECK_BIN=shellcheck \
         DS_REQUIRE_ACTIONLINT='' \
         ACTIONLINT_GLOBS="$TMP/quote-clean/*.yml" bash "$0"; then
        echo "check-actionlint: self-test FAIL: DS_ACTIONLINT_SHELLCHECK=1 rejected a correctly quoted run: block (expected rc=0)" >&2
        exit 1
    fi

    # (b) the SAME bad fixture with the toggle OFF must PASS — the default path
    # is unchanged even when a shellcheck binary is sitting on PATH.
    if ! PATH="$TMP/scbin:$PATH" DS_ACTIONLINT_SHELLCHECK='' DS_ACTIONLINT_SHELLCHECK_BIN=shellcheck \
         DS_REQUIRE_ACTIONLINT='' \
         ACTIONLINT_GLOBS="$TMP/quote-bug/*.yml" bash "$0"; then
        echo "check-actionlint: self-test FAIL: the quoting-bug fixture failed with DS_ACTIONLINT_SHELLCHECK unset — the default path must be unaffected by a shellcheck on PATH (expected rc=0)" >&2
        exit 1
    fi

    # (c)/(d) tool-ABSENT posture.  shellcheck cannot be hidden by shadowing, so
    # build a symlink farm of every executable on PATH EXCEPT shellcheck; keep
    # actionlint reachable (on many hosts it lives in the same directory) so the
    # arms fail for the right reason.
    build_shellcheck_free_path() {
        local dest="$1" d e n
        mkdir -p "$dest"
        while IFS= read -r d; do
            [ -n "$d" ] || continue
            [ -d "$d" ] || continue
            for e in "$d"/*; do
                [ -f "$e" ] || continue
                [ -x "$e" ] || continue
                n=${e##*/}
                if [ "$n" = shellcheck ]; then continue; fi
                [ -e "$dest/$n" ] || ln -s "$e" "$dest/$n" 2>/dev/null || true
            done
        done < <(printf '%s\n' "$PATH" | tr ':' '\n')
    }
    build_shellcheck_free_path "$TMP/nosc"
    if PATH="$TMP/nosc" command -v actionlint >/dev/null 2>&1 \
       && ! PATH="$TMP/nosc" command -v shellcheck >/dev/null 2>&1; then
        # (c) toggle ON, shellcheck absent: LOUD clean SKIP, exit 0.
        if ! PATH="$TMP/nosc" DS_ACTIONLINT_SHELLCHECK=1 DS_ACTIONLINT_SHELLCHECK_BIN=shellcheck \
             DS_REQUIRE_ACTIONLINT='' \
             ACTIONLINT_GLOBS="$TMP/quote-bug/*.yml" bash "$0" 2>"$TMP/nosc.err"; then
            echo "check-actionlint: self-test FAIL: DS_ACTIONLINT_SHELLCHECK=1 with shellcheck ABSENT did not degrade to a clean SKIP (expected rc=0); stderr follows" >&2
            cat "$TMP/nosc.err" >&2
            exit 1
        fi
        if ! grep -q 'SKIP (shellcheck integration)' "$TMP/nosc.err"; then
            echo "check-actionlint: self-test FAIL: the shellcheck-absent degradation was SILENT — expected a loud 'SKIP (shellcheck integration)' reason on stderr" >&2
            exit 1
        fi
        # (d) DS_REQUIRE_ACTIONLINT=1 turns that skip into a hard FAIL, so a CI
        # leg that provisions shellcheck can never widen vacuously.
        if PATH="$TMP/nosc" DS_ACTIONLINT_SHELLCHECK=1 DS_ACTIONLINT_SHELLCHECK_BIN=shellcheck \
           DS_REQUIRE_ACTIONLINT=1 \
           ACTIONLINT_GLOBS="$TMP/quote-clean/*.yml" bash "$0"; then
            echo "check-actionlint: self-test FAIL: DS_ACTIONLINT_SHELLCHECK=1 + DS_REQUIRE_ACTIONLINT=1 with shellcheck absent did not fail closed (expected rc=1)" >&2
            exit 1
        fi
    else
        echo "check-actionlint: SKIP — could not build a shellcheck-free PATH that still resolves actionlint; the DS_ACTIONLINT_SHELLCHECK tool-absent arms (c)/(d) were not run on this host (arms (a)/(a2)/(b) above still asserted)" >&2
    fi
    echo "check-actionlint: self-test OK (DS_ACTIONLINT_SHELLCHECK arms)"

    echo "check-actionlint: self-test OK"
    exit 0
}

if [ "${1:-}" = "--self-test" ]; then
    self_test
fi

# --- discover the workflows to lint -----------------------------------------
# Iterate the configured globs from the repo root.  Each glob is word-split
# deliberately (the env var holds a list of globs); the inner expansion is
# guarded so a glob that matches nothing contributes no phantom path.  Absolute
# globs (the --self-test sandbox retarget) are expanded as-is; relative globs
# are anchored at the repo root — check-shellcheck's "${ROOT}"/${glob} idiom
# silently mangles an absolute path, so the leading-slash arm is required.
FILES=()
for glob in $ACTIONLINT_GLOBS; do
    case "$glob" in
        /*) candidates=( ${glob} ) ;;
        *)  candidates=( "${ROOT}"/${glob} ) ;;
    esac
    for f in "${candidates[@]}"; do
        # When a glob matches nothing the literal pattern survives expansion;
        # skip any path that does not resolve to an existing file.
        [ -f "$f" ] || continue
        FILES+=("$f")
    done
done

if [ "${#FILES[@]}" -eq 0 ]; then
    echo "check-actionlint: SKIP — no workflow files matched [${ACTIONLINT_GLOBS}]; nothing to lint on this tree" >&2
    exit 0
fi

for f in "${FILES[@]}"; do
    echo "check-actionlint:   ${f#"${ROOT}"/}"
done

# --- runner-label reconcile against the TRACKED allowlist (always runs) ------
# Deliberately BEFORE the actionlint tool gate: this arm is pure text parsing, so
# it keeps the gate non-vacuous on hosts where the optional binary is absent —
# the case that would otherwise let an unknown self-hosted runner label ship
# unchecked.  Fails closed naming the file and the label.
if ! reconcile_labels "${FILES[@]}"; then
    echo "check-actionlint: ERROR: runner-label reconcile failed against ${ACTIONLINT_CONFIG#"${ROOT}"/} — failing closed" >&2
    exit 1
fi
echo "check-actionlint: OK — every discovered runs-on label is allowlisted in ${ACTIONLINT_CONFIG#"${ROOT}"/} (or a GitHub-hosted built-in)"

# --- LOUD SKIP (or FAIL when DS_REQUIRE_ACTIONLINT=1) when actionlint absent --
# NOTE: if no CI gate host has actionlint installed, the actionlint pass is
# skipped fleet-wide and the GitHub-workflow YAML surface goes unlinted (the
# runner-label reconcile above still runs everywhere).  Install the actionlint
# binary in at least one gate runner image to enforce the lint; set
# DS_REQUIRE_ACTIONLINT=1 on that gate leg to turn the skip into a hard failure
# so a provisioning regression is caught loudly.
if ! command -v actionlint >/dev/null 2>&1; then
    if [ "${DS_REQUIRE_ACTIONLINT:-}" = "1" ]; then
        echo "check-actionlint: ERROR: actionlint(1) not found on PATH and DS_REQUIRE_ACTIONLINT=1 — failing closed (install the actionlint binary on this gate host)" >&2
        exit 1
    fi
    echo "check-actionlint: SKIP — actionlint(1) not found on PATH; GitHub-workflow YAML lint is SKIPPED on this host (install actionlint to enforce the lint, or set DS_REQUIRE_ACTIONLINT=1 to turn this skip into a failure)" >&2
    exit 0
fi

echo "check-actionlint: linting ${#FILES[@]} workflow file(s) with $(actionlint -version | head -n1)"

# --- external-checker integrations: OFF by default, opt-in for shellcheck ----
# actionlint's external checkers are DISABLED by passing an EMPTY value
# (-shellcheck= / -pyflakes=).  They have to be explicit: when shellcheck or
# pyflakes merely happen to be on PATH, actionlint transparently lints every
# embedded `run:`/inline-python block, so the gate's verdict would depend on
# which optional tools the host image ships — a wall of findings on tool-equipped
# hosts and a silent pass elsewhere, i.e. local-green/CI-red drift by runner
# image.  The fix for that is NOT to leave the embedded shell unlinted forever
# (check-shellcheck.sh only covers standalone *.sh files, so `run:` blocks are a
# real gap) but to make the widening EXPLICIT and version-stable:
#
#   DS_ACTIONLINT_SHELLCHECK=1  drops ONLY the -shellcheck= suppression, so
#     actionlint hands each embedded `run:` script to shellcheck.  Default
#     (unset) keeps the byte-for-byte pre-existing behaviour, so `make
#     repo-lints` on a developer box is unchanged whether or not shellcheck
#     happens to be installed.
#   DS_ACTIONLINT_SHELLCHECK_BIN  names the binary (default: PATH `shellcheck`).
#     The CI gate leg points it at a PINNED shellcheck release binary — the
#     drift the suppression guarded against is precisely a floating tool
#     version, so reusing the runner's apt package would reintroduce it.
#   DS_ACTIONLINT_SHELLCHECK_SEVERITY  (default "error") is the additive entry
#     tier for a surface that was never linted before, mirroring the
#     --severity=error tier check-shellcheck.sh applies to its own newly-added
#     scripts/check-*.sh surface.
#
# -pyflakes= stays suppressed unconditionally (no inline-python surface has been
# triaged), and -config-file is passed on every path.
SHELLCHECK_FLAG='-shellcheck='
if [ "$DS_ACTIONLINT_SHELLCHECK" = "1" ]; then
    if SHELLCHECK_RESOLVED=$(command -v "$DS_ACTIONLINT_SHELLCHECK_BIN" 2>/dev/null); then
        SHELLCHECK_FLAG="-shellcheck=${SHELLCHECK_RESOLVED}"
        # The linter honours SHELLCHECK_OPTS for args actionlint does not pass
        # through; an inherited value is appended LAST so a caller can override
        # the severity floor without editing this script.
        export SHELLCHECK_OPTS="--severity=${DS_ACTIONLINT_SHELLCHECK_SEVERITY}${SHELLCHECK_OPTS:+ ${SHELLCHECK_OPTS}}"
        echo "check-actionlint: DS_ACTIONLINT_SHELLCHECK=1 — also linting embedded run: blocks with ${SHELLCHECK_RESOLVED} (--severity=${DS_ACTIONLINT_SHELLCHECK_SEVERITY})"
    elif [ "${DS_REQUIRE_ACTIONLINT:-}" = "1" ]; then
        echo "check-actionlint: ERROR: DS_ACTIONLINT_SHELLCHECK=1 requested the embedded run:-block shell lint but '${DS_ACTIONLINT_SHELLCHECK_BIN}' is not resolvable, and DS_REQUIRE_ACTIONLINT=1 — failing closed rather than skipping the widening vacuously (provision shellcheck on this gate host, or point DS_ACTIONLINT_SHELLCHECK_BIN at the binary)" >&2
        exit 1
    else
        echo "check-actionlint: SKIP (shellcheck integration) — DS_ACTIONLINT_SHELLCHECK=1 but '${DS_ACTIONLINT_SHELLCHECK_BIN}' was not found; embedded run: blocks are NOT shell-linted on this host. The actionlint YAML pass below still runs. Install shellcheck, point DS_ACTIONLINT_SHELLCHECK_BIN at it, or set DS_REQUIRE_ACTIONLINT=1 to turn this skip into a failure." >&2
    fi
fi

# --- run actionlint; fail closed on any finding -----------------------------
# ONE invocation over all discovered workflows so a multi-file diff surfaces
# every finding at once.  -config-file points at the TRACKED
# .github/actionlint.yaml — the same file a bare `actionlint` run picks up
# automatically — so the gate and a direct invocation can never disagree about
# the self-hosted label allowlist.
if actionlint -config-file "$ACTIONLINT_CONFIG" "$SHELLCHECK_FLAG" -pyflakes= "${FILES[@]}"; then
    echo "check-actionlint: OK — actionlint reported no findings"
    exit 0
else
    echo "check-actionlint: ERROR: actionlint reported findings over the GitHub-workflow YAML surface (see output above) — failing closed" >&2
    exit 1
fi
