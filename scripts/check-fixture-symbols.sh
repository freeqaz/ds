#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# check-fixture-symbols.sh — D50 synthetic-only fixture gate (ARCHIVE level).
#
# WHAT THIS GUARDS (and how it differs from check-fixture-provenance.sh). The
# provenance gate is a CONTENT-LEVEL git-side check over fixtures/ cassettes
# ("if it is in git, it is synthetic"). This is its ARCHIVE-LEVEL twin: it
# compiles a package's PRODUCTION archive (no _test.go), nm-sweeps the symbol
# table, and FAILS CLOSED if a TEST-ONLY synthetic stand-in (an in-process
# service fake / fault-injection consumer / ordering-journal harness) leaked
# into the shipped binary by living in a production .go file instead of a
# *_fixtures_test.go file.
#
# WHY IT EXISTS. The orchestrator internal/sessions package drives the FROZEN
# proto seams against in-process synthetic stand-ins (D50: no live VM / host
# agent / claude). Those stand-ins (e.g. an in-process DigestFeedService
# consumer with publishErr/dropEntries/revokeErr fault knobs + its shared
# ordering journal) belong ONLY in *_test.go and must NEVER compile into the
# production archive. A one-off `go tool nm` proof first surfaced such a leak;
# this turns that proof into a STANDING gate so a future edit that drops a fresh
# fake into hostredeploy.go / createspine.go / hosthandoff.go (rather than into
# the paired *_fixtures_test.go) is caught named, in CI, on the cleaned tree.
#
# SCOPE (AUTO-DISCOVERED per-MODULE map + suffix widening). The sessions package
# is no longer the only one driving frozen seams against in-process stand-ins —
# the host-agent leg (internal/hostagent), the level-triggered reconciler
# (internal/reconciler), and the control-plane wiring (internal/controlplane)
# all do too, AND the leak class is not confined to the orchestrator module:
# the client adapter (client/wrapper/adapters/claude-code drives the FROZEN
# Claude Code wire shapes against synthetic fixtures, D50), the vm guest legs
# (vm/entrypoint, vm/attachfwd, vm/cow), the identity grant-service (drives the
# FROZEN doc-16 §5.1/§5.4 grant seam against an in-process backend; D39/D52/D55/
# D83), and the assurance conformance adapters (each drives a FROZEN seam) carry
# the same exposure — a test-only fake/harness/recorder/sink dropped into one of
# THEIR production .go files would leak into THEIR shipped archive and the
# orchestrator-only sweep would never see it. A HAND-MAINTAINED package list is a
# standing liability: a fixture leak in a module/package nobody remembered to add
# is invisible. So the gate now DISCOVERS its scan map fail-closed-by-default
# (D47 spirit): it enumerates every `go.work` module root (`go work edit -json`),
# `go list ./...`s each, and sweeps the lot, MINUS an explicit SKIP-LIST for the
# two trees where a denylist-shaped symbol is legitimate-by-construction — the
# GENERATED `proto/gen/go` (exempt) and the contract-harness FAKE-PUBLISHER
# subtrees (`seams/*`, `fakegen`, `cmd/fakegen`), where "fakes ship with their
# contract, published by the seam owner" means a production `FakeDialer` is the
# job, not a leak. So a NEW module/package is covered the moment it lands, with
# no edit here, while the published-fake homes stay quiet. The hand-maintained
# DEFAULT_SCAN_MAP is retained as the fallback when discovery is unavailable
# (no go.work / no toolchain) or explicitly disabled, and now also names the
# orchestrator four + client adapter + three vm legs + identity grant-service +
# the grant-fetch conformance adapter. A test-only fake/harness/recorder/sink
# that leaks into ANY swept production archive, or that is named OUTSIDE the
# original fake/mock/stub/journal vocabulary (an ordering-journal `…Recorder`,
# a driver scaffold `…Harness`, an in-process consumer `…Sink`), slips the
# original tripwire. So the sweep covers all of them and
# FIXTURE_SYMBOL_RE adds the
# `…Recorder`/`…Harness`/`…Sink` suffix family — WITHOUT flagging the genuine
# PRODUCTION symbols that legitimately carry those suffixes (the segRecorder /
# ParkRecorderStore stores, the *FastStarter.Recorder accessor, the
# MintExpirySink / mintExpiryRearmSink mint-expiry rearm seams, the DriveSink /
# *SubTokenSink writer-relay+sub-token wire surfaces). Those production names
# are excluded by a SECOND-STAGE allowlist (FIXTURE_SYMBOL_ALLOW_RE): a denylist
# hit that ALSO matches the allowlist is production, not a leak. A false
# positive on a production synthetic is a FAIL, so the allowlist is load-bearing
# — the --self-test still plants a real leak and proves the gate flags it.
#
# THE CHECK. For each `<module-dir>|<package>` entry in SYMBOL_SCAN_MAP (default:
# the four orchestrator packages + the client claude-code adapter + the three vm
# legs), build that package's PRODUCTION archive via `go list -export` run from
# its own module root (this excludes every _test.go by construction) and `go tool
# nm` it. Any defined
# text/data symbol whose package-qualified name matches the FIXTURE-STAND-IN
# denylist regex (FIXTURE_SYMBOL_RE) AND does NOT match the production allowlist
# (FIXTURE_SYMBOL_ALLOW_RE) is a LEAK and fails the gate, naming the offending
# symbol. The denylist names the synthetic-stand-in vocabulary (fake / mock /
# stub / the in-process consumer + ordering-journal harness types + the
# `…Recorder`/`…Harness`/`…Sink` suffix family) WITHOUT matching the genuine
# PRODUCTION synthetic-entry stampers the controller legitimately uses on the
# wire (synthEntriesForVariant / synthAlgo / synthCredClassFor / the
# synthLiveSession live-session model) — those are production code
# (hostredeploy.go depends on them) and are explicitly NOT fixtures. The
# allowlist carries the production `…Recorder`/`…Sink` names the broadened suffix
# rule would otherwise sweep. The regex therefore targets the FAKE/HARNESS
# shapes, never the `synth*` entry-stamping family nor the production
# recorder/sink seams.
#
# POSIX sh. Exits 0 iff every scanned package's production archive is free of
# fixture-stand-in symbols; non-zero (and prints the offenders) on any leak.
#
# Env hooks (precedence: SYMBOL_SCAN_PKGS > SYMBOL_SCAN_MAP > auto-discovery >
# DEFAULT_SCAN_MAP fallback):
#   FIXTURE_SYMBOL_AUTODISCOVER — "1" (default) auto-DISCOVERS the scan map from
#                            the go.work module roots (see below); "0" disables
#                            discovery and uses DEFAULT_SCAN_MAP verbatim. Ignored
#                            when SYMBOL_SCAN_MAP or SYMBOL_SCAN_PKGS is set
#                            (an explicit override always wins).
#   SYMBOL_SCAN_SKIP_RE    — ERE matched against each DISCOVERED `<module-dir>|
#                            <package>` entry; a match drops the entry. Default
#                            skips the GENERATED proto module (proto/gen/go) and
#                            the contract-harness FAKE-PUBLISHER subtrees
#                            (seams/*, fakegen, cmd/fakegen), where a production
#                            fake symbol is legitimate by construction. Only the
#                            discovered set is filtered — an explicit
#                            SYMBOL_SCAN_MAP / SYMBOL_SCAN_PKGS is swept as-given.
#                            Overridable; the self-test sets it to prove the
#                            skip-list keeps a planted-fake skipped tree quiet.
#   SYMBOL_SCAN_MAP        — newline/space-separated `<module-dir>|<package>`
#                            entries to sweep. <module-dir> is resolved relative
#                            to the repo root (located from this script's path),
#                            so the gate runs from any cwd (CI or a manual run);
#                            an absolute <module-dir> is honored as-is. When set,
#                            it OVERRIDES auto-discovery and is swept verbatim.
#                            Default (discovery off / unavailable): the four
#                            orchestrator packages + the client claude-code
#                            adapter + vm/entrypoint, vm/attachfwd, vm/cow +
#                            identity/grant-service + the grant-fetch conformance
#                            adapter. Overridable.
#   SYMBOL_SCAN_PKGS       — BACKWARD-COMPAT: if set, the space-separated `go
#                            list` package patterns it names are swept against
#                            ORCH_MOD_DIR (the legacy single-module form), and
#                            both SYMBOL_SCAN_MAP and auto-discovery are IGNORED.
#                            Lets the original single-module override (and the
#                            self-test) keep working unchanged.
#   ORCH_MOD_DIR           — module dir paired with SYMBOL_SCAN_PKGS in the
#                            backward-compat path (default: <repo>/orchestrator).
#   FIXTURE_SYMBOL_RE      — ERE matched (case-insensitively) against each
#                            package-qualified symbol name; a match is a candidate
#                            leak. Overridable so the self-test can plant a token.
#   FIXTURE_SYMBOL_ALLOW_RE — ERE matched (case-insensitively) against a denylist
#                            hit; a match RESCUES it as a production symbol (so a
#                            genuine `…Recorder`/`…Sink` the suffix rule would
#                            otherwise sweep is not a leak). Overridable; the
#                            self-test sets it empty so a planted leak is caught.
#   GO                     — go binary (default: `go`).
#
# --self-test: prove the gate is NOT vacuous. It builds a throwaway module with
# packages — a CLEAN one (a production fake confined to a _fixtures_test.go,
# which must PASS) and a LEAKY one (the identical fake declared in a production
# .go file, which must FAIL) — and asserts the gate's verdict on each, then
# proves the AUTO-DISCOVERY arm directly: discover_scan_map over a throwaway
# go.work yields the planted-fake package only when it is NOT skip-listed, and
# the full normal-operation sweep over that discovered map FAILS named (file:line
# of the leak) while a planted-fake package whose path matches SYMBOL_SCAN_SKIP_RE
# stays quiet (the skip-list exemptions behave). Lives in the script (house
# precedent: check-fixture-provenance.sh / proto-gates.sh ship their own negative
# self-tests) so a local run gets the same proof CI does.

set -eu

# --- the fixture-stand-in denylist (ERE, matched case-insensitively) --------
# Names that denote a TEST-ONLY synthetic stand-in. Two families:
#   (1) the explicit fake/mock/stub/journal vocabulary (the original tripwire), and
#   (2) the suffix family `…Recorder`/`…Harness`/`…Sink` — the shapes a test-only
#       ordering recorder / driver-scaffold harness / in-process consumer sink
#       takes when it is named outside vocabulary (1). The suffix alternative
#       matches a type-name segment ending in one of those suffixes followed by a
#       symbol separator ([._)]) or end-of-string — so it catches both the bare
#       `type:…pkg.captureSink` form and the method form `…pkg.(*journalRecorder).record`.
# Deliberately PAIRED with FIXTURE_SYMBOL_ALLOW_RE below, which rescues the
# genuine PRODUCTION symbols that carry suffix (2) (segRecorder / ParkRecorderStore
# / MintExpirySink / *SubTokenSink / DriveSink / *RearmSink) and the production
# `synth*` entry-stamping family (synthEntriesForVariant / synthAlgo /
# synthCredClassFor / synthLiveSession) — genuine wire-shaping code, NOT fixtures.
# A leaked fake/consumer/journal/harness/recorder/sink symbol that survives the
# allowlist is the leak this gate fails on.
DEFAULT_FIXTURE_SYMBOL_RE='(^|[._])(fake|mock|stub)[A-Za-z0-9_]*|hostConsumer|handoffJournal|handoffEvent|inProcessFake|fixtureOnly|leakedFixture|[A-Za-z0-9_]*(Recorder|Harness|Sink)([._)]|$)'
FIXTURE_SYMBOL_RE=${FIXTURE_SYMBOL_RE:-$DEFAULT_FIXTURE_SYMBOL_RE}

# --- the production-symbol allowlist (ERE, matched case-insensitively) -------
# A denylist hit that ALSO matches this is a genuine PRODUCTION symbol, NOT a
# fixture leak — it is rescued (subtracted from the hit set) before the gate
# fails. It names exactly the production families that legitimately carry a
# `…Recorder`/`…Harness`/`…Sink` suffix (or the `synth*` prefix), enumerated from
# the four scanned packages' production archives:
#   synth*              — the §-wire synthetic-entry stampers (synthEntriesForVariant
#                         / synthAlgo / synthCredClassFor / synthLiveSession).
#   segRecorder         — the sessions step-9 routable-segment recorder (store).
#   FastStarter.Recorder — the sessions fast-start Recorder accessor (a method, not a fake).
#   ParkRecorderStore   — the controlplane D46 park-recorder store seam.
#   MintExpirySink / nopMintExpirySink — the sessions mint-expiry OnMintExpiry sink + its no-op.
#   RearmSink           — the reconciler/controlplane mint-expiry REARM sink
#                         (mintExpiryRearmSink / errNilRearmSink — D72 mintexpiry_rearm).
#   SubTokenSink        — the controlplane D18 sub-token write sinks
#                         (subTokenSink / fileSubTokenSink / memSubTokenSink).
#   DriveSink           — the controlplane W3 attach DriveSink wire surface.
# These are production code the controller depends on, so a match here is NEVER a
# leak. The self-test sets this EMPTY so a deliberately-planted leak is still caught.
DEFAULT_FIXTURE_SYMBOL_ALLOW_RE='synth|segRecorder|FastStarter|ParkRecorderStore|MintExpirySink|RearmSink|SubTokenSink|DriveSink'
FIXTURE_SYMBOL_ALLOW_RE=${FIXTURE_SYMBOL_ALLOW_RE-$DEFAULT_FIXTURE_SYMBOL_ALLOW_RE}

# --- the CONSERVATIVE denylist for AUTO-DISCOVERED packages -----------------
# The widened `…Recorder`/`…Harness`/`…Sink` SUFFIX family (above) is only safe
# against a per-package CURATED allowlist that enumerates every production
# recorder/sink/harness in the swept package (the metering.Sink, policylog
# AskEventSink/FleetDigestSink, createtiming.Recorder, askhold.ParkRecorder,
# tui.WriterSink, netflowadapter.NewSink, tlsproxy* CapturingEventSink … the
# real tree is FULL of legitimate production `…Sink`/`…Recorder` seams). Applying
# the suffix rule to every AUTO-DISCOVERED package would false-positive on all of
# them, and a repo-wide suffix allowlist is exactly the hand-maintained burden
# auto-discovery exists to remove. So discovered packages are swept with the
# CONSERVATIVE denylist ONLY — the unambiguous fake/mock/stub + named-harness
# vocabulary, which is unambiguously test-only and (verified) clean across the
# whole tree save one DOCUMENTED production fake (below) — and WITHOUT the suffix
# rule or the drift guard. The curated map keeps the full denylist + drift guard.
DEFAULT_FIXTURE_SYMBOL_DISCOVER_RE='(^|[._])(fake|mock|stub)[A-Za-z0-9_]*|hostConsumer|handoffJournal|handoffEvent|inProcessFake|fixtureOnly|leakedFixture'
FIXTURE_SYMBOL_DISCOVER_RE=${FIXTURE_SYMBOL_DISCOVER_RE:-$DEFAULT_FIXTURE_SYMBOL_DISCOVER_RE}

# --- the DISCOVERY allowlist (production fakes that legitimately ship) -------
# A conservative-denylist hit in a DISCOVERED package that ALSO matches this is a
# genuine PRODUCTION synthetic, NOT a test-only leak — rescued before failing.
# The one such symbol family on the real tree:
#   fakeEntrypointConfigSource / NewFakeEntrypointConfigSource — the libvirt
#     EntrypointConfigSource's GATE-AWARE OFFLINE default (the path taken OFF the
#     DS_HOSTAGENT_LIVE gate, i.e. in the sandbox / CI / every unit test). It is
#     PRODUCTION code reached by NewEntrypointConfigSource so the offline create
#     choreography is provable against fixtures (D50) — it ships by design, like
#     the `synth*` wire stampers in FIXTURE_SYMBOL_ALLOW_RE. The curated map does
#     NOT scan libvirt, so this rescue lives only on the discovery path. The
#     self-test forces it EMPTY so a planted discovered leak is still caught.
DEFAULT_FIXTURE_SYMBOL_DISCOVER_ALLOW_RE='fakeEntrypointConfigSource'
FIXTURE_SYMBOL_DISCOVER_ALLOW_RE=${FIXTURE_SYMBOL_DISCOVER_ALLOW_RE-$DEFAULT_FIXTURE_SYMBOL_DISCOVER_ALLOW_RE}
GO=${GO:-go}

# --- locate the repo root (works from any cwd) ------------------------------
# This script lives at <repo>/scripts/check-fixture-symbols.sh. Resolve the repo
# root via the script's own directory so a manual run from anywhere, and the CI
# `make repo-lints` run, both work. Per-module roots below are anchored here.
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
ORCH_MOD_DIR=${ORCH_MOD_DIR:-$repo_root/orchestrator}

# --- the per-MODULE scan map ------------------------------------------------
# Each entry is `<module-dir>|<package>`: a Go module root (relative to the repo
# root, or absolute) and a package within it. `go list -export` MUST run from the
# package's own module root, so the gate cannot assume a single module — it pairs
# every package with its module. The default map covers every tree that drives a
# FROZEN seam against in-process synthetic stand-ins (D50):
#   orchestrator: sessions (§4.1 spine), hostagent (host-agent leg), reconciler
#                 (level-triggered loop), controlplane (wiring).
#   client:       wrapper/adapters/claude-code (the Claude Code wire-shape adapter,
#                 driven against synthetic fixtures — a leaked fake here would ship
#                 in the OSS client archive).
#   vm:           entrypoint, attachfwd, cow (the guest legs).
# A test-only stand-in must never leak into ANY of these production archives.
# This list is the FALLBACK when auto-discovery is unavailable/disabled; in the
# steady state the discovery arm below sweeps a superset of it fail-closed. The
# `identity|…/grant-service` entry (frozen doc-16 §5.1/§5.4 grant seam driven
# against an in-process backend; D39/D52/D55/D83) and the grant-fetch conformance
# adapter (which dials that seam) are the audited high-risk additions for the
# assurance + identity trees; proto/gen/go is generated and exempt, and the
# contract-harness fake-publisher subtrees ship fakes by design (skip-list below).
DEFAULT_SCAN_MAP='orchestrator|github.com/dream-serpent/dream-serpent/orchestrator/internal/sessions
orchestrator|github.com/dream-serpent/dream-serpent/orchestrator/internal/hostagent
orchestrator|github.com/dream-serpent/dream-serpent/orchestrator/internal/reconciler
orchestrator|github.com/dream-serpent/dream-serpent/orchestrator/internal/controlplane
client|github.com/dream-serpent/dream-serpent/client/wrapper/adapters/claude-code
vm|github.com/dream-serpent/dream-serpent/vm/entrypoint
vm|github.com/dream-serpent/dream-serpent/vm/attachfwd
vm|github.com/dream-serpent/dream-serpent/vm/cow
identity/grant-service|github.com/dream-serpent/dream-serpent/identity/grant-service
assurance/conformance-adapter|github.com/dream-serpent/dream-serpent/assurance/conformance-adapter/grantfetchconform'

# --- the auto-discovery SKIP-LIST (ERE) -------------------------------------
# Matched against each DISCOVERED `<module-dir>|<package>` entry; a match drops
# it from the swept set. Only TWO trees are exempt, and both are
# legitimate-by-construction, never "hard to fix":
#   proto/gen/go            — GENERATED code (D24/D58/D80); a denylist-shaped name
#                             there is the generator's, not a leaked test fake.
#   contract-harness/{seams,fakegen,cmd/fakegen}
#                           — the FAKE-PUBLISHER home. "Fakes ship with their
#                             contract, published by the seam owner" (the repo
#                             charter):
#                             a production `FakeDialer` / `fakeTemplate` here is
#                             the charter, not a leak — sweeping it would be a
#                             guaranteed false positive.
# Everything else discovered from go.work is swept fail-closed. The `(^|[|/])`…
# `([|/]|$)` anchoring matches the module-dir or any path segment of the package
# (entries look like `assurance/contract-harness|github.com/.../seams/hostagent`),
# so it bites whether the token appears as the module dir or inside the package.
DEFAULT_SYMBOL_SCAN_SKIP_RE='(^|[|/])proto/gen/go([|/]|$)|(^|[|/])contract-harness/(seams|fakegen|cmd/fakegen)([|/]|$)|(^|[|/])boundary([|/]|$)'
SYMBOL_SCAN_SKIP_RE=${SYMBOL_SCAN_SKIP_RE-$DEFAULT_SYMBOL_SCAN_SKIP_RE}
FIXTURE_SYMBOL_AUTODISCOVER=${FIXTURE_SYMBOL_AUTODISCOVER:-1}

# resolve_mod_dir RAW — map a scan-map <module-dir> token to an absolute path:
# absolute as-is, otherwise relative to repo_root. Keeps the map cwd-independent.
resolve_mod_dir() {
	case $1 in
	/*) echo "$1" ;;
	*) echo "$repo_root/$1" ;;
	esac
}

# discover_scan_map WORK_ROOT — the FAIL-CLOSED auto-discovery arm. Enumerate
# every module root declared in WORK_ROOT/go.work (`go work edit -json`, whose
# DiskPath entries are repo-root-relative), `go list ./...` each, drop any
# `<module-dir>|<package>` entry that matches SYMBOL_SCAN_SKIP_RE, and emit the
# survivors (one `<module-dir>|<package>` per line) on stdout. A NEW module or
# package is therefore swept the instant it lands, with no edit to this script —
# coverage is opt-OUT (skip-list) rather than the old opt-IN hand list (D47
# spirit). DiskPath tokens are kept repo-root-relative so resolve_mod_dir anchors
# them exactly like the hand map. Returns non-zero (emitting nothing) when there
# is no go.work or `go work edit -json` fails, so the caller can fall back to the
# hand-maintained DEFAULT_SCAN_MAP. JSON is parsed with grep/sed (no jq
# dependency) against the fixed `"DiskPath": "<path>"` shape `go work` emits.
discover_scan_map() {
	_work_root=$1
	[ -f "$_work_root/go.work" ] || return 1
	_json=$( (cd "$_work_root" && "$GO" work edit -json) 2>/dev/null) || return 1
	[ -n "$_json" ] || return 1
	# Module roots, repo-root-relative, in go.work declaration order.
	_mods=$(printf '%s\n' "$_json" \
		| grep -oE '"DiskPath"[[:space:]]*:[[:space:]]*"[^"]*"' \
		| sed -E 's/.*"DiskPath"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/; s#^\./##; s#/$##')
	[ -n "$_mods" ] || return 1
	_any=0
	for _m in $_mods; do
		# Resolve the module dir against THIS workspace root (not the global
		# repo_root) so discovery is correct for both the real tree and the
		# self-test's throwaway go.work. The emitted token stays relative so the
		# normal loop's resolve_mod_dir re-anchors it under repo_root identically.
		case $_m in
		/*) _mdir=$_m ;;
		*) _mdir="$_work_root/$_m" ;;
		esac
		[ -d "$_mdir" ] || continue
		# Only enumerate packages that HAVE production .go files: a package with no
		# GoFiles (a test-only `_test` package, a migrations dir of .sql, an
		# embed-only stub) has no production archive and so cannot leak a fixture
		# symbol into one — `{{if .GoFiles}}` drops it at the source.
		_pkgs=$( (cd "$_mdir" && "$GO" list -f '{{if .GoFiles}}{{.ImportPath}}{{end}}' ./... 2>/dev/null) ) || continue
		for _p in $_pkgs; do
			[ -n "$_p" ] || continue
			_e="$_m|$_p"
			# Drop skip-listed entries (generated proto + fake-publisher trees).
			if [ -n "$SYMBOL_SCAN_SKIP_RE" ] && printf '%s' "$_e" | grep -qE "$SYMBOL_SCAN_SKIP_RE"; then
				continue
			fi
			# Tag DISCOVERED entries with a `|discovered` mode so the sweep loop
			# applies the CONSERVATIVE denylist (no suffix rule / no drift guard) to
			# them, while the hand-curated map stays on the full denylist + drift guard.
			printf '%s|discovered\n' "$_e"
			_any=1
		done
	done
	[ "$_any" -eq 1 ] || return 1
	return 0
}

if ! command -v "$GO" >/dev/null 2>&1; then
	echo "FATAL: the Go toolchain ($GO) is required for the nm symbol sweep but was not found" >&2
	exit 2
fi

# Resolve the effective scan map. Precedence:
#   1. SYMBOL_SCAN_PKGS (legacy single-module override) — paired with ORCH_MOD_DIR,
#      verbatim; both SYMBOL_SCAN_MAP and auto-discovery are ignored.
#   2. SYMBOL_SCAN_MAP (explicit map override) — swept verbatim (no skip-list).
#   3. AUTO-DISCOVERY (default) — discover from go.work, minus SYMBOL_SCAN_SKIP_RE.
#   4. DEFAULT_SCAN_MAP fallback — when discovery is disabled/unavailable.
# NOTE: the in-script self-test does NOT reach this top-level loop for the
# leak/clean cases — it calls sweep_pkg directly with explicit (package,
# $T-module-dir) args — so its throwaway module can never be confused with the
# real orchestrator regardless of this branch. (The discovery self-test arm calls
# discover_scan_map on its OWN throwaway go.work and exits before this runs.)
if [ -n "${SYMBOL_SCAN_PKGS:-}" ]; then
	SCAN_MAP=''
	for _p in $SYMBOL_SCAN_PKGS; do
		SCAN_MAP="$SCAN_MAP$ORCH_MOD_DIR|$_p
"
	done
elif [ -n "${SYMBOL_SCAN_MAP:-}" ]; then
	SCAN_MAP=$SYMBOL_SCAN_MAP
elif [ "$FIXTURE_SYMBOL_AUTODISCOVER" != "0" ] && SCAN_MAP=$(discover_scan_map "$repo_root") && [ -n "$SCAN_MAP" ]; then
	: # discovered from go.work, skip-list applied
else
	[ "$FIXTURE_SYMBOL_AUTODISCOVER" != "0" ] && \
		echo "fixture-symbols: auto-discovery unavailable (no go.work or go-work-edit failed); falling back to DEFAULT_SCAN_MAP" >&2
	SCAN_MAP=$DEFAULT_SCAN_MAP
fi

# sweep_pkg PKG MOD_DIR [DENY_RE ALLOW_RE] — nm the PRODUCTION archive of PKG
# (built from MOD_DIR) and print any fixture-stand-in symbol it carries. Returns 1
# on a leak, 0 clean (or cleanly SKIPPED). `go list -export` builds the package
# WITHOUT its _test.go files, so a symbol that survives into the archive is
# genuinely linked into the shipped binary. DENY_RE/ALLOW_RE default to the
# CURATED-map REs (FIXTURE_SYMBOL_RE / FIXTURE_SYMBOL_ALLOW_RE) so the existing
# callers (and the leak/clean self-test) are unchanged; the discovery loop passes
# the CONSERVATIVE pair so the suffix rule never floods on the broad tree.
sweep_pkg() {
	_pkg=$1
	_mod=$2
	_deny=${3-$FIXTURE_SYMBOL_RE}
	_allow=${4-$FIXTURE_SYMBOL_ALLOW_RE}
	_export=$( (cd "$_mod" && "$GO" list -export -f '{{.Export}}' "$_pkg") 2>/dev/null) || {
		echo "SYMBOL FAIL: $_pkg — could not build/locate its production archive (go list -export failed)" >&2
		return 1
	}
	if [ -z "$_export" ] || [ ! -f "$_export" ]; then
		# An empty export with NO production GoFiles is a TEST-ONLY / embed-only
		# package (e.g. an `_test`-suffixed package, or a migrations dir of .sql):
		# it has no production archive, so it CANNOT leak a fixture symbol into one.
		# Skip it cleanly rather than failing. A genuinely missing archive for a
		# package that DOES have production GoFiles is still a hard FAIL.
		_gofiles=$( (cd "$_mod" && "$GO" list -f '{{if .GoFiles}}1{{end}}' "$_pkg") 2>/dev/null || true)
		if [ -z "$_gofiles" ]; then
			echo "OK fixture-symbols: $_pkg (no production .go files — no archive to leak into; skipped)"
			return 0
		fi
		echo "SYMBOL FAIL: $_pkg — production archive path is empty or missing ($_export)" >&2
		return 1
	fi
	# nm prints "<addr> <type> <symbol>"; we only care about the symbol name.
	# Match the package-qualified name against the denylist (case-insensitive),
	# THEN subtract any production symbol the allowlist rescues — so the broadened
	# `…Recorder`/`…Sink` suffix rule never flags a genuine production seam
	# (segRecorder / ParkRecorderStore / MintExpirySink / *SubTokenSink / …). An
	# empty allowlist (the self-test sets it so) is a no-op that drops nothing.
	_hits=$("$GO" tool nm "$_export" 2>/dev/null \
		| awk '{print $NF}' \
		| grep -E "(^|[/.])${_pkg##*/}\." \
		| grep -iE "$_deny" \
		| { if [ -n "$_allow" ]; then grep -ivE "$_allow"; else cat; fi } \
		| sort -u || true)
	if [ -n "$_hits" ]; then
		echo "SYMBOL FAIL: $_pkg — TEST-ONLY fixture stand-in(s) leaked into the production archive:" >&2
		printf '  %s\n' $_hits >&2
		echo "  -> move them into a *_fixtures_test.go file (byte-for-byte; D50: no fake ships in the binary)" >&2
		return 1
	fi
	echo "OK fixture-symbols: $_pkg (production archive carries no fixture stand-in)"
	return 0
}

# --- the allowlist DRIFT GUARD ----------------------------------------------
# SUFFIX_RE isolates the WIDENED suffix family (`…Recorder`/`…Harness`/`…Sink`)
# from the full denylist — the only sub-rule that can sweep in a GENUINE
# production symbol and so the only one the allowlist has to actively rescue. The
# explicit fake/mock/stub/journal vocabulary is unambiguously test-only and never
# legitimately ships, so it is deliberately NOT part of the drift surface.
SUFFIX_RE='[A-Za-z0-9_]*(Recorder|Harness|Sink)([._)]|$)'

# derive_suffix_symbols MOD_DIR PKG — emit (one per line) every production symbol
# in PKG's archive whose package-qualified name matches the SUFFIX family. This is
# the candidate set the suffix rule would flag; each MUST be covered by the
# allowlist (FIXTURE_SYMBOL_ALLOW_RE) or it would false-positive a real sweep.
derive_suffix_symbols() {
	_dmod=$1
	_dpkg=$2
	_dexport=$( (cd "$_dmod" && "$GO" list -export -f '{{.Export}}' "$_dpkg") 2>/dev/null) || return 1
	[ -n "$_dexport" ] && [ -f "$_dexport" ] || return 1
	"$GO" tool nm "$_dexport" 2>/dev/null \
		| awk '{print $NF}' \
		| grep -E "(^|[/.])${_dpkg##*/}\." \
		| grep -iE "$SUFFIX_RE" \
		| sort -u || true
}

# --- Self-test mode: prove the gate is non-vacuous on BOTH denylist families --
# Four throwaway packages:
#   clean/      — a fake confined to *_fixtures_test.go            => must PASS
#   leaky/      — the IDENTICAL fake left in a production .go      => must FAIL (fake/mock/stub vocab)
#   suffixleak/ — a `…Sink`-named test stand-in in production .go  => must FAIL (the WIDENED suffix rule)
#   allowed/    — a production `…Recorder` matching the allowlist  => must PASS (allowlist rescue)
# suffixleak/ proves the broadened `…Recorder`/`…Harness`/`…Sink` rule catches a
# leak named OUTSIDE the fake/mock/stub vocabulary; allowed/ proves the allowlist
# rescues a genuine production recorder/sink so the suffix rule never false-positives.
if [ "${1:-}" = "--self-test" ]; then
	T=$(mktemp -d)
	trap 'rm -rf "$T"' EXIT

	mod=dsfixtureselftest
	mkdir -p "$T/clean" "$T/leaky" "$T/suffixleak" "$T/allowed"
	cat > "$T/go.mod" <<EOF
module $mod

go 1.21
EOF

	# A non-fixture production function so each package is non-empty and links.
	# clean/: the fake lives ONLY in a _fixtures_test.go (correct placement).
	cat > "$T/clean/clean.go" <<'EOF'
// SPDX-License-Identifier: Apache-2.0
package clean

// Production code (no fixture). Production archive must carry only this.
func ProdEntryClean() int { return 1 }
EOF
	cat > "$T/clean/clean_fixtures_test.go" <<'EOF'
// SPDX-License-Identifier: Apache-2.0
package clean

// fakeLeakedFixture is a test-only stand-in, correctly confined to a
// *_fixtures_test.go file — it must NOT appear in the production archive.
type fakeLeakedFixture struct{ n int }

func (f fakeLeakedFixture) leakedFixtureValue() int { return f.n }
EOF

	# leaky/: the IDENTICAL fake is declared in a PRODUCTION .go file (the leak).
	cat > "$T/leaky/leaky.go" <<'EOF'
// SPDX-License-Identifier: Apache-2.0
package leaky

func ProdEntryLeaky() int { return 1 }

// fakeLeakedFixture is a test-only stand-in WRONGLY left in a production .go
// file — it compiles into the production archive and must be caught.
type fakeLeakedFixture struct{ n int }

func (f fakeLeakedFixture) leakedFixtureValue() int { return f.n }

// reference it from production so the linker keeps the symbol.
func useLeak() int { return fakeLeakedFixture{n: 2}.leakedFixtureValue() }

var _ = useLeak
EOF

	# suffixleak/: a test-only stand-in named OUTSIDE the fake/mock/stub vocabulary
	# (a `…Sink`), WRONGLY left in a production .go file — only the WIDENED suffix
	# rule catches it. It does NOT match the production allowlist, so it must FAIL.
	cat > "$T/suffixleak/suffixleak.go" <<'EOF'
// SPDX-License-Identifier: Apache-2.0
package suffixleak

func ProdEntrySuffix() int { return 1 }

// captureSink is a test-only in-process consumer stand-in named outside the
// fake/mock/stub vocabulary; left in a production .go file it leaks. The widened
// `…Sink` suffix rule must catch it (it is NOT a production allowlist name).
type captureSink struct{ n int }

func (s captureSink) record() int { return s.n }

func useSuffixLeak() int { return captureSink{n: 3}.record() }

var _ = useSuffixLeak
EOF

	# allowed/: a PRODUCTION symbol whose `…Recorder` suffix matches the denylist
	# AND the production allowlist (segRecorder family) — it must be RESCUED, so the
	# package PASSES. This proves the allowlist actually subtracts production names.
	cat > "$T/allowed/allowed.go" <<'EOF'
// SPDX-License-Identifier: Apache-2.0
package allowed

func ProdEntryAllowed() int { return 1 }

// segRecorder is a genuine PRODUCTION recorder (the sessions step-9 routable
// segment store shape) — its `…Recorder` suffix matches the denylist but the
// production allowlist (segRecorder) rescues it, so the package must PASS.
type segRecorder struct{ n int }

func (r segRecorder) record() int { return r.n }

func useAllowed() int { return segRecorder{n: 4}.record() }

var _ = useAllowed
EOF

	rc=0

	# The CLEAN package must PASS (the fake is test-only, absent from the archive).
	if SYMBOL_SCAN_PKGS="$mod/clean" sweep_pkg "$mod/clean" "$T" >/dev/null 2>&1; then
		echo "SELF-TEST OK (clean PASSES): fake confined to *_fixtures_test.go"
	else
		echo "SELF-TEST FAIL: clean tree should PASS but the gate flagged it" >&2
		rc=1
	fi

	# The LEAKY package must FAIL (the fake leaked into the production archive). The
	# allowlist is forced EMPTY here so a planted leak can never be rescued by it.
	if SYMBOL_SCAN_PKGS="$mod/leaky" FIXTURE_SYMBOL_ALLOW_RE='' sweep_pkg "$mod/leaky" "$T" >/dev/null 2>&1; then
		echo "SELF-TEST FAIL: leaky tree should FAIL but the gate passed it" >&2
		rc=1
	else
		echo "SELF-TEST OK (leak FAILS): deliberately-leaked fixture symbol caught"
	fi

	# The SUFFIXLEAK package must FAIL on the WIDENED rule: a `…Sink`-named stand-in
	# OUTSIDE the fake/mock/stub vocabulary, in a production .go, with the allowlist
	# at its production default (captureSink is not a production name, so not rescued).
	if SYMBOL_SCAN_PKGS="$mod/suffixleak" sweep_pkg "$mod/suffixleak" "$T" >/dev/null 2>&1; then
		echo "SELF-TEST FAIL: suffixleak tree should FAIL on the widened …Sink rule but passed" >&2
		rc=1
	else
		echo "SELF-TEST OK (suffix leak FAILS): a …Sink-named stand-in outside the fake/mock/stub vocabulary is caught"
	fi

	# The ALLOWED package must PASS: a production `…Recorder` (segRecorder) matches
	# the denylist suffix rule but the production allowlist RESCUES it. This proves
	# the allowlist actually subtracts production names (no false positive on a synthetic).
	if SYMBOL_SCAN_PKGS="$mod/allowed" sweep_pkg "$mod/allowed" "$T" >/dev/null 2>&1; then
		echo "SELF-TEST OK (allowlist rescue PASSES): production segRecorder is not flagged"
	else
		echo "SELF-TEST FAIL: allowed tree should PASS (production segRecorder rescued) but the gate flagged it" >&2
		rc=1
	fi

	# --- DRIFT-GUARD non-vacuity: a production `…Recorder`/`…Sink` the allowlist
	# does NOT cover must be FLAGGED as drift. allowed/ contributes a covered
	# production recorder (segRecorder, in the allowlist); driftpkg/ below adds an
	# UNCOVERED production `…Sink` (acceptSink, NOT in the default allowlist). The
	# drift guard re-derives the suffix-family set from the archive and asserts the
	# allowlist covers each member — so it must report driftpkg's acceptSink as drift
	# while leaving allowed's segRecorder alone. (driftpkg lives in the same throwaway
	# module; it is not a leak, it is a production symbol the allowlist forgot.)
	mkdir -p "$T/driftpkg"
	cat > "$T/driftpkg/driftpkg.go" <<'EOF'
// SPDX-License-Identifier: Apache-2.0
package driftpkg

func ProdEntryDrift() int { return 1 }

// acceptSink is a genuine PRODUCTION sink whose `…Sink` suffix matches the
// denylist suffix rule but which is NOT in the default allowlist — exactly the
// "new production suffix symbol the allowlist forgot" the drift guard exists to
// surface before it false-positives a real sweep.
type acceptSink struct{ n int }

func (s acceptSink) accept() int { return s.n }

func useDrift() int { return acceptSink{n: 5}.accept() }

var _ = useDrift
EOF

	# allowed/ : every suffix symbol (segRecorder) IS covered by the default
	# allowlist -> derive must yield NO uncovered member (drift guard stays quiet).
	_uncovered_allowed=$(derive_suffix_symbols "$T" "$mod/allowed" \
		| { if [ -n "$DEFAULT_FIXTURE_SYMBOL_ALLOW_RE" ]; then grep -ivE "$DEFAULT_FIXTURE_SYMBOL_ALLOW_RE"; else cat; fi } || true)
	if [ -z "$_uncovered_allowed" ]; then
		echo "SELF-TEST OK (drift guard QUIET on covered tree): segRecorder is in the allowlist"
	else
		echo "SELF-TEST FAIL: drift guard flagged a covered production symbol ($_uncovered_allowed)" >&2
		rc=1
	fi

	# driftpkg/ : acceptSink is a suffix symbol NOT covered by the default allowlist
	# -> derive must yield it as an uncovered member (drift guard TRIPS).
	_uncovered_drift=$(derive_suffix_symbols "$T" "$mod/driftpkg" \
		| { if [ -n "$DEFAULT_FIXTURE_SYMBOL_ALLOW_RE" ]; then grep -ivE "$DEFAULT_FIXTURE_SYMBOL_ALLOW_RE"; else cat; fi } || true)
	if [ -n "$_uncovered_drift" ]; then
		echo "SELF-TEST OK (drift guard TRIPS on uncovered tree): acceptSink surfaced as allowlist drift"
	else
		echo "SELF-TEST FAIL: drift guard missed an uncovered production …Sink (acceptSink)" >&2
		rc=1
	fi

	# --- AUTO-DISCOVERY arm: a NEWLY-DISCOVERED module's planted leak must be
	# caught named, and a SKIP-LISTED package's identical leak must stay quiet.
	# Build a throwaway WORKSPACE root W with its own go.work that `use`s two
	# modules:
	#   newmod/leaky/  — a module NOT in the hand list, with a leaky package that
	#              ALSO carries a production `…Sink` AND a discovery-allowlisted
	#              production fake, so we prove all three discovery behaviors at once:
	#                * fakeDiscoveredLeak  => caught by the CONSERVATIVE denylist (FAIL)
	#                * captureSink         => NOT flagged (conservative denylist has no
	#                                         suffix rule — discovery never floods on a
	#                                         production sink)
	#                * fakeAllowedSource   => RESCUED by FIXTURE_SYMBOL_DISCOVER_ALLOW_RE
	#                                         when the allowlist names it (proves the
	#                                         real libvirt fakeEntrypointConfigSource
	#                                         rescue is load-bearing, not vacuous)
	#   skipmod/  — a module under a path the skip-list drops (we point
	#              SYMBOL_SCAN_SKIP_RE at it), carrying the IDENTICAL leak; discovery
	#              must NOT emit it, so it stays quiet (the skip-list exemption).
	# We exercise discover_scan_map directly (it must emit newmod's package but not
	# skipmod's) AND prove the discovered REGIME (conservative denylist + discovery
	# allowlist, the same pair the normal loop passes for a discovered entry) fails
	# closed on the real leak, NAMED, while leaving the production sink + the
	# allowlisted fake quiet.
	W=$(mktemp -d)
	# Reuse the outer EXIT trap target by chaining: remove BOTH temp dirs.
	trap 'rm -rf "$T" "$W"' EXIT
	mkdir -p "$W/newmod/leaky" "$W/skipmodtree/skipmod/leaky"
	cat > "$W/go.work" <<EOF
go 1.21

use (
	./newmod
	./skipmodtree/skipmod
)
EOF
	for _sub in newmod skipmodtree/skipmod; do
		_mp=$(printf '%s' "ds$_sub" | tr -d '/')
		cat > "$W/$_sub/go.mod" <<EOF
module $_mp

go 1.21
EOF
		cat > "$W/$_sub/leaky/leaky.go" <<EOF
// SPDX-License-Identifier: Apache-2.0
package leaky

func ProdEntry() int { return 1 }

// fakeDiscoveredLeak is a test-only stand-in WRONGLY left in a production .go
// file in a module the hand list never named — auto-discovery must surface it.
type fakeDiscoveredLeak struct{ n int }

func (f fakeDiscoveredLeak) leakValue() int { return f.n }

// captureSink is a GENUINE production sink: the conservative discovery denylist
// has NO suffix rule, so this must NOT be flagged on the discovery path (proving
// discovery does not flood on the real tree's many production …Sink seams).
type captureSink struct{ n int }

func (s captureSink) record() int { return s.n }

// fakeAllowedSource models the real libvirt fakeEntrypointConfigSource: a
// production fake the discovery allowlist names. When the allowlist names it, it
// must be RESCUED (no false positive); when forced empty, it is caught.
type fakeAllowedSource struct{ n int }

func (s fakeAllowedSource) fetch() int { return s.n }

func useLeak() int {
	return fakeDiscoveredLeak{n: 1}.leakValue() +
		captureSink{n: 2}.record() +
		fakeAllowedSource{n: 3}.fetch()
}

var _ = useLeak
EOF
	done

	# Skip-list drops anything whose entry contains the skipmod path segment.
	_disc_skip='(^|[|/])skipmodtree([|/]|$)'

	# discover_scan_map must emit newmod's leaky package and NOT skipmod's.
	_discovered=$(SYMBOL_SCAN_SKIP_RE="$_disc_skip" discover_scan_map "$W" || true)
	if printf '%s\n' "$_discovered" | grep -q 'newmod|dsnewmod/leaky'; then
		echo "SELF-TEST OK (discovery surfaces a new module): newmod/leaky discovered"
	else
		echo "SELF-TEST FAIL: auto-discovery did not surface the new module's package (got: $_discovered)" >&2
		rc=1
	fi
	if printf '%s\n' "$_discovered" | grep -q 'skipmod'; then
		echo "SELF-TEST FAIL: skip-list did not drop the skip-listed module (got: $_discovered)" >&2
		rc=1
	else
		echo "SELF-TEST OK (skip-list exempts the skipped tree): skipmod is not in the discovered map"
	fi

	# The DISCOVERED regime must FAIL CLOSED, NAMED, on the real leak. Sweep
	# newmod's package via sweep_pkg with the SAME (conservative denylist, discovery
	# allowlist) pair the normal loop passes for a `|discovered` entry. The leak
	# message must NAME the offending fakeDiscoveredLeak symbol so the dev knows
	# which file to move it to. The discovery allowlist here is the production
	# DEFAULT extended to also name fakeAllowedSource (so the rescue arm below has a
	# target) — fakeDiscoveredLeak is NOT in it, so the genuine leak still fails.
	_disc_allow="$DEFAULT_FIXTURE_SYMBOL_DISCOVER_ALLOW_RE|fakeAllowedSource"
	# Capture output + rc WITHOUT tripping `set -e` (sweep_pkg returns 1 on the
	# leak): the `&& _swrc=0 || _swrc=$?` idiom is the set -e-safe capture pattern.
	_swrc=0
	_sweepout=$(FIXTURE_SYMBOL_ALLOW_RE='' sweep_pkg 'dsnewmod/leaky' "$W/newmod" \
		"$DEFAULT_FIXTURE_SYMBOL_DISCOVER_RE" "$_disc_allow" 2>&1) && _swrc=0 || _swrc=$?
	if [ "$_swrc" -ne 0 ] && printf '%s' "$_sweepout" | grep -q 'fakeDiscoveredLeak'; then
		echo "SELF-TEST OK (discovered leak FAILS named): fakeDiscoveredLeak caught by the conservative denylist in a newly-discovered module"
	else
		echo "SELF-TEST FAIL: discovered leak not caught/named (rc=$_swrc): $_sweepout" >&2
		rc=1
	fi
	# The production captureSink must NOT appear in the leak output: the
	# conservative discovery denylist has no suffix rule, so discovery never floods
	# on a genuine production …Sink (the property that keeps the real tree green).
	if printf '%s' "$_sweepout" | grep -q 'captureSink'; then
		echo "SELF-TEST FAIL: discovery flagged a production …Sink (captureSink) — conservative denylist regressed" >&2
		rc=1
	else
		echo "SELF-TEST OK (discovery quiet on a production sink): captureSink not flagged on the discovery path"
	fi
	# The allowlisted production fake (fakeAllowedSource) must NOT appear either:
	# FIXTURE_SYMBOL_DISCOVER_ALLOW_RE rescued it. This proves the real-tree
	# fakeEntrypointConfigSource rescue is load-bearing, not vacuous.
	if printf '%s' "$_sweepout" | grep -q 'fakeAllowedSource'; then
		echo "SELF-TEST FAIL: discovery allowlist did not rescue an allowlisted production fake (fakeAllowedSource)" >&2
		rc=1
	else
		echo "SELF-TEST OK (discovery allowlist rescues a production fake): fakeAllowedSource not flagged"
	fi
	# Non-vacuity of the discovery allowlist: with it FORCED EMPTY, fakeAllowedSource
	# IS caught (it matches the conservative fake-vocab denylist) — so the rescue
	# above was a real subtraction, not a no-op.
	_emptyallow=$(FIXTURE_SYMBOL_ALLOW_RE='' sweep_pkg 'dsnewmod/leaky' "$W/newmod" \
		"$DEFAULT_FIXTURE_SYMBOL_DISCOVER_RE" '' 2>&1 || true)
	if printf '%s' "$_emptyallow" | grep -q 'fakeAllowedSource'; then
		echo "SELF-TEST OK (discovery allowlist is non-vacuous): fakeAllowedSource IS caught when the allowlist is empty"
	else
		echo "SELF-TEST FAIL: empty discovery allowlist should catch fakeAllowedSource but did not: $_emptyallow" >&2
		rc=1
	fi

	if [ "$rc" -ne 0 ]; then
		echo "Gate self-test: VACUOUS / BROKEN" >&2
		exit 1
	fi
	echo "Gate self-test: clean PASSES, a fake/mock/stub leak FAILS, a …Sink leak FAILS (curated suffix rule), a production …Recorder is rescued, the curated drift guard is non-vacuous, AUTO-DISCOVERY surfaces a new module's leak (failing closed, named) while the skip-list exempts the skipped tree, the conservative discovery denylist stays quiet on a production sink, and the discovery allowlist is a non-vacuous rescue — non-vacuous"
	exit 0
fi

# --- normal operation: sweep every configured package -----------------------
# Each scan-map entry is `<module-dir>|<package>` (CURATED) or
# `<module-dir>|<package>|discovered` (AUTO-DISCOVERED). Two sweep regimes:
#   CURATED — the hand-maintained / explicit-override packages, audited symbol by
#     symbol. Swept with the FULL denylist (incl. the widened suffix family) +
#     FIXTURE_SYMBOL_ALLOW_RE, PLUS the allowlist DRIFT GUARD: every production
#     symbol matching the suffix family MUST be covered by the allowlist, else a
#     future sweep would false-positive on it — a newly-landed production
#     `…Sink`/`…Recorder`/`…Harness` the allowlist does not yet name fails the
#     gate HERE, named, so the allowlist is grown deliberately rather than after a
#     confusing false-positive in CI.
#   DISCOVERED — the fail-closed go.work auto-discovered packages. Swept with the
#     CONSERVATIVE denylist (fake/mock/stub + named-harness vocab only, no suffix
#     rule) + FIXTURE_SYMBOL_DISCOVER_ALLOW_RE, and NO drift guard. The suffix
#     family / drift guard need a per-package curated allowlist that does not
#     exist repo-wide, so they stay scoped to the curated map; the conservative
#     denylist is what makes broad discovery green-by-default on the real tree.
# SCAN_MAP entries are newline-separated. Split on newline ONLY (so a <module-dir>
# token may legitimately contain spaces) by setting IFS to a literal newline for
# the `for` word-split, then restore IFS inside the body so every command
# substitution / pipeline below word-splits normally. The single split happens
# when the `for` is entered, so the in-body restore never re-splits the list.
fail=0
OLDIFS=$IFS
IFS='
'
# shellcheck disable=SC2086
set -- $SCAN_MAP
IFS=$OLDIFS
for _entry in "$@"; do
	# Tolerate stray surrounding whitespace on a map line; skip blank lines.
	_entry=$(printf '%s' "$_entry" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
	[ -n "$_entry" ] || continue
	case $_entry in
	*'|'*) : ;;
	*)
		echo "SYMBOL FAIL: malformed scan-map entry (expected '<module-dir>|<package>'): $_entry" >&2
		fail=1
		continue
		;;
	esac
	# Parse `<module-dir>|<package>[|<mode>]`. Default mode is `curated`; only the
	# discovery arm appends `|discovered`. The package field is everything between
	# the first `|` and the (optional) trailing `|<mode>`.
	_mod_raw=${_entry%%|*}
	_rest=${_entry#*|}
	case $_rest in
	*'|discovered') _pkg=${_rest%|discovered}; _mode=discovered ;;
	*'|curated') _pkg=${_rest%|curated}; _mode=curated ;;
	*) _pkg=$_rest; _mode=curated ;;
	esac
	_mod=$(resolve_mod_dir "$_mod_raw")
	if [ ! -d "$_mod" ]; then
		echo "SYMBOL FAIL: $_pkg — module dir not found: $_mod" >&2
		fail=1
		continue
	fi

	if [ "$_mode" = discovered ]; then
		# Discovered: conservative denylist + discovery allowlist, no drift guard.
		if ! sweep_pkg "$_pkg" "$_mod" "$FIXTURE_SYMBOL_DISCOVER_RE" "$FIXTURE_SYMBOL_DISCOVER_ALLOW_RE"; then
			fail=1
		fi
		continue
	fi

	# Curated: full denylist + curated allowlist, then the drift guard.
	if ! sweep_pkg "$_pkg" "$_mod"; then
		fail=1
	fi

	# Allowlist drift guard for this curated package.
	_drift=$(derive_suffix_symbols "$_mod" "$_pkg" \
		| { if [ -n "$FIXTURE_SYMBOL_ALLOW_RE" ]; then grep -ivE "$FIXTURE_SYMBOL_ALLOW_RE"; else cat; fi } || true)
	if [ -n "$_drift" ]; then
		echo "SYMBOL FAIL: $_pkg — production symbol(s) match the widened suffix rule but are NOT in FIXTURE_SYMBOL_ALLOW_RE (allowlist drift):" >&2
		printf '  %s\n' $_drift >&2
		echo "  -> if these are genuine production seams, add their family to DEFAULT_FIXTURE_SYMBOL_ALLOW_RE; if a test-only leak, move it into a *_fixtures_test.go" >&2
		fail=1
	fi
done

if [ "$fail" -ne 0 ]; then
	echo "FIXTURE SYMBOL SWEEP: FAILED" >&2
	exit 1
fi
echo "FIXTURE SYMBOL SWEEP: OK"
exit 0
