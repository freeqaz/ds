# Dream Serpent — repo-level convenience targets.
#
# taskdb is a local task/note store (see docs/21-taskdb-design.md). It builds
# to .bin/taskdb (gitignored). The git hooks under scripts/hooks/ call it to
# keep taskdb.sqlite and tasks/*.json in sync across commits and branch switches.
#
# The same binary hosts the dev-dispatch layer (see docs/22-dev-dispatch-design.md):
# `.bin/taskdb mcp` is the stdio MCP server agents talk to, alongside a local
# dispatcher that supervises headless agents across per-task git worktrees.
#
# check-doc-links lints all relative links and #fragment anchors across
# docs/**/*.md and README.md (no network; external URLs are skipped).
# Pre-existing failures are suppressed by scripts/doc-links-allowlist.txt;
# new breakage fails closed.  See scripts/check-doc-links.sh for details.

.PHONY: setup taskdb serpent live-stack ds-host-agent-live install-hooks uninstall-hooks \
	searchsvc-knobs-audit \
	check-doc-links check-image-drift check-image-drift-selftest check-spdx \
	check-fixture-provenance check-fixture-symbols \
	check-grantref-goldens check-snapshot-goldens \
	check-corpus-suffix check-searchsvc-routes \
	check-nft-mark-constants check-vendor-tracked \
	check-cow-readme check-shellcheck check-actionlint check-service-readme \
	check-macceil-drift \
	check-gomod-tidy check-no-loopback-bind \
	check-guardrail-map-tags check-guardrail-scope-select \
	check-controlplane-mtls-single-builder \
	check-gofmt check-shebang-invocation \
	check-spectate-fixture-pair \
	check-go-line-selftest repo-lints

BIN_DIR := .bin
TASKDB_BIN := $(BIN_DIR)/taskdb
HOOKS_PATH := scripts/hooks

# IMAGE_DRIFT_GLOB controls which lint scripts check-image-drift discovers.
# Default: every images/*/lint-*.sh in the tree (the naming convention every
# image-tree lint script MUST follow — see images/mirror/README.md and
# images/cache/README.md).  Overridable so a hermetic test harness can exercise
# the fail-closed zero-match path against a temp directory without touching real
# scripts.
IMAGE_DRIFT_GLOB ?= images/*/lint-*.sh

# setup is the one-shot fresh-clone bootstrap: build the tool, install hooks,
# thaw the live DB. Delegates to setup-repo.sh (the canonical front door).
setup:
	./setup-repo.sh

taskdb:
	@mkdir -p $(BIN_DIR)
	# GOWORK=off: taskdb is a standalone module, deliberately outside go.work
	# (like boundary/). The workspace must not resolve its SQLite dependency.
	cd scripts/taskdb && GOWORK=off go build -o ../../$(TASKDB_BIN) .
	@echo "built $(TASKDB_BIN)"

# serpent builds the OSS client entrypoint to .bin/serpent (gitignored). This is
# the binary `serpent claude [--vm]` runs — the default path wraps local Claude
# Code through the ds-capture egress gateway; `--vm` execs serpent-tui to route
# the session into a per-session KVM VM. Kept fresh here so `.bin/serpent` is a
# real build output, not a hand-rolled stale artifact.
serpent:
	@mkdir -p $(BIN_DIR)
	go build -o $(BIN_DIR)/serpent ./client/cmd/serpent
	@echo "built $(BIN_DIR)/serpent"

# live-stack builds every binary the serpent-cli live MVP needs (the same six
# scripts/live-mvp/ds-serve-stack.sh compiles) into .bin/: the serpent client +
# the standalone serpent-tui module (GOWORK=off, outside go.work) + the
# host-agent / orchestrator / driver-e2e control plane + the ds-hostbridge
# attach carrier. `ds-serve-stack.sh` defaults its build dir to .bin so the
# stack it launches and the `serpent` you run are the same fresh binaries.
live-stack: serpent
	@mkdir -p $(BIN_DIR)
	go build -o $(BIN_DIR)/ds-host-agent  ./orchestrator/cmd/host-agent
	go build -o $(BIN_DIR)/ds-orchestrator ./orchestrator/cmd/orchestrator
	go build -o $(BIN_DIR)/ds-driver-e2e   ./orchestrator/cmd/ds-driver-e2e
	go build -o $(BIN_DIR)/ds-hostbridge   ./client/cmd/ds-hostbridge
	cd serpent-tui && GOWORK=off go build -o ../$(BIN_DIR)/serpent-tui ./cmd/serpent-tui
	@echo "built live-stack into $(BIN_DIR): serpent serpent-tui ds-host-agent ds-orchestrator ds-driver-e2e ds-hostbridge"

# ds-host-agent-live builds the LIVE per-session NFT-write posture. Since D148
# (2026-07-30) that is NOT a tagged host-agent: the doc 14 §6 linker set is
# {ds-dnsgate, ds-nethelper}, so the ds-nft cgo edge lives in the setcap'd
# ds-nethelper HELPER and the host-agent builds UNTAGGED and runs fully
# unprivileged, forking the helper once per privileged op. Building the agent
# with `-tags nftgatelive` is now a COMPILE ERROR by design
# (orchestrator/cmd/host-agent/nftgatelive_refuse.go).
#
# The target name is kept: it still means "the build that can actually program
# taps + allow-sets" — the live half of the DS_NFTGATE_LIVE gate that programs
# the per-session tap + allow-sets inside the disposable L1 VM (the nested
# testbed's DEVICE-UNDER-TEST, scripts/nested-testbed/README.md). It is a
# host-parity build, NOT a host-enforcement step — all live nft writes run inside
# L1, never on this host (see the safety story in that README).
#
# Three steps, in order:
#   1. `cargo build -p ds-nft --release` produces the staticlib the cgo edge
#      links — dataplane/target/release/libds_nft.a — alongside the already
#      checked-in dataplane/crates/ds-nft/include/ds_nft.h. The cgo LDFLAGS
#      anchor `-L${SRCDIR}/../../../dataplane/target/release` (in nftbridge's own
#      dir) resolves the archive there, so this prereq MUST run first.
#   2. `go build -tags nftgatelive` on ds-nethelper selects the live backend
#      (backend_live.go → nftbridge writeedge.go) and links the staticlib's
#      transitive libc deps (-lpthread -ldl -lm). This is the ONE cgo binary here.
#   3. `go build` on the host-agent with NO tag — cgo-free, capability-free.
#
# REMINDER: the built helper is inert until it is INSTALLED and capability-armed.
# Capabilities are an xattr on the INSTALLED file, so this rebuild disarms any
# previous install. Run, every time:
#   DS_NETHELPER_APPLY=1 orchestrator/cmd/ds-nethelper/scripts/install-ds-nethelper.sh $(BIN_DIR)/ds-nethelper
# (0750 root:<agent-group> + `setcap cap_net_admin+eip` — +eip, NOT +ep — then a
# verify pass), and point the agent at it with -nethelper-path / DS_NETHELPER_PATH.
#
# Output is the SAME .bin/ds-host-agent path live-stack writes (now byte-identical
# in posture, since both are untagged) plus .bin/ds-nethelper.
ds-host-agent-live:
	@mkdir -p $(BIN_DIR)
	cd dataplane && cargo build -p ds-nft --release
	CGO_ENABLED=1 go build -tags nftgatelive -o $(BIN_DIR)/ds-nethelper ./orchestrator/cmd/ds-nethelper
	go build -o $(BIN_DIR)/ds-host-agent ./orchestrator/cmd/host-agent
	@echo "built $(BIN_DIR)/ds-nethelper (-tags nftgatelive: ds-nft cgo write edge) + $(BIN_DIR)/ds-host-agent (UNTAGGED, unprivileged; D148)"
	@echo "NEXT (required after EVERY rebuild — setcap is an xattr on the installed file):"
	@echo "  DS_NETHELPER_APPLY=1 orchestrator/cmd/ds-nethelper/scripts/install-ds-nethelper.sh $(BIN_DIR)/ds-nethelper"

# install-hooks points git at the tracked scripts/hooks/ directory rather than
# symlinking into .git/hooks/. New hooks added there are picked up with no
# re-install. core.hooksPath is local config git never auto-applies from a
# fresh checkout — but you rarely run this by hand: `taskdb setup` and every
# taskdb invocation auto-install it when unset (conflict-safe). This binary-free
# target is the fallback for a clone where .bin/taskdb isn't built yet.
install-hooks:
	@chmod +x $(HOOKS_PATH)/*
	git config core.hooksPath $(HOOKS_PATH)
	@echo "git hooks active via core.hooksPath=$(HOOKS_PATH)"

uninstall-hooks:
	git config --unset core.hooksPath || true
	@echo "core.hooksPath unset — git reverts to .git/hooks/"

# searchsvc-knobs-audit runs the "one knob, both legs" PARITY VERIFIER
# (scripts/taskdb/searchsvc/audit_knobs.py) through the searchsvc uv env so
# CI/operators have ONE command to assert the dense/sparse balance moves both the
# Python fusion leg and the Go ingest/search leg together. It exits non-zero when
# the shared W_ knobs diverge across legs. Hermetic + read-only: no live model /
# GPU / network beyond the uv package fetch (SSL_CERT_FILE routes that through the
# egress-gateway TLS proxy). Pass --json (via ARGS) for machine-readable output:
#   make searchsvc-knobs-audit ARGS=--json
#
# SSL_CERT_FILE GUARD lives HERE (the single place, task 01KV58DB6P): the recipe
# defaults SSL_CERT_FILE to the local mitmproxy CA so `uv` trusts the egress
# proxy, but UNSETS it when that CA file is absent (a runner with no proxy) so uv
# falls back to the system trust store instead of failing on a missing CA path.
# Never sets DS_EMBED_LIVE — this stays hermetic. Callers (the repo-lints CI step,
# operators) invoke a BARE `make searchsvc-knobs-audit` and inherit this guard;
# they no longer carry their own SSL_CERT_FILE default/unset logic.
SEARCHSVC_DIR := scripts/taskdb/searchsvc
searchsvc-knobs-audit:
	@cd $(SEARCHSVC_DIR) && \
		export SSL_CERT_FILE="$${SSL_CERT_FILE:-$$HOME/.mitmproxy/mitmproxy-ca-cert.pem}"; \
		[ -f "$$SSL_CERT_FILE" ] || unset SSL_CERT_FILE; \
		uv run --quiet python audit_knobs.py $(ARGS)

# ----------------------------------------------------------------- repo lints
# Fail-closed, network-free static checks over the tracked tree. Each is one
# command; CI runs the aggregate in .github/workflows/repo-lints.yml (push to
# main + PR + dispatch) by calling `make repo-lints` — the single source of
# truth so CI and local cannot drift.
#
#   check-doc-links           — relative-link + #fragment lint over docs/**/*.md
#                               and README.md (scripts/check-doc-links.sh;
#                               ratchet allowlist).
#   check-image-drift         — glob-discovers and runs every images/*/lint-*.sh
#                               in the tree; fails closed if no scripts match
#                               (D47 spirit). Each script is owned by its image
#                               tree and is only INVOKED here, never edited.
#   check-image-drift-selftest — runs the SAME glob-discovered images/*/lint-*.sh
#                               a second time, each under --self-test, so the
#                               standing gate exercises every script's internal
#                               regression harness (README-token / endpoint-port
#                               guards) that the clean-mode run does not fire.
#                               Same fail-closed presence + zero-match discovery
#                               (D47). Folds the previously on-demand-only
#                               self-tests into CI.
#   check-spdx                — SPDX-License-Identifier header lint over every
#                               source file in scope (scripts/check-spdx.sh).
#   check-fixture-provenance  — D50 synthetic-only fixture contract
#                               (scripts/check-fixture-provenance.sh).
#   check-fixture-symbols     — D50 archive-level fixture-leak gate
#                               (scripts/check-fixture-symbols.sh): nm-sweeps the
#                               orchestrator sessions PRODUCTION archive (no
#                               _test.go) and fails closed if a test-only
#                               synthetic stand-in (in-process service fake /
#                               fault-injection consumer / ordering journal)
#                               leaked into the shipped binary by living in a
#                               production .go file instead of a *_fixtures_test.go.
#                               POSIX sh; ships a non-vacuity --self-test (clean
#                               PASSES, a deliberate leak FAILS).
#   check-grantref-goldens    — byte-identity of the GrantRef cross-module
#                               golden carried in both identity/mint and
#                               identity/grant-service testdata/ (doc 16 §9;
#                               scripts/check-grantref-goldens.sh).
#   check-snapshot-goldens    — byte-identity of the snapshot content_hash
#                               cross-module golden carried in both the Go
#                               producer (orchestrator/internal/nftbridge) and
#                               the Rust verifier (dataplane/crates/ds-contracts)
#                               testdata/ (doc 13 §5.1, D120;
#                               scripts/check-snapshot-goldens.sh); fails closed
#                               on divergence or a missing copy.
#   check-corpus-suffix       — cross-reader drift-corpus canonical-suffix
#                               coupling (scripts/check-corpus-suffix.sh): the Go
#                               and Rust readers' suffix constants must be byte-
#                               identical; fails named on either side missing.
#   check-searchsvc-routes    — doc-vs-code route-parity over the searchsvc README
#                               "Wire contract" route table vs serve.py's FastAPI
#                               decorators AND stdlib fallback dispatch
#                               (scripts/check-searchsvc-routes.sh); fails closed
#                               on a route/README-row mismatch. READ-ONLY.
#   check-nft-mark-constants  — doc 14 §11 mark-constant lint of the NFT-1 boot-
#                               strap ruleset (scripts/check-nft-mark-constants.sh):
#                               the floor is mark-free by design (D76 — the ct-mark
#                               arrives with NFT-5 from ds-contracts), so any mark
#                               write/match in nft-1-bootstrap.nft FAILS. Cargo-free
#                               repo-lints twin of the Rust ds-nft-mark-lint; runs
#                               its --self-test first. LOUD SKIP when the artifact
#                               is absent (DS_REQUIRE_NFT_MARK_LINT=1 → FAIL).
#   check-vendor-tracked      — every path in dataplane/vendor/*/.cargo-checksum.json
#                               "files" map must appear in `git ls-files` for its
#                               crate directory; also asserts no untracked files
#                               lurk under dataplane/vendor/ (scripts/check-vendor-
#                               tracked.sh). LOUD SKIP (stderr, exit 0) when no
#                               crate directories are present (pre-vendor branches
#                               stay green). Catches gitignore-shadowed vendor files
#                               before they vanish in fresh clones (D47 spirit).
#   check-cow-readme          — asserts the vm/cow/README RAW example
#                               (RAW=.../m0-base-*.raw) matches the raw name
#                               boot-validate.sh derives from vm/m0-image/m0-image.env
#                               (M0_BASE_SUITE + M0_CC_VERSION), token-for-token, so a
#                               pin/suite bump cannot silently drift the hand-typed
#                               example (vm/cow/check-readme-rawname.sh).
#   check-shellcheck          — runs shellcheck(1) over the tracked shell-script
#                               surface (default glob scripts/taskdb/*.sh,
#                               overridable via SHELLCHECK_GLOBS), failing closed
#                               on a real finding (scripts/check-shellcheck.sh).
#                               LOUD SKIP (stderr, exit 0) when shellcheck is
#                               absent so machines without the tool stay green;
#                               DS_REQUIRE_SHELLCHECK=1 converts that skip to a
#                               FAIL on a gate leg that provisions shellcheck.
#   check-actionlint          — runs actionlint(1) over the tracked GitHub-
#                               workflow YAML (default globs .github/workflows/
#                               *.yml|*.yaml, overridable via ACTIONLINT_GLOBS),
#                               failing closed on a real finding
#                               (scripts/check-actionlint.sh). LOUD SKIP (stderr,
#                               exit 0) when actionlint is absent so machines
#                               without the tool stay green; DS_REQUIRE_ACTIONLINT=1
#                               converts the skip to a FAIL on the CI leg that
#                               provisions actionlint; ships a --self-test run in
#                               the gate.
#   check-service-readme      — dataplane/services/* README token guards against
#                               their crate-side source of truth (the workspace
#                               manifest pins), built on scripts/lint-readme-
#                               tokens.sh; first tree is ds-dnsgate (readme-survey
#                               P1: hickory/tokio version pins vs dataplane/
#                               Cargo.toml). READ-ONLY against README + crate.
#   check-guardrail-map-tags  — structural guardrail-map<->owning-package tag
#                               seam lint (scripts/check-guardrail-map-tags.sh):
#                               for every guardrail-map.yaml row whose glob is
#                               assurance/guardrail-conformance/<pkg>/**, asserts
#                               each named tag still appears as a whole token in
#                               that owning package's *.go (its const Tag / var
#                               Tags value, or the goldenfreshness doc.go
#                               REGISTRATION 'guardrail tag:' line). Fails closed
#                               on a package-only rename, a map-only rename, or an
#                               orphaned map row whose package dropped the tag —
#                               the seam the per-package TestTagStable guards
#                               cannot see (D51 single-sourcing; D47 fail-closed).
#                               POSIX sh, network-free; ships a --self-test.
#   check-controlplane-mtls-single-builder — asserts a SINGLE TLS-dial-credentials
#                               builder symbol in orchestrator/internal/controlplane
#                               (scripts/check-controlplane-mtls-single-builder.sh):
#                               (a) NO unexported func mTLSDialOptionFromEnv
#                               forwarder, and (b) at most ONE exported
#                               func *TLSDialOptionFromEnv builder (the lone
#                               MTLSDialOptionFromEnv) — the single source of truth
#                               for the live-dial mTLS posture (doc 15 §2, D35)
#                               composed into both live legs. Scans PRODUCTION *.go
#                               only (excludes *_test.go), fails closed naming the
#                               offending file:line. POSIX sh, network-free; ships a
#                               --self-test. Owned by its script; only invoked here.
#   check-go-line-selftest    — runs scripts/check-go-line.sh --self-test, the
#                               hermetic harness for the off-workspace go-line
#                               toolchain-coupling guard single-sourced by
#                               go.yml and grant-sigterm-drain.yml. Nothing else
#                               in this Makefile invokes that script and
#                               check-shellcheck's default globs cannot reach it,
#                               so without this leg its extract/compare logic
#                               only ran when CI happened to trigger those lanes.
#                               Offline (synthetic sandbox go.work + go.mods, a
#                               canary 1.99.1 that can never match the real tree).
#   check-guardrail-scope-select — runs the D47 fail-closed guardrail-scope
#                               selector's unit tests (python3 -m unittest
#                               discover -s scripts -p
#                               'test_guardrail_scope_select.py') so the
#                               security-critical fail-closed selection mechanism
#                               (scripts/guardrail-scope-select.py, which
#                               .github/workflows/guardrail-scope.yml now invokes)
#                               is exercised by the gate: unmapped -> full matrix,
#                               meta-change -> full matrix, most-specific-glob
#                               precedence, and the no-base / empty-diff sentinels
#                               (D47; doc 06 §3c/§4). Stdlib-only, network-free.
#   repo-lints                — aggregate: all the classes above.

# check-doc-links lints relative links and #fragment anchors in docs/**/*.md
# and README.md.  Pre-existing failures are allowlisted in
# scripts/doc-links-allowlist.txt; any NEW broken link or missing fragment
# causes a non-zero exit.  Never add --no-network; external URLs are already
# skipped unconditionally.
check-doc-links:
	bash scripts/check-doc-links.sh

# check-image-drift glob-discovers every images/*/lint-*.sh and runs them all.
# Each asserts the podman-quadlet generator-key literals stay in lockstep with
# their canonical .env / compose source (the egress-gateway TLS proxy cannot
# expand EnvironmentFile= vars, so literals are kept by hand and this catches
# divergence). Scripts are owned by their image tree and resolve their own
# paths, so they run from any cwd; they are INVOKED here, never edited.
#
# Fail-closed guarantees (D47):
#   1. Per-tree presence: every images/*/ subdirectory that contains a deploy/
#      directory MUST have at least one matching lint-*.sh — a deploy/ dir with
#      no lint script is a silent gap and fails named.
#   2. Zero-match: if the glob matches no scripts at all the check exits
#      non-zero immediately.
#   3. Whitespace-safe: script paths are iterated via while/read, not word-split
#      for/in, so trees or files with spaces in their names are handled safely.
check-image-drift:
	@set -e; \
	tree_glob=$$(echo '$(IMAGE_DRIFT_GLOB)' | sed 's|/[^/]*$$||'); \
	file_glob=$$(echo '$(IMAGE_DRIFT_GLOB)' | sed 's|.*/||'); \
	presence_failed=0; \
	for tree in $$tree_glob; do \
		[ -d "$$tree" ] || continue; \
		[ -d "$$tree/deploy" ] || continue; \
		found=$$(ls "$$tree"/$$file_glob 2>/dev/null || true); \
		if [ -z "$$found" ]; then \
			echo "check-image-drift: ERROR: $$tree has deploy/ but no $$file_glob — fail-closed (D47)"; \
			presence_failed=1; \
		fi; \
	done; \
	[ "$$presence_failed" -eq 0 ] || exit 1; \
	tmplist=$$(mktemp); \
	ls -1 $(IMAGE_DRIFT_GLOB) 2>/dev/null > "$$tmplist" || true; \
	if [ ! -s "$$tmplist" ]; then \
		rm -f "$$tmplist"; \
		echo "check-image-drift: ERROR: no $(IMAGE_DRIFT_GLOB) found — fail-closed (D47)"; \
		exit 1; \
	fi; \
	while IFS= read -r s; do \
		echo "check-image-drift: running $$s"; \
		sh "$$s"; \
	done < "$$tmplist"; \
	rm -f "$$tmplist"

# check-image-drift-selftest runs the SAME glob-discovered images/*/lint-*.sh
# scripts a SECOND time, each under its --self-test flag, so the standing gate
# exercises every script's internal regression harness (the README-token /
# endpoint-port self-tests that the clean-mode check-image-drift run does NOT
# fire).  Before this target those self-tests fired only under a manual
# `--self-test` invocation (or images/mirror's smoke.sh under DS_MIRROR_SMOKE),
# so a one-sided README/source token drift passed CI silently.  Folding this
# into repo-lints makes the guards
# load-bearing in CI.  Reuses the same fail-closed presence + zero-match
# discovery as check-image-drift so a deploy/ tree that drops its lint, or a
# zero-match glob, fails named here too.  Scripts are owned by their image tree
# and only INVOKED here, never edited.
check-image-drift-selftest:
	@set -e; \
	tree_glob=$$(echo '$(IMAGE_DRIFT_GLOB)' | sed 's|/[^/]*$$||'); \
	file_glob=$$(echo '$(IMAGE_DRIFT_GLOB)' | sed 's|.*/||'); \
	presence_failed=0; \
	for tree in $$tree_glob; do \
		[ -d "$$tree" ] || continue; \
		[ -d "$$tree/deploy" ] || continue; \
		found=$$(ls "$$tree"/$$file_glob 2>/dev/null || true); \
		if [ -z "$$found" ]; then \
			echo "check-image-drift-selftest: ERROR: $$tree has deploy/ but no $$file_glob — fail-closed (D47)"; \
			presence_failed=1; \
		fi; \
	done; \
	[ "$$presence_failed" -eq 0 ] || exit 1; \
	tmplist=$$(mktemp); \
	ls -1 $(IMAGE_DRIFT_GLOB) 2>/dev/null > "$$tmplist" || true; \
	if [ ! -s "$$tmplist" ]; then \
		rm -f "$$tmplist"; \
		echo "check-image-drift-selftest: ERROR: no $(IMAGE_DRIFT_GLOB) found — fail-closed (D47)"; \
		exit 1; \
	fi; \
	while IFS= read -r s; do \
		echo "check-image-drift-selftest: running $$s --self-test"; \
		sh "$$s" --self-test; \
	done < "$$tmplist"; \
	rm -f "$$tmplist"

# check-spdx verifies that every source file in scope carries an
# SPDX-License-Identifier header, keeping the OSS/paid split auditable.
check-spdx:
	bash scripts/check-spdx.sh

# check-fixture-provenance enforces the D50 synthetic-only fixture contract —
# the git-side twin of the canary test.
check-fixture-provenance:
	sh scripts/check-fixture-provenance.sh

# check-fixture-symbols is the ARCHIVE-LEVEL twin of check-fixture-provenance
# (D50): it compiles the orchestrator sessions package's PRODUCTION archive (no
# _test.go), nm-sweeps the symbol table, and fails closed if a TEST-ONLY
# synthetic stand-in (an in-process service fake / fault-injection consumer /
# ordering-journal harness) leaked into the shipped binary by living in a
# production .go file instead of a *_fixtures_test.go file. Turns the one-off
# `go tool nm` fixture-leak proof into a standing gate. Owned by its script;
# only INVOKED here, never edited. Runs the script's non-vacuity --self-test
# first (clean PASSES / a deliberate leak FAILS) so the gate proves itself, then
# sweeps the real tree — the check-fixture-provenance self-test-in-the-gate
# precedent.
check-fixture-symbols:
	sh scripts/check-fixture-symbols.sh --self-test
	sh scripts/check-fixture-symbols.sh

# check-grantref-goldens asserts the GrantRef cross-module golden fixture is
# byte-identical in both modules that share it. mint (writer) and grant-service
# (reader) are standalone GOWORK=off modules; each suite pins only its own copy,
# so this repo-level lint is the only thing gating that the two committed copies
# stay identical (doc 16 §9 grant-fetch row), plus SHAPE-valid (doc 16 §5.1:
# .format string, .cases non-empty, ref derives as grant:<session>:<service>).
# The git-side twin of the two per-module round-trip tests. The --self-test leg
# runs FIRST so the gate proves its own adversarial arms (divergence, missing
# copy, symmetric malformed JSON, the four shape arms) still fail closed before
# the production sweep — the check-fixture-symbols self-test-in-the-gate
# precedent.
check-grantref-goldens:
	sh scripts/check-grantref-goldens.sh --self-test
	sh scripts/check-grantref-goldens.sh

# check-snapshot-goldens asserts the snapshot content_hash cross-module golden
# fixture is byte-identical in both modules that share it: the Go PRODUCER
# (orchestrator/internal/nftbridge) and the Rust VERIFIER (dataplane/crates/
# ds-contracts). Each side's suite pins only its own copy, so this repo-level
# lint is the only thing gating that the two committed copies stay identical
# (doc 13 §5.1, D120). The git-side twin of the two per-module cross-checks.
# Owned by its script; only invoked here, never edited.
check-snapshot-goldens:
	sh scripts/check-snapshot-goldens.sh

# check-corpus-suffix asserts the drift-corpus canonical-suffix constant is
# byte-identical across the Go reader (assurance/conformance-adapter/resolverlock)
# and the Rust reader (dataplane/.../pack_drift_corpus.rs), AND that the D127
# token-scope taxonomy is byte-identical across its three sites — a fail-closed
# coupling assertion: a missing or unparseable constant on either side fails
# named. Runs the script's non-vacuity --self-test FIRST (it proves the D127
# scope-parity gate fails closed on a divergent mint literal), then sweeps the
# real tree — the self-test-in-the-gate precedent.
# Owned by its script; only invoked here, never edited.
check-corpus-suffix:
	sh scripts/check-corpus-suffix.sh --self-test
	sh scripts/check-corpus-suffix.sh

# check-searchsvc-routes is a doc-vs-code route-parity lint: it asserts the
# searchsvc README "Wire contract" route table (scripts/taskdb/searchsvc/
# README.md) lists exactly the routes serve.py serves — both the FastAPI
# @app.post("/route") decorators AND the stdlib fallback self.path == "/route"
# dispatch. The table drifted from serve.py once already; this fails CLOSED the
# next time a route lands without a README row (or a README row outlives its
# route), instead of a manual reconcile. Network-free, READ-ONLY (greps both
# files, edits neither). Owned by its script; only invoked here, never edited.
check-searchsvc-routes:
	bash scripts/check-searchsvc-routes.sh

# check-nft-mark-constants is the doc 14 §11 mark-constant lint of the NFT-1
# bootstrap ruleset (dataplane/artifacts/nft/nft-1-bootstrap.nft): the floor is
# MARK-FREE by design (D76 — the composite ct-mark arrives with NFT-5 from
# ds-contracts, never authored in the floor), and this cargo-free static scan
# fails the land gate if a mark write/match is introduced there. The Rust
# ds-nft-mark-lint (dataplane/scripts/lint-nft-artifacts.sh) is the full
# bit-discipline + composition-order model over the whole artifacts/nft dir in
# the rust-dataplane / ci workflows; this is its repo-lints twin so the invariant
# holds even on a checkout with no Rust toolchain. Additive — neither replaces nor
# weakens the Rust lint. Runs the script's non-vacuity --self-test first (a clean
# ruleset PASSES / a planted mark FAILS), then scans the real artifact — the
# check-fixture-provenance self-test-in-the-gate precedent.
# Owned by its script; only INVOKED here, never edited.
check-nft-mark-constants:
	bash scripts/check-nft-mark-constants.sh --self-test
	bash scripts/check-nft-mark-constants.sh

# check-vendor-tracked asserts that every path listed in a vendored crate's
# .cargo-checksum.json "files" map is tracked by git, and that no untracked
# files lurk under dataplane/vendor/. A gitignore pattern shadowing a vendored
# file causes fresh-clone breakage (cargo build --locked checksum failure) while
# the authoring tree stays green. This lint catches that class at static-analysis
# time (D47 spirit). LOUD SKIP (exit 0, reason on stderr) when dataplane/vendor/
# has no crate directories so pre-vendor branches stay green.
check-vendor-tracked:
	bash scripts/check-vendor-tracked.sh

# check-cow-readme asserts the vm/cow/README RAW example (RAW=.../m0-base-*.raw)
# stays in lockstep with the pins boot-validate.sh derives from
# vm/m0-image/m0-image.env (M0_BASE_SUITE + M0_CC_VERSION -> m0-base-<suite>-cc<ver>).
# A CC-pin or suite bump that updates the env alone silently drifts the hand-typed
# README example; this leg recomputes the expected raw name from the env and fails
# named on any token-for-token mismatch. The vm/cow twin of verify-image-pins.sh's
# README<->env agreement, scoped to the one RAW example line. Owned by its script;
# only invoked here, never edited.
check-cow-readme:
	bash vm/cow/check-readme-rawname.sh

# check-shellcheck runs shellcheck(1) over the tracked shell-script surface
# under scripts/taskdb/ (default glob; overridable via SHELLCHECK_GLOBS),
# failing closed on a real finding. shellcheck is optional: when it is absent
# this is a LOUD clean SKIP (reason on stderr, exit 0) so machines and gate
# hosts without the tool stay green — the same fail-open-on-missing-tool
# discipline check-vendor-tracked.sh uses. Set
# DS_REQUIRE_SHELLCHECK=1 on a gate leg that provisions shellcheck to convert
# the skip into a FAIL and assert the lint is actually exercised. Owned by its
# script; only invoked here, never edited. Network-free.
check-shellcheck:
	bash scripts/check-shellcheck.sh

# check-actionlint runs actionlint(1) over the tracked GitHub-workflow YAML
# surface (.github/workflows/*.yml|*.yaml; default glob, overridable via
# ACTIONLINT_GLOBS), failing closed on a real workflow finding. actionlint is
# optional: when it is absent this is a LOUD clean SKIP (reason on stderr, exit
# 0) so machines and gate hosts without the tool stay green — the same
# fail-open-on-missing-tool discipline check-shellcheck.sh uses. Set DS_REQUIRE_ACTIONLINT=1 on a gate leg that provisions actionlint to
# convert the skip into a FAIL and assert the lint is actually exercised. Runs
# the --self-test in the gate first (the check-controlplane-mtls-single-builder
# self-test-in-the-gate precedent — both arms LOUD-SKIP rc=0 when the tool is
# absent, so a tool-less host stays green), then sweeps the real tree. Owned by
# its script; only invoked here, never edited. Network-free.
check-actionlint:
	bash scripts/check-actionlint.sh --self-test
	bash scripts/check-actionlint.sh

# check-gomod-tidy asserts the identity Go modules (identity/grant-service,
# identity/mint by default; overridable via GOMOD_TIDY_MODULES) are `go mod
# tidy`-clean, running `GOWORK=off go mod tidy -diff` per module. Nothing in the
# build gate runs `go mod tidy`, so `go work`/root `go build` resolve but never
# PRUNE the graph, and a stale `// indirect` on a now-directly-imported dep drifts
# unnoticed (mint is additionally out-of-go.work, so even the workspace tidy never
# reaches it); this fails that drift closed at lint time. READ-ONLY: `-diff` never
# edits go.mod/go.sum (no version bumps possible). Network-free (GOPROXY=off,
# resolving only the warm local cache + local `replace` targets). go is optional:
# when it is absent this is a LOUD clean SKIP (reason on stderr, exit 0) — the
# same fail-open-on-missing-tool discipline check-shellcheck.sh / check-vendor-
# tracked.sh use; a module unresolvable offline (cold cache) is likewise a loud
# per-module SKIP, not a failure. Set DS_REQUIRE_GOMOD_TIDY=1 on a gate leg that
# provisions the Go toolchain + a warm cache to convert those skips into a FAIL
# and assert the lint is actually exercised. Owned by its script; only invoked
# here, never edited.
check-gomod-tidy:
	bash scripts/check-gomod-tidy.sh

# check-no-loopback-bind is a fail-closed lint asserting the identity/ test tree
# stands up its in-process gRPC harnesses over an in-memory bufconn pipe, never a
# real loopback-TCP `net.Listen("tcp", "127.0.0.1:…")` socket bind (which fails
# under a hardened CI sandbox with no network namespace). cmd/**/main_test.go is
# allowlisted — a package-main e2e test legitimately drives the real serve path
# that binds an ephemeral socket. READ-ONLY: greps identity/**/*_test.go and
# edits nothing. grep/git only, network-free. Runs the --self-test in the gate
# first (the check-actionlint / check-macceil-drift self-test-in-the-gate
# precedent) so a refactor that neuters the matcher fails loudly, then sweeps the
# real tree. Owned by its script; only invoked here, never edited.
check-no-loopback-bind:
	bash scripts/check-no-loopback-bind.sh --self-test
	bash scripts/check-no-loopback-bind.sh

# check-service-readme guards the dataplane/services/* README load-bearing
# token literals against their crate-side source of truth (the workspace
# manifest pins), built on the shared scripts/lint-readme-tokens.sh helper
# (sourcing API, unique-match anchoring, rc 0=match / 1=drift / 2=structural).
# The first wired tree is ds-dnsgate (readme-survey P1): its frozen-stack line
# pins hickory-server/hickory-resolver and tokio versions, reconciled against
# dataplane/Cargo.toml's [workspace.dependencies] block.  READ-ONLY — it greps
# the README and manifest and edits NEITHER, and touches no crate source. The
# script carries its own regression harness (`scripts/check-service-readme.sh
# --self-test`); this target runs the production path. Owned by its script; only
# invoked here, never edited.
check-service-readme:
	sh scripts/check-service-readme.sh

# check-macceil-drift guards the nested-testbed routed-tap MAC/ceiling literals
# the manual-qemu boot path (scripts/nested-testbed/inside-l1/l2-up.sh) hand-
# maintains against their SINGLE Go source of truth: macForIndex's
# `fmt.Sprintf("52:54:00:77:%02x:01", index)` in orchestrator/internal/
# hypervisor/libvirt/live.go (the render conversion + the OUI prefix) and the
# netConfigMaxIndexThirdOct=255 /31 third-octet ceiling in the sibling
# netconfig.go. The orchestrator-driven and manual boot paths MUST pin the SAME
# MAC for a given session index or the fat-L2 image's MAC-matched *.network unit
# never fires and the guest comes up with no IP; a one-sided edit (e.g. flipping
# %02x back to %02d, which emits a malformed octet at idx 100) now fails closed.
# READ-ONLY — it greps live.go, netconfig.go, and l2-up.sh and edits NONE of them
# (l2-up.sh is owned elsewhere). POSIX sh, network-free; ships a --self-test
# (clean PASSES, each mutated literal / reworded anchor FAILS). Runs the self-test
# in the gate first (the check-controlplane-mtls / check-fixture-symbols
# self-test-in-the-gate precedent), then sweeps the real tree. Owned by its
# script; only invoked here, never edited.
check-macceil-drift:
	sh scripts/check-macceil-drift.sh --self-test
	sh scripts/check-macceil-drift.sh

# check-guardrail-map-tags asserts the seam between the repo-root
# guardrail-map.yaml and the owning guardrail-conformance packages: for every map
# row whose glob is assurance/guardrail-conformance/<pkg>/**, every tag it names
# must still appear as a whole token in that package's *.go (the const Tag / var
# Tags value, or the doc.go REGISTRATION 'guardrail tag:' line). This catches a
# tag renamed in the package only, renamed in the map only, or an orphaned map row
# whose package dropped the tag — none of which the per-package TestTagStable /
# TestTagsStable guards can see (they pin each package against itself, not the
# map). D51 single-sourcing; D47 fail-closed scoping. POSIX sh, network-free,
# go-tooling-free; ships a --self-test. Owned by its script; only invoked here.
check-guardrail-map-tags:
	sh scripts/check-guardrail-map-tags.sh

# check-controlplane-mtls-single-builder asserts a SINGLE TLS-dial-credentials
# builder symbol in orchestrator/internal/controlplane: (a) NO unexported
# in-package forwarder func mTLSDialOptionFromEnv, and (b) at most ONE exported
# func *TLSDialOptionFromEnv builder (the lone MTLSDialOptionFromEnv). That
# builder is the single source of truth for the orchestrator's live-dial mTLS
# posture (doc 15 §2, D35) composed into BOTH live legs (the hypervisor.v1
# driver dial AND the Identity D22/D82 dial); a second builder or an unexported
# forwarder splits that source and lets the two legs drift their TLS floor /
# CA-pinning / half-config posture. Scans PRODUCTION *.go only (excludes
# *_test.go, where the builder is legitimately named many times), fails closed
# naming the offending file:line. POSIX sh, network-free; ships a --self-test
# (clean PASSES, a planted second builder / unexported forwarder FAIL). Owned by
# its script; only invoked here, never edited. Runs the self-test in the gate
# first (the check-fixture-symbols self-test-in-the-gate precedent), then sweeps
# the real tree.
check-controlplane-mtls-single-builder:
	sh scripts/check-controlplane-mtls-single-builder.sh --self-test
	sh scripts/check-controlplane-mtls-single-builder.sh

# check-go-line-selftest runs the hermetic regression harness for the
# off-workspace go-line toolchain-coupling guard (scripts/check-go-line.sh),
# which is single-sourced by .github/workflows/go.yml's off-workspace-modules
# lane AND .github/workflows/grant-sigterm-drain.yml's grant-process-smoke lane.
# WHY a standing LOCAL gate: nothing in this Makefile invoked check-go-line.sh,
# and check-shellcheck's default SHELLCHECK_GLOBS (scripts/taskdb/*.sh) cannot
# match it — so its extract/compare logic only ever ran when a CI push happened
# to trigger one of those two workflows, and could regress silently in between.
# The --self-test is fully offline (synthetic sandbox go.work pinned to a canary
# 1.99.1 that can never match the real tree, plus synthetic module go.mods; four
# arms: matched -> 0, divergent -> 1, no-go-line -> 1, missing file -> per-arg
# skip 0). No toolchain, no network. `sh` (not bash) matches its `#!/bin/sh`
# shebang — see check-shebang-invocation. Owned by its script; only invoked here,
# never edited.
check-go-line-selftest:
	sh scripts/check-go-line.sh --self-test

# check-guardrail-scope-select runs the unit tests for the D47 fail-closed
# guardrail-scope selector (scripts/guardrail-scope-select.py). The selector was
# EXTRACTED from an inline heredoc in .github/workflows/guardrail-scope.yml so
# the security-critical fail-closed behavior is testable; the workflow now
# invokes the script. The tests (scripts/test_guardrail_scope_select.py, against
# SYNTHETIC fixture maps — never the live guardrail-map.yaml) cover: an unmapped
# path -> full matrix, a meta-change (an edit to the map itself) -> full matrix,
# most-specific-glob precedence (a narrowing row never weakens a broader one),
# and the no-base / empty-diff sentinels -> full matrix (D47; doc 06 §3c/§4).
# Wiring it here makes the wave/CI gate run it green. Stdlib-only, network-free.
# Owned by its scripts; only invoked here, never edited.
check-guardrail-scope-select:
	python3 -m unittest discover -s scripts -p 'test_guardrail_scope_select.py'

# check-gofmt is the toolchain-pinned gofmt formatting gate: every tracked Go
# file in the CI-built trees (orchestrator client vm proto/gen/go assurance
# scripts/taskdb identity; boundary/ excluded by design, D26) must be gofmt-clean
# under the gofmt of the go.work-PINNED toolchain (resolved via GOTOOLCHAIN so a
# dev box's newer gofmt cannot render a different verdict than CI). Pre-existing
# drift in trees this gate did not introduce is ratcheted via
# scripts/check-gofmt-allowlist.txt (the doc-links-allowlist precedent); NEW
# drift fails closed, naming the file and printing the exact `gofmt -w` fix. Runs
# the script's non-vacuity --self-test first (clean PASSES / a deliberately dirty
# file FAILS / an allowlisted dirty file PASSES) so the gate proves itself, then
# sweeps the real tree — the check-fixture-symbols self-test-in-the-gate
# precedent. Owned by its script; only INVOKED here, never edited.
check-gofmt:
	sh scripts/check-gofmt.sh --self-test
	sh scripts/check-gofmt.sh

# check-shebang-invocation is the per-invocation shebang-discipline guard: it
# cross-references EVERY literal `sh|bash <path>.sh` invocation in the Makefile
# recipe lines AND the ci.yml `run:` steps against the target script's shebang,
# failing closed when a caller's interpreter does not match. `bash foo.sh` on a
# `#!/bin/sh` script masks accidental bashisms (the class the ci.yml
# check-corpus-suffix / check-grantref-goldens lines fell into); `sh foo.sh` on a
# `#!/usr/bin/env bash` script breaks at runtime under a strict POSIX /bin/sh.
# This locks that class as a standing gate. READ-ONLY (greps the Makefile, ci.yml,
# and target shebangs; edits nothing). POSIX sh, network-free. Runs the
# non-vacuity --self-test first (matched invocations PASS; a bash-invokes-sh /
# sh-invokes-bash / missing-target / unrecognised-shebang mutation FAILS) — the
# check-fixture-symbols self-test-in-the-gate precedent — then sweeps the real
# tree. Owned by its script; only invoked here, never edited.
check-shebang-invocation:
	sh scripts/check-shebang-invocation.sh --self-test
	sh scripts/check-shebang-invocation.sh

# check-spectate-fixture-pair pins the D80-crossing golden spectate fixture's
# PRODUCER and CONSUMER into ONE gate step. The fixture file
# client/cmd/serpent/testdata/spectate_golden.frames is the SOLE artifact crossing
# the D80 module fence (the stdlib-only client tree cannot import the orchestrator),
# so its two guardian tests live in DIFFERENT Go modules:
#   - PRODUCER: orchestrator TestContentRelay_WritesGoldenSpectateFixture byte-asserts
#     the on-disk fixture against the REAL WatchSession handler's wire output;
#   - CONSUMER: client TestSpectateGoldenFixtureReplay decodes+renders the same file
#     and asserts the fixed spectator want-strings.
# Run as independent sharded `go test` jobs those two could disagree silently: a PR
# that regenerates the fixture (DS_REGEN_SPECTATE_FIXTURE=1) without refreshing the
# client want-strings — or edits the want-strings without regenerating — would go
# green if only one shard ran. Folding BOTH into one target repo-lints depends on
# makes either half-edit RED. DS_REGEN_SPECTATE_FIXTURE is cleared here so this gate
# always ASSERTS, never rewrites, the fixture. -count=1 defeats the go test cache so
# a fixture edit is always re-observed. Both modules are in go.work; no scripts/
# helper — the two `go test` invocations ARE the gate.
check-spectate-fixture-pair:
	cd orchestrator && DS_REGEN_SPECTATE_FIXTURE= go test ./internal/controlplane/ -run '^TestContentRelay_WritesGoldenSpectateFixture$$' -count=1
	cd client && DS_REGEN_SPECTATE_FIXTURE= go test ./cmd/serpent/ -run '^TestSpectateGoldenFixtureReplay$$' -count=1

# repo-lints is the single-source aggregate fail-closed gate: doc links,
# image-config drift (all images/*/lint-*.sh, clean mode AND --self-test), SPDX
# headers, fixture provenance, the doc 15 §6.1 freeze riders, GrantRef golden
# byte-identity, the snapshot content_hash golden byte-identity, the
# cross-reader corpus-suffix coupling, the searchsvc README
# route-parity, the docs/partners §2.7.1 runbook-nft grammar, vendor tracking
# hygiene, the runbook-nft selftest harness, the vm/cow/README RAW-example pin
# agreement, the scripts/taskdb shellcheck pass, the GitHub-workflow actionlint
# pass (clean mode AND --self-test), the dataplane/services/*
# README token guards, the nested-testbed routed-tap MAC render + /31 ceiling
# drift guard (l2-up.sh vs the live.go/netconfig.go Go source), the
# guardrail-map<->owning-package tag seam, the
# D47 fail-closed guardrail-scope selector unit tests, the off-workspace
# go-line guard's own --self-test, the toolchain-pinned gofmt formatting gate,
# the per-invocation shebang-discipline guard, and the
# D80-crossing spectate golden-fixture producer/consumer pair (one gate so a
# fixture regeneration and its client want-strings can never drift apart across
# sharded jobs).
# `make repo-lints` is what developers run locally AND what CI invokes — keeping
# the two in lockstep by construction.
repo-lints: check-doc-links check-image-drift check-image-drift-selftest \
	check-spdx check-fixture-provenance check-fixture-symbols \
	check-grantref-goldens check-snapshot-goldens \
	check-corpus-suffix check-searchsvc-routes \
	check-nft-mark-constants \
	check-vendor-tracked check-cow-readme \
	check-shellcheck check-actionlint check-service-readme check-macceil-drift \
	check-gomod-tidy check-no-loopback-bind \
	check-guardrail-map-tags \
	check-guardrail-scope-select check-controlplane-mtls-single-builder \
	check-go-line-selftest check-gofmt \
	check-shebang-invocation check-spectate-fixture-pair
