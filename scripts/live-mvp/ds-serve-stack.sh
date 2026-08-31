#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# ds-serve-stack.sh — bring up the production-shaped service stack for
#   `serpent claude` -> running orchestrator -> per-session KVM VM -> interactive in-VM CC.
#
# MVP scope (contained to a single trusted host): NO auth (fake/no-op the attach token +
# identity), SLIRP-direct egress, the OAuth token injected into the VM. The gated-egress
# gateways (ds-dnsgate/ds-tlsproxy) + real auth are SEPARATE later phases — NOT started here.
#
# This script starts, as services on the host:
#   (2) the HOST-AGENT (hypervisor.v1 HypervisorDriverService) — owns the VM lifecycle,
#       boots the rootless direct-kernel M0 image, serves the writer-seat attach UDS.
#   (3) the ORCHESTRATOR control plane (SessionService) — CreateSession routes to the
#       host-agent via the DriverRegistry; Attach returns the served writer UDS.
# The everyday command then runs in a SEPARATE terminal (printed at the end):
#       serpent claude --vm --repo demo --env-config-ref demo-env --launching-user mvp-user
#
# Rootless: /dev/kvm + /dev/vhost-vsock are 0666; qemu:///session autospawns virtqemud.
# All scratch under ~/tmp (btrfs/reflink), never /tmp.
#
# Usage:
#   scripts/live-mvp/ds-serve-stack.sh up        # build (if needed) + start host-agent + orchestrator
#   scripts/live-mvp/ds-serve-stack.sh down      # stop both services
#   scripts/live-mvp/ds-serve-stack.sh build     # (re)build the binaries into <repo>/.bin
#   scripts/live-mvp/ds-serve-stack.sh preflight # check artifacts/binaries + the auth credential, boot nothing
#   scripts/live-mvp/ds-serve-stack.sh status    # show running pids + the served attach sockets/overlays
#   scripts/live-mvp/ds-serve-stack.sh command   # print the `serpent claude --vm` command to run
#
# Auth: DS_AUTH_POSTURE=oauth (default, ~/.claude/.credentials.json) | swap
# (a host-local token-swap proxy). Either way the credential goes to the host-agent
# in a 0600 -launch-env-file, never on an argv.
set -euo pipefail

# --- repo + paths -----------------------------------------------------------
# This script lives in <repo>/scripts/live-mvp/. SCRIPT_DIR anchors the sibling
# helper (ds-genisoimage-podman.sh). REPO defaults to the checkout two levels up
# (so `up` builds the branch the script is checked out on); override for a
# different worktree: REPO=/path/to/worktree scripts/live-mvp/ds-serve-stack.sh up
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="${REPO:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
# Build into the repo's .bin (gitignored) by default — the same dir `make
# live-stack` writes — so the stack this script launches and the `.bin/serpent`
# you run are one fresh build. Override with DS_BIN_DIR for an out-of-tree build.
BIN="${DS_BIN_DIR:-$REPO/.bin}"
IMAGES="${DS_IMAGES_DIR:-$HOME/tmp/ds-images}"
OVERLAYS="${DS_OVERLAY_DIR:-$HOME/tmp/ds-overlays}"
ATTACH="${DS_ATTACH_DIR:-$HOME/tmp/ds-attach}"
RUN="${DS_RUN_DIR:-$HOME/tmp/ds-serve-run}"   # pids + logs

HOSTAGENT_LISTEN="${HOSTAGENT_LISTEN:-127.0.0.1:18091}"
ORCH_LISTEN="${ORCH_LISTEN:-127.0.0.1:18090}"
HOST_ID="${HOST_ID:-local-dev}"

# SESSION_MODE selects the in-VM CC surface:
#   structured (default) — headless stream-json CC, attach.v1 events over a DIRECT
#                          endpoint (the bubbletea TUI / `serpent claude --vm`).
#   terminal             — raw pty TUI: the host lowers stdio=PTY and serves a
#                          RAW_TERMINAL carriage; the dev's terminal IS the in-VM CC
#                          (`serpent claude --vm --raw on`). REQUIRES a pty-mode image
#                          (ds-entrypoint with the PTY launch-mode baked in).
SESSION_MODE="${DS_SESSION_MODE:-structured}"

# In-guest CC posture knobs, needed by headless lanes that do real work in the
# workspace (e.g. the manclaw taskq work-product lane):
#   DS_WORKING_DIR     — where CC starts in the guest. The default is the guest
#                        home; a workspace-disk lane wants /work/<repo> so the
#                        repo IS the project dir.
#   DS_PERMISSION_MODE — CC --permission-mode. Headless structured runs have no
#                        interactive ask-answerer: a can_use_tool ask nobody
#                        answers is an auto-deny, so a lane that must WRITE files
#                        needs acceptEdits (edits auto-approved; bash still asks).
#   DS_TRUST_WORKSPACE — 1 adds -launch-env CLAUDE_TRUST_WORKSPACE=1 (skip the
#                        untrusted-directory gate for the workspace mount).
WORKING_DIR="${DS_WORKING_DIR:-/home/ds}"
PERMISSION_MODE="${DS_PERMISSION_MODE:-default}"
TRUST_WORKSPACE="${DS_TRUST_WORKSPACE:-0}"

# Defaults track the artifacts the current rootless bake produces (routed-cc);
# the older -v2/-v3 names are gone. preflight names the override var for whichever
# one is missing, so a stale default can never boot the wrong image silently.
KERNEL="${DS_KERNEL_PATH:-$IMAGES/m0-vmlinuz-routed-cc}"
INITRD="${DS_INITRD_PATH:-$IMAGES/m0-initrd-routed-cc.img}"
# Terminal mode needs the pty-launch ds-entrypoint in the rootfs. Prefer the
# pty-baked image when present and DS_BASE_IMAGE wasn't pinned; otherwise fall
# back to routed-cc (structured) and let preflight warn if terminal mode was requested.
if [[ -z "${DS_BASE_IMAGE:-}" && "$SESSION_MODE" == "terminal" && -r "$IMAGES/m0-base-pty.raw" ]]; then
  BASE_IMAGE="$IMAGES/m0-base-pty.raw"
else
  BASE_IMAGE="${DS_BASE_IMAGE:-$IMAGES/m0-base-routed-cc.raw}"
fi
OVERLAY_CREATE="${DS_OVERLAY_CREATE:-$REPO/vm/cow/overlay-create.sh}"

# ip=dhcp is a WORKAROUND for a defect in the routed-cc image, not a preference.
# That bake runs apt with --no-install-recommends and never lists dbus, so the
# guest has no system bus; ds-slirp-net.service (which installs the SLIRP DHCP
# .network) ends with `networkctl reload`, which on systemd 252 REQUIRES the bus.
# The reload fails -> the unit fails -> the already-running networkd never re-reads
# the dropped config -> the NIC is never addressed -> in-guest CC dies with
# "API Error: FailedToOpenSocket". ip=dhcp sidesteps the reload entirely:
# systemd-network-generator renders the config into /run/systemd/network BEFORE
# networkd starts. This script is SLIRP-ONLY (it never passes -routed-tap, whose
# guests get a STATIC 10.77.<idx>.1/31 from the config-drive), so there is no
# DHCP-vs-static race here. DROP this default once a dbus-bearing image is baked
# and live-validated. The rest is libvirt.DefaultKernelCmdline verbatim
# (orchestrator/internal/hypervisor/libvirt/live.go).
KCMDLINE="${DS_KERNEL_CMDLINE:-root=LABEL=DS_M0ROOT console=ttyS0,115200 rw ip=dhcp}"

mkdir -p "$BIN" "$OVERLAYS" "$ATTACH" "$RUN"

HA_PID="$RUN/host-agent.pid"; HA_LOG="$RUN/host-agent.log"
ORCH_PID="$RUN/orchestrator.pid"; ORCH_LOG="$RUN/orchestrator.log"

# --- build ------------------------------------------------------------------
build() {
  echo ">> building 6 binaries from $REPO into $BIN"
  ( cd "$REPO" && go build -o "$BIN/ds-host-agent"  ./orchestrator/cmd/host-agent )
  ( cd "$REPO" && go build -o "$BIN/ds-orchestrator" ./orchestrator/cmd/orchestrator )
  ( cd "$REPO" && go build -o "$BIN/ds-driver-e2e"   ./orchestrator/cmd/ds-driver-e2e )
  ( cd "$REPO" && go build -o "$BIN/ds-hostbridge"   ./client/cmd/ds-hostbridge )
  ( cd "$REPO" && go build -o "$BIN/serpent"         ./client/cmd/serpent )
  ( cd "$REPO/serpent-tui" && GOWORK=off go build -o "$BIN/serpent-tui" ./cmd/serpent-tui )
  echo ">> built: $(ls -1 "$BIN")"
}

# --- in-guest CC credential (NEVER printed/logged) --------------------------
# The credential reaches the host-agent through a 0600 KEY=VALUE file, NOT the
# argv: /proc/<pid>/cmdline is world-readable, so a `-launch-env TOKEN=...` entry
# publishes the secret to every local process (which is why the host-agent's own
# -launch-env help says non-secret references ONLY, D7/D39). The host-agent reads
# -launch-env-file ONCE at flag-parse time and REJECTS modes looser than 0600, so
# start_hostagent deletes the file as soon as the child is up.
#
# DS_AUTH_POSTURE selects the credential SOURCE:
#   oauth (default) — the operator's Claude OAuth access token from
#                     ~/.claude/.credentials.json (the historical behavior).
#   swap            — posture B: the in-guest CC talks to a HOST-local token-swap
#                     proxy, so the secret is that proxy's bearer token and the
#                     endpoint is a non-secret argv env entry. Use this when the
#                     on-disk OAuth credential is a stub (empty accessToken).
AUTH_POSTURE="${DS_AUTH_POSTURE:-oauth}"
SECRETS_ENV="$RUN/launch-secrets.env"
# 10.0.2.2 is SLIRP's alias for the host, so the guest reaches a host-local
# token proxy without depending on LAN routing. Address only — never a secret.
SWAP_BASE_URL="${DS_SWAP_BASE_URL:-http://10.0.2.2:8787}"
SWAP_TOKEN_FILE="${DS_SWAP_TOKEN_FILE:-$HOME/.config/dream-serpent/proxy-auth-token}"

# write_secret_env <dest> — render the chosen posture's credential into a 0600
# KEY=VALUE file. The token is never echoed, never exported, never on an argv.
write_secret_env() {
  local dest="${1:-$SECRETS_ENV}"
  local tok=""
  # Unlink FIRST: `>` truncates in place, so a pre-existing file keeps its (possibly
  # 0644) mode for the whole write window, and a pre-planted SYMLINK would redirect the
  # token somewhere else entirely. Removing it makes the redirect a fresh create under
  # the umask below; the chmod at the end is then only a belt-and-braces assert.
  rm -f "$dest"
  case "$AUTH_POSTURE" in
    oauth)
      local cred="$HOME/.claude/.credentials.json"
      if [[ ! -r "$cred" ]]; then
        echo "ERROR: ~/.claude/.credentials.json not readable — log in to Claude, or use DS_AUTH_POSTURE=swap if this host runs a token-swap proxy" >&2
        return 1
      fi
      tok="$(jq -r '.claudeAiOauth.accessToken // empty' "$cred")"
      if [[ -z "$tok" || "$tok" == "null" ]]; then
        echo "ERROR: OAuth credential at ~/.claude/.credentials.json is missing/stub (empty accessToken) — refresh your Claude login, or use DS_AUTH_POSTURE=swap if this host runs a token-swap proxy" >&2
        return 1
      fi
      ( umask 077; printf 'CLAUDE_CODE_OAUTH_TOKEN=%s\n' "$tok" > "$dest" ) || return 1
      ;;
    swap)
      if [[ ! -r "$SWAP_TOKEN_FILE" ]]; then
        echo "ERROR: token-swap proxy token file not readable: $SWAP_TOKEN_FILE — start the proxy, or point DS_SWAP_TOKEN_FILE at the right file" >&2
        return 1
      fi
      tok="$(tr -d '\r\n' < "$SWAP_TOKEN_FILE")"
      if [[ -z "$tok" ]]; then
        echo "ERROR: token-swap proxy token file is empty: $SWAP_TOKEN_FILE — point DS_SWAP_TOKEN_FILE at the right file" >&2
        return 1
      fi
      ( umask 077; printf 'ANTHROPIC_AUTH_TOKEN=%s\n' "$tok" > "$dest" ) || return 1
      ;;
    *)
      echo "ERROR: unknown DS_AUTH_POSTURE=$AUTH_POSTURE — valid values: oauth, swap" >&2
      return 1
      ;;
  esac
  # umask only bounds a CREATE; an inherited looser file would survive it.
  chmod 600 "$dest"
}

# --- preflight --------------------------------------------------------------
preflight() {
  local ok=1
  # Each artifact carries the env var that overrides it, so a missing default is
  # always actionable (and a stale default can never boot the wrong file silently).
  local pair f var
  for pair in "$KERNEL:DS_KERNEL_PATH" "$INITRD:DS_INITRD_PATH" "$BASE_IMAGE:DS_BASE_IMAGE"; do
    f="${pair%:*}"; var="${pair##*:}"
    [[ -r "$f" ]] || { echo "MISSING rootless M0 artifact: $f — set $var to override, or place the file there" >&2; ok=0; }
  done
  [[ -x "$OVERLAY_CREATE" ]] || { echo "MISSING/!exec overlay-create: $OVERLAY_CREATE" >&2; ok=0; }
  [[ -x "$BIN/ds-host-agent" && -x "$BIN/ds-orchestrator" && -x "$BIN/ds-hostbridge" && -x "$BIN/serpent" && -x "$BIN/serpent-tui" ]] \
    || { echo "binaries missing under $BIN — run '$0 build'" >&2; ok=0; }
  if [[ "$SESSION_MODE" == "terminal" ]]; then
    # The host-agent must understand -session-mode (rebuild from current main if not),
    # and terminal mode needs a pty-baked image or the guest serves no pty carriage.
    local hahelp; hahelp="$("$BIN/ds-host-agent" -h 2>&1 || true)"
    case "$hahelp" in
      *-session-mode*) : ;;
      *) echo "host-agent has no -session-mode flag — rebuild from current main: make live-stack" >&2; ok=0 ;;
    esac
    case "$BASE_IMAGE" in
      *m0-base-pty*) : ;;
      *) echo "WARN: terminal mode but BASE_IMAGE=$BASE_IMAGE is not a pty-baked image — the guest may serve no pty carriage. Rebake (vm/m0-image/build-m0-image.sh --build) or pin DS_BASE_IMAGE to the pty .raw." >&2 ;;
    esac
  fi
  [[ -c /dev/kvm ]] || { echo "WARN: /dev/kvm absent — boot will fail" >&2; }
  # Credential prerequisites are POSTURE-scoped: jq only parses the OAuth JSON.
  case "$AUTH_POSTURE" in
    oauth)
      command -v jq >/dev/null || { echo "MISSING jq (needed to read the OAuth credential under DS_AUTH_POSTURE=oauth)" >&2; ok=0; }
      ;;
    swap)
      if [[ ! -r "$SWAP_TOKEN_FILE" ]]; then
        echo "MISSING token-swap proxy token file: $SWAP_TOKEN_FILE — start the proxy, or set DS_SWAP_TOKEN_FILE" >&2; ok=0
      elif [[ ! -s "$SWAP_TOKEN_FILE" ]]; then
        echo "EMPTY token-swap proxy token file: $SWAP_TOKEN_FILE — set DS_SWAP_TOKEN_FILE" >&2; ok=0
      fi
      ;;
    *)
      echo "BAD DS_AUTH_POSTURE=$AUTH_POSTURE — valid values: oauth, swap" >&2; ok=0
      ;;
  esac
  [[ $ok == 1 ]] || { echo "preflight failed" >&2; return 1; }
}

# --- start host-agent (step 2) ----------------------------------------------
start_hostagent() {
  if [[ -f "$HA_PID" ]] && kill -0 "$(cat "$HA_PID")" 2>/dev/null; then
    echo ">> host-agent already running (pid $(cat "$HA_PID"))"; return 0
  fi
  write_secret_env "$SECRETS_ENV"
  echo ">> starting host-agent on $HOSTAGENT_LISTEN ($SESSION_MODE mode, rootless direct-kernel M0, SLIRP, CC auth posture: $AUTH_POSTURE)"
  # The launch argv depends on SESSION_MODE. STRUCTURED folds the DRIVABLE stream-json
  # CC argv through the EntrypointProducer (attach.v1 events over a DIRECT endpoint).
  # TERMINAL drops the headless-only flags (--input-format/--output-format/--verbose/
  # --no-session-persistence/--permission-prompt-tool=stdio — the host strips them too,
  # but we keep the argv honest) and passes -session-mode terminal so the host lowers
  # stdio=PTY and serves a RAW_TERMINAL pty carriage: CC starts as an interactive TUI.
  local mode_args=() launch_args=()
  if [[ "$SESSION_MODE" == "terminal" ]]; then
    mode_args=(-session-mode terminal)
    launch_args=(
      -launch-command /usr/bin/claude
      -launch-arg --model -launch-arg sonnet
      -launch-arg --permission-mode -launch-arg "$PERMISSION_MODE"
      -launch-arg --max-budget-usd -launch-arg 1
    )
  else
    launch_args=(
      -launch-command /usr/bin/claude
      -launch-arg --input-format -launch-arg stream-json
      -launch-arg --output-format -launch-arg stream-json
      -launch-arg --verbose
      -launch-arg --no-session-persistence
      -launch-arg --model -launch-arg sonnet
      -launch-arg --permission-mode -launch-arg "$PERMISSION_MODE"
      -launch-arg --permission-prompt-tool -launch-arg stdio
      -launch-arg --max-budget-usd -launch-arg 1
    )
  fi
  # Non-secret in-guest env travels on the argv; the credential does NOT (see
  # write_secret_env). The swap posture's base URL is an ADDRESS, so it belongs here.
  local env_args=(
    -launch-env HOME=/home/ds
    -launch-env CLAUDE_CONFIG_DIR=/home/ds/.claude
    -launch-env NODE_OPTIONS=--max-old-space-size=1536
  )
  if [[ "$AUTH_POSTURE" == "swap" ]]; then
    env_args+=(-launch-env "ANTHROPIC_BASE_URL=$SWAP_BASE_URL")
  fi
  if [[ "$TRUST_WORKSPACE" == "1" ]]; then
    env_args+=(-launch-env CLAUDE_TRUST_WORKSPACE=1)
  fi
  # DS_HOSTAGENT_LIVE=1 arms the libvirt booter. DS_KERNEL_PATH/DS_INITRD_PATH select the
  # rootless direct-kernel boot. SLIRP = omit -routed-tap. DS_SERIAL_LOG parks each guest's
  # serial log next to its overlay (the only view of a guest that never gets to the attach
  # carriage — e.g. a NIC that never addressed).
  DS_HOSTAGENT_LIVE=1 \
  DS_KERNEL_PATH="$KERNEL" \
  DS_INITRD_PATH="$INITRD" \
  DS_SERIAL_LOG="$OVERLAYS" \
  DS_HOSTAGENT_SKIP_CA_INJECT=1 \
  DS_HOSTAGENT_GENISOIMAGE_BIN="${DS_GENISOIMAGE_BIN:-$SCRIPT_DIR/ds-genisoimage-podman.sh}" \
  DS_HOSTBRIDGE_NO_AUTH=1 \
  nohup "$BIN/ds-host-agent" \
    -listen "$HOSTAGENT_LISTEN" \
    -host-id "$HOST_ID" \
    -base-image "$BASE_IMAGE" \
    -kernel-cmdline "$KCMDLINE" \
    -overlay-create-script "$OVERLAY_CREATE" \
    -overlay-dir "$OVERLAYS" \
    -attach-socket-dir "$ATTACH" \
    -hostbridge-bin "$BIN/ds-hostbridge" \
    -orchestrator-addr "$ORCH_LISTEN" \
    -event-socket-path /run/ds/attach.sock \
    -working-dir "$WORKING_DIR" \
    "${mode_args[@]}" \
    "${launch_args[@]}" \
    "${env_args[@]}" \
    -launch-env-file "$SECRETS_ENV" \
    >"$HA_LOG" 2>&1 &
  echo $! > "$HA_PID"
  sleep 1
  if ! kill -0 "$(cat "$HA_PID")" 2>/dev/null; then
    rm -f "$SECRETS_ENV"
    echo "host-agent exited immediately — see $HA_LOG" >&2; tail -20 "$HA_LOG" >&2; return 1
  fi
  # The host-agent read the file at flag-parse time; nothing re-reads it, so it
  # must not outlive the launch (a live process is the only holder of the secret).
  rm -f "$SECRETS_ENV"
  echo ">> host-agent pid $(cat "$HA_PID") (log: $HA_LOG)"

  # Seed the D38 opaque EntrypointConfig role-overlay drop the host-agent's gap-1
  # EntrypointProducer fetches at step-8 (it fail-closes on a missing drop:
  # "entrypoint ref <ref> not present in host store .ds-entrypoint-refs"). The orchestrator
  # is the producer of this drop in the full design; on this single-box MVP the bringup
  # pre-materializes it. The bytes are an OPAQUE, runtime-ignorant role overlay the host
  # never inspects (the role's runtime axis) — the DRIVABLE CC launch (the stream-json claude
  # argv + the injected OAuth token) comes from the host-agent's -launch-* facts, NOT this
  # overlay — so a minimal non-credential blob satisfies the fail-closed fetch. The ref MUST
  # equal the create's --env-config-ref (demo-env).
  EPREFS="$OVERLAYS/.ds-entrypoint-refs"
  mkdir -p "$EPREFS"
  if [[ ! -s "$EPREFS/demo-env" ]]; then
    printf '{"ds_role_overlay":"mvp","runtime":null}\n' > "$EPREFS/demo-env"
    echo ">> seeded D38 opaque entrypoint-config role-overlay drop at $EPREFS/demo-env"
  fi

  # Open the recover-before-serve latch (D66) on this recovery-wired (LIVE) host so the
  # orchestrator's first CloneFromImage may serve. RecoverSessions is host-side and
  # idempotent (it boots no VM); the single-box MVP runs it once here, standing in for an
  # orchestrator-driven RecoverSessions on host registration. Without it CreateSession
  # fails at 4-host-alloc: "recover-before-serve: RecoverSessions must complete before
  # CloneFromImage on a recovery-wired host (D66)".
  if [[ -x "$BIN/ds-driver-e2e" ]]; then
    echo ">> opening recover-before-serve latch (RecoverSessions, no VM boot) on $HOST_ID"
    "$BIN/ds-driver-e2e" -addr "$HOSTAGENT_LISTEN" -host-id "$HOST_ID" -mode recover 2>&1 \
      | sed 's/^/   /' || echo "   WARN: RecoverSessions latch open failed — CreateSession may fail at 4-host-alloc" >&2
  fi
}

# --- start orchestrator (step 3) --------------------------------------------
start_orchestrator() {
  if [[ -f "$ORCH_PID" ]] && kill -0 "$(cat "$ORCH_PID")" 2>/dev/null; then
    echo ">> orchestrator already running (pid $(cat "$ORCH_PID"))"; return 0
  fi
  echo ">> starting orchestrator on $ORCH_LISTEN (in-memory store, no auth, dialing $HOSTAGENT_LISTEN)"
  # In-memory store (DS_ORCH_PG_DSN unset). No TLS / no identity endpoint (insecure, MVP).
  # DS_ORCH_HOST_DRIVERS host_id MUST equal the host-agent -host-id. The attach-socket-dir
  # MUST match the host-agent's so the served writer UDS is the one serpent-tui dials.
  # DS_ORCH_SEED_ENV_CONFIG seeds the §4.1 step-1 env config so a fresh in-memory live run
  # can complete CreateSession (the GAP-A fix); DS_ORCH_SEED_REPO_ID matches the create --repo.
  # DS_ORCH_FAKE_IDENTITY=1 = the MVP no-auth in-process loopback identity (no real
  # identity.v1 service). DS_ORCH_OVERLAY_DIR matches the host-agent -overlay-dir so the
  # minted throwaway CA bundle drops where the host-agent's step-7 inject consumer reads it.
  DS_ORCH_LIVE=1 \
  DS_ORCH_LISTEN="$ORCH_LISTEN" \
  DS_ORCH_HOST_DRIVERS="$HOST_ID=$HOSTAGENT_LISTEN" \
  DS_ORCH_DEFAULT_ORG=mvp-org \
  DS_ORCH_ROLES_DIR="$REPO/roles" \
  DS_ORCH_ATTACH_SOCKET_DIR="$ATTACH" \
  DS_ORCH_OVERLAY_DIR="$OVERLAYS" \
  DS_ORCH_FAKE_IDENTITY=1 \
  DS_ORCH_SEED_ENV_CONFIG="demo-env=m0-base" \
  DS_ORCH_SEED_REPO_ID=demo \
  nohup "$BIN/ds-orchestrator" >"$ORCH_LOG" 2>&1 &
  echo $! > "$ORCH_PID"
  sleep 1
  if ! kill -0 "$(cat "$ORCH_PID")" 2>/dev/null; then
    echo "orchestrator exited immediately — see $ORCH_LOG" >&2; tail -20 "$ORCH_LOG" >&2; return 1
  fi
  echo ">> orchestrator pid $(cat "$ORCH_PID") (log: $ORCH_LOG)"
}

stop_one() {
  local pidf="$1" name="$2"
  if [[ -f "$pidf" ]] && kill -0 "$(cat "$pidf")" 2>/dev/null; then
    echo ">> stopping $name (pid $(cat "$pidf"))"
    kill "$(cat "$pidf")" 2>/dev/null || true
    sleep 1
    kill -9 "$(cat "$pidf")" 2>/dev/null || true
  fi
  rm -f "$pidf"
}

# destroy_session_domains tears down every lingering per-session VM (libvirt domain).
# A session is a persistent, re-attachable resource (D61): the host-agent does NOT reap
# it when a client detaches, and killing the host-agent PROCESS does not stop its domains —
# so a plain `down` would leak every booted VM (8G each) as an orphaned qemu:///session
# domain. A DestroySession DOES now destroy the domain (the host-agent's §4.2 step 1 runs
# the real `virsh destroy ds-<uuid>` under DS_HOSTAGENT_LIVE), so a session torn down
# through the product leaves nothing here; this sweep remains the BACKSTOP for the cases
# that never reach a Destroy — a crashed/killed host-agent, an aborted run, a session the
# operator never destroyed. Session overlays under $OVERLAYS are KEPT (they hold session
# data); `down --purge` also removes them. (The durable in-product fix is U-IDLE-REAPER +
# serpent --rm; this is the operator-side stack-teardown sweep.)
destroy_session_domains() {
  command -v virsh >/dev/null || return 0
  local doms d
  doms="$(virsh -c qemu:///session list --name 2>/dev/null | grep '^ds-sess-' || true)"
  [[ -z "$doms" ]] && return 0
  while IFS= read -r d; do
    [[ -z "$d" ]] && continue
    echo ">> destroying lingering session VM: $d"
    virsh -c qemu:///session destroy "$d" >/dev/null 2>&1 || true
  done <<< "$doms"
}

print_command() {
  local raw_flag="" raw_note=""
  if [[ "$SESSION_MODE" == "terminal" ]]; then
    raw_flag=" --raw on"
    raw_note="The handle advertises a RAW_TERMINAL endpoint, so your terminal BECOMES the in-VM
Claude Code TUI (ssh/mosh-style): Ctrl-C interrupts CC, Ctrl-] detaches (the VM keeps running;
re-attach with --session). Run in a REAL terminal (raw mode needs a TTY)."
  else
    raw_note="Structured mode: the bubbletea attach loop drives + renders attach.v1 events. Add a
pty-baked image + DS_SESSION_MODE=terminal for the raw-terminal CC TUI (serpent claude --vm --raw on)."
  fi
  cat <<EOF

=== run the everyday command in a SEPARATE terminal ($SESSION_MODE mode) ===
  export DS_ORCHESTRATOR=$ORCH_LISTEN
  $BIN/serpent claude --vm$raw_flag --repo demo --env-config-ref demo-env --launching-user mvp-user

  # equivalent fully-explicit form (no env reliance):
  $BIN/serpent claude --vm$raw_flag \\
    --orchestrator $ORCH_LISTEN --repo demo --env-config-ref demo-env --launching-user mvp-user

This EXECs serpent-tui up -> CreateSession (orchestrator boots the per-session KVM VM via the
host-agent) -> Attach(WRITER) -> the interactive loop that IS the CC inside the VM.
$raw_note
The default 'serpent claude' (no --vm, no DS_ORCHESTRATOR) still runs LOCAL CC via ds-capture, unchanged.

=== Tier-2 host-agent leg only (real KVM boot + writer attach handle, no orchestrator) ===
  $BIN/ds-driver-e2e -addr $HOSTAGENT_LISTEN -session host-agent-mvp-1 -host-id $HOST_ID
EOF
}

case "${1:-up}" in
  build) build ;;
  preflight)
    # No-VM verification hook: check the artifacts/binaries AND prove the chosen
    # posture's credential source actually resolves, WITHOUT starting anything.
    # Both halves always run (a missing binary must not hide a stub credential),
    # and the scratch render lands under $RUN and is deleted immediately.
    PF_RC=0
    preflight || PF_RC=$?
    CHECK_ENV="$RUN/launch-secrets.check.env"
    if write_secret_env "$CHECK_ENV"; then
      echo "auth posture '$AUTH_POSTURE': credential source OK (rendered $(stat -c %a "$CHECK_ENV") $CHECK_ENV, deleted)"
    else
      PF_RC=1
    fi
    rm -f "$CHECK_ENV"
    if [[ $PF_RC == 0 ]]; then
      echo "preflight OK ($AUTH_POSTURE posture, kernel cmdline: $KCMDLINE)"
    fi
    exit "$PF_RC"
    ;;
  up)
    [[ -x "$BIN/ds-host-agent" ]] || build
    preflight
    # Orchestrator FIRST so the host-agent's heartbeat reporter (-orchestrator-addr)
    # connects immediately and the scheduler's candidate feed has this host before the
    # first CreateSession (else placement fails "no placeable host: candidate set empty").
    # Both dials are otherwise lazy (orchestrator->host-agent driver dial is per-RPC), so
    # the reverse start order only matters for the heartbeat warm-up window.
    start_orchestrator
    start_hostagent
    print_command
    ;;
  down)
    stop_one "$ORCH_PID" orchestrator
    stop_one "$HA_PID" host-agent
    destroy_session_domains
    if [[ "${2:-}" == "--purge" ]]; then
      echo ">> --purge: removing session overlays and CA bundles under $OVERLAYS"
      rm -f "$OVERLAYS"/sess-*.qcow2 "$OVERLAYS"/sess-*.config.iso 2>/dev/null || true
      rm -rf "$OVERLAYS"/sess-*.config.d 2>/dev/null || true
      # Per-session serial logs (ds-<uuid>.serial.log, from DS_SERIAL_LOG=$OVERLAYS).
      # They hold the raw guest console and §4.2 teardown does not purge them, so the
      # stack teardown must.
      rm -f "$OVERLAYS"/ds-*.serial.log 2>/dev/null || true
      # The host-side per-session stores. destroy_session_domains is the BACKSTOP path
      # (a killed host-agent, an aborted run) — it kills the domain but never runs the
      # §4.2 teardown, so these survive: the attach token (D39), the minted per-session
      # CA + its PRIVATE KEY (D17), the session-mode marker and the session record.
      # All are 0600 inside 0700 dirs, so this is hygiene rather than exposure, but a
      # `--purge` that leaves a CA private key behind is lying about what it did.
      rm -f "$OVERLAYS"/.ds-attach-tokens/sess-* \
            "$OVERLAYS"/.ds-ca-bundles/ca_sess-* \
            "$OVERLAYS"/.ds-session-mode/sess-* \
            "$OVERLAYS"/.ds-sessions/sess-* 2>/dev/null || true
      # CA-bundle reclamation backstop. The sess-prefixed glob above only matches refs
      # whose session id carries this stack's `sess-` prefix; a bundle dropped for any
      # other ref shape survives it, and so do the producer's atomic-write leftovers
      # (os.CreateTemp names them `<leaf>.pem.<random>`, so an interrupted drop can strand
      # a complete PRIVATE KEY under a temp name). `*.pem*` catches the cert, the .key.pem
      # sibling and both temp forms. The dir holds nothing but per-session bundles.
      rm -f "$OVERLAYS"/.ds-ca-bundles/*.pem* 2>/dev/null || true
    fi
    ;;
  status)
    for p in "$HA_PID:host-agent" "$ORCH_PID:orchestrator"; do
      pf="${p%%:*}"; nm="${p##*:}"
      if [[ -f "$pf" ]] && kill -0 "$(cat "$pf")" 2>/dev/null; then
        echo "$nm: RUNNING (pid $(cat "$pf"))"
      else
        echo "$nm: stopped"
      fi
    done
    echo "attach sockets ($ATTACH):"; ls -la "$ATTACH" 2>/dev/null || true
    echo "overlays ($OVERLAYS):"; ls -la "$OVERLAYS" 2>/dev/null || true
    ;;
  command) print_command ;;
  *) echo "usage: $0 {up|down [--purge]|build|preflight|status|command}   (auth: DS_AUTH_POSTURE=oauth|swap)" >&2; exit 2 ;;
esac
