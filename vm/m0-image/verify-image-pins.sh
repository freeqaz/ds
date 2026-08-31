#!/usr/bin/env bash
# verify-image-pins.sh — anti-drift guard for the M0 base-image artifact.
#
# Asserts that the pins, the prose, and the guest-config cannot silently drift
# apart:
#   1. README.md quotes M0_CC_VERSION / M0_ENTRYPOINT_PATH / M0_PTY_TERM
#      token-for-token from m0-image.env (a pin bump is one reviewed diff that
#      updates both, not the env alone with a stale README — the same posture as
#      images/mirror's lint-env-drift.sh, applied to THIS tree). M0_PTY_TERM is the
#      terminal/PTY-mode TERM whose terminfo build-m0-image.sh asserts is baked.
#      The SAME check also pins the host-side DefaultTerminalTERM const (the value
#      the terminal launch-mode injects into the guest CC env) equal to M0_PTY_TERM:
#      the two MUST move in lockstep, or a TERM bump silently injects a TERM the
#      baked image has no terminfo for and the in-VM TUI garbles (see the SINGLE-
#      SOURCED note on sessionmode.go's DefaultTerminalTERM). The (1c) check pins
#      the sibling DefaultTerminalCOLORTERM const equal to M0_PTY_COLORTERM the
#      same way — COLORTERM rides alongside TERM into the guest CC env, so a
#      COLORTERM bump that did not move the env pin silently changes the in-VM
#      color palette while TERM stays pinned. Both const extractions tolerate the
#      const being top-level (`const NAME = "..."`) OR inside a grouped `const ( )`
#      block (indented `NAME = "..."`), so a benign sessionmode.go refactor to a
#      const block does not break (or worse, silently disarm) the lockstep lint.
#   2. the D75 guest IPv6 drop-in disables v6 on the egress NIC, never touches
#      lo/all/default, and never sets the forbidden kernel ipv6.disable=1.
#   3. the ds-entrypoint.service launches the staged entrypoint path (D38) and
#      is fail-closed when that binary is absent.
#   4. the gap-1 config-drive mount unit (run-ds-entrypoint.mount) mounts the
#      host-stamped config-drive by LABEL, read-only, at M0_ENTRYPOINT_CONFIG_DIR,
#      ordered Before=ds-entrypoint.service (so loadConfig finds config.pb), with
#      the unit file named the systemd-escaped mount path.
#   5. the gap-3 attach-forwarder unit (ds-attachfwd.service) launches the staged
#      forwarder path on the UDS + the :M0_ATTACH_PORT carriage, is fail-closed
#      when the binary is absent, and is ordered Before=ds-entrypoint.service.
#   6. the DELIBERATE fail-posture asymmetry between the two attach-side units that
#      both order Before=ds-entrypoint.service: the config-drive mount is
#      RequiredBy=ds-entrypoint.service (fail-closed — no config drive => no
#      config.pb => no entrypoint => no runtime => no egress), while the attach
#      forwarder is WantedBy=ds-entrypoint.service (best-effort — a forwarder
#      hiccup must NOT fail-close the boot; a not-yet-carried session is still a
#      valid booted session whose attach leg the host-agent bridge re-dials,
#      attachbridge.go's best-effort posture). A flip of either dependency (mount
#      downgraded to Wanted, or forwarder upgraded to Required) inverts the boot
#      fail-posture and is a defect — this guard pins the asymmetry both ways.
#   8. the SLIRP DHCP egress: a DHCP .network (matching the SLIRP NIC as eth0 under
#      net.ifnames=0 AND en* under default naming) is STAGED off networkd's search
#      path and installed at runtime by ds-slirp-net.service ONLY when the routed-tap
#      signal ds-net.env is absent, so the .network provably cannot catch the routed
#      tap; and BOTH bake paths enable systemd-networkd + the installer unit. Without
#      this the M0-minimal SLIRP guest gets no IP/DNS and CC loops on api_retry.
#
# DELIBERATELY NOT named images/*/lint-*.sh and NOT under images/: it lives in
# the vm/ tree (this artifact is VM & runtime's own, doc 05 §3 seam statement),
# so it is outside the Makefile `check-image-drift` glob (images/*/lint-*.sh,
# owned by the Image & cache builder). It is invoked by the gate directly
# (see README "Gate") and self-tested with --self-test.
#
# Usage:
#   vm/m0-image/verify-image-pins.sh             # run the checks
#   vm/m0-image/verify-image-pins.sh --self-test # regression harness (inject drift)
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ST_TMP=""  # self-test temp dir; referenced by the EXIT trap (see self_test)

run_checks() {
  local dir="${1:-$HERE}"
  local env="${dir}/m0-image.env"
  local readme="${dir}/README.md"
  local ipv6="${dir}/guest-config/99-ds-disable-ipv6.conf"
  local unit="${dir}/guest-config/ds-entrypoint.service"
  local mount_unit="${dir}/guest-config/run-ds-entrypoint.mount"
  local fwd_unit="${dir}/guest-config/ds-attachfwd.service"
  local netcfg_script="${dir}/guest-config/ds-apply-netcfg.sh"
  local netcfg_unit="${dir}/guest-config/ds-netcfg.service"
  local slirp_network="${dir}/guest-config/ds-slirp-dhcp.network"
  local slirp_unit="${dir}/guest-config/ds-slirp-net.service"
  local build_sh="${dir}/build-m0-image.sh"
  local build_rootless="${dir}/build-m0-image-rootless.sh"
  # The host-side terminal launch-mode source carrying DefaultTerminalTERM. It lives
  # OUTSIDE this tree (orchestrator/, not vm/m0-image/), so it is resolved against the
  # REAL artifact dir ($HERE), never the self-test's copied subtree ($dir, which only
  # holds m0-image/ files). DS_VERIFY_SESSIONMODE_GO lets the --self-test point the
  # check at an injected copy with a drifted const without disturbing the env/README
  # copy harness.
  local sessionmode_go="${DS_VERIFY_SESSIONMODE_GO:-${HERE}/../../orchestrator/internal/hypervisor/libvirt/sessionmode.go}"
  # The data-plane's pinned Rust channel. Like sessionmode.go this lives OUTSIDE this
  # tree, so it resolves against the REAL artifact dir; DS_VERIFY_RUST_TOOLCHAIN lets
  # --self-test point at an injected copy.
  local rust_toolchain="${DS_VERIFY_RUST_TOOLCHAIN:-${HERE}/../../dataplane/rust-toolchain.toml}"
  local fail=0
  err() { printf 'verify-image-pins: FAIL: %s\n' "$*" >&2; fail=1; }

  # const_value <name> <file> — extract the double-quoted string literal of a Go
  # string const, tolerant of BOTH declaration forms:
  #   top-level :  const DefaultTerminalTERM = "xterm-256color"
  #   grouped   :  const (
  #                  DefaultTerminalTERM = "xterm-256color"   // indented, no `const`
  #                )
  # The anchor allows leading whitespace and an OPTIONAL `const ` prefix, then the
  # exact const name as a whole word, `=`, and the opening quote. A leading-whitespace
  # match is required so a grouped-block member is found, but the name is bounded
  # ([[:space:]]*= after it) so `DefaultTerminalTERM` does NOT also match a longer
  # sibling like `DefaultTerminalTERMFoo`. Prints the literal (no quotes) on stdout, or
  # NOTHING (empty, exit 0) if the const is absent — the caller fails closed on the empty
  # result with a precise message. The `|| true` on the grep is LOAD-BEARING: without it
  # grep's exit-1-on-no-match would (under `set -o pipefail`) make the command
  # substitution non-zero, and `set -e` would abort the whole script on the assignment
  # line BEFORE the caller's emptiness check could print its diagnostic. Uses the first
  # match only (head -n1) so a doc-comment example line cannot shadow it — comment lines
  # start with `//` and never match the `(const )?NAME =` anchor anyway.
  const_value() {
    local name="$1" file="$2"
    { grep -E "^[[:space:]]*(const[[:space:]]+)?${name}[[:space:]]*=[[:space:]]*\"" "$file" || true; } \
      | head -n1 \
      | sed -E "s/^[[:space:]]*(const[[:space:]]+)?${name}[[:space:]]*=[[:space:]]*\"([^\"]*)\".*/\2/"
  }

  for f in "$env" "$readme" "$ipv6" "$unit" "$mount_unit" "$fwd_unit" "$netcfg_script" "$netcfg_unit" "$slirp_network" "$slirp_unit" "$build_sh" "$build_rootless" "$sessionmode_go"; do
    [ -f "$f" ] || err "missing $f"
  done
  [ "$fail" = 0 ] || return 1

  # --- (1) README quotes the env pins token-for-token ---
  local cc path ptyterm
  cc="$(grep -E '^M0_CC_VERSION=' "$env" | cut -d= -f2-)"
  path="$(grep -E '^M0_ENTRYPOINT_PATH=' "$env" | cut -d= -f2-)"
  ptyterm="$(grep -E '^M0_PTY_TERM=' "$env" | cut -d= -f2-)"
  [ -n "$cc" ]   || err "M0_CC_VERSION absent from $env"
  [ -n "$path" ] || err "M0_ENTRYPOINT_PATH absent from $env"
  [ -n "$ptyterm" ] || err "M0_PTY_TERM absent from $env"
  # The README must mention the EXACT pinned CC version, the EXACT entrypoint path,
  # and the EXACT terminal/PTY-mode TERM; a drifted README is a defect (the user-
  # facing prose lies about the pin).
  grep -qF "$cc" "$readme"   || err "README does not quote M0_CC_VERSION=$cc"
  grep -qF "$path" "$readme" || err "README does not quote M0_ENTRYPOINT_PATH=$path"
  grep -qF "$ptyterm" "$readme" || err "README does not quote M0_PTY_TERM=$ptyterm"

  # --- (1b) host-side DefaultTerminalTERM const == M0_PTY_TERM (lockstep) ---
  # The terminal launch-mode (orchestrator sessionmode.go) injects DefaultTerminalTERM
  # into the guest CC env; M0_PTY_TERM is the TERM whose terminfo build-m0-image.sh
  # asserts is baked. If they drift, a launch-mode TERM bump injects a TERM the baked
  # image has no terminfo for => a garbled TUI with NO rebake error. The const is
  # SINGLE-SOURCED to this pin (sessionmode.go's DefaultTerminalTERM doc-comment);
  # this lint is the lockstep guard. Extract the const's string literal (tolerant of a
  # grouped const() block via const_value) and assert it is byte-equal to M0_PTY_TERM.
  local constterm
  constterm="$(const_value DefaultTerminalTERM "$sessionmode_go")"
  [ -n "$constterm" ] \
    || err "DefaultTerminalTERM const not found (or empty) in $sessionmode_go"
  [ "$constterm" = "$ptyterm" ] \
    || err "lockstep: DefaultTerminalTERM=$constterm != M0_PTY_TERM=$ptyterm (a TERM bump must move BOTH the env pin and sessionmode.go's const, or the launch-mode injects a TERM the baked image has no terminfo for)"

  # --- (1c) host-side DefaultTerminalCOLORTERM const == M0_PTY_COLORTERM (lockstep) ---
  # The terminal launch-mode also injects DefaultTerminalCOLORTERM (sessionmode.go:
  # `COLORTERM=<this>` appended to out.Env) alongside TERM. Unlike TERM it has NO
  # terminfo/README dependency — "truecolor" is a free-standing capability hint CC's
  # palette detection reads — so this is a pure host-const<->env-pin lockstep: a COLORTERM
  # bump that did not move M0_PTY_COLORTERM silently changes the in-VM color palette while
  # TERM stays pinned. Same fail-closed posture as (1b): empty extraction is a failure.
  local colorterm constcolorterm
  colorterm="$(grep -E '^M0_PTY_COLORTERM=' "$env" | cut -d= -f2-)"
  [ -n "$colorterm" ] || err "M0_PTY_COLORTERM absent from $env"
  constcolorterm="$(const_value DefaultTerminalCOLORTERM "$sessionmode_go")"
  [ -n "$constcolorterm" ] \
    || err "DefaultTerminalCOLORTERM const not found (or empty) in $sessionmode_go"
  [ -n "$colorterm" ] && [ "$constcolorterm" != "$colorterm" ] \
    && err "lockstep: DefaultTerminalCOLORTERM=$constcolorterm != M0_PTY_COLORTERM=$colorterm (a COLORTERM bump must move BOTH the env pin and sessionmode.go's const, or the launch-mode advertises a color palette the env pin no longer reflects)"

  # --- (2) D75 guest IPv6 invariants ---
  # Reason about ACTIVE sysctl lines only; the drop-in legitimately quotes the
  # forbidden forms (lo, kernel ipv6.disable=1) in its header comments.
  local active; active="$(grep -vE '^[[:space:]]*#' "$ipv6" | grep -vE '^[[:space:]]*$')"
  printf '%s\n' "$active" | grep -q '__IFACE__\.disable_ipv6 = 1' \
    || err "D75: drop-in does not disable v6 on the egress NIC"
  printf '%s\n' "$active" | grep -Eq 'net\.ipv6\.conf\.(lo|all|default)\.' \
    && err "D75: drop-in touches lo/all/default (must be per-egress-NIC only)"
  printf '%s\n' "$active" | grep -q 'ipv6\.disable=1' \
    && err "D75: drop-in sets the forbidden kernel ipv6.disable=1"

  # --- (3) D38 entrypoint launch is path-bound + fail-closed ---
  grep -q 'ExecStart=__ENTRYPOINT_PATH__' "$unit" \
    || err "D38: unit ExecStart is not bound to the entrypoint-path token"
  grep -q 'ConditionFileIsExecutable=__ENTRYPOINT_PATH__' "$unit" \
    || err "D38: unit is not fail-closed on a missing entrypoint binary"

  # --- (4) gap-1 config-drive mount unit (matches configdrive.go via env pins) ---
  # The new pins MUST be present (single source of truth for the mount unit's
  # tokens; they replicate configdrive.go's label/fs — D80, replicated not imported).
  local cdlabel cdfs cdir
  cdlabel="$(grep -E '^M0_CONFIG_DRIVE_LABEL=' "$env" | cut -d= -f2-)"
  cdfs="$(grep -E '^M0_CONFIG_DRIVE_FS=' "$env" | cut -d= -f2-)"
  cdir="$(grep -E '^M0_ENTRYPOINT_CONFIG_DIR=' "$env" | cut -d= -f2-)"
  [ -n "$cdlabel" ] || err "M0_CONFIG_DRIVE_LABEL absent from $env"
  [ -n "$cdfs" ]    || err "M0_CONFIG_DRIVE_FS absent from $env"
  [ -n "$cdir" ]    || err "M0_ENTRYPOINT_CONFIG_DIR absent from $env"
  # The mount unit is token-bound to the env pins (build-m0-image.sh expands them);
  # assert each token appears so a stale unit cannot drift off the pins.
  grep -q 'What=/dev/disk/by-label/__CONFIG_DRIVE_LABEL__' "$mount_unit" \
    || err "gap-1: mount unit What is not bound to the config-drive-label token"
  grep -q 'Where=__ENTRYPOINT_CONFIG_DIR__' "$mount_unit" \
    || err "gap-1: mount unit Where is not bound to the config-dir token"
  grep -q 'Type=__CONFIG_DRIVE_FS__' "$mount_unit" \
    || err "gap-1: mount unit Type is not bound to the config-drive-fs token"
  grep -Eq '^Options=.*\bro\b' "$mount_unit" \
    || err "gap-1: mount unit is not read-only (Options=ro)"
  grep -q 'Before=ds-entrypoint.service' "$mount_unit" \
    || err "gap-1: mount unit not ordered Before=ds-entrypoint.service"
  # systemd rejects a .mount whose name is not the escaped mount path; assert the
  # file name matches the escaped M0_ENTRYPOINT_CONFIG_DIR (so the bake cannot stage
  # a unit systemd will refuse).
  local escaped="${cdir#/}"; escaped="${escaped//\//-}"
  [ -f "${dir}/guest-config/${escaped}.mount" ] \
    || err "gap-1: mount unit file name != systemd-escaped ${cdir} (expected ${escaped}.mount)"

  # --- (5) gap-3 attach-forwarder unit is path/port-bound + fail-closed + ordered ---
  local fwdpath fwduds aport
  fwdpath="$(grep -E '^M0_ATTACHFWD_PATH=' "$env" | cut -d= -f2-)"
  fwduds="$(grep -E '^M0_ATTACHFWD_UDS_PATH=' "$env" | cut -d= -f2-)"
  aport="$(grep -E '^M0_ATTACH_PORT=' "$env" | cut -d= -f2-)"
  [ -n "$fwdpath" ] || err "M0_ATTACHFWD_PATH absent from $env"
  [ -n "$fwduds" ]  || err "M0_ATTACHFWD_UDS_PATH absent from $env"
  [ -n "$aport" ]   || err "M0_ATTACH_PORT absent from $env"
  grep -q 'ExecStart=__ATTACHFWD_PATH__ ' "$fwd_unit" \
    || err "gap-3: forwarder unit ExecStart is not bound to the forwarder-path token"
  grep -q -- '--uds-path __ATTACHFWD_UDS_PATH__' "$fwd_unit" \
    || err "gap-3: forwarder unit --uds-path is not bound to the UDS-path token"
  grep -q -- '--vsock-port __ATTACH_PORT__' "$fwd_unit" \
    || err "gap-3: forwarder unit --vsock-port is not bound to the attach-port token"
  grep -q 'ConditionFileIsExecutable=__ATTACHFWD_PATH__' "$fwd_unit" \
    || err "gap-3: forwarder unit is not fail-closed on a missing forwarder binary"
  grep -q 'Before=ds-entrypoint.service' "$fwd_unit" \
    || err "gap-3: forwarder unit not ordered Before=ds-entrypoint.service"

  # --- (6) DELIBERATE fail-posture asymmetry on the two attach-side units ---
  # Both order Before=ds-entrypoint.service, but their reverse-dependency on the
  # entrypoint differs ON PURPOSE and must not silently flip:
  #   mount   : RequiredBy=ds-entrypoint.service (fail-closed — no config drive
  #             => no entrypoint), and NEVER merely WantedBy (a downgrade would
  #             let the entrypoint launch without config.pb).
  #   forwarder: WantedBy=ds-entrypoint.service (best-effort — a forwarder hiccup
  #             must not fail-close the boot), and NEVER RequiredBy (an upgrade
  #             would let a carriage hiccup take down an otherwise-valid session).
  # Match the unit-name token-for-token (anchored, no trailing chars) so the
  # forwarder's own `WantedBy=multi-user.target` install line cannot satisfy the
  # ds-entrypoint.service assertion.
  grep -Eq '^RequiredBy=ds-entrypoint\.service[[:space:]]*$' "$mount_unit" \
    || err "asymmetry: mount unit is not RequiredBy=ds-entrypoint.service (fail-closed: no config drive => no entrypoint)"
  grep -Eq '^WantedBy=ds-entrypoint\.service[[:space:]]*$' "$mount_unit" \
    && err "asymmetry: mount unit is WantedBy=ds-entrypoint.service — must be RequiredBy (a Wanted config drive would let the entrypoint launch without config.pb)"
  grep -Eq '^WantedBy=ds-entrypoint\.service[[:space:]]*$' "$fwd_unit" \
    || err "asymmetry: forwarder unit is not WantedBy=ds-entrypoint.service (best-effort: a forwarder hiccup must not fail-close the boot)"
  grep -Eq '^RequiredBy=ds-entrypoint\.service[[:space:]]*$' "$fwd_unit" \
    && err "asymmetry: forwarder unit is RequiredBy=ds-entrypoint.service — must be WantedBy (a Required carriage would let a forwarder hiccup take down an otherwise-valid session)"

  # --- (7) U4 per-session guest static net config (matches netconfig.go) ---
  # The new pins MUST be present; the apply script + unit are token-bound to them.
  local ncscript ncfile
  ncscript="$(grep -E '^M0_NETCFG_SCRIPT_PATH=' "$env" | cut -d= -f2-)"
  ncfile="$(grep -E '^M0_NETCFG_FILE=' "$env" | cut -d= -f2-)"
  [ -n "$ncscript" ] || err "M0_NETCFG_SCRIPT_PATH absent from $env"
  [ -n "$ncfile" ]   || err "M0_NETCFG_FILE absent from $env"
  # The apply script reads the net-config file from the config-dir token, consumes
  # the three renderer keys (netconfig.go renderNetConfigEnv), and NO-OPS when the
  # file is absent (the SLIRP path — `exit 0` on the absent branch).
  grep -q '__NETCFG_FILE__' "$netcfg_script" \
    || err "U4: apply script is not bound to the net-config file-name token"
  grep -q '__ENTRYPOINT_CONFIG_DIR__' "$netcfg_script" \
    || err "U4: apply script is not bound to the config-dir token"
  for k in DS_NET_GUEST_IP DS_NET_PREFIX DS_NET_GATEWAY; do
    grep -q "$k" "$netcfg_script" \
      || err "U4: apply script does not consume the renderer key $k"
  done
  grep -Eq '^[[:space:]]*exit 0' "$netcfg_script" \
    || err "U4: apply script has no clean no-op exit (the SLIRP/absent path must succeed)"
  # The service unit runs the script path, is fail-closed on a missing script, is
  # ordered Before=ds-entrypoint.service, runs After the config-drive mount, and
  # must NEVER gate on network-online.target (it brings the NIC up — a Wants/After
  # would deadlock). Reason about ACTIVE lines only (the header quotes the forbidden
  # target in prose explaining why it is forbidden).
  grep -q 'ExecStart=__NETCFG_SCRIPT_PATH__' "$netcfg_unit" \
    || err "U4: net-config unit ExecStart is not bound to the apply-script token"
  grep -q 'ConditionPathExists=__NETCFG_SCRIPT_PATH__' "$netcfg_unit" \
    || err "U4: net-config unit is not fail-closed on a missing apply script"
  grep -q 'Before=ds-entrypoint.service' "$netcfg_unit" \
    || err "U4: net-config unit not ordered Before=ds-entrypoint.service"
  grep -q 'After=run-ds-entrypoint.mount' "$netcfg_unit" \
    || err "U4: net-config unit not ordered After=run-ds-entrypoint.mount (it reads the net config off the mounted drive)"
  local nc_active; nc_active="$(grep -vE '^[[:space:]]*#' "$netcfg_unit" | grep -vE '^[[:space:]]*$')"
  printf '%s\n' "$nc_active" | grep -qE 'network-online\.target' \
    && err "U4: net-config unit gates on network-online.target (it BRINGS the NIC up — would deadlock)"

  # --- (8) SLIRP DHCP egress — the .network provably cannot catch the routed tap ---
  # The M0-minimal SLIRP NIC needs DHCP or CC hangs on api_retry (live-found 2026-06-18).
  # The DHCP .network is STAGED at M0_SLIRP_NETWORK_STAGE — a NON-networkd-search path —
  # and installed into /run/systemd/network by ds-slirp-net.service ONLY when the
  # routed-tap signal ds-net.env is ABSENT. On a routed-tap boot the .network is never
  # loaded, so its [Match] can never catch the tap. This section pins every load-bearing
  # part of that invariant so it cannot silently drift back to the pre-fix (no-DHCP) or
  # to a blanket DHCP that races ds-netcfg's static apply.
  local slirpstage
  slirpstage="$(grep -E '^M0_SLIRP_NETWORK_STAGE=' "$env" | cut -d= -f2-)"
  [ -n "$slirpstage" ] || err "M0_SLIRP_NETWORK_STAGE absent from $env"
  # (8a) The staged .network path must NOT be inside a systemd-networkd search dir —
  # else networkd would auto-load it at boot on BOTH paths and its Name=eth0/en* match
  # WOULD catch the routed tap (the exact race this design avoids). It must be staged
  # off-search and installed at runtime only on the SLIRP path.
  case "$slirpstage" in
    /etc/systemd/network/*|/run/systemd/network/*|/usr/lib/systemd/network/*|/lib/systemd/network/*)
      err "SLIRP: staged .network path $slirpstage is inside a networkd search dir (it would auto-load and its match could catch the routed tap)";;
  esac
  # (8b) The .network matches the SLIRP NIC under BOTH namings (eth0 for net.ifnames=0,
  # en* via the single-sourced glob token for default naming) and does IPv4 DHCP.
  local slirp_match; slirp_match="$(grep -E '^Name=' "$slirp_network" || true)"
  printf '%s\n' "$slirp_match" | grep -qw 'eth0' \
    || err "SLIRP: .network [Match] Name does not include eth0 (the net.ifnames=0 SLIRP NIC name)"
  printf '%s\n' "$slirp_match" | grep -q '__EGRESS_NIC_GLOB__' \
    || err "SLIRP: .network [Match] Name is not bound to the __EGRESS_NIC_GLOB__ token (the en* default-naming SLIRP NIC)"
  grep -qE '^DHCP=ipv4' "$slirp_network" \
    || err "SLIRP: .network does not enable IPv4 DHCP (DHCP=ipv4)"
  # Reason about ACTIVE lines only for the installer's directives — the header quotes
  # several of these forms in prose explaining the design, so a comment must not be able
  # to satisfy (or mask the removal of) a real directive.
  local slirp_active; slirp_active="$(grep -vE '^[[:space:]]*#' "$slirp_unit" | grep -vE '^[[:space:]]*$')"
  # (8c) The installer unit is GATED off the routed tap: it runs ONLY when ds-net.env is
  # absent. This ConditionPathExists=! is THE reason the DHCP .network cannot catch the
  # routed tap — its removal would install DHCP on the routed-tap boot and race ds-netcfg.
  printf '%s\n' "$slirp_active" | grep -qF 'ConditionPathExists=!__ENTRYPOINT_CONFIG_DIR__/__NETCFG_FILE__' \
    || err "SLIRP: installer unit is not gated off the routed tap (ConditionPathExists=!<config-dir>/<ds-net.env>) — DHCP could race ds-netcfg on the routed tap"
  # (8d) It reads that signal off the MOUNTED config-drive, so it must order After the
  # mount (else the condition would see ds-net.env as not-yet-present and wrongly DHCP).
  printf '%s\n' "$slirp_active" | grep -qE '^After=run-ds-entrypoint\.mount' \
    || err "SLIRP: installer unit not ordered After=run-ds-entrypoint.mount (the routed-tap ds-net.env signal rides the mounted drive)"
  # (8e) It installs the STAGED .network into networkd's runtime dir + reloads networkd,
  # is fail-closed on a missing stage, ordered before the entrypoint, and never gates on
  # network-online.target (it brings the network up — that would deadlock).
  printf '%s\n' "$slirp_active" | grep -qF '__SLIRP_NETWORK_STAGE__' \
    || err "SLIRP: installer unit is not bound to the staged-.network token (__SLIRP_NETWORK_STAGE__)"
  printf '%s\n' "$slirp_active" | grep -q '/run/systemd/network' \
    || err "SLIRP: installer unit does not install the .network into /run/systemd/network"
  printf '%s\n' "$slirp_active" | grep -q 'networkctl reload' \
    || err "SLIRP: installer unit does not reload networkd (networkctl reload) after installing the .network"
  printf '%s\n' "$slirp_active" | grep -qF 'ConditionPathExists=__SLIRP_NETWORK_STAGE__' \
    || err "SLIRP: installer unit is not fail-closed on a missing staged .network"
  printf '%s\n' "$slirp_active" | grep -qE '^Before=ds-entrypoint\.service' \
    || err "SLIRP: installer unit not ordered Before=ds-entrypoint.service"
  printf '%s\n' "$slirp_active" | grep -qE 'network-online\.target' \
    && err "SLIRP: installer unit gates on network-online.target (it brings the NIC up — would deadlock)"
  # (8f) BOTH bake paths must enable systemd-networkd AND the SLIRP installer unit —
  # a DHCP .network with networkd disabled is inert (the pre-fix no-egress state).
  for bs in "$build_sh" "$build_rootless"; do
    grep -q 'systemctl enable systemd-networkd' "$bs" \
      || err "SLIRP: $(basename "$bs") does not enable systemd-networkd (the SLIRP DHCP would never run)"
    grep -q 'systemctl enable ds-slirp-net' "$bs" \
      || err "SLIRP: $(basename "$bs") does not enable ds-slirp-net.service (the SLIRP DHCP .network would never be installed)"
  done

  # (9a) TOOLCHAIN LOCKSTEP: the image's baked Rust MUST equal dataplane/rust-toolchain.toml's
  # pinned channel. If these drift, cargo inside the VM honours the repo's rust-toolchain.toml,
  # tries to fetch that channel from static.rust-lang.org — which the POL-2 egress baseline
  # deliberately does NOT allowlist — and dies at the gate. The symptom looks like a network
  # fault and the cause is a version pin; that misattribution is worth a check to prevent.
  if [ -r "$rust_toolchain" ]; then
    local want_rust have_rust
    want_rust="$(sed -n 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$rust_toolchain" | head -1)"
    have_rust="$(sed -n 's/^M0_RUST_VERSION=//p' "$env" | head -1)"
    if [ -z "$have_rust" ]; then
      err "M0_RUST_VERSION missing from m0-image.env (the baked Rust toolchain pin)"
    elif [ -n "$want_rust" ] && [ "$want_rust" != "$have_rust" ]; then
      err "M0_RUST_VERSION=$have_rust != dataplane/rust-toolchain.toml channel=$want_rust — an in-VM cargo build would try to FETCH $want_rust from static.rust-lang.org, which the egress baseline does not allow"
    fi
  fi
  # (9b) The toolchain tarballs must carry pinned checksums. This compiler builds the code
  # the agent then runs, so an unpinned toolchain is the highest-leverage supply-chain hole
  # in the image — and the bake pulls it over a TLS-intercepting gateway.
  local hh
  for hh in M0_GO_SHA256 M0_RUST_SHA256; do
    grep -qE "^${hh}=[0-9a-f]{64}$" "$env" \
      || err "$hh missing or not a 64-hex sha256 in m0-image.env (the bake verifies each toolchain tarball before unpacking it)"
  done
  # (9c) The runtime unit must export the toolchain PATH. /etc/environment does NOT reach a
  # systemd system service and /etc/profile.d does not reach the agent's non-login shell, so
  # without this line the toolchains sit on disk and are invisible (live-found 2026-07-29).
  grep -q '^Environment=PATH=' "$unit" \
    || err "ds-entrypoint.service does not export a PATH — the baked toolchains would be unreachable from the agent's shell"
  # (9d) The workspace mount must stay FAIL-OPEN: pulled in by the DS_WORKSPACE device unit,
  # never RequiredBy the entrypoint. A workspace that fails to mount must not kill a session
  # (that is the config-drive's fail-closed job, not this carrier's).
  local ws_unit="${dir}/guest-config/work.mount"
  if [ -r "$ws_unit" ]; then
    grep -q '^WantedBy=dev-disk-by' "$ws_unit" \
      || err "work.mount is not installed onto the workspace DEVICE unit — it would either never mount or fail the boot when no workspace is attached"
    grep -q '^RequiredBy=' "$ws_unit" \
      && err "work.mount declares RequiredBy — the workspace carrier must be fail-OPEN; a missing/broken workspace must not take down the session"
  fi

  [ "$fail" = 0 ] || return 1
  echo "verify-image-pins: OK (CC=$cc entrypoint=$path; pty-term=$ptyterm==DefaultTerminalTERM; pty-colorterm=$colorterm==DefaultTerminalCOLORTERM; config-drive=$cdlabel/$cdfs@$cdir; netcfg=$ncscript<-$ncfile; forwarder=$fwdpath :$aport; slirp-dhcp=$slirpstage gated-off-routed-tap+networkd-enabled; mount=RequiredBy/forwarder=WantedBy ds-entrypoint.service; D75/D38/gap-1/gap-3/U4/SLIRP invariants hold)"
}

self_test() {
  # Copy the artifact to a temp dir, confirm the clean copy passes, then inject
  # each recognised drift one at a time and confirm the check catches it.
  # ST_TMP is script-scoped (not `local`) so the EXIT trap can still see it when
  # the shell exits after this function returns (with set -u, a stale local
  # would be unbound at trap time).
  ST_TMP="$(mktemp -d "${TMPDIR:-/tmp}/m0pins.XXXXXX")"
  trap 'rm -rf "${ST_TMP:-}"' EXIT
  cp -a "$HERE/." "$ST_TMP/"
  local tmp="$ST_TMP"

  echo "self-test: clean copy must PASS"
  run_checks "$tmp" >/dev/null || { echo "self-test FAIL: clean copy did not pass" >&2; exit 1; }

  inject_and_expect_fail() {
    local label="$1"; shift
    local work; work="$(mktemp -d "${TMPDIR:-/tmp}/m0pins.XXXXXX")"
    cp -a "$HERE/." "$work/"
    "$@" "$work"
    if run_checks "$work" >/dev/null 2>&1; then
      echo "self-test FAIL: drift '$label' was NOT caught" >&2; rm -rf "$work"; exit 1
    fi
    echo "self-test: drift '$label' caught (good)"
    rm -rf "$work"
  }

  # inject_and_expect_fail_sessionmode injects drift into a COPY of the host-side
  # sessionmode.go (which lives outside the m0-image/ subtree) via a sed script, points
  # the check at it through DS_VERIFY_SESSIONMODE_GO, and asserts the lockstep lint
  # fails. The m0-image dir copy is otherwise clean — this isolates the const drift so a
  # passing result proves the (1b)/(1c) lockstep check (not some other invariant) caught
  # it. An OPTIONAL third arg is an expected-stderr substring: when given, the run must
  # not only fail but also EMIT that diagnostic on stderr. This pins the "fails closed
  # with a precise message" contract — a regression to a `set -e`/pipefail abort on the
  # empty-const assignment (which exits non-zero but prints nothing) would be caught here.
  inject_and_expect_fail_sessionmode() {
    local label="$1" sed_script="$2" want_msg="${3:-}"
    local work; work="$(mktemp -d "${TMPDIR:-/tmp}/m0pins.XXXXXX")"
    cp -a "$HERE/." "$work/"
    local src="${HERE}/../../orchestrator/internal/hypervisor/libvirt/sessionmode.go"
    local drifted="${work}/sessionmode-drift.go"
    sed -E "$sed_script" "$src" > "$drifted"
    local errlog="${work}/stderr.log"
    if DS_VERIFY_SESSIONMODE_GO="$drifted" run_checks "$work" >/dev/null 2>"$errlog"; then
      echo "self-test FAIL: drift '$label' was NOT caught" >&2; rm -rf "$work"; exit 1
    fi
    if [ -n "$want_msg" ] && ! grep -qF "$want_msg" "$errlog"; then
      echo "self-test FAIL: drift '$label' caught but did NOT emit the expected diagnostic '$want_msg' (a silent set -e/pipefail abort would do this)" >&2
      rm -rf "$work"; exit 1
    fi
    echo "self-test: drift '$label' caught (good)"
    rm -rf "$work"
  }

  # rewrite_and_expect_pass_sessionmode runs a sed transform over a COPY of the real
  # sessionmode.go and asserts the lint STILL PASSES against it — used to prove a benign
  # refactor (e.g. collapsing the two top-level consts into a grouped `const ( ... )`
  # block) does not break (or silently disarm) the (1b)/(1c) lockstep extraction. The
  # m0-image dir copy is clean, so a pass proves both consts were still extracted and
  # matched their env pins under the refactored form.
  rewrite_and_expect_pass_sessionmode() {
    local label="$1" sed_script="$2"
    local work; work="$(mktemp -d "${TMPDIR:-/tmp}/m0pins.XXXXXX")"
    cp -a "$HERE/." "$work/"
    local src="${HERE}/../../orchestrator/internal/hypervisor/libvirt/sessionmode.go"
    local rewritten="${work}/sessionmode-block.go"
    sed -E "$sed_script" "$src" > "$rewritten"
    # Belt-and-suspenders: the rewrite must actually produce the grouped form, else the
    # fixture would vacuously "pass" by leaving the top-level consts untouched.
    grep -Eq '^[[:space:]]+DefaultTerminalTERM[[:space:]]*=' "$rewritten" \
      && grep -Eq '^[[:space:]]+DefaultTerminalCOLORTERM[[:space:]]*=' "$rewritten" \
      || { echo "self-test FAIL: fixture '$label' did not produce a grouped const block" >&2; rm -rf "$work"; exit 1; }
    if ! DS_VERIFY_SESSIONMODE_GO="$rewritten" run_checks "$work" >/dev/null 2>&1; then
      echo "self-test FAIL: fixture '$label' did NOT pass (const-block extraction broke)" >&2; rm -rf "$work"; exit 1
    fi
    echo "self-test: fixture '$label' passes (good)"
    rm -rf "$work"
  }

  # Drift A: README quotes a stale CC version.
  inject_and_expect_fail "stale README CC pin" bash -c '
    sed -i "s/2\.1\.173/9.9.999/g" "$1/README.md"' _
  # Drift B: drop-in touches lo (D75 violation).
  inject_and_expect_fail "drop-in touches lo" bash -c '
    printf "\nnet.ipv6.conf.lo.disable_ipv6 = 1\n" >> "$1/guest-config/99-ds-disable-ipv6.conf"' _
  # Drift C: unit no longer fail-closed.
  inject_and_expect_fail "unit not fail-closed" bash -c '
    sed -i "/ConditionFileIsExecutable=/d" "$1/guest-config/ds-entrypoint.service"' _
  # Drift D: config-drive mount no longer read-only (gap-1 — would let the guest
  # write the per-session config drive).
  inject_and_expect_fail "config-drive mount not read-only" bash -c '
    sed -i "s/^Options=ro,/Options=rw,/" "$1/guest-config/run-ds-entrypoint.mount"' _
  # Drift E: config-drive mount no longer ordered before the entrypoint (gap-1 —
  # the entrypoint could load before config.pb is mounted).
  inject_and_expect_fail "config-drive mount unordered" bash -c '
    sed -i "/Before=ds-entrypoint.service/d" "$1/guest-config/run-ds-entrypoint.mount"' _
  # Drift F: attach forwarder no longer fail-closed (gap-3 — a missing binary would
  # not condition the unit off).
  inject_and_expect_fail "forwarder not fail-closed" bash -c '
    sed -i "/ConditionFileIsExecutable=/d" "$1/guest-config/ds-attachfwd.service"' _
  # Drift G: config-drive label pin dropped from the env (gap-1 — the mount unit
  # would expand to an empty LABEL the host never stamps).
  inject_and_expect_fail "config-drive label pin missing" bash -c '
    sed -i "/^M0_CONFIG_DRIVE_LABEL=/d" "$1/m0-image.env"' _
  # Drift H: mount unit downgraded RequiredBy -> WantedBy on ds-entrypoint.service
  # (asymmetry flip — a Wanted config drive would let the entrypoint launch with
  # no config.pb; the fail-closed posture is lost).
  inject_and_expect_fail "mount RequiredBy flipped to WantedBy" bash -c '
    sed -i "s/^RequiredBy=ds-entrypoint\.service$/WantedBy=ds-entrypoint.service/" "$1/guest-config/run-ds-entrypoint.mount"' _
  # Drift I: forwarder unit upgraded WantedBy -> RequiredBy on ds-entrypoint.service
  # (asymmetry flip — a Required carriage would let a forwarder hiccup fail-close an
  # otherwise-valid session). Anchored to the ds-entrypoint.service line so the
  # unit's own WantedBy=multi-user.target install line is untouched.
  inject_and_expect_fail "forwarder WantedBy flipped to RequiredBy" bash -c '
    sed -i "s/^WantedBy=ds-entrypoint\.service$/RequiredBy=ds-entrypoint.service/" "$1/guest-config/ds-attachfwd.service"' _
  # Drift J: U4 net-config unit gains a network-online.target gate (would deadlock —
  # the unit brings the NIC up, so waiting on the NIC being up is a cycle).
  inject_and_expect_fail "net-config unit gates on network-online" bash -c '
    printf "\nWants=network-online.target\n" >> "$1/guest-config/ds-netcfg.service"' _
  # Drift K: U4 net-config unit no longer fail-closed on a missing apply script.
  inject_and_expect_fail "net-config unit not fail-closed" bash -c '
    sed -i "/ConditionPathExists=__NETCFG_SCRIPT_PATH__/d" "$1/guest-config/ds-netcfg.service"' _
  # Drift L: U4 apply script loses its clean no-op exit on the absent-file path
  # (the SLIRP/offline path would then fail rather than no-op).
  inject_and_expect_fail "net-config script no clean no-op exit" bash -c '
    sed -i "/^  log \"no \${NETCFG_FILE}/,/^  exit 0$/d" "$1/guest-config/ds-apply-netcfg.sh"' _
  # Drift M: U4 net-config file-name pin dropped from the env (the apply script would
  # expand to an empty file name the host never stamps).
  inject_and_expect_fail "net-config file pin missing" bash -c '
    sed -i "/^M0_NETCFG_FILE=/d" "$1/m0-image.env"' _
  # Drift N: README quotes a stale PTY TERM (the terminal/PTY-mode pin drifts from
  # the env — the README would lie about the TERM the baked terminfo supports).
  inject_and_expect_fail "stale README PTY TERM pin" bash -c '
    sed -i "s/xterm-256color/xterm-stale999/g" "$1/README.md"' _
  # Drift O: M0_PTY_TERM dropped from the env entirely.
  inject_and_expect_fail "PTY TERM pin missing" bash -c '
    sed -i "/^M0_PTY_TERM=/d" "$1/m0-image.env"' _

  # Drift P: the host-side DefaultTerminalTERM const drifts off M0_PTY_TERM (a
  # launch-mode TERM bump that did NOT move the env pin in lockstep — the const would
  # inject a TERM the baked image has no terminfo for). The const source lives outside
  # the copied m0-image subtree, so inject a drifted COPY of sessionmode.go and point
  # DS_VERIFY_SESSIONMODE_GO at it for the one run; the m0-image dir copy is untouched.
  inject_and_expect_fail_sessionmode "DefaultTerminalTERM const drifted off M0_PTY_TERM" \
    's/^const DefaultTerminalTERM = "[^"]*"/const DefaultTerminalTERM = "xterm-drift999"/'
  # Drift Q: the DefaultTerminalTERM const is removed entirely (a refactor that drops
  # the single-sourced pin — the lint must fail with the precise "not found" diagnostic,
  # NOT silently abort: the want_msg arg proves the empty-extraction path reaches err()).
  inject_and_expect_fail_sessionmode "DefaultTerminalTERM const removed" \
    '/^const DefaultTerminalTERM = /d' \
    'DefaultTerminalTERM const not found'

  # Drift R: M0_PTY_COLORTERM dropped from the env entirely (the (1c) lockstep loses its
  # env side — the lint must fail closed rather than silently skip the COLORTERM check).
  inject_and_expect_fail "PTY COLORTERM pin missing" bash -c '
    sed -i "/^M0_PTY_COLORTERM=/d" "$1/m0-image.env"' _
  # Drift S: the host-side DefaultTerminalCOLORTERM const drifts off M0_PTY_COLORTERM (a
  # launch-mode COLORTERM bump that did NOT move the env pin in lockstep — the const would
  # advertise a color palette the env pin no longer reflects).
  inject_and_expect_fail_sessionmode "DefaultTerminalCOLORTERM const drifted off M0_PTY_COLORTERM" \
    's/^const DefaultTerminalCOLORTERM = "[^"]*"/const DefaultTerminalCOLORTERM = "drift999color"/'
  # Drift T: the DefaultTerminalCOLORTERM const is removed entirely (a refactor that drops
  # the single-sourced pin — the (1c) lint must fail with the precise "not found"
  # diagnostic, NOT silently abort (want_msg proves the empty-extraction path reaches err).
  inject_and_expect_fail_sessionmode "DefaultTerminalCOLORTERM const removed" \
    '/^const DefaultTerminalCOLORTERM = /d' \
    'DefaultTerminalCOLORTERM const not found'

  # Fixture U: a benign refactor collapses BOTH top-level consts into a grouped
  # `const ( ... )` block (indented members, no per-line `const`). The hardened
  # const_value extraction must still find BOTH consts and match their env pins, so the
  # lint PASSES under the refactored form (a regression here would mean the lockstep
  # silently disarms on a legal Go reshuffle). The sed: turn the first `const Default...`
  # line into `const (\n\t<member>`, drop the `const ` prefix off the second, and append
  # a closing `)` right after the second member.
  rewrite_and_expect_pass_sessionmode "grouped const() block form" \
    's/^const DefaultTerminalTERM = (.*)$/const (\n\tDefaultTerminalTERM = \1/; s/^const DefaultTerminalCOLORTERM = (.*)$/\tDefaultTerminalCOLORTERM = \1\n)/'

  # --- SLIRP DHCP drift arms (section 8) — each planted drift must FAIL closed ---
  # Drift V: the SLIRP .network [Match] loses eth0 (the net.ifnames=0 SLIRP NIC name —
  # the rootless/direct-kernel boot would no longer get DHCP).
  inject_and_expect_fail "SLIRP .network match loses eth0" bash -c '
    sed -i "/^Name=/ s/eth0 //" "$1/guest-config/ds-slirp-dhcp.network"' _
  # Drift W: the SLIRP .network [Match] loses the en* glob token (the default-naming
  # SLIRP NIC would no longer get DHCP on the grub boot).
  inject_and_expect_fail "SLIRP .network match loses the en* glob token" bash -c '
    sed -i "/^Name=/ s/ __EGRESS_NIC_GLOB__//" "$1/guest-config/ds-slirp-dhcp.network"' _
  # Drift X: the SLIRP .network no longer does IPv4 DHCP (the SLIRP NIC gets no lease).
  inject_and_expect_fail "SLIRP .network drops DHCP=ipv4" bash -c '
    sed -i "s/^DHCP=ipv4/DHCP=no/" "$1/guest-config/ds-slirp-dhcp.network"' _
  # Drift Y: the SLIRP installer loses its routed-tap gate (ConditionPathExists=!ds-net.env).
  # THIS is the load-bearing "provably cannot catch the routed tap" arm: without the gate
  # the DHCP .network would be installed on the routed-tap boot and DHCP-race ds-netcfg.
  inject_and_expect_fail "SLIRP installer loses the routed-tap gate" bash -c '
    sed -i "/^ConditionPathExists=!/d" "$1/guest-config/ds-slirp-net.service"' _
  # Drift Z: the SLIRP installer no longer orders After=run-ds-entrypoint.mount (its
  # ds-net.env gate would evaluate before the config-drive is mounted => a routed-tap
  # boot could read ds-net.env as absent and wrongly install DHCP).
  inject_and_expect_fail "SLIRP installer unordered vs the config-drive mount" bash -c '
    sed -i "/^After=run-ds-entrypoint.mount/d" "$1/guest-config/ds-slirp-net.service"' _
  # Drift AA: the staged .network path is moved INTO a networkd search dir (it would then
  # auto-load at boot on BOTH paths and its match could catch the routed tap).
  inject_and_expect_fail "SLIRP .network staged inside a networkd search dir" bash -c '
    sed -i "s#^M0_SLIRP_NETWORK_STAGE=.*#M0_SLIRP_NETWORK_STAGE=/etc/systemd/network/10-ds-slirp-dhcp.network#" "$1/m0-image.env"' _
  # Drift AB: a bake path stops enabling systemd-networkd (a staged DHCP .network with
  # networkd disabled is inert — the pre-fix no-egress state).
  inject_and_expect_fail "bake path no longer enables systemd-networkd" bash -c '
    sed -i "/systemctl enable systemd-networkd/d" "$1/build-m0-image.sh"' _
  # Drift AC: the M0_SLIRP_NETWORK_STAGE pin is dropped from the env entirely.
  inject_and_expect_fail "SLIRP network-stage pin missing" bash -c '
    sed -i "/^M0_SLIRP_NETWORK_STAGE=/d" "$1/m0-image.env"' _

  # Drift AD: the baked Rust pin drifts from dataplane/rust-toolchain.toml. In a live VM
  # this does not fail loudly at bake — it fails at BUILD time, as cargo tries to fetch the
  # repo-pinned channel from static.rust-lang.org and is refused by the egress gate.
  inject_and_expect_fail "baked Rust pin drifts from dataplane/rust-toolchain.toml" bash -c '
    sed -i "s/^M0_RUST_VERSION=.*/M0_RUST_VERSION=0.0.0-drifted/" "$1/m0-image.env"' _
  # Drift AE: a toolchain tarball loses its pinned checksum (unverified compiler).
  inject_and_expect_fail "toolchain tarball checksum pin removed" bash -c '
    sed -i "/^M0_GO_SHA256=/d" "$1/m0-image.env"' _
  # Drift AF: the runtime unit stops exporting PATH — the toolchains are on disk but the
  # agent's non-login shell cannot see them (the live-found 2026-07-29 failure).
  inject_and_expect_fail "runtime unit no longer exports the toolchain PATH" bash -c '
    sed -i "/^Environment=PATH=/d" "$1/guest-config/ds-entrypoint.service"' _
  # Drift AG: the workspace mount is made fail-CLOSED, so a session with no workspace disk
  # (or a workspace that fails to mount) would be taken down instead of running without one.
  inject_and_expect_fail "workspace mount made fail-closed (RequiredBy)" bash -c '
    printf "RequiredBy=ds-entrypoint.service\n" >> "$1/guest-config/work.mount"' _

  echo "verify-image-pins: --self-test OK"
}

case "${1:-}" in
  --self-test) self_test ;;
  "" ) run_checks ;;
  *) echo "usage: $0 [--self-test]" >&2; exit 2 ;;
esac
