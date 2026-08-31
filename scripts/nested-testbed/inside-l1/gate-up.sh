#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# gate-up.sh — runs INSIDE L1. Stand up the gated-egress boundary that L2's egress
# is forced through: the nft floor (default-deny forward) + the 53/80/443 redirects
# + a routed tap (dstap-<idx>) + ds-dnsgate + ds-tlsproxy. This is the ds-gated-egress.sh
# shape — but here it is SAFE: L1 is a disposable VM, so we can run the real
# input-policy-drop appliance floor without any risk to the host or its Tailscale link.
#
#   --strict   apply the REAL appliance floor: `chain input policy drop` (nft-1) with
#              explicit accepts for the redirected gateway flows + the SLIRP mgmt iface
#              (so ssh survives). Default (no flag) uses input=accept (the netns-proven
#              host-script shape) — the egress gate is the forward DROP either way.
#
#   --no-filter-reset   (env DS_GATE_PRESERVE_FILTER=1)  PRESERVE-FILTER mode: compose
#              the appliance floor WITH the host-agent's live per-session NFT instead of
#              owning the world. The host-agent's InstantiateSessionNFT already created
#              `table inet ds_filter` + the per-session `allow4_<idx>`/`allow6_<idx>` sets
#              (the DNS-admitted allow path), and already created+addressed the routed
#              tap `dstap-<idx>` (CreateTap). The default path's step-2 `delete table inet
#              ds_filter` + recreate WIPES those live sets, and step-3's `ip tuntap add`
#              races CreateTap. In preserve mode we therefore: (a) apply ONLY `inet
#              ds_boundary` (the floor: forward DROP + the 53/80/443 redirects + the QUIC
#              reject) and DO NOT touch `inet ds_filter` (the host-agent owns it); (b) skip
#              the tap create/addr when the tap already exists, applying only the route.
#              The gateways start in both modes. Default (non-preserve) is byte-identical.
set -uo pipefail
STRICT=""; PRESERVE=""
[ "${DS_GATE_PRESERVE_FILTER:-}" = "1" ] && PRESERVE=1
for arg in "$@"; do
  case "$arg" in
    --strict)          STRICT=1 ;;
    --no-filter-reset) PRESERVE=1 ;;
  esac
done
IDX="${DS_SESSION_IDX:-7}"
TAP="dstap-${IDX}"
NET="10.77.${IDX}"
# D63 boundary-readiness pre-step (01KV9B2DGN): when set, apply the host-WIDE floor (the
# three RequiredBoundaryTables) + start the gateways but SKIP the per-session routed-tap
# block — no tap exists yet (the host-agent's CreateTap makes it at step-4, AFTER the
# readiness probe). The normal post-CreateSession gate-up pass then does the per-tap route.
FLOOR_ONLY="${DS_GATE_FLOOR_ONLY:-}"
BIN="${DS_BIN:-/opt/ds/bin}"
RUN="${DS_GATE_RUN:-/run/ds-gate}"
DNS_PORT=15353; HTTP_PORT=18080; HTTPS_PORT=18443
mkdir -p "$RUN"
say(){ printf '\033[1;36m[gate] %s\033[0m\n' "$*"; }
die(){ printf '\033[1;31m[gate][FATAL] %s\033[0m\n' "$*" >&2; exit 1; }

# --- posture-(b) cred-swap knobs (DS_GATE_TLS_MODE=swap only; additive) -------
# Agreed env-knob names (shared verbatim with the ds-tlsproxy session-ca-ingest unit
# and consumed by ds-tlsproxy main.rs): the interception CA is provided to ds-tlsproxy
# via DS_TLSPROXY_SESSION_CA_CERT (PEM cert) + DS_TLSPROXY_SESSION_CA_KEY (PEM key);
# the swap gates are DS_TLS3_LIVE=1 / DS_SWAP_VALIDATE_LIVE=1 / DS_SWAP_VALIDATE_UDS /
# DS_TLSPROXY_SECRET_DIR / DS_SWAP_REGISTRY_PACK / DS_TLSPROXY_UPSTREAM_ROOTS. The fake
# D22 Validate server is /opt/ds/bin/ds-identity-validate-fake (staged by
# build-dataplane-debian.sh); the swap grant_ref is "grant-anthropic" (the credential
# FILE name ds-tlsproxy resolves under DS_TLSPROXY_SECRET_DIR — see main.rs
# `$DS_TLSPROXY_SECRET_DIR` resolve-by-grant_ref-first). These default to the testbed
# conventions; an operator may pre-set any of them to override.
VALIDATE_FAKE_BIN="${DS_VALIDATE_FAKE_BIN:-$BIN/ds-identity-validate-fake}"
SWAP_VALIDATE_UDS="${DS_SWAP_VALIDATE_UDS:-/run/ds-identity/validate.sock}"
SWAP_SECRET_DIR="${DS_TLSPROXY_SECRET_DIR:-$RUN/secrets}"
SWAP_REGISTRY_PACK="${DS_SWAP_REGISTRY_PACK:-$RUN/swap-registry.pack}"
SWAP_UPSTREAM_ROOTS="${DS_TLSPROXY_UPSTREAM_ROOTS:-/etc/ssl/certs/ca-certificates.crt}"
SWAP_GRANT_REF="grant-anthropic"
# The per-run interception CA the proxy presents leaves under (so the in-VM CC trusts
# the terminated TLS). Honor an operator-provided pair; otherwise generate one below.
SWAP_CA_CERT="${DS_TLSPROXY_SESSION_CA_CERT:-$RUN/intercept-ca.crt}"
SWAP_CA_KEY="${DS_TLSPROXY_SESSION_CA_KEY:-$RUN/intercept-ca.key}"
# The shared per-session AdmissionMap key both gateways agree on (DS_SESSION_UUID): ds-dnsgate
# WRITES each Allow admission under {DS_SESSION_UUID, fqdn} and ds-tlsproxy READS its TLS-1
# ReAdmit / TLS-3 CV3 lookup under the same key — so the FORWARD admission hits (else the write
# key "src:<addr>" and the read key "" never match → tls1-readmit-denied). Single-VM testbed
# default; the production agreement is the orchestrator session-record join. Unset on EITHER
# process ⇒ the historical mismatch (byte-identical pre-agreement behavior).
SWAP_SESSION_UUID="${DS_SESSION_UUID:-sess-nested-testbed-0001}"
# The real Anthropic CC OAuth token is read at RUNTIME (never echoed/logged/committed,
# D50): DS_CC_OAUTH_TOKEN preferred, else the staged file DS_CC_TOKEN_FILE.
CC_TOKEN_FILE="${DS_CC_TOKEN_FILE:-/opt/ds/secrets/cc-oauth-token}"

[ -x "$BIN/ds-dnsgate" ]  || die "ds-dnsgate not at $BIN (stage the 9p share)"
[ -x "$BIN/ds-tlsproxy" ] || die "ds-tlsproxy not at $BIN"

say "1. kernel modules + ip_forward"
for m in nf_tables nft_redir nft_nat nf_nat nft_reject_inet tun; do modprobe "$m" 2>/dev/null || true; done
sysctl -wq net.ipv4.ip_forward=1
sysctl -wq net.ipv4.conf.all.rp_filter=0 2>/dev/null || true

# --- the floor --------------------------------------------------------------
INPUT_POLICY="accept"; EXTRA_INPUT=""
if [ -n "$STRICT" ]; then
  INPUT_POLICY="drop"
  MGMT="$(ip -o route show default 2>/dev/null | awk '{print $5; exit}')"; MGMT="${MGMT:-eth0}"
  EXTRA_INPUT=$(cat <<EOF

		# STRICT: real nft-1 input policy DROP. Accept the redirected gateway flows
		# (REDIRECT DNATs them to the local tap addr, so they land in input) and keep
		# the SLIRP management iface alive (else this very ssh session is cut — the
		# host-floor hazard, here harmless: drive L1 via the serial console).
		iifname "${MGMT}" accept
		iifname "dstap-*" udp dport ${DNS_PORT} accept
		iifname "dstap-*" tcp dport { ${DNS_PORT}, ${HTTP_PORT}, ${HTTPS_PORT} } accept
EOF
)
fi
# The `inet ds_filter` table (the per-session allow4_<idx>/allow6_<idx> sets) is owned
# by the host-agent's InstantiateSessionNFT on the combined up-orch path. In the DEFAULT
# (standalone) flow gate-up.sh owns it and resets it; in PRESERVE-FILTER mode we leave it
# entirely to the host-agent (delete/recreate would WIPE its live DNS-admitted allow-sets).
FILTER_BLOCK=""
if [ -z "$PRESERVE" ]; then
  FILTER_BLOCK=$(cat <<NFTFILTER

table inet ds_filter
delete table inet ds_filter
table inet ds_filter {
	set allow4_${IDX} { type ipv4_addr; flags timeout; }
	set allow6_${IDX} { type ipv6_addr; flags timeout; }
}
NFTFILTER
)
else
  say "2. PRESERVE-FILTER: leaving inet ds_filter to the host-agent (skipping delete/create of its allow4_${IDX}/allow6_${IDX} sets)"
fi
say "2. apply nft floor (input=${INPUT_POLICY}, forward=drop, 53->:${DNS_PORT} 80->:${HTTP_PORT} 443->:${HTTPS_PORT})"
nft -f - <<NFT || die "nft apply failed"
table inet ds_boundary
delete table inet ds_boundary
table inet ds_boundary {
	chain input {
		type filter hook input priority filter; policy ${INPUT_POLICY};
		ct state established,related accept
		iifname "lo" accept${EXTRA_INPUT}
	}
	chain forward {
		# THE EGRESS GATE: default-deny. Direct VM egress is dropped here; only the
		# REDIRECT'd 53/80/443 flows (DNAT'd to local, handled in input) get through.
		type filter hook forward priority filter; policy drop;
		ct state established,related accept
		iifname "dstap-*" ct state new udp dport 443 counter reject with icmpx type port-unreachable
		iifname "dstap-*" ct state new counter drop
	}
	chain output { type filter hook output priority filter; policy accept; }
	chain prerouting {
		type nat hook prerouting priority dstnat; policy accept;
		iifname "dstap-*" udp dport 53 redirect to :${DNS_PORT}
		iifname "dstap-*" tcp dport 53 redirect to :${DNS_PORT}
		iifname "dstap-*" tcp dport 80 redirect to :${HTTP_PORT}
		iifname "dstap-*" tcp dport 443 redirect to :${HTTPS_PORT}
	}
}
table inet ds_resolver_closure
delete table inet ds_resolver_closure
table inet ds_resolver_closure { }
table inet ds_proxy_out
delete table inet ds_proxy_out
table inet ds_proxy_out { }${FILTER_BLOCK}
NFT

# --- routed tap -------------------------------------------------------------
# In PRESERVE-FILTER mode the host-agent's CreateTap already created + addressed
# dstap-<idx>; re-creating/flushing/re-addressing it would race that owner and could
# tear the live link. So if the tap already exists we apply ONLY the route (idempotent,
# the route-if-missing leg) and leave the interface + its address to the host-agent.
if [ -n "$FLOOR_ONLY" ]; then
  say "3. FLOOR_ONLY (D63 readiness pre-step): skipping the per-session routed tap — the host-agent's CreateTap owns dstap-<idx> at step-4; the per-tap route lands on the post-CreateSession gate-up pass"
elif [ -n "$PRESERVE" ] && ip link show "$TAP" >/dev/null 2>&1; then
  say "3. routed tap $TAP exists (host-agent CreateTap) — route-only ($NET.1 dev $TAP)"
  ip route replace "$NET.1/32" dev "$TAP"
else
  say "3. routed tap $TAP ($NET.0/31, route to $NET.1)"
  ip link show "$TAP" >/dev/null 2>&1 || ip tuntap add "$TAP" mode tap
  ip addr flush dev "$TAP" 2>/dev/null || true
  ip addr add "$NET.0/31" dev "$TAP"
  ip link set "$TAP" up
  ip route replace "$NET.1/32" dev "$TAP"
fi

# ds-dnsgate reads its POL-2 baseline policy pack from a path baked at COMPILE time
# (env!("CARGO_MANIFEST_DIR")/../../artifacts/policy-packs/pol2-system-baseline.pol1.yaml)
# = /work/dataplane/artifacts/policy-packs/... — non-overridable. Recreate that exact
# path inside L1 by symlinking it at the staged artifacts dir (else dnsgate exits with
# "reading shipped POL-2 baseline pack … No such file or directory").
if [ -d /opt/ds/artifacts/policy-packs ]; then
  mkdir -p /work/dataplane
  ln -sfn /opt/ds/artifacts /work/dataplane/artifacts
  say "   wired ds-dnsgate policy pack: /work/dataplane/artifacts -> /opt/ds/artifacts"
else
  say "   WARN: /opt/ds/artifacts/policy-packs missing — ds-dnsgate will fail to start (stage dataplane/artifacts)"
fi

# --- gateways ---------------------------------------------------------------
# TLS mode (DS_GATE_TLS_MODE):
#   opaque (default) — POSTURE=a: ds-tlsproxy terminates+forwards ANY 443 to its real
#                      destination (the gate enforces "443 only via the proxy", not which
#                      host). DS_TLS1_LIVE/DS_TLS3_LIVE must be UNSET — the code treats a
#                      PRESENT-but-empty var as "armed", so `env -u` guarantees opaque.
#   enforce          — arm TLS-1 SNI admission: the proxy refuses any SNI the policy pack
#                      doesn't admit (tls1-policy-deny). The stricter, real posture.
#   swap             — POSTURE=b (D39 credential swap): ds-tlsproxy TERMINATES the VM's
#                      TLS with a per-session interception CA (TLS-3, DS_TLS3_LIVE=1) and
#                      SWAPS the placeholder Authorization header CC sends for the REAL
#                      Anthropic token fetched host-side (TLS-5, DS_SWAP_VALIDATE_LIVE=1).
#                      The real token NEVER enters the VM — it lives only in the host
#                      secret store (DS_TLSPROXY_SECRET_DIR/grant-anthropic); the VM is
#                      handed a PLACEHOLDER (orchestrator-boot-l2.sh) + the CA cert via
#                      NODE_EXTRA_CA_CERTS so its CC trusts the terminated TLS. opaque
#                      stays the default; swap is purely additive (opaque/enforce
#                      byte-identical).
TLS_MODE="${DS_GATE_TLS_MODE:-opaque}"

# --- posture-(b) swap prep (DS_GATE_TLS_MODE=swap only) -----------------------
# Stand up the four host-side facts the swap path needs BEFORE launching ds-tlsproxy:
#   (a) a per-run interception CA (generated unless an operator provided the pair);
#   (b) the swap registry pack naming the anthropic service + its host + cred location;
#   (c) the secret dir + the REAL token staged at /<grant_ref> (runtime-read, never
#       logged — D50); fail-soft with a WARN if the token source is absent;
#   (d) the fake D22 Validate server on the swap validate UDS.
# Each sub-step is no-op outside swap mode, so opaque/enforce are unchanged.
swap_prep() {
  # (a) interception CA: honor an operator-provided pair, else self-generate via openssl.
  if [ -r "$SWAP_CA_CERT" ] && [ -r "$SWAP_CA_KEY" ]; then
    say "   swap(a): using provided interception CA cert=$SWAP_CA_CERT key=$SWAP_CA_KEY"
  elif command -v openssl >/dev/null 2>&1; then
    say "   swap(a): generating per-run interception CA at $SWAP_CA_CERT (+ key, mode 0600)"
    # A self-signed CA whose subject CN follows the ds-session-ca-<id> convention ca.rs
    # asserts (issuer provenance); -nodes => unencrypted key (the proxy ingests raw PEM).
    openssl req -x509 -newkey rsa:2048 -nodes \
      -keyout "$SWAP_CA_KEY" -out "$SWAP_CA_CERT" \
      -days 7 -subj "/CN=ds-session-ca-l1-testbed" >/dev/null 2>&1 \
      || die "swap(a): openssl failed to generate the interception CA"
    chmod 600 "$SWAP_CA_KEY" 2>/dev/null || true
  else
    die "swap(a): no interception CA — set DS_TLSPROXY_SESSION_CA_CERT/KEY or install openssl (the proxy needs a CA to present trustable leaves)"
  fi

  # (b) swap registry pack. NOTE: ds-tlsproxy main.rs (load_swap_registry_from_pack)
  # parses a TAB-separated text pack — `service<TAB>hosts<TAB>cred_location<TAB>cred_name`
  # — NOT JSON (it adds no serde dep, D40/D67 offline). One row arms the anthropic swap
  # for api.anthropic.com via the Authorization header. The row is secret-free.
  printf 'anthropic\tapi.anthropic.com\theader\tAuthorization\n' > "$SWAP_REGISTRY_PACK"
  say "   swap(b): wrote swap registry pack $SWAP_REGISTRY_PACK (anthropic/api.anthropic.com/header/Authorization)"

  # (c) secret dir (0700) + the REAL token staged at /<grant_ref>. Read at RUNTIME from
  # $DS_CC_OAUTH_TOKEN (preferred) or the staged file $DS_CC_TOKEN_FILE; NEVER echoed,
  # logged, or committed (D50 raw-class). ds-tlsproxy resolves the credential FILE by
  # grant_ref first, so the file name is exactly the grant_ref (grant-anthropic).
  #
  # STORE THE BARE TOKEN, NOT "Bearer <token>": ds-tlsproxy substitutes the outbound
  # Authorization value as `<scheme> <fetched-bytes>` where <scheme> is the hardcoded
  # INSPECT_AUTH_SCHEME="Bearer" (main.rs) → swap::substitute_authorization joins
  # "Bearer" + " " + the file's bytes. The fetcher also trims exactly one trailing
  # newline. So the file must contain ONLY the raw token — storing "Bearer <token>"
  # here would egress the broken `Authorization: Bearer Bearer <token>` upstream.
  mkdir -p "$SWAP_SECRET_DIR"
  chmod 700 "$SWAP_SECRET_DIR" 2>/dev/null || true
  local tokfile="$SWAP_SECRET_DIR/$SWAP_GRANT_REF"
  if [ -n "${DS_CC_OAUTH_TOKEN:-}" ]; then
    # Bare token only — the proxy adds the "Bearer " scheme. Written umask-tight, never echoed.
    ( umask 077; printf '%s' "$DS_CC_OAUTH_TOKEN" > "$tokfile" )
    say "   swap(c): staged the real token at $tokfile (from \$DS_CC_OAUTH_TOKEN; value never logged)"
  elif [ -r "$CC_TOKEN_FILE" ]; then
    ( umask 077; printf '%s' "$(tr -d '\r\n' < "$CC_TOKEN_FILE")" > "$tokfile" )
    say "   swap(c): staged the real token at $tokfile (from $CC_TOKEN_FILE; value never logged)"
  else
    say "   swap(c): WARN no CC OAuth token (set \$DS_CC_OAUTH_TOKEN or stage $CC_TOKEN_FILE) — the secret store has no $SWAP_GRANT_REF; the swap fetch will fail-closed until staged"
  fi

  # (d) the fake D22 Validate server on the swap validate UDS.
  #
  # DEFAULT is always-ALLOW (TEST ONLY): with neither DS_SWAP_VALIDATE_VERDICT nor
  # DS_SWAP_VALIDATE_REASON set, the launch argv is BYTE-IDENTICAL to the historical
  # invocation (only --uds/--grant-ref) — the fake's own default is verdict=allow, so
  # the always-ALLOW leg is untouched. Setting DS_SWAP_VALIDATE_VERDICT (allow|deny|
  # unspecified|garbage) forwards it as --verdict so the posture-(b) testbed can drive
  # the DENY leg and (once the fake's unspecified/garbage emitters exist) the FAIL-CLOSED
  # half of the client's verdict-mapping; DS_SWAP_VALIDATE_REASON forwards --reason (the
  # machine_readable_reason a deny carries). The verdict arg vector stays EMPTY unless an
  # env knob is set, so the default path is preserved exactly.
  mkdir -p "$(dirname "$SWAP_VALIDATE_UDS")"
  local verdict_report="allow (default)"
  local -a verdict_args=()
  if [ -n "${DS_SWAP_VALIDATE_VERDICT:-}" ]; then
    verdict_args+=(--verdict "$DS_SWAP_VALIDATE_VERDICT")
    verdict_report="$DS_SWAP_VALIDATE_VERDICT (DS_SWAP_VALIDATE_VERDICT)"
  fi
  if [ -n "${DS_SWAP_VALIDATE_REASON:-}" ]; then
    verdict_args+=(--reason "$DS_SWAP_VALIDATE_REASON")
    verdict_report="$verdict_report reason=$DS_SWAP_VALIDATE_REASON"
  fi
  if [ -x "$VALIDATE_FAKE_BIN" ]; then
    pkill -f "$VALIDATE_FAKE_BIN" 2>/dev/null || true
    rm -f "$SWAP_VALIDATE_UDS" 2>/dev/null || true
    nohup "$VALIDATE_FAKE_BIN" --uds "$SWAP_VALIDATE_UDS" --grant-ref "$SWAP_GRANT_REF" "${verdict_args[@]}" \
      >"$RUN/validate-fake.log" 2>&1 & echo $! >"$RUN/validate-fake.pid"; disown
    sleep 0.3
    say "   swap(d): started ds-identity-validate-fake on $SWAP_VALIDATE_UDS (grant-ref=$SWAP_GRANT_REF, verdict=$verdict_report, pid $(cat "$RUN/validate-fake.pid"))"
  else
    say "   swap(d): WARN ds-identity-validate-fake not at $VALIDATE_FAKE_BIN — DS_SWAP_VALIDATE_LIVE has no responder; the swap will fail-closed (stage it via build-dataplane-debian.sh)"
  fi
}

[ "$TLS_MODE" = "swap" ] && { say "4a. posture-(b) cred-swap prep (interception CA + registry pack + secret store + fake Validate)"; swap_prep; }

say "4. start ds-dnsgate (0.0.0.0:${DNS_PORT}) then ds-tlsproxy (0.0.0.0:${HTTP_PORT}/${HTTPS_PORT}, tls=${TLS_MODE})"
pkill -f "$BIN/ds-tlsproxy" 2>/dev/null || true
pkill -f "$BIN/ds-dnsgate"  2>/dev/null || true
sleep 0.3
# ds-dnsgate FIRST in swap mode: it is the WRITER/creator of the DNS-2b AdmissionMap shm
# (DS_ADMISSION_SHM_LIVE) that ds-tlsproxy only READS. If the reader (tlsproxy) touches the
# segment first, a 0-byte placeholder shadows dnsgate's create-or-reattach so dnsgate fails to
# bind :15353 (no DNS → no egress; the live-debug RC). Clear any STALE segment from a prior run
# and let dnsgate create the sized (~6.5MB) segment before the reader attaches. Segment name =
# ds_contracts admission_shm_name() → /dev/shm/ds-admission. DS_NFTGATE_LIVE left UNSET so
# dnsgate's RecordingSetProgrammer does not race the host-agent's InstantiateSessionNFT.
if [ "$TLS_MODE" = "swap" ]; then
  rm -f /dev/shm/ds-admission 2>/dev/null || true
  DS_DNSGATE_LISTEN="0.0.0.0:${DNS_PORT}" DS_ADMISSION_SHM_LIVE=1 DS_SESSION_UUID="$SWAP_SESSION_UUID" nohup "$BIN/ds-dnsgate" >"$RUN/dnsgate.log" 2>&1 & echo $! >"$RUN/dnsgate.pid"; disown
  sleep 1.0   # let dnsgate create + size the shm before the reader (tlsproxy) attaches
else
  DS_DNSGATE_LISTEN="0.0.0.0:${DNS_PORT}" nohup "$BIN/ds-dnsgate" >"$RUN/dnsgate.log" 2>&1 & echo $! >"$RUN/dnsgate.pid"; disown
fi
# --nodaemon keeps pingora in the foreground so the pid + logs are ours (it daemonizes by default).
if [ "$TLS_MODE" = "swap" ]; then
  # POSTURE=b: arm TLS-3 termination (DS_TLS3_LIVE=1) + the TLS-5 live credential swap
  # (DS_SWAP_VALIDATE_LIVE=1). The proxy ingests the per-session interception CA from
  # DS_TLSPROXY_SESSION_CA_CERT/KEY (the session-ca-ingest unit's acquire_session_ca),
  # validates the placeholder Authorization against the fake D22 Validate UDS, fetches
  # the REAL token from the host secret store, swaps it in, and re-originates upstream
  # over the system trust roots (DS_TLSPROXY_UPSTREAM_ROOTS). NONE of these vars are set
  # on the opaque/enforce paths, so those stay byte-identical.
  #
  # DS_TLS1_LIVE=1 is ALSO required here: the TLS-3 swap path's CV3 check (the CDN
  # shared-IP hole guard) re-validates the kernel original_dst against the live FORWARD
  # AdmissionMap, but acquire_admission_map() only attaches the shared shm reader when
  # tls1_live_enabled(); without it the reader is the empty in-process fake and EVERY
  # inspected flow fail-closes ("no live FORWARD admission including the kernel
  # original_dst"). Pairs with ds-dnsgate's DS_ADMISSION_SHM_LIVE=1 writer below.
  DS_TLS1_LIVE=1 \
  DS_TLS3_LIVE=1 \
  DS_SESSION_UUID="$SWAP_SESSION_UUID" \
  DS_TLSPROXY_BOOT_POLICY="${DS_TLSPROXY_BOOT_POLICY:-/opt/ds/artifacts/policy-packs/pol2-system-baseline.pol1.yaml}" \
  DS_SWAP_VALIDATE_LIVE=1 \
  DS_SWAP_VALIDATE_UDS="$SWAP_VALIDATE_UDS" \
  DS_TLSPROXY_SECRET_DIR="$SWAP_SECRET_DIR" \
  DS_SWAP_REGISTRY_PACK="$SWAP_REGISTRY_PACK" \
  DS_TLSPROXY_UPSTREAM_ROOTS="$SWAP_UPSTREAM_ROOTS" \
  DS_TLSPROXY_SESSION_CA_CERT="$SWAP_CA_CERT" \
  DS_TLSPROXY_SESSION_CA_KEY="$SWAP_CA_KEY" \
    nohup "$BIN/ds-tlsproxy" --nodaemon >"$RUN/tlsproxy.log" 2>&1 & echo $! >"$RUN/tlsproxy.pid"; disown
elif [ "$TLS_MODE" = "enforce" ]; then
  DS_TLS1_LIVE=1 nohup "$BIN/ds-tlsproxy" --nodaemon >"$RUN/tlsproxy.log" 2>&1 & echo $! >"$RUN/tlsproxy.pid"; disown
else
  nohup env -u DS_TLS1_LIVE -u DS_TLS3_LIVE "$BIN/ds-tlsproxy" --nodaemon >"$RUN/tlsproxy.log" 2>&1 & echo $! >"$RUN/tlsproxy.pid"; disown
fi
# (ds-dnsgate already started above — first in swap mode so it creates the shm before
# ds-tlsproxy attaches as reader.)
sleep 1.5

say "5. boundary up — listeners:"
ss -ltnup 2>/dev/null | grep -E ":${DNS_PORT}|:${HTTP_PORT}|:${HTTPS_PORT}" || say "  (no listeners yet — check $RUN/*.log)"
echo "   dnsgate: $(grep -m1 'listeners up' "$RUN/dnsgate.log" 2>/dev/null || echo '?')"
echo "   tlsproxy: $(grep -m1 'listening on' "$RUN/tlsproxy.log" 2>/dev/null || echo '?')"
if [ "$TLS_MODE" = "swap" ]; then
  # Export the interception CA cert PATH (not the key) on stdout in a stable, greppable
  # form so the caller (orchestrator-boot-l2.sh) can inject it into the guest as
  # NODE_EXTRA_CA_CERTS. The cert is non-secret (a CA public cert); the key is NEVER
  # printed (D50). Also drop the path into a well-known file under $RUN for callers that
  # run gate-up.sh detached.
  printf '%s\n' "$SWAP_CA_CERT" > "$RUN/intercept-ca.path"
  echo "DS_GATE_INTERCEPT_CA_CERT=$SWAP_CA_CERT"
  say "   swap: interception CA cert at $SWAP_CA_CERT (inject into the guest as NODE_EXTRA_CA_CERTS; the CA KEY is never printed)"
fi
say "DONE. Boot L2 with: /opt/ds/inside-l1/l2-up.sh   then validate: /opt/ds/inside-l1/validate.sh"
