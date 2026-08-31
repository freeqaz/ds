#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# spire-live-multitier.sh — stand up a single-host MULTI-TIER SPIRE so the served
# X.509-SVIDs carry a REAL interposed intermediate, for the DEFERRED live-validation
# leg of identity/mint (TestSpireLiveE2E / TestSpireLiveDeepChain, env-gated on
# DS_SPIRE_LIVE — see identity/mint/spire_live_e2e_test.go).
#
# WHY MULTI-TIER. A vanilla SPIRE server is its own CA: the trust bundle IS the
# signing root, so leaf SVIDs chain DIRECTLY to the bundle (a flat trust domain, the
# shape the synthetic flat fake covers). To exercise the authority's interposed-CA
# chain-walk against a REAL deployment we point SPIRE's UpstreamAuthority at a disk
# root CA: SPIRE's own CA then becomes an INTERMEDIATE signed by that disk root, the
# PUBLISHED trust bundle is the disk root, and a served leaf chains
# leaf -> SPIRE-CA(interposed) -> disk-root. That is the >=1 interposed intermediate
# (x5c len >= 2) the deep-chain test asserts walks IDENTICALLY to the synthetic
# depth-2 fake (synthetic == live).
#
# WHAT IT DOES (idempotent, single host):
#   1. generate a self-signed disk ROOT CA (openssl) — the upstream authority;
#   2. write spire-server.conf with UpstreamAuthority "disk" pointing at that root
#      (so the published bundle = the disk root and SPIRE's CA is the interposed
#      intermediate) + a join-token NodeAttestor;
#   3. write spire-agent.conf (insecure_bootstrap, join_token NodeAttestor, unix
#      WorkloadAttestor, socket_path);
#   4. start spire-server, generate a join token, start the agent;
#   5. create a workload registration entry (parentID = the attested agent id,
#      spiffeID = spiffe://dream-serpent.test/session/e2e-live-0001,
#      selector unix:uid:$(id -u)) and wait for the agent to sync it;
#   6. print the SPIFFE_ENDPOINT_SOCKET value to export + the exact
#      `DS_SPIRE_LIVE=1 SPIFFE_ENDPOINT_SOCKET=... go test ...` command to run.
#
# This script is NOT run in the wave/CI (there is no live SPIRE socket in CI — D50);
# it is authored from the documented SPIRE 1.15 config surface and validated MANUALLY
# on a live box afterward. It speaks ONLY to a local SPIRE you provision; it never
# reaches the network beyond the loopback server<->agent gRPC.
#
# Requires: bash, openssl, spire-server, spire-agent (provide their dir via SPIRE_BIN
# or have them on PATH). Network: loopback only.
#
# Usage:
#   scripts/spire-live-multitier.sh up        # provision + start (default)
#   scripts/spire-live-multitier.sh down      # teardown (pkill daemons, keep workdir)
#   scripts/spire-live-multitier.sh print     # re-print the export + run command
#
# Knobs (env or leading VAR=val):
#   SPIRE_BIN   dir holding spire-server / spire-agent (default: PATH)
#   WORKDIR     work/state dir (default: ~/tmp/ds-spire-live-multitier)
#   TRUST_DOMAIN  SPIFFE trust domain (default: dream-serpent.test)
#   WORKLOAD_ID   the registered workload SPIFFE ID
#                 (default: spiffe://$TRUST_DOMAIN/session/e2e-live-0001)
#   SERVER_PORT   spire-server bind port (default: 8081)

set -euo pipefail

# --- knobs ------------------------------------------------------------------
SPIRE_BIN="${SPIRE_BIN:-}"
WORKDIR="${WORKDIR:-${HOME}/tmp/ds-spire-live-multitier}"
TRUST_DOMAIN="${TRUST_DOMAIN:-dream-serpent.test}"
WORKLOAD_ID="${WORKLOAD_ID:-spiffe://${TRUST_DOMAIN}/session/e2e-live-0001}"
SERVER_PORT="${SERVER_PORT:-8081}"

# Derived paths. Everything lives under WORKDIR so a teardown + re-run is clean.
ROOT_KEY="${WORKDIR}/upstream-root.key.pem"
ROOT_CRT="${WORKDIR}/upstream-root.crt.pem"
SERVER_CONF="${WORKDIR}/spire-server.conf"
AGENT_CONF="${WORKDIR}/spire-agent.conf"
SERVER_SOCK="${WORKDIR}/server-api.sock"
AGENT_SOCK="${WORKDIR}/agent-api.sock"
SERVER_DATA="${WORKDIR}/server-data"
AGENT_DATA="${WORKDIR}/agent-data"
SERVER_LOG="${WORKDIR}/spire-server.log"
AGENT_LOG="${WORKDIR}/spire-agent.log"
SERVER_PIDF="${WORKDIR}/spire-server.pid"
AGENT_PIDF="${WORKDIR}/spire-agent.pid"

# Resolve the SPIRE binaries: prefer SPIRE_BIN, fall back to PATH.
spire_bin() {
    local name="$1"
    if [ -n "${SPIRE_BIN}" ] && [ -x "${SPIRE_BIN}/${name}" ]; then
        printf '%s\n' "${SPIRE_BIN}/${name}"
        return 0
    fi
    if command -v "${name}" >/dev/null 2>&1; then
        command -v "${name}"
        return 0
    fi
    echo "spire-live-multitier: ERROR: ${name} not found (set SPIRE_BIN=<dir> or put it on PATH)" >&2
    return 1
}

require_tool() {
    local name="$1"
    if ! command -v "${name}" >/dev/null 2>&1; then
        echo "spire-live-multitier: ERROR: required tool '${name}' not found on PATH" >&2
        exit 1
    fi
}

# --- the upstream disk ROOT CA (the interposed-intermediate enabler) ---------
gen_root_ca() {
    if [ -f "${ROOT_CRT}" ] && [ -f "${ROOT_KEY}" ]; then
        echo "spire-live-multitier: upstream root CA already present (${ROOT_CRT}) — reusing" >&2
        return 0
    fi
    echo "spire-live-multitier: generating upstream disk root CA -> ${ROOT_CRT}" >&2
    # A self-signed EC P-256 root with the CA basic constraint + cert-sign usage. SPIRE
    # signs its own CA (the interposed intermediate) under THIS root, so the published
    # trust bundle is this root and served leaves chain leaf -> SPIRE-CA -> this-root.
    openssl ecparam -name prime256v1 -genkey -noout -out "${ROOT_KEY}"
    openssl req -new -x509 -key "${ROOT_KEY}" -out "${ROOT_CRT}" \
        -days 3650 -sha256 \
        -subj "/O=dream-serpent (live multi-tier upstream root)/CN=ds-spire-upstream-root" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign"
}

# --- config files (documented SPIRE 1.15 HCL surface) -----------------------
write_server_conf() {
    echo "spire-live-multitier: writing ${SERVER_CONF}" >&2
    # UpstreamAuthority "disk" makes SPIRE's signing CA an INTERMEDIATE issued under the
    # disk root; the published bundle = the disk root (upstream_bundle = true). The
    # join_token NodeAttestor lets the local agent attest with a one-shot token.
    cat >"${SERVER_CONF}" <<EOF
server {
    bind_address = "127.0.0.1"
    bind_port = "${SERVER_PORT}"
    socket_path = "${SERVER_SOCK}"
    trust_domain = "${TRUST_DOMAIN}"
    data_dir = "${SERVER_DATA}"
    log_level = "INFO"
    log_file = "${SERVER_LOG}"
    ca_ttl = "24h"
    default_x509_svid_ttl = "1h"
}

plugins {
    DataStore "sql" {
        plugin_data {
            database_type = "sqlite3"
            connection_string = "${SERVER_DATA}/datastore.sqlite3"
        }
    }

    NodeAttestor "join_token" {
        plugin_data {}
    }

    KeyManager "disk" {
        plugin_data {
            keys_path = "${SERVER_DATA}/keys.json"
        }
    }

    UpstreamAuthority "disk" {
        plugin_data {
            cert_file_path = "${ROOT_CRT}"
            key_file_path = "${ROOT_KEY}"
            # Publish the upstream root in the bundle so served leaves chain
            # leaf -> SPIRE-intermediate -> upstream-root (the multi-tier shape).
            upstream_bundle = true
        }
    }
}
EOF
}

write_agent_conf() {
    echo "spire-live-multitier: writing ${AGENT_CONF}" >&2
    # insecure_bootstrap = true: trust the server's bundle on first contact (acceptable
    # for a local, throwaway, single-host bring-up). The unix WorkloadAttestor matches
    # the workload by its uid/gid so the registration entry's unix:uid selector resolves.
    cat >"${AGENT_CONF}" <<EOF
agent {
    data_dir = "${AGENT_DATA}"
    log_level = "INFO"
    log_file = "${AGENT_LOG}"
    server_address = "127.0.0.1"
    server_port = "${SERVER_PORT}"
    socket_path = "${AGENT_SOCK}"
    trust_domain = "${TRUST_DOMAIN}"
    insecure_bootstrap = true
}

plugins {
    NodeAttestor "join_token" {
        plugin_data {}
    }

    KeyManager "memory" {
        plugin_data {}
    }

    WorkloadAttestor "unix" {
        plugin_data {}
    }
}
EOF
}

# --- daemon lifecycle -------------------------------------------------------
is_running() {
    local pidf="$1"
    [ -f "${pidf}" ] || return 1
    local pid
    pid="$(cat "${pidf}")"
    [ -n "${pid}" ] && kill -0 "${pid}" 2>/dev/null
}

wait_for_socket() {
    local sock="$1" label="$2" tries=0
    while [ "${tries}" -lt 50 ]; do
        [ -S "${sock}" ] && return 0
        tries=$((tries + 1))
        sleep 0.2
    done
    echo "spire-live-multitier: ERROR: ${label} socket ${sock} did not appear (see logs in ${WORKDIR})" >&2
    return 1
}

start_server() {
    local server
    server="$(spire_bin spire-server)"
    if is_running "${SERVER_PIDF}"; then
        echo "spire-live-multitier: spire-server already running (pid $(cat "${SERVER_PIDF}"))" >&2
        return 0
    fi
    echo "spire-live-multitier: starting spire-server" >&2
    "${server}" run -config "${SERVER_CONF}" >"${SERVER_LOG}" 2>&1 &
    echo "$!" >"${SERVER_PIDF}"
    wait_for_socket "${SERVER_SOCK}" "spire-server"
}

start_agent() {
    local agent server token
    agent="$(spire_bin spire-agent)"
    server="$(spire_bin spire-server)"
    if is_running "${AGENT_PIDF}"; then
        echo "spire-live-multitier: spire-agent already running (pid $(cat "${AGENT_PIDF}"))" >&2
        return 0
    fi
    # Generate a one-shot join token bound to a node SPIFFE ID the workload entry parents
    # under. -output json keeps the token machine-parseable across SPIRE versions.
    echo "spire-live-multitier: generating join token" >&2
    token="$("${server}" token generate \
        -socketPath "${SERVER_SOCK}" \
        -spiffeID "spiffe://${TRUST_DOMAIN}/node/live-multitier" \
        -output json | sed -n 's/.*"value"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
    if [ -z "${token}" ]; then
        echo "spire-live-multitier: ERROR: failed to parse a join token from spire-server" >&2
        return 1
    fi
    echo "spire-live-multitier: starting spire-agent" >&2
    "${agent}" run -config "${AGENT_CONF}" -joinToken "${token}" >"${AGENT_LOG}" 2>&1 &
    echo "$!" >"${AGENT_PIDF}"
    wait_for_socket "${AGENT_SOCK}" "spire-agent"
}

# --- workload registration --------------------------------------------------
register_workload() {
    local server
    server="$(spire_bin spire-server)"
    echo "spire-live-multitier: registering workload entry ${WORKLOAD_ID}" >&2
    # parentID = the attested node id (the join_token node); selector unix:uid:<me> so
    # the agent's unix WorkloadAttestor matches the go-test process running as this uid.
    # Idempotent: a duplicate entry is reported by spire-server and ignored here.
    "${server}" entry create \
        -socketPath "${SERVER_SOCK}" \
        -parentID "spiffe://${TRUST_DOMAIN}/node/live-multitier" \
        -spiffeID "${WORKLOAD_ID}" \
        -selector "unix:uid:$(id -u)" \
        -x509SVIDTTL 3600 >>"${SERVER_LOG}" 2>&1 || \
        echo "spire-live-multitier: entry create returned non-zero (likely already exists) — continuing" >&2
    # Give the agent a moment to sync the new entry from the server.
    sleep 2
}

# --- output -----------------------------------------------------------------
print_run_command() {
    local sock_uri="unix://${AGENT_SOCK}"
    cat <<EOF

================================================================================
 SPIRE multi-tier (UpstreamAuthority disk) bring-up READY.

 Trust domain : ${TRUST_DOMAIN}
 Workload SVID: ${WORKLOAD_ID}
 Upstream root: ${ROOT_CRT}   (published trust bundle = this root)
 Agent socket : ${AGENT_SOCK}

 Export the Workload-API socket:

   export SPIFFE_ENDPOINT_SOCKET="${sock_uri}"

 Run the env-gated live deep-chain leg (from the identity/mint module dir):

   DS_SPIRE_LIVE=1 SPIFFE_ENDPOINT_SOCKET="${sock_uri}" \\
     GOWORK=off go test -run 'TestSpireLive' -v ./identity/mint

 Or cross-compile the test binary and run it on the SPIRE host:

   GOWORK=off go test -c -o /tmp/mint.test ./identity/mint
   DS_SPIRE_LIVE=1 SPIFFE_ENDPOINT_SOCKET="${sock_uri}" \\
     /tmp/mint.test -test.run 'TestSpireLive' -test.v

 Teardown when done:

   scripts/spire-live-multitier.sh down
================================================================================
EOF
}

# --- subcommands ------------------------------------------------------------
do_up() {
    require_tool openssl
    spire_bin spire-server >/dev/null
    spire_bin spire-agent >/dev/null
    mkdir -p "${WORKDIR}" "${SERVER_DATA}" "${AGENT_DATA}"
    gen_root_ca
    write_server_conf
    write_agent_conf
    start_server
    start_agent
    register_workload
    print_run_command
}

do_down() {
    echo "spire-live-multitier: tearing down daemons" >&2
    local pidf pid
    for pidf in "${AGENT_PIDF}" "${SERVER_PIDF}"; do
        if [ -f "${pidf}" ]; then
            pid="$(cat "${pidf}")"
            if [ -n "${pid}" ] && kill -0 "${pid}" 2>/dev/null; then
                kill "${pid}" 2>/dev/null || true
            fi
            rm -f "${pidf}"
        fi
    done
    # Belt-and-suspenders: pkill any stragglers bound to THIS workdir's configs only,
    # so a co-tenant SPIRE on the box is left untouched.
    pkill -f "spire-server run -config ${SERVER_CONF}" 2>/dev/null || true
    pkill -f "spire-agent run -config ${AGENT_CONF}" 2>/dev/null || true
    echo "spire-live-multitier: down (workdir ${WORKDIR} kept; rm -rf it to fully reset)" >&2
}

do_print() {
    if [ ! -S "${AGENT_SOCK}" ]; then
        echo "spire-live-multitier: agent socket ${AGENT_SOCK} not present — run '$0 up' first" >&2
        exit 1
    fi
    print_run_command
}

main() {
    local cmd="${1:-up}"
    case "${cmd}" in
        up) do_up ;;
        down) do_down ;;
        print) do_print ;;
        *)
            echo "usage: $0 [up|down|print]" >&2
            exit 2
            ;;
    esac
}

main "$@"
