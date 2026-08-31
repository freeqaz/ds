#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# bootstrap.sh — apply the declarative proxy-repo manifest (repos.yaml) to a
# running Nexus instance via its REST API. Idempotent: re-running reconciles.
#
# D41: this provisions an off-the-shelf cache. It contains ZERO registry-protocol
# code — it only POSTs Nexus's own repository-creation API the set of upstreams
# the cache should front. Nexus implements every registry semantic; we declare
# desired state and walk away.
#
# Run AFTER the container is up and its status endpoint is green:
#   images/cache/deploy/bootstrap.sh
#
# Env knobs (all optional, defaults match deploy/nexus.container):
#   NEXUS_URL     base URL of the Nexus core API   (default http://localhost:8081)
#   NEXUS_USER    admin user                        (default admin)
#   NEXUS_PASS    admin password                    (default: read from the
#                 container's first-boot admin.password file, see below)
#   DOCKER_HTTP_PORT  OCI connector port            (default 5000)
#
# First-boot password: Nexus writes a random admin password to
# /nexus-data/admin.password inside the container on first start. Retrieve it
# with:  podman exec ds-cache-nexus cat /nexus-data/admin.password
# then export NEXUS_PASS before running this script, or rotate it in the UI.

set -euo pipefail

NEXUS_URL="${NEXUS_URL:-http://localhost:8081}"
NEXUS_USER="${NEXUS_USER:-admin}"
NEXUS_PASS="${NEXUS_PASS:-}"
DOCKER_HTTP_PORT="${DOCKER_HTTP_PORT:-5000}"

API="${NEXUS_URL%/}/service/rest/v1"

die() { printf 'bootstrap: %s\n' "$1" >&2; exit 1; }

command -v curl >/dev/null 2>&1 || die "curl is required"

if [ -z "${NEXUS_PASS}" ]; then
  die "set NEXUS_PASS (first-boot value: podman exec ds-cache-nexus cat /nexus-data/admin.password)"
fi

# Wait for the status endpoint before provisioning.
printf 'bootstrap: waiting for Nexus at %s ...\n' "${NEXUS_URL}"
i=0
until curl -fsS "${API}/status" >/dev/null 2>&1; do
  i=$((i + 1))
  [ "${i}" -gt 60 ] && die "Nexus did not become ready within ~5 minutes"
  sleep 5
done
printf 'bootstrap: Nexus is ready.\n'

# create_proxy <api-path-segment> <json-body>
# PUTs (update) if the repo exists, POSTs (create) otherwise. Both are the
# documented Nexus repositories API; this is config application, not protocol.
create_proxy() {
  seg="$1"; name="$2"; body="$3"
  url="${API}/repositories/${seg}"
  code=$(curl -s -o /dev/null -w '%{http_code}' \
    -u "${NEXUS_USER}:${NEXUS_PASS}" \
    "${API}/repositories/${name}")
  if [ "${code}" = "200" ]; then
    printf 'bootstrap: updating %s\n' "${name}"
    curl -fsS -u "${NEXUS_USER}:${NEXUS_PASS}" \
      -H 'Content-Type: application/json' \
      -X PUT "${url}/${name}" -d "${body}" \
      || die "update ${name} failed"
  else
    printf 'bootstrap: creating %s\n' "${name}"
    curl -fsS -u "${NEXUS_USER}:${NEXUS_PASS}" \
      -H 'Content-Type: application/json' \
      -X POST "${url}" -d "${body}" \
      || die "create ${name} failed"
  fi
}

# Shared storage block (default blob store; single-host CE).
STORAGE='"storage":{"blobStoreName":"default","strictContentTypeValidation":true}'
NEGATIVE='"negativeCache":{"enabled":true,"timeToLive":15}'
HTTPCLIENT='"httpClient":{"blocked":false,"autoBlock":true}'

# --- npm -------------------------------------------------------------------
create_proxy "npm/proxy" "npm-proxy" "{
  \"name\":\"npm-proxy\",\"online\":true,
  ${STORAGE},
  \"proxy\":{\"remoteUrl\":\"https://registry.npmjs.org/\",\"contentMaxAge\":1440,\"metadataMaxAge\":1440},
  ${NEGATIVE},${HTTPCLIENT}
}"

# --- PyPI ------------------------------------------------------------------
create_proxy "pypi/proxy" "pypi-proxy" "{
  \"name\":\"pypi-proxy\",\"online\":true,
  ${STORAGE},
  \"proxy\":{\"remoteUrl\":\"https://pypi.org/\",\"contentMaxAge\":1440,\"metadataMaxAge\":1440},
  ${NEGATIVE},${HTTPCLIENT}
}"

# --- Go module proxy -------------------------------------------------------
create_proxy "go/proxy" "go-proxy" "{
  \"name\":\"go-proxy\",\"online\":true,
  ${STORAGE},
  \"proxy\":{\"remoteUrl\":\"https://proxy.golang.org/\",\"contentMaxAge\":1440,\"metadataMaxAge\":1440},
  ${NEGATIVE},${HTTPCLIENT}
}"

# --- OCI / Docker ----------------------------------------------------------
# Docker proxy needs its own HTTP connector port (DOCKER_HTTP_PORT) — that is
# the :5000 published by the deploy unit.
create_proxy "docker/proxy" "docker-proxy" "{
  \"name\":\"docker-proxy\",\"online\":true,
  ${STORAGE},
  \"proxy\":{\"remoteUrl\":\"https://registry-1.docker.io\",\"contentMaxAge\":1440,\"metadataMaxAge\":1440},
  ${NEGATIVE},${HTTPCLIENT},
  \"docker\":{\"v1Enabled\":false,\"forceBasicAuth\":false,\"httpPort\":${DOCKER_HTTP_PORT}},
  \"dockerProxy\":{\"indexType\":\"HUB\"}
}"

# --- OCI / ghcr.io (GitHub Container Registry) -----------------------------
# DISABLED BY DEFAULT — no golden image (../../golden/) pulls from ghcr.io yet,
# so this connector stays defined-but-unopened.  To enable, uncomment the block
# below TOGETHER WITH the ghcr-proxy entry in repos.yaml, the ghcr-proxy
# PublishPort in nexus.container, and the ghcr.io stanza in
# ../wiring/registries.conf — all four must agree on connector port :5001.
# Once the registries.conf stanza is active, lint-image-drift.sh fails closed
# (rc=1) on any one-sided edit of that port and rc=2 if this block loses its
# httpPort.  The port is written as a LITERAL here (not a DOCKER_HTTP_PORT-style
# env knob) precisely so it is a reconcilable encoding of the connector port;
# override at run time by editing this block when you enable it.
# create_proxy "docker/proxy" "ghcr-proxy" "{
#   \"name\":\"ghcr-proxy\",\"online\":true,
#   ${STORAGE},
#   \"proxy\":{\"remoteUrl\":\"https://ghcr.io\",\"contentMaxAge\":1440,\"metadataMaxAge\":1440},
#   ${NEGATIVE},${HTTPCLIENT},
#   \"docker\":{\"v1Enabled\":false,\"forceBasicAuth\":false,\"httpPort\":5001},
#   \"dockerProxy\":{\"indexType\":\"REGISTRY\"}
# }"

# --- OCI / quay.io ---------------------------------------------------------
# DISABLED BY DEFAULT — same shape as the ghcr.io block above; connector port
# :5002 (distinct from :5000 Docker Hub and :5001 ghcr.io — one mirror endpoint
# fronts exactly one upstream).  Uncomment together with the quay-proxy entry in
# repos.yaml, the quay-proxy PublishPort in nexus.container, and the quay.io
# stanza in ../wiring/registries.conf.
# create_proxy "docker/proxy" "quay-proxy" "{
#   \"name\":\"quay-proxy\",\"online\":true,
#   ${STORAGE},
#   \"proxy\":{\"remoteUrl\":\"https://quay.io\",\"contentMaxAge\":1440,\"metadataMaxAge\":1440},
#   ${NEGATIVE},${HTTPCLIENT},
#   \"docker\":{\"v1Enabled\":false,\"forceBasicAuth\":false,\"httpPort\":5002},
#   \"dockerProxy\":{\"indexType\":\"REGISTRY\"}
# }"

printf 'bootstrap: all proxy repositories reconciled.\n'
printf 'bootstrap: verify endpoints listed in deploy/repos.yaml, then run smoke.sh on the host.\n'
