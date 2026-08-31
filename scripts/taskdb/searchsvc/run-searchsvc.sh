#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# run-searchsvc.sh — OPERATOR launcher for the LIVE BGE-M3 searchsvc.
#
# This is the deferred operator step (NOT run by CI/fleet): it installs the
# [live] extra (torch + FlagEmbedding) and serves the real BGE-M3 embedder
# behind DS_EMBED_LIVE=1 on localhost. Without DS_EMBED_LIVE the service serves
# the hermetic fake instead and needs none of this.
#
# Usage:   ./run-searchsvc.sh            # serve on 127.0.0.1:8088, GPU cuda:0
# Env (all optional):
#   SEARCHSVC_HOST/PORT   bind address          (default 127.0.0.1:8088)
#   DS_EMBED_DEVICE       GPU device            (default cuda:0 — ONE device;
#                                                FlagEmbedding multi-GPU spawns a
#                                                pool that deadlocks under uv-run)
#   DS_EMBED_MAX_LENGTH   max tokens            (default 1024; do NOT use 8192)
#   SEARCHSVC_DB          index sqlite path     (default: the repo taskdb.sqlite;
#                                                point at a hydrated index copy)
#   HF_HUB_OFFLINE=1      use the cached model  (set once weights are pulled)
#
# Single worker only: a second uvicorn worker duplicates the 569M model in VRAM.
set -euo pipefail
cd "$(dirname "$0")"

HOST="${SEARCHSVC_HOST:-127.0.0.1}"
PORT="${SEARCHSVC_PORT:-8088}"

# uv resolves an interpreter + the [live] extra (torch/FlagEmbedding). The egress
# proxy CA is needed for the package/model fetch through ds-tlsproxy.
export SSL_CERT_FILE="${SSL_CERT_FILE:-$HOME/.mitmproxy/mitmproxy-ca-cert.pem}"
uv sync --extra live --quiet

export DS_EMBED_LIVE=1
export DS_EMBED_DEVICE="${DS_EMBED_DEVICE:-cuda:0}"
export DS_EMBED_MAX_LENGTH="${DS_EMBED_MAX_LENGTH:-1024}"

echo "searchsvc: live BGE-M3 on ${HOST}:${PORT} (device=${DS_EMBED_DEVICE}, db=${SEARCHSVC_DB:-<repo taskdb.sqlite>})" >&2
exec uv run uvicorn --factory serve:build_app --host "$HOST" --port "$PORT" --workers 1
