#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# lockserver-tunnel.sh — keep the taskdb shared-lock-server SSH tunnel up.
#
# Opens (and auto-reconnects) a local forward from 127.0.0.1:<LOCAL_PORT> to the
# lock-server box's localhost Postgres through a locked-down forward-only SSH
# account, so taskdb can reach the shared lock registry. Postgres itself is
# never exposed publicly; the tunnel account should be able to forward ONLY to
# 127.0.0.1:5432 and run no shell.
#
# The shared lock server is OPTIONAL and OFF by default — taskdb locks locally
# unless you stand one up (see LOCKSERVER.md and lockserver-provision.sql).
# Prerequisite (one-time, per dev): an admin authorizes your SSH public key on
# the tunnel account's authorized_keys.
#
# Usage:
#   SSH_HOST=lock.example.com scripts/taskdb/lockserver-tunnel.sh
#   SSH_HOST=... SSH_USER=tunnel LOCAL_PORT=5433 scripts/taskdb/lockserver-tunnel.sh
#
# SSH_HOST is required; the remaining defaults match the example
# scripts/taskdb/lockserver.json. Keep this running in its own terminal (or
# under a process manager); ctrl-c stops it.
set -euo pipefail

SSH_HOST="${SSH_HOST:-}"
SSH_USER="${SSH_USER:-tunnel}"
if [[ -z "$SSH_HOST" ]]; then
  echo "lockserver-tunnel.sh: set SSH_HOST to your lock server (e.g. SSH_HOST=lock.example.com $0)" >&2
  echo "the shared lock server is optional; without it taskdb locks locally. See LOCKSERVER.md." >&2
  exit 2
fi
REMOTE_PG_HOST="${REMOTE_PG_HOST:-127.0.0.1}"
REMOTE_PG_PORT="${REMOTE_PG_PORT:-5432}"
LOCAL_PORT="${LOCAL_PORT:-5433}"

echo "taskdb lock tunnel: 127.0.0.1:${LOCAL_PORT} -> ${SSH_USER}@${SSH_HOST} -> ${REMOTE_PG_HOST}:${REMOTE_PG_PORT}"
echo "(ctrl-c to stop; auto-reconnects on drop)"

while true; do
  ssh -N \
    -o ExitOnForwardFailure=yes \
    -o ServerAliveInterval=30 \
    -o ServerAliveCountMax=3 \
    -L "${LOCAL_PORT}:${REMOTE_PG_HOST}:${REMOTE_PG_PORT}" \
    "${SSH_USER}@${SSH_HOST}" || true
  echo "tunnel dropped (exit $?); reconnecting in 3s..." >&2
  sleep 3
done
