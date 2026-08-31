#!/usr/bin/env bash
# setup-repo.sh — one-shot bootstrap for a fresh clone (and safe to re-run).
#
# Does the three things a new checkout needs before the taskdb agent loop works:
#   1. build .bin/taskdb            (the standalone Go tool; GOWORK=off)
#   2. taskdb setup                 (point git at scripts/hooks — conflict-safe)
#   3. taskdb thaw                  (rebuild the live taskdb.sqlite from tasks/*.json)
#
# After this, `git commit` auto-freezes the DB to tasks/*.json and stages it,
# and branch switches/merges auto-rebuild the DB. taskdb also self-heals on
# every invocation (re-installs hooks if unset, warns on a stale binary), so
# this script is the explicit front door, not the only path.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

echo "==> Building .bin/taskdb"
make taskdb

echo "==> Installing git hooks"
.bin/taskdb setup

echo "==> Rebuilding the live DB from tasks/*.json (thaw)"
if [[ -d tasks ]] && compgen -G 'tasks/*.json' >/dev/null; then
	.bin/taskdb thaw
else
	echo "  (no tasks/*.json yet — skipping thaw)"
fi

echo
echo "Repo ready. Try:  .bin/taskdb status   and   .bin/taskdb task list --ready"
