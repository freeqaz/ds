#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""ready-work — THIN SHIM over `taskdb work`.

The ready-frontier triage that this script used to implement in Python now lives
in Go as a first-class verb: `taskdb work` (alias `taskdb audit work`). The Go
command is a strict superset — it carries the SAME buckets and the SAME flag
surface (`--substantive`, `--epic`, `--tag`, `--all`, `--json`) VERBATIM, talks
to the DB/lock layer directly (no shell-out, no `--json` re-parse), and adds two
things this script could not: live CONTENTION flags (lock holders +
`.claude/worktrees/agent-*` trees) and CONFIG-DRIVEN bucket keywords
(`TASKDB_WORK_BUCKETS` / `scripts/taskdb/work-buckets.json`). See
`scripts/taskdb/cmd_work.go` and `.claude/workflows/FINDING-WORK.md` §1.1.

This file is kept only as a compatibility shim for any caller that still invokes
`scripts/taskdb/ready-work.py`: it locates the taskdb binary the same way it
always did and execs `taskdb work`, forwarding ALL arguments unchanged. Prefer
`taskdb work` directly; this shim is a thin redirect and carries no logic of its
own.

Usage (identical to `taskdb work` — args are forwarded verbatim):
  scripts/taskdb/ready-work.py                 # substantive + docs, grouped by epic
  scripts/taskdb/ready-work.py --substantive   # ONLY substantive (hide docs too)
  scripts/taskdb/ready-work.py --epic 01KTWJ1VX0   # one root epic
  scripts/taskdb/ready-work.py --tag gated     # list a set-aside bucket
  scripts/taskdb/ready-work.py --all           # every ready task incl. bookkeeping
  scripts/taskdb/ready-work.py --json          # machine-readable {buckets: {...}}
"""
import os, shutil, sys


def _bin():
    # Resolution contract preserved from the original script so existing callers
    # keep working: an explicit TASKDB_BIN env wins, else .bin/taskdb under the
    # repo root (cwd-anchored, then anchored to this file's location), else
    # whatever 'taskdb' is on PATH.
    env = os.environ.get("TASKDB_BIN")
    if env and os.path.exists(env):
        return env
    here = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    for root in (os.getcwd(), here):
        cand = os.path.join(root, ".bin", "taskdb")
        if os.path.exists(cand):
            return cand
    onpath = shutil.which("taskdb")
    if onpath:
        return onpath
    sys.exit("ready-work: cannot find .bin/taskdb — run `make taskdb` from the repo root, or set TASKDB_BIN.")


def main():
    taskdb = _bin()
    argv = [taskdb, "work", *sys.argv[1:]]
    try:
        os.execv(taskdb, argv)
    except OSError as e:
        sys.exit(f"ready-work: failed to exec {taskdb} work: {e}")


if __name__ == "__main__":
    main()
