// SPDX-License-Identifier: Apache-2.0

// Command ds-entrypoint is the guest-side D38 VM entrypoint binary, baked into
// the M0 image at /usr/local/bin/ds-entrypoint and started by
// ds-entrypoint.service on VM boot. It loads and TOTALLY validates the
// EntrypointConfig the host agent dropped in DS_ENTRYPOINT_CONFIG_DIR, launches
// and supervises the agent runtime, bridges the runtime's stdio onto the
// guest-local host-agent event socket, and reports readiness/exit — FAIL-CLOSED
// throughout (no valid config => no runtime => no egress).
//
// RUNTIME-AGNOSTIC (D20/D38): this binary launches a generic process and copies
// bytes; it never parses the runtime's protocol. NO CREDENTIALS (D17/D39/D50):
// the config carries references only; the session token is fetched in-guest.
//
// CONFIG-PRESENCE LAUNCH SIGNAL (maintainer ruling 2026-06-15): a valid
// EntrypointConfig present in DS_ENTRYPOINT_CONFIG_DIR is itself the signal to
// launch and supervise the runtime — there is no separate env gate. The
// no-launch path is loadConfig failing (absent/empty/invalid config.pb): the
// binary reports the fail-closed verdict without exec-ing a runtime, which is
// the boot-validate / dry-boot case (it drops no config).
package main

import (
	"context"
	"os"

	"github.com/dream-serpent/dream-serpent/vm/entrypoint"
)

// main is the thin process shell; the real wiring lives in entrypoint.Main so it
// is exercised by the package's own offline tests.
func main() {
	os.Exit(entrypoint.Main(context.Background(), os.Getenv, os.Stderr))
}
