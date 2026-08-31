// SPDX-License-Identifier: Apache-2.0

// Command ds-attachfwd is the guest-side attach CARRIAGE forwarder, baked into the
// M1 image at /usr/local/bin/ds-attachfwd and started by ds-attachfwd.service BEFORE
// ds-entrypoint (the entrypoint dials the UDS this forwarder serves). It bridges the
// guest-local attach event-socket UDS (runtime.v1 AttachWiring.event_socket_path,
// which ds-entrypoint emits CC stdio onto) to an AF_VSOCK carriage the host-agent's
// per-session attach bridge dials at guestCID:port over virtio-vsock — the M1
// guest<->host carriage (no tap/IP/nft;
// docs/sessions/spikes/m1-live-session-transport.md).
//
// It is a 1:1 byte splice and nothing else: the D61 fan-out, the token-auth, and the
// writer-seat all live host-side at the host-agent attach Server (the guest is the
// untrusted runtime; enforcement must not live here). RUNTIME-AGNOSTIC (D20/D38).
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/dream-serpent/dream-serpent/vm/attachfwd"
)

func main() {
	udsPath := flag.String("uds-path", "/run/ds/attach.sock", "guest-local attach event-socket UDS (AttachWiring.event_socket_path); ds-entrypoint dials it, this forwarder serves it")
	vsockPort := flag.Uint("vsock-port", uint(attachfwd.WireAttachPort), "AF_VSOCK port the host-agent attach bridge dials at guestCID:port over virtio-vsock")
	flag.Parse()

	// SIGINT/SIGTERM cancel the serve so systemd stop is graceful.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	f, err := attachfwd.Listen(attachfwd.Config{UDSPath: *udsPath, VsockPort: uint32(*vsockPort)})
	if err != nil {
		fmt.Fprintf(os.Stderr, "ds-attachfwd: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()
	fmt.Fprintf(os.Stderr, "ds-attachfwd: carriage up (uds=%s vsock=%s)\n", *udsPath, f.VsockAddr())

	if err := f.Serve(ctx); err != nil && ctx.Err() == nil {
		fmt.Fprintf(os.Stderr, "ds-attachfwd: serve: %v\n", err)
		os.Exit(1)
	}
}
