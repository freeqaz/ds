// SPDX-License-Identifier: Apache-2.0

// Command fakegen is the generator main for the programmable-fake pipeline
// (doc 06 §2.1, doc 15 §5.6). It emits one programmable in-memory fake per
// gRPC service across the frozen M0 proto packages — orchestrator.v1
// (SessionService, PolicyService), hypervisor.v1 (HypervisorDriverService),
// hostagent.v1 (HostAgentService), boundary.v1 (PolicyStreamService),
// identity.v1 (IdentityMintService, IdentityValidationService,
// DigestFeedService, GrantFetchService), canvas.v1 (BoardService),
// roles.v1 (RoleCatalogService), runtime.v1 (EntrypointService), and
// attach.v1 (WriterRelayService — the D137 writer-seat write leg) — into
// proto/gen/go, beside the stubs they fake (the same shared module everyone
// imports).
//
// It drives off the COMPILED contract: each target imports its stub package
// (which registers the proto file in the global registry at init) and hands the
// stub's exported grpc.ServiceDesc plus Go-package coordinates to fakegen. The
// generated fakes therefore track exactly the frozen stubs — a re-freeze that
// adds an RPC re-emits a fake covering it automatically, and the codegen-drift
// gate (proto/FREEZE.md) catches a stale committed fake.
//
// Usage (run from anywhere in the workspace; -out defaults to the repo's
// proto/gen/go tree resolved relative to this file's module):
//
//	go run ./assurance/contract-harness/cmd/fakegen -out <proto/gen/go path>
//
// With -check, it generates into a temp dir and diffs against the committed
// tree, exiting non-zero on drift — the CI form of the codegen-drift gate for
// the fake half of the pipeline.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/dream-serpent/dream-serpent/assurance/contract-harness/fakegen"

	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
	canvasv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/canvas/v1"
	hostagentv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hostagent/v1"
	hypervisorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hypervisor/v1"
	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
	orchestratorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/orchestrator/v1"
	rolesv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/roles/v1"
	runtimev1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/runtime/v1"
)

const genModulePrefix = "github.com/dream-serpent/dream-serpent/proto/gen/go/"

// target is one service contract to generate a fake for, plus where the emitted
// fake file lands under the proto/gen/go tree.
type target struct {
	input   fakegen.Input
	relPath string // path under proto/gen/go, e.g. "dreamserpent/hostagent/v1/hostagentv1fake/fake.gen.go"
}

func targets() []target {
	return []target{
		{
			input: fakegen.Input{
				ServiceDesc:     &hostagentv1.HostAgentService_ServiceDesc,
				StubImportPath:  genModulePrefix + "dreamserpent/hostagent/v1",
				StubPackageName: "hostagentv1",
				GoServiceName:   "HostAgentService",
			},
			relPath: "dreamserpent/hostagent/v1/hostagentv1fake/fake.gen.go",
		},
		{
			input: fakegen.Input{
				ServiceDesc:     &hypervisorv1.HypervisorDriverService_ServiceDesc,
				StubImportPath:  genModulePrefix + "dreamserpent/hypervisor/v1",
				StubPackageName: "hypervisorv1",
				GoServiceName:   "HypervisorDriverService",
			},
			relPath: "dreamserpent/hypervisor/v1/hypervisorv1fake/fake.gen.go",
		},
		{
			input: fakegen.Input{
				ServiceDesc:     &orchestratorv1.SessionService_ServiceDesc,
				StubImportPath:  genModulePrefix + "dreamserpent/orchestrator/v1",
				StubPackageName: "orchestratorv1",
				GoServiceName:   "SessionService",
			},
			relPath: "dreamserpent/orchestrator/v1/orchestratorv1fake/session_fake.gen.go",
		},
		{
			input: fakegen.Input{
				ServiceDesc:     &orchestratorv1.PolicyService_ServiceDesc,
				StubImportPath:  genModulePrefix + "dreamserpent/orchestrator/v1",
				StubPackageName: "orchestratorv1",
				GoServiceName:   "PolicyService",
			},
			relPath: "dreamserpent/orchestrator/v1/orchestratorv1fake/policy_fake.gen.go",
		},
		{
			input: fakegen.Input{
				ServiceDesc:     &boundaryv1.PolicyStreamService_ServiceDesc,
				StubImportPath:  genModulePrefix + "dreamserpent/boundary/v1",
				StubPackageName: "boundaryv1",
				GoServiceName:   "PolicyStreamService",
			},
			relPath: "dreamserpent/boundary/v1/boundaryv1fake/policy_stream_fake.gen.go",
		},
		{
			input: fakegen.Input{
				ServiceDesc:     &identityv1.IdentityMintService_ServiceDesc,
				StubImportPath:  genModulePrefix + "dreamserpent/identity/v1",
				StubPackageName: "identityv1",
				GoServiceName:   "IdentityMintService",
			},
			relPath: "dreamserpent/identity/v1/identityv1fake/mint_fake.gen.go",
		},
		{
			input: fakegen.Input{
				ServiceDesc:     &identityv1.IdentityValidationService_ServiceDesc,
				StubImportPath:  genModulePrefix + "dreamserpent/identity/v1",
				StubPackageName: "identityv1",
				GoServiceName:   "IdentityValidationService",
			},
			relPath: "dreamserpent/identity/v1/identityv1fake/validation_fake.gen.go",
		},
		{
			input: fakegen.Input{
				ServiceDesc:     &identityv1.DigestFeedService_ServiceDesc,
				StubImportPath:  genModulePrefix + "dreamserpent/identity/v1",
				StubPackageName: "identityv1",
				GoServiceName:   "DigestFeedService",
			},
			relPath: "dreamserpent/identity/v1/identityv1fake/digest_feed_fake.gen.go",
		},
		{
			input: fakegen.Input{
				ServiceDesc:     &identityv1.GrantFetchService_ServiceDesc,
				StubImportPath:  genModulePrefix + "dreamserpent/identity/v1",
				StubPackageName: "identityv1",
				GoServiceName:   "GrantFetchService",
			},
			relPath: "dreamserpent/identity/v1/identityv1fake/grant_fetch_fake.gen.go",
		},
		{
			input: fakegen.Input{
				ServiceDesc:     &canvasv1.BoardService_ServiceDesc,
				StubImportPath:  genModulePrefix + "dreamserpent/canvas/v1",
				StubPackageName: "canvasv1",
				GoServiceName:   "BoardService",
			},
			relPath: "dreamserpent/canvas/v1/canvasv1fake/board_fake.gen.go",
		},
		{
			// roles.v1 RoleCatalogService — the READ-path catalog API (ListRoles /
			// GetRole). The write path (PutRole / ratification) is M2-DEFERRED and
			// reserved, so the fake covers only the two frozen read RPCs; a later
			// additive write RPC re-emits the fake covering it automatically (the
			// fakegen-tracks-the-frozen-stub contract).
			input: fakegen.Input{
				ServiceDesc:     &rolesv1.RoleCatalogService_ServiceDesc,
				StubImportPath:  genModulePrefix + "dreamserpent/roles/v1",
				StubPackageName: "rolesv1",
				GoServiceName:   "RoleCatalogService",
			},
			relPath: "dreamserpent/roles/v1/rolesv1fake/catalog_fake.gen.go",
		},
		{
			// runtime.v1 EntrypointService — the host-agent-side terminator the
			// GUEST dials to report boot-to-entrypoint readiness and runtime exit
			// (D38/D81; the second D20 runtime seam). The fake covers the two frozen
			// RPCs (ReportReady / ReportExit); a later additive RPC re-emits the fake
			// covering it automatically (the fakegen-tracks-the-frozen-stub contract).
			input: fakegen.Input{
				ServiceDesc:     &runtimev1.EntrypointService_ServiceDesc,
				StubImportPath:  genModulePrefix + "dreamserpent/runtime/v1",
				StubPackageName: "runtimev1",
				GoServiceName:   "EntrypointService",
			},
			relPath: "dreamserpent/runtime/v1/runtimev1fake/entrypoint_fake.gen.go",
		},
		{
			// attach.v1 WriterRelayService — the D137 browser writer-seat WRITE
			// leg (RequestWriterSeat / YieldWriterSeat / DriveSession; the latter
			// bidi-streaming). Added when the freeze-reopen extended attach.v1 in
			// place with its first service; the read schema (SessionEvent etc.)
			// carries no service and is faked by the goldentrace/cassette harness,
			// not here. A later additive RPC re-emits this fake automatically (the
			// fakegen-tracks-the-frozen-stub contract).
			input: fakegen.Input{
				ServiceDesc:     &attachv1.WriterRelayService_ServiceDesc,
				StubImportPath:  genModulePrefix + "dreamserpent/attach/v1",
				StubPackageName: "attachv1",
				GoServiceName:   "WriterRelayService",
			},
			relPath: "dreamserpent/attach/v1/attachv1fake/writer_relay_fake.gen.go",
		},
	}
}

func main() {
	out := flag.String("out", "", "proto/gen/go tree to write generated fakes into (required unless -check resolves it)")
	check := flag.Bool("check", false, "generate to a scratch dir and diff against -out; exit non-zero on drift")
	flag.Parse()

	if *out == "" {
		fmt.Fprintln(os.Stderr, "fakegen: -out <proto/gen/go path> is required")
		os.Exit(2)
	}

	if *check {
		if err := runCheck(*out); err != nil {
			fmt.Fprintf(os.Stderr, "fakegen -check: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("fakegen -check: committed fakes match regenerated output. PASS.")
		return
	}

	for _, t := range targets() {
		dst := filepath.Join(*out, t.relPath)
		if err := fakegen.GenerateToFile(t.input, dst); err != nil {
			fmt.Fprintf(os.Stderr, "fakegen: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("fakegen: wrote %s\n", t.relPath)
	}
}

// runCheck regenerates every fake and compares against the committed file under
// out, reporting the first drift it finds.
func runCheck(out string) error {
	for _, t := range targets() {
		want, err := fakegen.Generate(t.input)
		if err != nil {
			return err
		}
		committed, err := os.ReadFile(filepath.Join(out, t.relPath))
		if err != nil {
			return fmt.Errorf("read committed %s: %w", t.relPath, err)
		}
		if !bytes.Equal(want, committed) {
			return fmt.Errorf("CODEGEN DRIFT: %s differs from regenerated output — "+
				"run `go run ./assurance/contract-harness/cmd/fakegen -out <proto/gen/go>` and commit", t.relPath)
		}
	}
	return nil
}
