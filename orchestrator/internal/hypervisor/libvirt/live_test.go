// SPDX-License-Identifier: Apache-2.0

package libvirt

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

// liveTestConfig is the host-fact config the live-binding tests construct
// against. It points at placeholder paths — NO file is touched: the arg-
// construction assertions are pure, and the run-path assertions use a fake
// runner (recordingRunner) that records the command line without exec.
func liveTestConfig() LiveConfig {
	return LiveConfig{
		OverlayCreateScript: "/opt/ds/vm/cow/overlay-create.sh",
		OverlayDir:          "/var/lib/ds/overlays",
		BaseImage:           "/var/lib/libvirt/images/ds-build/m0-base.qcow2",
		VirshBin:            "virsh",
	}
}

// mustXML renders the single-disk domain XML and fails the test on an unexpected
// error — the vast majority of the render tests exercise the LEGITIMATE (nil-err)
// paths (gate-OFF, empty-tap, a well-formed routed tap), so this keeps their call
// sites a single expression usable inside a composite literal. The fail-closed error
// path (RoutedTap + non-empty tap + macOK=false) is asserted separately, against the
// two-value form directly, so it does NOT flow through this helper.
func mustXML(t *testing.T, cfg LiveConfig, sessionUUID, overlayPath, entrypointConfigRef string, vsockCID uint32) string {
	t.Helper()
	xml, err := domainDefineXML(cfg, sessionUUID, overlayPath, entrypointConfigRef, vsockCID)
	if err != nil {
		t.Fatalf("mustXML(t, %q) unexpected error: %v", sessionUUID, err)
	}
	return xml
}

// mustXMLDrive is mustXML for the config-drive form (the (string,error) render with a
// config-drive path and tap name). It fails the test on an unexpected error so the
// nil-err call sites stay single expressions; the fail-closed refusal is asserted
// separately against the two-value form.
func mustXMLDrive(t *testing.T, cfg LiveConfig, sessionUUID, overlayPath, entrypointConfigRef, configDrivePath, tapName string, vsockCID uint32) string {
	t.Helper()
	xml, err := domainDefineXMLWithConfigDrive(cfg, sessionUUID, overlayPath, entrypointConfigRef, configDrivePath, tapName, vsockCID)
	if err != nil {
		t.Fatalf("mustXMLDrive(t, %q, tap=%q) unexpected error: %v", sessionUUID, tapName, err)
	}
	return xml
}

// recordingRunner is a fake runner that records invocations and returns canned
// output, so the live bindings' command construction + ordering can be asserted
// WITHOUT launching virsh / overlay-create.sh / any subprocess.
type recordingRunner struct {
	calls   [][]string // each entry: name followed by args
	outputs []string   // canned stdout per call (by index), "" when short
	errs    []error    // canned err per call (by index), nil when short
	// createdXML captures the contents of the staged domain XML at `virsh create`
	// time (keyed by the temp-file path the call points at). liveBooter.Boot
	// `defer`-removes that temp file at return, so a test can only inspect the
	// materialized domain XML by snapshotting it here, while the file still exists.
	createdXML map[string]string
}

func (r *recordingRunner) run(_ context.Context, name string, args ...string) (string, error) {
	idx := len(r.calls)
	r.calls = append(r.calls, append([]string{name}, args...))
	// Snapshot the staged domain XML before the booter removes it (the `create
	// <xmlPath>` call). Best-effort: a missing/unreadable path just records nothing.
	if len(args) == 2 && args[0] == "create" {
		if b, err := os.ReadFile(args[1]); err == nil {
			if r.createdXML == nil {
				r.createdXML = map[string]string{}
			}
			r.createdXML[args[1]] = string(b)
		}
	}
	var out string
	if idx < len(r.outputs) {
		out = r.outputs[idx]
	}
	var err error
	if idx < len(r.errs) {
		err = r.errs[idx]
	}
	return out, err
}

// ── PURE arg-construction (always runs; touches no substrate) ────────────────

func TestOverlayCreateArgs(t *testing.T) {
	cfg := liveTestConfig()
	name, args := overlayCreateArgs(cfg, "/var/lib/ds/overlays/sess-1.qcow2")
	if name != cfg.OverlayCreateScript {
		t.Fatalf("script = %q, want %q", name, cfg.OverlayCreateScript)
	}
	got := strings.Join(args, " ")
	want := "--base " + cfg.BaseImage + " --overlay /var/lib/ds/overlays/sess-1.qcow2"
	if got != want {
		t.Fatalf("args = %q, want %q", got, want)
	}
}

func TestDomainDefineXMLWiresOverlayNotBase(t *testing.T) {
	cfg := liveTestConfig()
	overlay := "/var/lib/ds/overlays/sess-7.qcow2"
	xml := mustXML(t, cfg, "sess-7", overlay, "entry-ref", 0)
	if !strings.Contains(xml, "<source file='"+overlay+"'/>") {
		t.Fatalf("domain xml does not wire the overlay as disk source:\n%s", xml)
	}
	// The raw base must NOT be referenced directly — the qcow2 backing chain
	// carries it read-only (D29). A direct base reference would be a clone-of-
	// nothing / write-through hazard.
	if strings.Contains(xml, cfg.BaseImage) {
		t.Fatalf("domain xml references the raw base directly (D29 violation):\n%s", xml)
	}
	if !strings.Contains(xml, "<name>ds-sess-7</name>") {
		t.Fatalf("domain xml missing stable transient name:\n%s", xml)
	}
	if !strings.Contains(xml, "entrypoint='entry-ref'") {
		t.Fatalf("domain xml missing entrypoint metadata (D38 referent):\n%s", xml)
	}
}

// TestDomainDefineXMLHasVsockControlChannel asserts every live domain XML carries
// the virtio-vsock device — the host-agent's AF_VSOCK attach byte-path carrier (no
// tap, no guest IP, no nft). With NO deterministic CID threaded (vsockCID 0) it
// falls back to the libvirt auto-assigned form (`auto='yes'`); the deterministic
// pinned form is asserted separately (TestDomainDefineXMLPinsDeterministicVsockCID).
// The device must ride on BOTH the single-disk form (domainDefineXML) and the
// config-drive form (domainDefineXMLWithConfigDrive), since the attach leg is
// independent of whether a config-drive is attached.
func TestDomainDefineXMLHasVsockControlChannel(t *testing.T) {
	cfg := liveTestConfig()
	overlay := "/var/lib/ds/overlays/sess-vsock.qcow2"

	// Single-disk form (the no-config-drive boot path), CID auto-assigned (0).
	single := mustXML(t, cfg, "sess-vsock", overlay, "entry-ref", 0)
	if !strings.Contains(single, "<vsock model='virtio'>") {
		t.Fatalf("single-disk domain xml missing the virtio-vsock device:\n%s", single)
	}
	if !strings.Contains(single, "<cid auto='yes'/>") {
		t.Fatalf("single-disk domain xml missing the auto-CID vsock cid:\n%s", single)
	}

	// Config-drive form (the 2nd-disk boot path) carries it too.
	withDrive := mustXMLDrive(t, cfg, "sess-vsock", overlay, "entry-ref", "/var/lib/ds/overlays/sess-vsock.config.iso", "", 0)
	if !strings.Contains(withDrive, "<vsock model='virtio'>") {
		t.Fatalf("config-drive domain xml missing the virtio-vsock device:\n%s", withDrive)
	}
	if !strings.Contains(withDrive, "<cid auto='yes'/>") {
		t.Fatalf("config-drive domain xml missing the auto-CID vsock cid:\n%s", withDrive)
	}

	// Exactly one vsock device per domain (not duplicated across the disk branches).
	if n := strings.Count(withDrive, "<vsock model='virtio'>"); n != 1 {
		t.Fatalf("expected exactly 1 vsock device, got %d:\n%s", n, withDrive)
	}
}

// TestDomainDefineXMLPinsDeterministicVsockCID asserts that when a deterministic
// per-session CID is threaded (vsockCID != 0), the control-channel device is PINNED
// as `<cid auto='no' address='<cid>'/>` — the host-predictable CID the host agent
// dials (guestCID:port) — and the auto-assign form is NOT emitted. It rides on both
// disk forms, exactly once per domain.
func TestDomainDefineXMLPinsDeterministicVsockCID(t *testing.T) {
	cfg := liveTestConfig()
	overlay := "/var/lib/ds/overlays/sess-cid.qcow2"
	const cid uint32 = 42

	for _, tc := range []struct {
		name string
		xml  string
	}{
		{"single-disk", mustXML(t, cfg, "sess-cid", overlay, "entry-ref", cid)},
		{"config-drive", mustXMLDrive(t, cfg, "sess-cid", overlay, "entry-ref", "/var/lib/ds/overlays/sess-cid.config.iso", "", cid)},
	} {
		if !strings.Contains(tc.xml, "<cid auto='no' address='42'/>") {
			t.Fatalf("%s: domain xml missing the pinned deterministic vsock cid:\n%s", tc.name, tc.xml)
		}
		if strings.Contains(tc.xml, "<cid auto='yes'/>") {
			t.Fatalf("%s: domain xml must NOT auto-assign when a deterministic cid is pinned:\n%s", tc.name, tc.xml)
		}
		if n := strings.Count(tc.xml, "<vsock model='virtio'>"); n != 1 {
			t.Fatalf("%s: expected exactly 1 vsock device, got %d:\n%s", tc.name, n, tc.xml)
		}
	}
}

// TestDomainDefineXMLHasUsermodeEgressNIC asserts every live domain XML carries the
// minimal usermode (SLIRP) egress NIC — `<interface type='user'><model type='virtio'/>`
// — the M0-minimal API-egress path (no host tap/bridge; works under qemu:///session).
// It is NOT the per-session default-deny enforcement (the nft4 keystone). It rides on
// BOTH disk forms, regardless of whether the CID is pinned or auto-assigned, exactly
// once per domain.
func TestDomainDefineXMLHasUsermodeEgressNIC(t *testing.T) {
	cfg := liveTestConfig()
	overlay := "/var/lib/ds/overlays/sess-nic.qcow2"

	for _, tc := range []struct {
		name string
		xml  string
	}{
		{"single-disk/auto-cid", mustXML(t, cfg, "sess-nic", overlay, "entry-ref", 0)},
		{"config-drive/pinned-cid", mustXMLDrive(t, cfg, "sess-nic", overlay, "entry-ref", "/var/lib/ds/overlays/sess-nic.config.iso", "", 7)},
	} {
		if !strings.Contains(tc.xml, "<interface type='user'>") {
			t.Fatalf("%s: domain xml missing the usermode egress interface:\n%s", tc.name, tc.xml)
		}
		if !strings.Contains(tc.xml, "<model type='virtio'/>") {
			t.Fatalf("%s: egress interface missing the virtio model:\n%s", tc.name, tc.xml)
		}
		if n := strings.Count(tc.xml, "<interface type='user'>"); n != 1 {
			t.Fatalf("%s: expected exactly 1 usermode egress NIC, got %d:\n%s", tc.name, n, tc.xml)
		}
		// M0-minimal: NO routed-tap / bridged enforcement NIC (that is the nft4 lane).
		if strings.Contains(tc.xml, "type='bridge'") || strings.Contains(tc.xml, "type='network'") {
			t.Fatalf("%s: domain xml must carry ONLY the usermode egress NIC (no bridge/network NIC):\n%s", tc.name, tc.xml)
		}
	}
}

// TestDomainDefineXMLHasHostPassthroughCPU asserts every live domain XML carries the
// host-passthrough <cpu> element — the libvirt equivalent of qemu `-cpu host`, which
// exposes the real host CPU's feature set (incl. AVX2) to the guest. It is a CORRECTNESS
// requirement, NOT gated: without it libvirt/qemu default to the qemu64 model (no AVX2),
// and modern self-contained binaries — notably Claude Code's bundled Node/V8 single-
// executable — die with SIGILL ("trap invalid opcode") ~13s in (live-found 2026-06-18).
// It must ride on BOTH disk forms (single-disk and config-drive) and on both the disk-
// boot and direct-kernel <os> paths, exactly once per domain. A future removal of the
// <cpu> line fails this test.
func TestDomainDefineXMLHasHostPassthroughCPU(t *testing.T) {
	cfg := liveTestConfig()
	overlay := "/var/lib/ds/overlays/sess-cpu.qcow2"

	dkCfg := liveTestConfig()
	dkCfg.KernelPath = "/var/lib/ds/m0-vmlinuz"
	dkCfg.InitrdPath = "/var/lib/ds/m0-initrd.img"

	for _, tc := range []struct {
		name string
		xml  string
	}{
		{"single-disk/disk-boot", mustXML(t, cfg, "sess-cpu", overlay, "entry-ref", 0)},
		{"config-drive/disk-boot", mustXMLDrive(t, cfg, "sess-cpu", overlay, "entry-ref", "/var/lib/ds/overlays/sess-cpu.config.iso", "", 0)},
		{"single-disk/direct-kernel", mustXML(t, dkCfg, "sess-cpu", overlay, "entry-ref", 0)},
	} {
		if !strings.Contains(tc.xml, "<cpu mode='host-passthrough' check='none'/>") {
			t.Fatalf("%s: domain xml missing the host-passthrough <cpu> element (qemu64 default lacks AVX2 -> CC V8 SIGILL):\n%s", tc.name, tc.xml)
		}
		// The host-passthrough CPU is the only <cpu> element — not duplicated.
		if n := strings.Count(tc.xml, "<cpu "); n != 1 {
			t.Fatalf("%s: expected exactly 1 <cpu> element, got %d:\n%s", tc.name, n, tc.xml)
		}
	}
}

// routedTapSlirpBlock is the exact historical usermode-SLIRP egress-NIC block the
// gate-OFF render MUST emit byte-for-byte (the load-bearing byte-identity invariant
// of U2). It is the literal four-line `<interface type='user'>` fragment
// domainDefineXMLWithConfigDrive has always written; the OFF-branch render must
// contain it unchanged regardless of whether a tap name is threaded.
const routedTapSlirpBlock = "    <interface type='user'>\n" +
	"      <model type='virtio'/>\n" +
	"    </interface>\n"

// TestDomainDefineXMLMemorySizing asserts the per-session guest RAM is sized for a real
// CC launch: a render with no explicit MemoryMiB falls back to DefaultVMMemoryMiB (NOT the
// historical 2048 MiB, which OOM-killed CC at cold start), and an explicit MemoryMiB is
// honored verbatim. The 8192-default matches the proven-working headless drive.
func TestDomainDefineXMLMemorySizing(t *testing.T) {
	overlay := "/var/lib/ds/overlays/sess-mem.qcow2"

	// Default (MemoryMiB unset): DefaultVMMemoryMiB, never the OOM-prone 2048.
	def := mustXML(t, liveTestConfig(), "sess-mem", overlay, "entry-ref", 0)
	if !strings.Contains(def, fmt.Sprintf("<memory unit='MiB'>%d</memory>", DefaultVMMemoryMiB)) {
		t.Fatalf("default render must size guest RAM at DefaultVMMemoryMiB (%d):\n%s", DefaultVMMemoryMiB, def)
	}
	if strings.Contains(def, "<memory unit='MiB'>2048</memory>") {
		t.Fatalf("default render must NOT use the OOM-prone historical 2048 MiB:\n%s", def)
	}
	if DefaultVMMemoryMiB < 4096 {
		t.Fatalf("DefaultVMMemoryMiB=%d is too small for a real CC launch (want >=4096)", DefaultVMMemoryMiB)
	}

	// Explicit override honored.
	cfg := liveTestConfig()
	cfg.MemoryMiB = 6144
	got := mustXML(t, cfg, "sess-mem", overlay, "entry-ref", 0)
	if !strings.Contains(got, "<memory unit='MiB'>6144</memory>") {
		t.Fatalf("explicit MemoryMiB=6144 not honored:\n%s", got)
	}
}

// TestDomainDefineXMLSerialConsoleGate asserts the OPTIONAL serial-console device:
// OFF (cfg.SerialLogPath empty, the default) the render carries NO <serial>/<console>
// and is BYTE-IDENTICAL to the unconfigured render; ON it adds a <serial type='file'>
// + <console> pointing at the per-session log file under the configured dir, on BOTH
// disk forms. It is a diagnostic only — never on the vsock attach path.
func TestDomainDefineXMLSerialConsoleGate(t *testing.T) {
	overlay := "/var/lib/ds/overlays/sess-serial.qcow2"
	drive := "/var/lib/ds/overlays/sess-serial.config.iso"

	// OFF (default): no serial/console, byte-identical to the unconfigured render.
	off := liveTestConfig()
	for _, tc := range []struct {
		name string
		xml  string
	}{
		{"single-disk", mustXML(t, off, "sess-serial", overlay, "entry-ref", 42)},
		{"config-drive", mustXMLDrive(t, off, "sess-serial", overlay, "entry-ref", drive, "", 42)},
	} {
		if strings.Contains(tc.xml, "<serial") || strings.Contains(tc.xml, "<console") {
			t.Fatalf("%s: gate OFF must render NO serial/console device:\n%s", tc.name, tc.xml)
		}
	}

	// ON: a <serial type='file'> + <console> at the per-session log path, once each.
	on := liveTestConfig()
	on.SerialLogPath = "/var/log/ds-serial"
	wantPath := "/var/log/ds-serial/ds-sess-serial.serial.log"
	for _, tc := range []struct {
		name string
		xml  string
	}{
		{"single-disk", mustXML(t, on, "sess-serial", overlay, "entry-ref", 42)},
		{"config-drive", mustXMLDrive(t, on, "sess-serial", overlay, "entry-ref", drive, "", 42)},
	} {
		if !strings.Contains(tc.xml, "<serial type='file'>") {
			t.Fatalf("%s: gate ON missing the <serial type='file'> device:\n%s", tc.name, tc.xml)
		}
		if !strings.Contains(tc.xml, "<console type='file'>") {
			t.Fatalf("%s: gate ON missing the <console> device:\n%s", tc.name, tc.xml)
		}
		if !strings.Contains(tc.xml, "<source path='"+wantPath+"'/>") {
			t.Fatalf("%s: serial/console source path %q not found:\n%s", tc.name, wantPath, tc.xml)
		}
		if n := strings.Count(tc.xml, "<serial type='file'>"); n != 1 {
			t.Fatalf("%s: expected exactly 1 <serial> device, got %d:\n%s", tc.name, n, tc.xml)
		}
		// The attach path is vsock, never serial — the vsock device still rides alongside.
		if !strings.Contains(tc.xml, "<vsock model='virtio'>") {
			t.Fatalf("%s: vsock control channel must still ride alongside the serial console:\n%s", tc.name, tc.xml)
		}
	}
}

// TestDomainDefineXMLRoutedTapOff pins the gate-OFF byte-identity: with
// cfg.RoutedTap=false the render emits the historical usermode-SLIRP egress NIC
// byte-for-byte EVEN WHEN a tap name is threaded — the U2 gate defaults to the
// historical behavior so the landing is a zero-default-change. A non-empty tapName
// under the OFF gate must be ignored: no ethernet NIC, no `dstap-7`, just SLIRP.
func TestDomainDefineXMLRoutedTapOff(t *testing.T) {
	cfg := liveTestConfig()
	cfg.RoutedTap = false
	overlay := "/var/lib/ds/overlays/sess-7.qcow2"
	// A tap name IS threaded — the OFF gate must ignore it and render SLIRP.
	xml := mustXMLDrive(t, cfg, "sess-7", overlay, "entry-ref", "", "dstap-7", 0)

	// Byte-identity: the exact historical SLIRP block is present, unchanged.
	if !strings.Contains(xml, routedTapSlirpBlock) {
		t.Fatalf("gate-OFF render dropped the byte-identical historical SLIRP block:\n%s", xml)
	}
	if !strings.Contains(xml, "<interface type='user'>") {
		t.Fatalf("gate-OFF render missing the usermode SLIRP interface:\n%s", xml)
	}
	if !strings.Contains(xml, "<model type='virtio'/>") {
		t.Fatalf("gate-OFF SLIRP interface missing the virtio model:\n%s", xml)
	}
	// Exactly one interface, and it is NOT a routed tap (no ethernet NIC, no tap name).
	if n := strings.Count(xml, "<interface "); n != 1 {
		t.Fatalf("gate-OFF render expected exactly 1 interface, got %d:\n%s", n, xml)
	}
	if strings.Contains(xml, "type='ethernet'") {
		t.Fatalf("gate-OFF render must NOT emit a routed-tap ethernet NIC:\n%s", xml)
	}
	if strings.Contains(xml, "dstap-7") {
		t.Fatalf("gate-OFF render must NOT reference the threaded tap name:\n%s", xml)
	}

	// Strongest form: the gate-OFF render is byte-identical to the no-tap-threaded
	// render — a stray byte anywhere fails. (Threading a tap under the OFF gate must
	// change NOTHING.)
	noTap := mustXMLDrive(t, cfg, "sess-7", overlay, "entry-ref", "", "", 0)
	if xml != noTap {
		t.Fatalf("gate-OFF render with a tap threaded must be byte-identical to the no-tap render.\n got=%q\nwant=%q", xml, noTap)
	}
}

// TestDomainDefineXMLRoutedTapOn asserts the gate-ON render: with cfg.RoutedTap=true
// and a non-empty tapName the egress NIC is the per-session routed tap
// (`<interface type='ethernet'><target dev='dstap-7' managed='no'/><mac address='52:54:00:77:07:01'/><model type='virtio'/>`),
// NOT the usermode SLIRP NIC — the U2 host-XML half. Exactly one interface, no SLIRP.
// managed='no' is required: the AttachPrimitive pre-creates the tap, so libvirt must attach
// to the existing dstap-<idx> rather than try to create it (D66). The DETERMINISTIC <mac>
// (52:54:00:77:<idx>:01) is the load-bearing addition: without it libvirt randomizes the
// MAC and the fat L2 image's MAC-matched networkd drop-in (52:54:00:77:07:01 for dstap-7)
// never fires, so the guest never gets its 10.77.7.1/31 IP. The MAC must match l2-up.sh's
// manual qemu `-device ...,mac=52:54:00:77:07:01` byte-for-byte (idx 7 -> 07).
func TestDomainDefineXMLRoutedTapOn(t *testing.T) {
	cfg := liveTestConfig()
	cfg.RoutedTap = true
	overlay := "/var/lib/ds/overlays/sess-7.qcow2"
	xml := mustXMLDrive(t, cfg, "sess-7", overlay, "entry-ref", "", "dstap-7", 0)

	if !strings.Contains(xml, "<interface type='ethernet'>") {
		t.Fatalf("gate-ON render missing the routed-tap ethernet interface:\n%s", xml)
	}
	if !strings.Contains(xml, "<target dev='dstap-7' managed='no'/>") {
		t.Fatalf("gate-ON render missing the per-session tap target (managed='no'):\n%s", xml)
	}
	// The deterministic MAC for index 7 — byte-identical to l2-up.sh / the fat image's
	// 05-l2-routedtap.network [Match] MACAddress. Without it the guest never self-configures.
	if !strings.Contains(xml, "<mac address='52:54:00:77:07:01'/>") {
		t.Fatalf("gate-ON render missing the deterministic routed-tap MAC for dstap-7 (52:54:00:77:07:01):\n%s", xml)
	}
	if !strings.Contains(xml, "<model type='virtio'/>") {
		t.Fatalf("gate-ON routed-tap interface missing the virtio model:\n%s", xml)
	}
	// Exactly one interface, and it is the tap — NOT usermode SLIRP.
	if n := strings.Count(xml, "<interface "); n != 1 {
		t.Fatalf("gate-ON render expected exactly 1 interface, got %d:\n%s", n, xml)
	}
	// Exactly one <mac> (the randomized auto-assign would have none; a duplicate would
	// be a render bug).
	if n := strings.Count(xml, "<mac "); n != 1 {
		t.Fatalf("gate-ON render expected exactly 1 <mac>, got %d:\n%s", n, xml)
	}
	if strings.Contains(xml, "type='user'") {
		t.Fatalf("gate-ON render must NOT emit the usermode SLIRP NIC:\n%s", xml)
	}
}

// TestDomainDefineXMLRoutedTapMACMatchesIndex asserts the deterministic MAC tracks the
// host-session index recovered from the tap name (the dstap-<idx> join key), with the
// 2-HEX-digit %02x render — so each per-session routed tap gets a distinct, reproducible
// MAC the guest image's MAC-match net config can pin against, well-formed for the whole
// idx 0..255 range (the /31 ceiling). idx 7 -> 07, idx 0 -> 00, idx 42 -> 2a (hex),
// idx 100 -> 64 (previously a malformed 3-digit octet under %02d), idx 255 -> ff.
func TestDomainDefineXMLRoutedTapMACMatchesIndex(t *testing.T) {
	cfg := liveTestConfig()
	cfg.RoutedTap = true
	overlay := "/var/lib/ds/overlays/sess.qcow2"
	for _, tc := range []struct {
		tap     string
		wantMAC string
	}{
		{"dstap-0", "52:54:00:77:00:01"},
		{"dstap-7", "52:54:00:77:07:01"}, // byte-stable pinned demo index (hex == decimal)
		{"dstap-42", "52:54:00:77:2a:01"},
		{"dstap-100", "52:54:00:77:64:01"}, // hex fixes the old malformed "52:54:00:77:100:01"
		{"dstap-255", "52:54:00:77:ff:01"}, // the /31 third-octet ceiling
	} {
		xml := mustXMLDrive(t, cfg, "sess", overlay, "entry-ref", "", tc.tap, 0)
		if !strings.Contains(xml, "<mac address='"+tc.wantMAC+"'/>") {
			t.Fatalf("%s: render missing deterministic MAC %q:\n%s", tc.tap, tc.wantMAC, xml)
		}
		if !strings.Contains(xml, "<target dev='"+tc.tap+"' managed='no'/>") {
			t.Fatalf("%s: render missing the tap target:\n%s", tc.tap, xml)
		}
	}
}

// TestDomainDefineXMLRoutedTapOverCeilingRefuses pins the render-level FAIL-CLOSED
// posture: gate-ON with a NON-EMPTY tap name whose index is past the /31 third-octet
// ceiling (255, netConfigMaxIndexThirdOct) must REFUSE the domain-define (a non-nil
// error, no XML) rather than silently downgrade to the UNGATED SLIRP NIC — a
// routed-tap session that names a tap must attach to it (with its per-session NFT in
// place, D66) or not boot at all; a SLIRP fall-through here would un-gate the
// session's egress (a render-layer fail-open in the no-partial-boundary sense).
// Unreachable via the sanctioned allocator (Allocate() fails closed through
// netConfigForIndex on the same ceiling before such a Binding exists); this guards the
// render against a non-allocator tap name. This case previously fell through to SLIRP —
// the assertion below (non-nil err, empty XML, no `<interface type='user'>`) fails
// against that old render and passes only against the fail-closed one.
func TestDomainDefineXMLRoutedTapOverCeilingRefuses(t *testing.T) {
	cfg := liveTestConfig()
	cfg.RoutedTap = true
	overlay := "/var/lib/ds/overlays/sess.qcow2"
	for _, over := range []string{"dstap-256", "dstap-1000"} {
		xml, err := domainDefineXMLWithConfigDrive(cfg, "sess", overlay, "entry-ref", "", over, 0)
		if err == nil {
			t.Fatalf("%s: over-ceiling routed tap must REFUSE (non-nil error), not fall through to SLIRP; got xml:\n%s", over, xml)
		}
		if xml != "" {
			t.Fatalf("%s: a refused render must return EMPTY xml, got:\n%s", over, xml)
		}
		// Belt-and-suspenders: whatever the empty return, no ungated SLIRP NIC leaked.
		if strings.Contains(xml, "<interface type='user'>") {
			t.Fatalf("%s: a refused over-ceiling routed tap must NOT emit the ungated SLIRP NIC:\n%s", over, xml)
		}
		// The error names the offending tap and the ceiling so an operator can diagnose.
		if !strings.Contains(err.Error(), over) {
			t.Fatalf("%s: refusal error must name the offending tap; got %v", over, err)
		}
	}
}

// macForIndex / macForTapName are the pure derivation helpers; assert them directly so
// the index->MAC contract is pinned independent of the XML render. The 5th octet is
// TWO HEX DIGITS (%02x), well-formed for the WHOLE idx 0..255 range — the SAME ceiling
// netConfigForIndex admits for the /31 third octet (netConfigMaxIndexThirdOct). This
// reconciles the two ceilings (option (a)): a routed-tap session that gets a valid
// 10.77.<idx>.1/31 also gets a well-formed MAC, where the old %02d render emitted a
// malformed 3-digit octet at idx 100..255. Byte-stability at the pinned demo idx 7:
// "07" is identical in hex and decimal, so the baked fat-L2 image is unaffected.
func TestMacForIndexAndTapName(t *testing.T) {
	// macForIndex: well-formed 2-hex-digit 5th octet through the /31 ceiling (255).
	// idx 7 renders "07" identically in hex and decimal (byte-stability guard); idx
	// >=10 diverges from the old decimal render (e.g. 100 -> hex "64", not "100").
	for _, tc := range []struct {
		idx  uint64
		want string
	}{
		{0, "52:54:00:77:00:01"},
		{7, "52:54:00:77:07:01"}, // pinned demo index — MUST stay "07" (hex == decimal)
		{99, "52:54:00:77:63:01"},
		{100, "52:54:00:77:64:01"}, // was malformed "52:54:00:77:100:01" under %02d
		{255, "52:54:00:77:ff:01"}, // the /31 third-octet ceiling, well-formed in hex
	} {
		if got := macForIndex(tc.idx); got != tc.want {
			t.Fatalf("macForIndex(%d) = %q, want %q", tc.idx, got, tc.want)
		}
	}

	// macForTapName recovers the index from the `dstap-<idx>` name and returns a
	// well-formed MAC through the SAME 255 ceiling netConfigForIndex fail-closes on.
	for _, tc := range []struct {
		tap  string
		want string
	}{
		{"dstap-0", "52:54:00:77:00:01"},
		{"dstap-7", "52:54:00:77:07:01"},
		{"dstap-99", "52:54:00:77:63:01"},
		{"dstap-100", "52:54:00:77:64:01"},
		{"dstap-255", "52:54:00:77:ff:01"},
	} {
		mac, ok := macForTapName(tc.tap)
		if !ok || mac != tc.want {
			t.Fatalf("macForTapName(%q) = %q, %v; want %q, true", tc.tap, mac, ok, tc.want)
		}
	}

	// Past the /31 ceiling (idx > 255): macForTapName reports ok=false, so the routed-tap
	// render falls through to the SLIRP NIC (the same fallback the unparseable-tap tests
	// pin) rather than emit an out-of-/31 octet — matching netConfigForIndex's own
	// fail-closed posture past netConfigMaxIndexThirdOct. Unreachable via the sanctioned
	// allocator (Allocate() fails closed on the same ceiling first); this is the render's
	// defense-in-depth.
	for _, over := range []string{"dstap-256", "dstap-300", "dstap-1000"} {
		if mac, ok := macForTapName(over); ok {
			t.Fatalf("macForTapName(%q) = %q, ok=true; want ok=false past the /31 ceiling (%d)", over, mac, macIndexMaxOctet)
		}
	}

	// Unparseable / malformed tap names report ok=false so the caller falls back to SLIRP
	// rather than emit a randomized or malformed MAC.
	for _, bad := range []string{"", "dstap-", "eth0", "dstap-xyz", "dstap-7a"} {
		if _, ok := macForTapName(bad); ok {
			t.Fatalf("macForTapName(%q) reported ok=true; want false (malformed tap name)", bad)
		}
	}

	// The Go render and netConfigForIndex share ONE ceiling: every idx macForTapName
	// admits, netConfigForIndex must also admit (and vice versa) — the two ceilings
	// agree by construction, which is the whole point of option (a).
	for _, idx := range []uint64{0, 7, 99, 100, 255, 256} {
		_, macOK := macForTapName(tapName(idx))
		_, netErr := netConfigForIndex(idx)
		if macOK != (netErr == nil) {
			t.Fatalf("ceiling drift at idx %d: macForTapName ok=%v but netConfigForIndex err=%v — the MAC and /31 ceilings must agree", idx, macOK, netErr)
		}
	}
}

// TestDomainDefineXMLRoutedTapOnUnparseableTapRefuses asserts the index-recovery guard's
// FAIL-CLOSED posture: gate-ON with a NON-EMPTY but UNPARSEABLE tap name (no dstap-<idx>
// index, so macForTapName reports macOK=false) must REFUSE the domain-define (non-nil
// error, no XML) rather than silently downgrade to the ungated SLIRP NIC — the MAC
// derivation is part of the routed-tap render's well-formedness precondition, and a
// SLIRP fall-through would un-gate a routed-tap session (D66 no-partial-boundary). This
// is the SAME refusal the over-ceiling case takes; only an EMPTY tap name (the 'no
// binding yet' fall-through) legitimately falls back to SLIRP.
func TestDomainDefineXMLRoutedTapOnUnparseableTapRefuses(t *testing.T) {
	cfg := liveTestConfig()
	cfg.RoutedTap = true
	overlay := "/var/lib/ds/overlays/sess-7.qcow2"
	xml, err := domainDefineXMLWithConfigDrive(cfg, "sess-7", overlay, "entry-ref", "", "eth0", 0)

	if err == nil {
		t.Fatalf("gate-ON with unparseable non-empty tap must REFUSE (non-nil error), not fall through to SLIRP; got xml:\n%s", xml)
	}
	if xml != "" {
		t.Fatalf("a refused render must return EMPTY xml, got:\n%s", xml)
	}
	if strings.Contains(xml, "<interface type='user'>") {
		t.Fatalf("a refused unparseable routed tap must NOT emit the ungated SLIRP NIC:\n%s", xml)
	}
	if !strings.Contains(err.Error(), "eth0") {
		t.Fatalf("refusal error must name the offending tap; got %v", err)
	}
}

// TestDomainDefineXMLRoutedTapOnEmptyTapFallsBackToSlirp asserts the empty-tap
// footgun guard: gate-ON but with an EMPTY tapName must fall back to the historical
// SLIRP NIC rather than emit a malformed `<target dev=”/>` ethernet NIC.
func TestDomainDefineXMLRoutedTapOnEmptyTapFallsBackToSlirp(t *testing.T) {
	cfg := liveTestConfig()
	cfg.RoutedTap = true
	overlay := "/var/lib/ds/overlays/sess-7.qcow2"
	xml := mustXMLDrive(t, cfg, "sess-7", overlay, "entry-ref", "", "", 0)

	if !strings.Contains(xml, routedTapSlirpBlock) {
		t.Fatalf("gate-ON with empty tap must fall back to the byte-identical SLIRP block:\n%s", xml)
	}
	if strings.Contains(xml, "type='ethernet'") {
		t.Fatalf("gate-ON with empty tap must NOT emit a routed-tap ethernet NIC:\n%s", xml)
	}
	if strings.Contains(xml, "<target dev=''/>") {
		t.Fatalf("gate-ON with empty tap must NOT emit a malformed empty target:\n%s", xml)
	}
	// And it is byte-identical to the gate-OFF render (the safe fallback).
	cfgOff := liveTestConfig()
	cfgOff.RoutedTap = false
	if off := mustXMLDrive(t, cfgOff, "sess-7", overlay, "entry-ref", "", "", 0); xml != off {
		t.Fatalf("gate-ON empty-tap fallback must be byte-identical to the gate-OFF render.\n got=%q\nwant=%q", xml, off)
	}
}

// TestNewLiveBooterSourcesRoutedTapFromEnv asserts NewLiveBooter populates
// LiveConfig.RoutedTap from the DS_ROUTED_TAP env at construction (the same
// construction-time fill it does for VirshBin) — NOT from a main.go-set field. With
// the env unset the field defaults false (the gate-OFF default); set to "1" it is
// true. Read once at construction, mirroring LiveEnabled.
func TestNewLiveBooterSourcesRoutedTapFromEnv(t *testing.T) {
	cfg := liveTestConfig()

	t.Setenv(EnvRoutedTap, "")
	bOff, err := NewLiveBooter(cfg)
	if err != nil {
		t.Fatalf("NewLiveBooter (gate unset): %v", err)
	}
	if bOff.(*liveBooter).cfg.RoutedTap {
		t.Fatal("RoutedTap should default false when DS_ROUTED_TAP is unset (gate-OFF default)")
	}

	t.Setenv(EnvRoutedTap, "1")
	bOn, err := NewLiveBooter(cfg)
	if err != nil {
		t.Fatalf("NewLiveBooter (gate on): %v", err)
	}
	if !bOn.(*liveBooter).cfg.RoutedTap {
		t.Fatal("RoutedTap should be true when DS_ROUTED_TAP=1 (construction-time env fill)")
	}
}

// historicalDiskBootOS is the exact single-line `<os>` block the disk-boot
// (gate-OFF, default) render MUST emit byte-for-byte — the canonical grub-image
// path. The direct-kernel gate is ADDITIVE: with no KernelPath the render must be
// byte-identical to before, so this literal is the load-bearing zero-default-change
// invariant.
const historicalDiskBootOS = "  <os><type arch='x86_64'>hvm</type></os>\n"

// TestDomainDefineXMLDirectKernelOff pins the gate-OFF byte-identity: with an empty
// KernelPath (the zero value / default) the `<os>` is the historical single-line
// disk-boot block, byte-for-byte — the canonical grub-image path is untouched. The
// InitrdPath/KernelCmdline fields are ignored when KernelPath is empty.
func TestDomainDefineXMLDirectKernelOff(t *testing.T) {
	cfg := liveTestConfig()
	// Even with initrd/cmdline set, an empty KernelPath keeps the disk-boot `<os>`.
	cfg.InitrdPath = "/ignored/initrd.img"
	cfg.KernelCmdline = "ignored=cmdline"
	overlay := "/var/lib/ds/overlays/sess-disk.qcow2"
	xml := mustXML(t, cfg, "sess-disk", overlay, "entry-ref", 0)

	if !strings.Contains(xml, historicalDiskBootOS) {
		t.Fatalf("gate-OFF render dropped the byte-identical historical disk-boot <os>:\n%s", xml)
	}
	if strings.Contains(xml, "<kernel>") || strings.Contains(xml, "<initrd>") || strings.Contains(xml, "<cmdline>") {
		t.Fatalf("gate-OFF render must NOT emit any direct-kernel element:\n%s", xml)
	}

	// Strongest form: the gate-OFF render is byte-identical to the render with NO
	// direct-kernel fields set at all — the ignored initrd/cmdline change NOTHING.
	bare := liveTestConfig()
	if base := mustXML(t, bare, "sess-disk", overlay, "entry-ref", 0); xml != base {
		t.Fatalf("gate-OFF render with ignored initrd/cmdline must be byte-identical to the bare render.\n got=%q\nwant=%q", xml, base)
	}
}

// TestDomainDefineXMLDirectKernelOn asserts the gate-ON render: with KernelPath set
// the `<os>` is the direct-kernel form (`<kernel>/<initrd>/<cmdline>`), the cmdline
// is XML-escaped, and the disk source is still the per-session overlay (only the
// `<os>` block changes — the kernel mounts the same vda as root).
func TestDomainDefineXMLDirectKernelOn(t *testing.T) {
	cfg := liveTestConfig()
	cfg.KernelPath = "/var/lib/ds/m0-vmlinuz"
	cfg.InitrdPath = "/var/lib/ds/m0-initrd.img"
	cfg.KernelCmdline = "root=LABEL=DS_M0ROOT console=ttyS0,115200 rw"
	overlay := "/var/lib/ds/overlays/sess-dk.qcow2"
	xml := mustXML(t, cfg, "sess-dk", overlay, "entry-ref", 0)

	wantOS := "  <os><type arch='x86_64'>hvm</type>" +
		"<kernel>/var/lib/ds/m0-vmlinuz</kernel>" +
		"<initrd>/var/lib/ds/m0-initrd.img</initrd>" +
		"<cmdline>root=LABEL=DS_M0ROOT console=ttyS0,115200 rw</cmdline></os>\n"
	if !strings.Contains(xml, wantOS) {
		t.Fatalf("gate-ON render missing the direct-kernel <os> block.\n got=%s\nwant substring=%q", xml, wantOS)
	}
	// The historical single-line disk-boot <os> must NOT appear (it is replaced).
	if strings.Contains(xml, historicalDiskBootOS) {
		t.Fatalf("gate-ON render must REPLACE the disk-boot <os>, not also emit it:\n%s", xml)
	}
	// Only the <os> changes — the overlay is still the disk source (kernel mounts it).
	if !strings.Contains(xml, "<source file='"+overlay+"'/>") {
		t.Fatalf("gate-ON render dropped the overlay disk source (kernel mounts the same vda root):\n%s", xml)
	}
}

// TestDomainDefineXMLDirectKernelEscapesCmdline asserts the `<cmdline>` is XML-escaped
// so a cmdline carrying & < > or quoted args cannot break the domain XML.
func TestDomainDefineXMLDirectKernelEscapesCmdline(t *testing.T) {
	cfg := liveTestConfig()
	cfg.KernelPath = "/k/vmlinuz"
	cfg.InitrdPath = "/k/initrd.img"
	cfg.KernelCmdline = `root=LABEL=DS_M0ROOT foo="a & b" x<y`
	xml := mustXML(t, cfg, "sess-esc", "/ov/sess-esc.qcow2", "entry-ref", 0)

	if !strings.Contains(xml, "<cmdline>root=LABEL=DS_M0ROOT foo=&#34;a &amp; b&#34; x&lt;y</cmdline>") {
		t.Fatalf("direct-kernel <cmdline> not XML-escaped:\n%s", xml)
	}
	if strings.Contains(xml, `x<y`) {
		t.Fatalf("direct-kernel <cmdline> leaked a raw '<' into the XML:\n%s", xml)
	}
}

// TestNewLiveBooterSourcesDirectKernelFromEnv asserts NewLiveBooter populates the
// direct-kernel fields env-OR-explicit-field (the same construction-time fill it
// does for VirshBin/RoutedTap): unset env keeps the field, set env fills it, and a
// kernel path with no cmdline defaults to DefaultKernelCmdline. Read once at
// construction, mirroring LiveEnabled/RoutedTapEnabled.
func TestNewLiveBooterSourcesDirectKernelFromEnv(t *testing.T) {
	cfg := liveTestConfig()

	// All unset ⇒ direct-kernel OFF (the disk-boot default).
	t.Setenv(EnvKernelPath, "")
	t.Setenv(EnvInitrdPath, "")
	t.Setenv(EnvKernelCmdline, "")
	bOff, err := NewLiveBooter(cfg)
	if err != nil {
		t.Fatalf("NewLiveBooter (gate unset): %v", err)
	}
	if bOff.(*liveBooter).cfg.KernelPath != "" {
		t.Fatal("KernelPath should default empty when DS_KERNEL_PATH is unset (gate-OFF default)")
	}

	// Env-sourced kernel path with no cmdline ⇒ DefaultKernelCmdline.
	t.Setenv(EnvKernelPath, "/env/vmlinuz")
	t.Setenv(EnvInitrdPath, "/env/initrd.img")
	bOn, err := NewLiveBooter(cfg)
	if err != nil {
		t.Fatalf("NewLiveBooter (gate on): %v", err)
	}
	on := bOn.(*liveBooter).cfg
	if on.KernelPath != "/env/vmlinuz" {
		t.Fatalf("KernelPath should be env-sourced, got %q", on.KernelPath)
	}
	if on.InitrdPath != "/env/initrd.img" {
		t.Fatalf("InitrdPath should be env-sourced, got %q", on.InitrdPath)
	}
	if on.KernelCmdline != DefaultKernelCmdline {
		t.Fatalf("KernelCmdline should default to %q when kernel set + cmdline empty, got %q", DefaultKernelCmdline, on.KernelCmdline)
	}

	// An explicit field set takes precedence over an empty env (env-OR-field), and an
	// explicit cmdline is NOT overwritten by the default.
	t.Setenv(EnvKernelPath, "")
	t.Setenv(EnvKernelCmdline, "")
	cfgExplicit := liveTestConfig()
	cfgExplicit.KernelPath = "/explicit/vmlinuz"
	cfgExplicit.KernelCmdline = "custom=cmdline"
	bExp, err := NewLiveBooter(cfgExplicit)
	if err != nil {
		t.Fatalf("NewLiveBooter (explicit field): %v", err)
	}
	exp := bExp.(*liveBooter).cfg
	if exp.KernelPath != "/explicit/vmlinuz" {
		t.Fatalf("explicit KernelPath should survive an unset env, got %q", exp.KernelPath)
	}
	if exp.KernelCmdline != "custom=cmdline" {
		t.Fatalf("explicit KernelCmdline must NOT be overwritten by the default, got %q", exp.KernelCmdline)
	}
}

func TestDomainDefineAndLookupArgs(t *testing.T) {
	cfg := liveTestConfig()
	name, args := domainDefineArgs(cfg, "/tmp/dom.xml")
	if name != "virsh" || strings.Join(args, " ") != "create /tmp/dom.xml" {
		t.Fatalf("define args = %q %q", name, args)
	}
	lname, largs := domainLookupArgs(cfg, "sess-3")
	if lname != "virsh" || strings.Join(largs, " ") != "domuuid ds-sess-3" {
		t.Fatalf("lookup args = %q %q", lname, largs)
	}
}

// ── live-binding behavior via the fake runner (gated; skips when env unset) ──

// TestLiveOverlayStoreCreateInvocation drives the live OverlayStore's
// CreateOverlay over a recording runner and asserts the proven overlay-create.sh
// command line + the deterministic per-session overlay path. It is GATED on
// DS_HOSTAGENT_LIVE so the default offline path is the only one the sandbox / CI
// exercises; the fake runner means even under the gate NO subprocess is launched.
func TestLiveOverlayStoreCreateInvocation(t *testing.T) {
	requireLiveGate(t)
	cfg := liveTestConfig()
	rr := &recordingRunner{}
	s := &liveOverlayStore{cfg: cfg, run: rr}

	path, err := s.CreateOverlay(context.Background(), "sess-9", "img-abc")
	if err != nil {
		t.Fatalf("CreateOverlay: %v", err)
	}
	wantPath := "/var/lib/ds/overlays/sess-9.qcow2"
	if path != wantPath {
		t.Fatalf("overlay path = %q, want %q", path, wantPath)
	}
	if len(rr.calls) != 1 {
		t.Fatalf("expected 1 exec, got %d: %v", len(rr.calls), rr.calls)
	}
	got := strings.Join(rr.calls[0], " ")
	want := cfg.OverlayCreateScript + " --base " + cfg.BaseImage + " --overlay " + wantPath
	if got != want {
		t.Fatalf("clone invocation = %q, want %q", got, want)
	}
}

// TestLiveBooterDefinesOverlayDomain drives the live Booter's Boot over a
// recording runner: the idempotent lookup (empty → not running) then virsh create
// then a read-back returning the uuid. Gated; uses the fake runner (no virsh).
func TestLiveBooterDefinesOverlayDomain(t *testing.T) {
	requireLiveGate(t)
	cfg := liveTestConfig()
	// call 0: domuuid (pre-check) → empty (not running)
	// call 1: virsh create → ok
	// call 2: domuuid (read-back) → the uuid
	rr := &recordingRunner{outputs: []string{"", "", "dom-uuid-xyz\n"}}
	b := &liveBooter{cfg: cfg, run: rr}

	const cid uint32 = 9
	uuid, err := b.Boot(context.Background(), "sess-5", "/var/lib/ds/overlays/sess-5.qcow2", "entry-ref", "", cid)
	if err != nil {
		t.Fatalf("Boot: %v", err)
	}
	if uuid != "dom-uuid-xyz" {
		t.Fatalf("domain uuid = %q, want dom-uuid-xyz", uuid)
	}
	if len(rr.calls) != 3 {
		t.Fatalf("expected 3 execs (lookup, create, read-back), got %d: %v", len(rr.calls), rr.calls)
	}
	if strings.Join(rr.calls[0], " ") != "virsh domuuid ds-sess-5" {
		t.Fatalf("pre-check = %q", rr.calls[0])
	}
	if rr.calls[1][0] != "virsh" || rr.calls[1][1] != "create" {
		t.Fatalf("define = %q", rr.calls[1])
	}
	// The materialized domain XML (snapshotted by the runner at `virsh create` time, since
	// Boot `defer`-removes the temp file at return) PINS the deterministic per-session vsock
	// CID Boot threaded — `<cid auto='no' address='9'/>` — so the host agent can dial a
	// host-predictable guestCID:port. Asserting it through the real liveBooter.Boot (not just
	// the pure builder) proves the vsockCID arg reaches the render rather than the auto-assign
	// fallback.
	xmlPath := rr.calls[1][2]
	xml, ok := rr.createdXML[xmlPath]
	if !ok {
		t.Fatalf("runner did not capture the staged domain xml for %q (calls: %v)", xmlPath, rr.calls)
	}
	if !strings.Contains(xml, "<cid auto='no' address='9'/>") {
		t.Fatalf("live Boot domain xml did not pin the threaded vsock cid:\n%s", xml)
	}
	if strings.Contains(xml, "<cid auto='yes'/>") {
		t.Fatalf("live Boot domain xml must NOT auto-assign when a deterministic cid is threaded:\n%s", xml)
	}
}

// TestLiveBooterIdempotentShortCircuit: an already-running domain is reported
// back without a second virsh create (the seams.go idempotency contract).
func TestLiveBooterIdempotentShortCircuit(t *testing.T) {
	requireLiveGate(t)
	cfg := liveTestConfig()
	rr := &recordingRunner{outputs: []string{"already-running-uuid\n"}}
	b := &liveBooter{cfg: cfg, run: rr}

	uuid, err := b.Boot(context.Background(), "sess-2", "/var/lib/ds/overlays/sess-2.qcow2", "entry-ref", "", 0)
	if err != nil {
		t.Fatalf("Boot: %v", err)
	}
	if uuid != "already-running-uuid" {
		t.Fatalf("uuid = %q, want already-running-uuid", uuid)
	}
	if len(rr.calls) != 1 {
		t.Fatalf("expected 1 exec (lookup short-circuit), got %d: %v", len(rr.calls), rr.calls)
	}
}

func TestLiveOverlayStoreCloneFailureSurfaces(t *testing.T) {
	requireLiveGate(t)
	cfg := liveTestConfig()
	rr := &recordingRunner{errs: []error{errors.New("qemu-img create failed")}}
	s := &liveOverlayStore{cfg: cfg, run: rr}
	if _, err := s.CreateOverlay(context.Background(), "sess-x", "img"); err == nil {
		t.Fatal("expected CreateOverlay to surface the clone failure")
	}
}

// ── live-config validation + dispose guards (always run; no substrate) ───────

func TestNewLiveOverlayStoreRejectsIncompleteConfig(t *testing.T) {
	if _, err := NewLiveOverlayStore(LiveConfig{}); err == nil {
		t.Fatal("expected NewLiveOverlayStore to reject empty config")
	}
	if _, err := NewLiveOverlayStore(LiveConfig{OverlayCreateScript: "x", OverlayDir: "y"}); err == nil {
		t.Fatal("expected NewLiveOverlayStore to require a base image")
	}
}

func TestLiveOverlayDisposeRefusesOutsideOverlayDir(t *testing.T) {
	cfg := liveTestConfig()
	s := &liveOverlayStore{cfg: cfg, run: &recordingRunner{}}
	if err := s.DisposeOverlay(context.Background(), "/etc/passwd"); err == nil {
		t.Fatal("expected DisposeOverlay to refuse a path outside the overlay dir")
	}
	if err := s.DisposeOverlay(context.Background(), cfg.BaseImage); err == nil {
		t.Fatal("expected DisposeOverlay to refuse disposing the shared raw base")
	}
	// Empty path is a tolerated no-op (nothing to dispose).
	if err := s.DisposeOverlay(context.Background(), ""); err != nil {
		t.Fatalf("empty dispose should be a no-op, got %v", err)
	}
}

// ── gate-aware constructors: offline default must NOT touch substrate ────────

func TestGateAwareConstructorsDefaultOffline(t *testing.T) {
	if LiveEnabled() {
		t.Skip("DS_HOSTAGENT_LIVE set: this asserts the offline default; live path covered by the gated tests")
	}
	cfg := liveTestConfig()
	store, err := NewOverlayStore(cfg)
	if err != nil {
		t.Fatalf("NewOverlayStore (offline): %v", err)
	}
	if _, ok := store.(offlineOverlayStore); !ok {
		t.Fatalf("offline default OverlayStore = %T, want offlineOverlayStore", store)
	}
	// The offline store derives the deterministic per-session path without disk.
	path, err := store.CreateOverlay(context.Background(), "sess-1", "img")
	if err != nil {
		t.Fatalf("offline CreateOverlay: %v", err)
	}
	if path != "/var/lib/ds/overlays/sess-1.qcow2" {
		t.Fatalf("offline overlay path = %q", path)
	}
	booter, err := NewBooter(cfg)
	if err != nil {
		t.Fatalf("NewBooter (offline): %v", err)
	}
	if _, ok := booter.(offlineBooter); !ok {
		t.Fatalf("offline default Booter = %T, want offlineBooter", booter)
	}
	uuid, err := booter.Boot(context.Background(), "sess-1", "/x.qcow2", "e", "", 0)
	if err != nil || uuid == "" {
		t.Fatalf("offline Boot = %q, %v", uuid, err)
	}
}

// requireLiveGate skips a test unless DS_HOSTAGENT_LIVE=1. The live-binding tests
// assert the real OverlayStore/Booter code paths (over a fake runner, never a
// real subprocess), but they are reachable only on the operator-host gate so the
// default offline path is the sole one the sandbox / CI exercises.
func requireLiveGate(t *testing.T) {
	t.Helper()
	if os.Getenv(EnvHostAgentLive) != "1" {
		t.Skipf("live binding test: set %s=1 to run (default offline path stays green)", EnvHostAgentLive)
	}
}

// TestDomainDefineXMLWorkspaceDiskIsAdditive asserts the per-session WORKSPACE disk
// (the dogfood carrier, 01KWHCG6EV) is strictly additive: absent by default, and
// when present it attaches as a READ-WRITE third disk without disturbing the
// overlay or the config-drive.
//
// The read-write assertion is the load-bearing one. The config-drive above it is
// <readonly/>, and the natural mistake when copying that block is to carry the flag
// along — which produces a workspace the agent cannot write, a failure that surfaces
// only once a real session tries to save a file.
func TestDomainDefineXMLWorkspaceDiskIsAdditive(t *testing.T) {
	cfg := liveTestConfig()
	overlay := "/var/lib/ds/overlays/sess-9.qcow2"

	// (a) UNSET: no third disk, and the render is unchanged from the historical form.
	base := mustXMLDrive(t, cfg, "sess-9", overlay, "entry-ref", "/var/lib/ds/drives/sess-9.iso", "", 0)
	if strings.Contains(base, "vdc") {
		t.Fatalf("workspace disk rendered with no WorkspaceDisk configured:\n%s", base)
	}

	// (b) SET: a third read-write disk pointing at the configured image.
	ws := "/var/lib/ds-host-gated/workspaces/dream-serpent.ext4"
	cfg.WorkspaceDisk = ws
	got := mustXMLDrive(t, cfg, "sess-9", overlay, "entry-ref", "/var/lib/ds/drives/sess-9.iso", "", 0)
	if !strings.Contains(got, "<source file='"+ws+"'/>") {
		t.Fatalf("domain xml does not wire the workspace image as a disk source:\n%s", got)
	}
	if !strings.Contains(got, "<target dev='vdc' bus='virtio'/>") {
		t.Fatalf("workspace disk is not attached at the fixed vdc target:\n%s", got)
	}
	// The overlay (vda) and config-drive (vdb) must be untouched by the addition.
	if !strings.Contains(got, "<target dev='vda' bus='virtio'/>") ||
		!strings.Contains(got, "<target dev='vdb' bus='virtio'/>") {
		t.Fatalf("workspace disk displaced the overlay or config-drive:\n%s", got)
	}
	// Exactly ONE <readonly/> must remain — the config-drive's. A second would mean
	// the workspace came out read-only.
	if n := strings.Count(got, "<readonly/>"); n != 1 {
		t.Fatalf("expected exactly 1 <readonly/> (the config-drive); got %d — the workspace must be writable:\n%s", n, got)
	}

	// (c) A workspace with NO config-drive still attaches: the two carriers are
	// independent, so vdc must not depend on vdb being present.
	solo := mustXMLDrive(t, cfg, "sess-9", overlay, "entry-ref", "", "", 0)
	if !strings.Contains(solo, "<target dev='vdc' bus='virtio'/>") {
		t.Fatalf("workspace disk did not attach without a config-drive:\n%s", solo)
	}
	if strings.Contains(solo, "<target dev='vdb' bus='virtio'/>") {
		t.Fatalf("config-drive rendered when none was configured:\n%s", solo)
	}
}

// ── per-session workspace clone (01KYRGC5NC) ─────────────────────────────────

func TestWorkspacePathForAndCloneArgs(t *testing.T) {
	if got := workspacePathFor("/var/lib/ds/overlays", "sess-4"); got != "/var/lib/ds/overlays/sess-4.workspace.ext4" {
		t.Fatalf("workspacePathFor = %q", got)
	}
	name, args := workspaceCloneArgs("/var/lib/ds/workspaces/golden.ext4", "/var/lib/ds/overlays/sess-4.workspace.ext4")
	if name != "cp" || strings.Join(args, " ") != "--reflink=auto /var/lib/ds/workspaces/golden.ext4 /var/lib/ds/overlays/sess-4.workspace.ext4" {
		t.Fatalf("clone invocation = %q %q", name, args)
	}
}

// TestLiveBooterClonesWorkspacePerSession is the structural anti-corruption
// assertion for 01KYRGC5NC: with a golden workspace configured, Boot clones it to
// the deterministic per-session path and the domain XML references ONLY the
// clone — the golden never appears in any domain's XML, so two concurrent
// sessions can never mount one ext4 read-write from two kernels. Two sessions
// get two distinct clones; an EXISTING clone is reused (a retry / recovery
// re-boot must converge on the session's own edits, not a fresh golden copy).
// Gated; fake runner — no cp, virsh, or substrate is ever exec'd, and the only
// filesystem touched is a t.TempDir().
func TestLiveBooterClonesWorkspacePerSession(t *testing.T) {
	requireLiveGate(t)
	cfg := liveTestConfig()
	cfg.OverlayDir = t.TempDir()
	cfg.WorkspaceDisk = "/var/lib/ds/workspaces/golden.ext4"

	boot := func(sessionUUID string) (*recordingRunner, string) {
		t.Helper()
		// call 0: domuuid (pre-check) → empty (not running)
		// call 1: cp --reflink=auto golden → per-session clone
		// call 2: virsh create → ok
		// call 3: domuuid (read-back) → the uuid
		rr := &recordingRunner{outputs: []string{"", "", "", "dom-" + sessionUUID + "\n"}}
		b := &liveBooter{cfg: cfg, run: rr}
		uuid, err := b.Boot(context.Background(), sessionUUID, cfg.OverlayDir+"/"+sessionUUID+".qcow2", "", "", 0)
		if err != nil {
			t.Fatalf("Boot(%s): %v", sessionUUID, err)
		}
		if uuid != "dom-"+sessionUUID {
			t.Fatalf("Boot(%s) uuid = %q", sessionUUID, uuid)
		}
		return rr, workspacePathFor(cfg.OverlayDir, sessionUUID)
	}

	rrA, cloneA := boot("sess-a")
	if len(rrA.calls) != 4 {
		t.Fatalf("expected 4 execs (lookup, cp, create, read-back), got %d: %v", len(rrA.calls), rrA.calls)
	}
	if got := strings.Join(rrA.calls[1], " "); got != "cp --reflink=auto "+cfg.WorkspaceDisk+" "+cloneA {
		t.Fatalf("workspace clone invocation = %q", got)
	}
	xml := rrA.createdXML[rrA.calls[2][2]]
	if !strings.Contains(xml, "<source file='"+cloneA+"'/>") {
		t.Fatalf("domain xml does not attach the per-session workspace clone:\n%s", xml)
	}
	if strings.Contains(xml, cfg.WorkspaceDisk) {
		t.Fatalf("domain xml references the GOLDEN workspace image — the shared-mount corruption case:\n%s", xml)
	}

	// A second session clones to a DIFFERENT per-session path.
	rrB, cloneB := boot("sess-b")
	if cloneB == cloneA {
		t.Fatalf("two sessions derived the same workspace clone path %q", cloneA)
	}
	if got := strings.Join(rrB.calls[1], " "); got != "cp --reflink=auto "+cfg.WorkspaceDisk+" "+cloneB {
		t.Fatalf("second session clone invocation = %q", got)
	}

	// An EXISTING clone is reused, never re-cloned: the retry / recovery path must
	// keep the session's edits. (The fake runner never ran cp, so materialize the
	// clone by hand.)
	if err := os.WriteFile(cloneA, []byte("session edits"), 0o644); err != nil {
		t.Fatalf("stage existing clone: %v", err)
	}
	rr2 := &recordingRunner{outputs: []string{"", "", "dom-sess-a\n"}}
	b2 := &liveBooter{cfg: cfg, run: rr2}
	if _, err := b2.Boot(context.Background(), "sess-a", cfg.OverlayDir+"/sess-a.qcow2", "", "", 0); err != nil {
		t.Fatalf("re-Boot(sess-a): %v", err)
	}
	for _, call := range rr2.calls {
		if call[0] == "cp" {
			t.Fatalf("re-boot re-cloned an existing workspace (would clobber the session's edits): %v", rr2.calls)
		}
	}
	if got, _ := os.ReadFile(cloneA); string(got) != "session edits" {
		t.Fatalf("existing clone was modified on re-boot: %q", got)
	}

	// A clone FAILURE refuses the boot (fail-closed): a session configured for a
	// workspace must not come up with an empty /work.
	rr3 := &recordingRunner{outputs: []string{"", ""}, errs: []error{nil, errors.New("cp: no space left on device")}}
	b3 := &liveBooter{cfg: cfg, run: rr3}
	if _, err := b3.Boot(context.Background(), "sess-c", cfg.OverlayDir+"/sess-c.qcow2", "", "", 0); err == nil {
		t.Fatal("expected Boot to surface the workspace clone failure")
	}
}
