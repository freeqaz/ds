// SPDX-License-Identifier: Apache-2.0

package nftgate

// live_probe_nft4_test.go — the NFT-4 closure live runners (DoT-853 drop, QUIC
// udp/443 reject) wired against the ds_resolver_closure table layered on the M0
// boundary. Like the other wired runners they observe the wire from the guest and
// are cross-checked against referencePosture by the TestLive_M0Boundary loop;
// gated behind DS_NFTGATE_LIVE=1, skip-by-default offline/CI.
//
// FAITHFULNESS: both runners ADMIT the probe IP first so the observation isolates
// the NFT-4 closure verdict from the NFT-1 default-deny floor — a DoT drop / QUIC
// reject seen on an ADMITTED destination is NFT-4's doing, not generic default-
// deny (which would drop ANY unadmitted port). Each pairs the closure verdict with
// a tcp/443 control that REACHES the same admitted IP, proving the IP is reachable
// and only the closure port/proto is blocked. The QUIC runner distinguishes a
// REJECT (ICMP port-unreachable → ECONNREFUSED, fast) from a silent DROP (recv
// timeout) — the D70 reject-not-drop requirement.
//
// NOTE (M0 demo-floor caveat): the M0 setup-net boundary's NFT-1 floor (the
// ds-filter-demo table) does not itself carry the canonical floor's udp/443
// reject, so an UNADMITTED udp/443 is dropped by default-deny here; the NFT-4
// reject is observed on an ADMITTED destination. On a canonical nft-1-bootstrap
// floor the reject also covers the unadmitted default.

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

// guestTCPConnect attempts a bounded TCP connect from the guest to ip:port and
// reports whether it CONNECTED (reached) vs was blocked.
func (b liveBoundary) guestTCPConnect(t *testing.T, ip string, port, timeoutSecs int) (reached bool, detail string) {
	t.Helper()
	cmd := fmt.Sprintf("timeout %d bash -c 'exec 3<>/dev/tcp/%s/%d' 2>&1 && echo DS-CONNECTED || echo DS-BLOCKED", timeoutSecs, ip, port)
	out, _ := b.guestSSHCmd(t, cmd)
	return strings.Contains(out, "DS-CONNECTED"), oneLine(out)
}

// guestQUICProbe sends a udp/443 datagram from the guest to ip and classifies the
// boundary's disposition: "rejected" (ICMP port-unreachable → ECONNREFUSED),
// "dropped" (no reply within the timeout), "reply" (an answer came back), or
// "err". The python is base64-piped to sidestep ssh/shell quoting.
func (b liveBoundary) guestQUICProbe(t *testing.T, ip string) (verdict, raw string) {
	t.Helper()
	py := fmt.Sprintf(`import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.connect((%q,443))
try:
 s.send(b"q"); s.settimeout(5); s.recv(64); print("DS-REPLY")
except ConnectionRefusedError: print("DS-REJECTED")
except socket.timeout: print("DS-DROPPED")
except Exception as e: print("DS-ERR",type(e).__name__)`, ip)
	b64 := base64.StdEncoding.EncodeToString([]byte(py))
	out, _ := b.guestSSHCmd(t, "echo "+b64+" | base64 -d | timeout 9 python3 2>&1")
	raw = oneLine(out)
	switch {
	case strings.Contains(out, "DS-REJECTED"):
		return "rejected", raw
	case strings.Contains(out, "DS-DROPPED"):
		return "dropped", raw
	case strings.Contains(out, "DS-REPLY"):
		return "reply", raw
	default:
		return "err", raw
	}
}

// dohDotBypassLiveRunner — RowDoHDoTBypass. The DoT (tcp/853) leg is wired against
// NFT-4; the DoH leg is honestly skipped: DoH denial is a DNS-3/TLS-1 + POL-2
// baseline-blocklist policy control (the named-resolver half), not an L3/4 rule,
// so it is asserted by the resolverlock/policy-core conformance, not a wire probe.
func dohDotBypassLiveRunner(t *testing.T, f Fixture) {
	if f.Kind == AttemptDoH {
		t.Skipf("DoH fixture %q (want %q) is a DNS-3/TLS-1 + POL-2 baseline-blocklist policy control (named-resolver "+
			"half), not an L3/4 rule — asserted by resolverlock/policy-core conformance, not a wire probe; the DoT leg is wired",
			f.Attempt.Name, f.Want)
	}
	if f.Kind != AttemptDoT {
		t.Fatalf("dohDotBypassLiveRunner: unexpected attempt kind %q for %q", f.Kind, f.Attempt.Name)
	}
	b := liveBoundaryFromEnv(t)
	b.admit(t, b.probeIP)
	defer b.unadmit(t, b.probeIP)

	// Control: the admitted IP IS reachable on tcp/443 (so a :853 block is DoT-specific, not default-deny).
	if reach, d := b.guestTCPConnect(t, b.probeIP, 443, 7); !reach {
		t.Fatalf("dot-drop[%s]: control tcp/443 to ADMITTED %s did not reach (%s); cannot attribute a :853 block to NFT-4 DoT-drop", f.Attempt.Name, b.probeIP, d)
	}
	// DoT: tcp/853 to the SAME admitted IP must STILL be dropped (NFT-4, even though admitted).
	if reach, d := b.guestTCPConnect(t, b.probeIP, 853, 7); reach {
		t.Fatalf("dot-drop[%s]: tcp/853 to ADMITTED %s CONNECTED (%s); NFT-4 must drop DoT even to an admitted destination", f.Attempt.Name, b.probeIP, d)
	}
	t.Logf("WIRE OK dot-drop[%s]: tcp/853 to admitted %s DROPPED while tcp/443 reaches (DoT-specific, NFT-4), want=%s", f.Attempt.Name, b.probeIP, f.Want)
}

// quicRejectLiveRunner — RowQUICReject: udp/443 is REJECTED with ICMP
// port-unreachable (not silently dropped), the D70 reject-not-drop requirement.
func quicRejectLiveRunner(t *testing.T, f Fixture) {
	if f.Kind != AttemptQUIC {
		t.Fatalf("quicRejectLiveRunner: unexpected attempt kind %q for %q", f.Kind, f.Attempt.Name)
	}
	b := liveBoundaryFromEnv(t)
	b.admit(t, b.probeIP)
	defer b.unadmit(t, b.probeIP)

	// Control: the admitted IP reaches on tcp/443 (so a udp/443 reject is the QUIC rule, not default-deny).
	if reach, d := b.guestTCPConnect(t, b.probeIP, 443, 7); !reach {
		t.Fatalf("quic-reject[%s]: control tcp/443 to ADMITTED %s did not reach (%s); cannot isolate the udp/443 reject", f.Attempt.Name, b.probeIP, d)
	}
	verdict, raw := b.guestQUICProbe(t, b.probeIP)
	switch verdict {
	case "rejected":
		t.Logf("WIRE OK quic-reject[%s]: udp/443 to admitted %s REJECTED (ICMP port-unreachable → ECONNREFUSED, not a silent drop), want=%s", f.Attempt.Name, b.probeIP, f.Want)
	case "dropped":
		t.Fatalf("quic-reject[%s]: udp/443 to admitted %s was SILENTLY DROPPED (recv timeout: %s); D70 requires a REJECT with ICMP port-unreachable, never a silent drop", f.Attempt.Name, b.probeIP, raw)
	default:
		t.Fatalf("quic-reject[%s]: udp/443 to admitted %s gave an unexpected disposition %q (%s); expected an ICMP-port-unreachable reject", f.Attempt.Name, b.probeIP, verdict, raw)
	}
}
