// SPDX-License-Identifier: Apache-2.0

package nftgate

// live_probe_test.go — the FIRST wired live runner (RowDefaultDeny), replacing
// the notYetWired scaffold for the M0 default-deny row. It drives a REAL boundary
// (NFT-1 ds_filter ruleset + a guest VM on the ds tap) and observes the actual
// L3/4 disposition of an egress attempt, then cross-checks it against the same
// modeled posture the offline half asserts (referencePosture, applied by the
// TestLive_M0Boundary loop BEFORE this runs — so the wire verdict can never
// diverge from the offline spec).
//
// STILL DEFERRED-MANUAL and gated behind DS_NFTGATE_LIVE=1 + an operator-provided
// boundary (never CI; needs CAP_NET_ADMIN + a live guest). Operator inputs (env):
//
//   DS_NFTGATE_LIVE_GUEST     ssh target of the guest on the ds tap, e.g. root@10.0.99.2 (REQUIRED)
//   DS_NFTGATE_LIVE_SSH_KEY   path to the guest ssh key (optional; uses agent/default if unset)
//   DS_NFTGATE_LIVE_PROBE_IP   a REAL routable IP toggled in/out of the allow set (default 1.1.1.1)
//   DS_NFTGATE_LIVE_PROBE_HOST a domain with a valid cert for PROBE_IP (default one.one.one.one)
//   DS_NFTGATE_LIVE_NFT_TABLE  the boundary nft table family+name (default "inet ds_filter")
//   DS_NFTGATE_LIVE_ALLOW_SET  the v4 admit set name (default "allow4")
//
// SYNTHETIC-FIXTURE → LIVE-ENDPOINT MAPPING (D50): the fixtures use RFC-5737
// documentation IPs that are not live destinations. The live runner observes the
// same DISPOSITION CLASS using a real routable endpoint whose admission state it
// controls: for the deny fixture it ensures PROBE_IP is NOT admitted and asserts
// the guest connect is DROPPED (no SYN/ACK → connect-timeout); for the allow
// CONTROL it admits PROBE_IP and asserts the connect REACHES (an HTTP status came
// back) — proving the deny is the DEFAULT, not a blanket block (D4).

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

func liveEnvOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// liveBoundary is the operator-provisioned boundary handle the wired runners
// drive. All host-side mutations go through the ds_filter allow set; all guest
// observations go through ssh to the guest on the ds tap.
type liveBoundary struct {
	guestSSH  string // ssh target, e.g. root@10.0.99.2
	sshKey    string // guest ssh key path ("" → ssh default/agent)
	probeIP   string // real routable IP toggled in/out of the allow set
	probeHost string // domain with a valid cert for probeIP (for a real TLS reach)
	nftTable  string // boundary nft table, e.g. "inet ds_filter"
	allowSet  string // v4 admit set, e.g. "allow4"

	// DNS-leg endpoints (operator invariants for the dnsgate-enforced rows):
	allowedName     string // a real ALLOWLISTED name that HAS upstream A + AAAA + HTTPS records (so a stripped/suppressed answer is non-vacuous)
	blockedName     string // a real NON-allowlisted name the foreign resolver WOULD resolve (so ds-dnsgate's REFUSED proves the :53 redirect)
	foreignResolver string // a public resolver IP an in-VM `nameserver` would aim at (must be funneled to ds-dnsgate)
}

func liveBoundaryFromEnv(t *testing.T) liveBoundary {
	t.Helper()
	guest := os.Getenv("DS_NFTGATE_LIVE_GUEST")
	if guest == "" {
		t.Skipf("DS_NFTGATE_LIVE_GUEST unset: the wired live runner needs an operator-provisioned boundary " +
			"(a guest ssh target on the ds tap, with the NFT-1 ds_filter ruleset loaded); set it to e.g. root@10.0.99.2")
	}
	return liveBoundary{
		guestSSH:  guest,
		sshKey:    os.Getenv("DS_NFTGATE_LIVE_SSH_KEY"),
		probeIP:   liveEnvOr("DS_NFTGATE_LIVE_PROBE_IP", "1.1.1.1"),
		probeHost: liveEnvOr("DS_NFTGATE_LIVE_PROBE_HOST", "one.one.one.one"),
		nftTable:  liveEnvOr("DS_NFTGATE_LIVE_NFT_TABLE", "inet ds_filter"),
		allowSet:  liveEnvOr("DS_NFTGATE_LIVE_ALLOW_SET", "allow4"),

		allowedName:     liveEnvOr("DS_NFTGATE_LIVE_ALLOWED_NAME", "api.anthropic.com"),
		blockedName:     liveEnvOr("DS_NFTGATE_LIVE_BLOCKED_NAME", "example.org"),
		foreignResolver: liveEnvOr("DS_NFTGATE_LIVE_FOREIGN_RESOLVER", "8.8.8.8"),
	}
}

// guestSSHCmd runs remoteCmd on the guest and returns its trimmed combined output.
func (b liveBoundary) guestSSHCmd(t *testing.T, remoteCmd string) (string, error) {
	t.Helper()
	args := []string{"-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8"}
	if b.sshKey != "" {
		args = append(args, "-i", b.sshKey)
	}
	args = append(args, b.guestSSH, remoteCmd)
	out, err := exec.Command("ssh", args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// hostNft runs an nft fragment on the HOST (the boundary) under sudo. Used to
// toggle the admission state of probeIP for the deny-vs-allow observation.
func (b liveBoundary) hostNft(t *testing.T, fragment string) error {
	t.Helper()
	cmd := exec.Command("sudo", "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(fragment + "\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft %q: %v: %s", fragment, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (b liveBoundary) admit(t *testing.T, ip string) {
	t.Helper()
	if err := b.hostNft(t, fmt.Sprintf("add element %s %s { %s timeout 900s }", b.nftTable, b.allowSet, ip)); err != nil {
		t.Fatalf("admit %s: %v", ip, err)
	}
}

func (b liveBoundary) unadmit(t *testing.T, ip string) {
	t.Helper()
	// Delete of an absent element aborts the batch; tolerate it (the goal is the
	// post-state: ip is NOT in the set).
	_ = b.hostNft(t, fmt.Sprintf("delete element %s %s { %s }", b.nftTable, b.allowSet, ip))
}

// guestReach probes host (resolved to ip) over HTTPS FROM THE GUEST and reports
// whether the connect REACHED a server. A default-deny DROP yields no SYN/ACK, so
// curl burns the whole connect-timeout and reports http_code 000; a REACH returns
// an HTTP status (or fails TLS fast, well under the timeout). The reach signal is
// therefore: an HTTP status came back (code != 000).
func (b liveBoundary) guestReach(t *testing.T, host, ip string, connectTimeout time.Duration) (reached bool, code string, secs float64) {
	t.Helper()
	to := int(connectTimeout.Seconds())
	// `|| true` so a non-zero curl exit (the drop case) does not fail the ssh; we
	// read the disposition from the -w fields, not the exit code.
	remote := fmt.Sprintf(
		"timeout %d curl -s -o /dev/null -w '%%{http_code} %%{time_total}' --connect-timeout %d --resolve %s:443:%s https://%s/ || true",
		to+4, to, host, ip, host)
	out, err := b.guestSSHCmd(t, remote)
	if err != nil && out == "" {
		t.Fatalf("guest probe ssh failed: %v", err)
	}
	fields := strings.Fields(out)
	if len(fields) >= 2 {
		code = fields[0]
		secs, _ = strconv.ParseFloat(fields[1], 64)
	} else {
		code = "000"
	}
	return code != "000", code, secs
}

// defaultDenyLiveRunner is the wired RowDefaultDeny observation. The L3/4 leg
// (AttemptL34Direct) is fully driven here; the via-proxy leg (AttemptProxiedTLS)
// is honestly skipped until ds-tlsproxy is stood up alongside the NFT-1 boundary.
func defaultDenyLiveRunner(t *testing.T, f Fixture) {
	if f.Kind == AttemptProxiedTLS {
		t.Skipf("RowDefaultDeny via-proxy fixture %q (want %q) needs ds-tlsproxy stood up for TLS-1 (domain,IP) "+
			"admission; the L3/4 NFT-1 leg is wired, the proxy leg is the next stand-up step", f.Attempt.Name, f.Want)
	}
	if f.Kind != AttemptL34Direct {
		t.Fatalf("defaultDenyLiveRunner: unexpected attempt kind %q for %q", f.Kind, f.Attempt.Name)
	}
	b := liveBoundaryFromEnv(t)

	switch f.Want {
	case DispDropL34:
		b.unadmit(t, b.probeIP) // ensure the probe target is NOT admitted
		reached, code, secs := b.guestReach(t, b.probeHost, b.probeIP, 6*time.Second)
		if reached {
			t.Fatalf("default-deny[%s]: guest connect to UNADMITTED %s (%s) REACHED (http=%s t=%.2fs); "+
				"the NFT-1 inet default-drop must drop it", f.Attempt.Name, b.probeIP, b.probeHost, code, secs)
		}
		t.Logf("WIRE OK default-deny[%s]: unadmitted %s (%s) DROPPED (http=%s t=%.2fs ~ connect-timeout), want=%s",
			f.Attempt.Name, b.probeIP, b.probeHost, code, secs, f.Want)
	case DispAllow:
		b.admit(t, b.probeIP)
		defer b.unadmit(t, b.probeIP)
		reached, code, secs := b.guestReach(t, b.probeHost, b.probeIP, 8*time.Second)
		if !reached {
			t.Fatalf("default-deny control[%s]: guest connect to ADMITTED %s (%s) did NOT reach (http=%s t=%.2fs); "+
				"admitted egress must pass — proves the deny is the default, not a blanket block (D4)",
				f.Attempt.Name, b.probeIP, b.probeHost, code, secs)
		}
		t.Logf("WIRE OK default-deny control[%s]: admitted %s (%s) REACHED (http=%s t=%.2fs), want=%s",
			f.Attempt.Name, b.probeIP, b.probeHost, code, secs, f.Want)
	default:
		t.Fatalf("defaultDenyLiveRunner: unexpected want %q for %q", f.Want, f.Attempt.Name)
	}
}
