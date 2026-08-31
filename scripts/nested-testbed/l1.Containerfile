# SPDX-License-Identifier: Apache-2.0
# l1.Containerfile — rootless bake of the "L1" outer-VM rootfs for the nested-VM
# NFTables testbed. L1 is the DEVICE UNDER TEST host: it runs the real appliance
# nft floor (input policy DROP) + the egress gateways (ds-dnsgate/ds-tlsproxy) +
# a NESTED KVM "L2" agent VM whose egress is forced through L1's floor. Breaking
# L1's networking is harmless (just reboot the VM) — the HOST is never touched.
#
# Built the SAME proven rootless way as the M0 image (podman -> mke2fs -d ->
# direct-kernel qemu), but "fat": adds qemu-system-x86 + nftables + ssh so L1 can
# nest L2 and be driven over ssh. It does NOT bake CC / ds-entrypoint — L1 is the
# HOST of the inner VM, not the agent. The dataplane binaries + the L2 image +
# the inside-L1 scripts are MOUNTED at runtime via 9p (/opt/ds), so iterating on
# them never requires a rebake.
FROM debian:bookworm

# --- egress: optional mitmproxy CA + proxy ------------------------------------
# On a host whose outbound HTTPS is TLS-intercepted on :18080, build-l1-image.sh
# passes the CA (as egress-ca.crt) + proxy ARGs. On a direct-internet host (CI runner)
# egress-ca.crt is empty and the proxy ARGs are unset — apt goes direct.
COPY egress-ca.crt /tmp/egress-ca.crt
ARG http_proxy=
ARG https_proxy=
ARG HTTP_PROXY=
ARG HTTPS_PROXY=
ENV DEBIAN_FRONTEND=noninteractive

# --- base userland + nested-virt + gateway tooling -----------------------------
#   systemd-sysv          -> /sbin/init = systemd (PID 1)
#   linux-image-amd64     -> the Debian generic kernel (carries kvm_amd + vhost_vsock)
#   qemu-system-x86/-utils-> boot + image-manage the nested L2 VM
#   libvirt-daemon-system -> libvirtd + the qemu:///system socket, so the host-agent
#                            Booter (orchestrator/internal/hypervisor/libvirt/live.go,
#                            DS_HOSTAGENT_LIVE) can `virsh create` the nested L2 VM
#   libvirt-clients       -> the virsh CLI the Booter shells out to (define/start/domuuid)
#   nftables iproute2     -> apply the floor + program the routed tap + allow-sets
#   openssh-server        -> drive L1 over ssh (hostfwd 2222->22)
#   dnsutils/curl/nc      -> in-L1 egress validation (dig / curl / nc the gate)
RUN set -eux; \
    if [ -s /tmp/egress-ca.crt ]; then \
      mkdir -p /usr/local/share/ca-certificates; \
      cp /tmp/egress-ca.crt /usr/local/share/ca-certificates/ds-egress-gateway.crt; fi; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      systemd-sysv ca-certificates curl gnupg \
      linux-image-amd64 \
      iproute2 iptables nftables kmod udev \
      qemu-system-x86 qemu-utils seabios \
      libvirt-daemon-system libvirt-clients \
      genisoimage \
      openssh-server \
      sudo libcap2-bin \
      jq procps less tcpdump dnsutils netcat-openbsd iputils-ping socat; \
    update-ca-certificates; \
    rm -f /tmp/egress-ca.crt; \
    apt-get clean; rm -rf /var/lib/apt/lists/*

# --- nested-virt + vsock + tun module autoload (L2 needs these inside L1) -------
RUN printf 'kvm\nkvm_amd\nvhost_vsock\ntun\n' > /etc/modules-load.d/ds-nested.conf

# --- libvirt: bring libvirtd + the qemu:///system socket up at L1 boot ----------
# The host-agent Booter (orchestrator/internal/hypervisor/libvirt/live.go, behind
# DS_HOSTAGENT_LIVE) drives the nested L2 session VM by shelling out to `virsh
# create`/`domuuid` against qemu:///system. L1 runs as root (direct-kernel boot,
# serial autologin), so qemu:///system is the right scope — no per-user session
# bus needed. Enable the service so libvirtd + its sockets are listening the moment
# L1 reaches multi-user; the .socket units are pulled in transitively. ContainerEnv
# can't run the postinst's systemd-machinery, so we enable here exactly like the
# ssh/networkd services below (systemctl enable just creates the wants symlinks,
# which the baked rootfs carries into the booted VM).
RUN set -eux; \
    systemctl enable libvirtd.service; \
    systemctl enable libvirtd.socket libvirtd-ro.socket virtlogd.socket

# --- L1 uplink: DHCP the SLIRP NIC via systemd-networkd --------------------------
# Without this the NIC has no IP, so the host's hostfwd (2222->:22) can't reach
# sshd (the "banner exchange timeout" symptom) and L1 has no outbound. SLIRP hands
# out 10.0.2.15 + gateway 10.0.2.2 + DNS 10.0.2.3 (the latter is fixed in qemu user
# networking, so resolv.conf is static — avoids pulling systemd-resolved).
RUN set -eux; \
    printf '[Match]\nName=en*\n\n[Network]\nDHCP=yes\n' > /etc/systemd/network/10-uplink.network; \
    systemctl enable systemd-networkd.service; \
    printf 'nameserver 10.0.2.3\n' > /etc/resolv.conf

# --- L2-flavor routed-tap static config (testbed IDX=7) -------------------------
# When THIS image is reused as the nested L2 guest, its NIC gets a fixed MAC
# (52:54:00:77:07:01, set by l2-up.sh / the orchestrator live.go macForIndex) and must
# come up STATIC on the /31 routed tap (no DHCP server there). Match by MAC so it
# applies ONLY to L2 — L1's own NIC has a different MAC and still falls through to the
# en* DHCP above. The 5th octet is the session index in TWO HEX DIGITS (see l2-up.sh /
# live.go macForIndex, hex over the full 0..255 range); this drop-in is pinned to the
# demo IDX=7, whose hex "07" equals its decimal "07" — byte-stable across the hex
# render, so no rebake. A different pinned index would use its hex octet here.
# Filename sorts BEFORE 10-uplink on purpose: networkd uses the first matching .network
# in lexical order, and with net.ifnames=0 the NIC keeps a predictable ALT-name (enp0s3)
# that `Name=en*` would otherwise match first — so the MAC rule must be evaluated first.
RUN printf '[Match]\nMACAddress=52:54:00:77:07:01\n\n[Network]\nAddress=10.77.7.1/31\nGateway=10.77.7.0\n' \
      > /etc/systemd/network/05-l2-routedtap.network

# --- ssh: key-only root login for the operator (LOCAL testbed only) -------------
# Host keys are generated at BAKE time (the container postinst can't), and UseDNS
# is OFF — over SLIRP the client appears as 10.0.2.2 and sshd's reverse-DNS lookup
# stalls the banner exchange for tens of seconds (the "Connection timed out during
# banner exchange" symptom). GSSAPI off for the same reason.
COPY authorized_keys /root/.ssh/authorized_keys
COPY id_ed25519 /root/.ssh/id_ed25519
RUN set -eux; \
    chmod 700 /root/.ssh; chmod 600 /root/.ssh/authorized_keys /root/.ssh/id_ed25519; \
    mkdir -p /etc/ssh/sshd_config.d; \
    printf 'PermitRootLogin prohibit-password\nUseDNS no\nGSSAPIAuthentication no\n' \
      > /etc/ssh/sshd_config.d/ds-testbed.conf; \
    ssh-keygen -A; \
    systemctl enable ssh.service

# --- serial console: root autologin (lifeline if ssh/networking breaks) ---------
RUN set -eux; \
    mkdir -p /etc/systemd/system/serial-getty@ttyS0.service.d; \
    printf '[Service]\nExecStart=\nExecStart=-/sbin/agetty --autologin root --keep-baud 115200,57600,38400,9600 %%I $TERM\n' \
      > /etc/systemd/system/serial-getty@ttyS0.service.d/autologin.conf; \
    systemctl enable serial-getty@ttyS0.service

# --- ds-agent: the non-root exec-authn identity the host-agent runs as ----------
# D148 ROOT-HELPER model: the ds-host-agent runs UNPRIVILEGED and forks the setcap'd
# ds-nethelper for every privileged tap/nft op. The helper's trust boundary REJECTS a
# root caller (owner_uid must be nonzero AND == the invoking uid — nethelperseams.go /
# ValidateCreateTap), so L1 must run the agent as a non-root uid, mirroring the live
# host stack. The `libvirt` supplementary group is LOAD-BEARING: the agent's live.go
# Booter shells `virsh -c qemu:///system create`, which needs libvirt-group membership
# to reach the system socket; `kvm` is defensive (direct /dev/kvm access if ever needed).
# The helper is installed root:ds-agent 0750 (orchestrator-boot-l2.sh install_nethelper,
# DS_NETHELPER_GROUP=ds-agent), so ONLY this identity may exec it.
RUN set -eux; \
    groupadd --system ds-agent; \
    useradd --system --gid ds-agent --groups libvirt,kvm \
      --home-dir /home/ds --create-home --shell /usr/sbin/nologin ds-agent

# --- 9p mountpoint for the host-shared artifacts (binaries + L2 image + scripts) -
RUN set -eux; \
    mkdir -p /opt/ds /var/lib/ds/overlays; \
    [ -e /sbin/init ] || ln -s /lib/systemd/systemd /sbin/init

# Direct-kernel boot passes root=LABEL=DS_L1ROOT; the 9p share auto-mounts at /opt/ds.
RUN printf 'LABEL=DS_L1ROOT / ext4 defaults 0 1\nds9p /opt/ds 9p trans=virtio,version=9p2000.L,nofail,msize=262144 0 0\n' > /etc/fstab
