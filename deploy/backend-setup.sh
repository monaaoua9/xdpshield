#!/usr/bin/env bash
# run on every backend: decapsulate ipip from the lb and answer clients directly (DSR)
set -euo pipefail

VIP=${1:?usage: backend-setup.sh <vip-address>}

modprobe ipip
ip link set tunl0 up
ip addr add "$VIP/32" dev tunl0 2>/dev/null || true

# the reply leaves with src=VIP on the normal interface, so rp_filter on tunl0 has to be off
sysctl -w net.ipv4.conf.tunl0.rp_filter=0
sysctl -w net.ipv4.conf.all.rp_filter=0
sysctl -w net.ipv4.conf.tunl0.accept_local=1 2>/dev/null || true

# the tunnel eats 20 bytes: clamp mss so clients don't send packets we can't forward
iptables -t mangle -C OUTPUT -p tcp --sport 443 --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1440 2>/dev/null \
  || iptables -t mangle -A OUTPUT -p tcp --sport 443 --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1440
echo "backend ready for $VIP"
