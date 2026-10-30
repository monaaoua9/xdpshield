#!/usr/bin/env bash
# run on every backend: decapsulate ipip (and 6in4 for v6 vips) from the lb and answer clients directly (DSR)
set -euo pipefail

VIP=${1:?usage: backend-setup.sh <vip-address> [<vip6-address>]}
VIP6=${2:-}
# set TUNNEL6=1 when this backend has an ipv6 address in the lb config (ipip6 / ip6ip6 from the lb)
TUNNEL6=${TUNNEL6:-}

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

if [ -n "$VIP6" ]; then
  # v6 clients arrive as proto 41 inside ipv4, sit0 is the catch-all decap device
  modprobe sit
  ip link set sit0 up
  ip -6 addr add "$VIP6/128" dev sit0 2>/dev/null || true
  sysctl -w net.ipv4.conf.sit0.rp_filter=0
  # 20 outer + 40 ip6 + 20 tcp off a 1500 link
  ip6tables -t mangle -C OUTPUT -p tcp --sport 443 --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1420 2>/dev/null     || ip6tables -t mangle -A OUTPUT -p tcp --sport 443 --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1420
fi

if [ -n "$TUNNEL6" ]; then
  # ip6tnl0 is the catch-all decap device for ipv4/ipv6 inside ipv6
  modprobe ip6_tunnel
  ip link set ip6tnl0 up
  ip addr add "$VIP/32" dev ip6tnl0 2>/dev/null || true
  [ -n "$VIP6" ] && { ip -6 addr add "$VIP6/128" dev ip6tnl0 2>/dev/null || true; }
  sysctl -w net.ipv4.conf.ip6tnl0.rp_filter=0
  # 40 outer + 20 or 40 inner + 20 tcp off a 1500 link
  ip6tables -t mangle -C OUTPUT -p tcp --sport 443 --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1400 2>/dev/null     || ip6tables -t mangle -A OUTPUT -p tcp --sport 443 --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1400
fi
echo "backend ready for $VIP $VIP6"
