#!/usr/bin/env bash
# One-arm lab on a single linux box: client, lb and two backends in netns, joined by a bridge.
#   sudo test/lab.sh up      build the lab and start xdpshield in the background
#   sudo test/lab.sh test    curl the vip from the client, then fire a syn flood
#   sudo test/lab.sh down
set -euo pipefail

BR=br-lab
SUBNET=10.77.0
VIP=10.77.0.100
BIN=${BIN:-bin/xdpshield}
CFG=/tmp/xdpshield-lab.yaml

mac() { ip netns exec "$1" cat /sys/class/net/"$2"/address; }

up() {
  ip link add $BR type bridge && ip link set $BR up && ip addr add $SUBNET.254/24 dev $BR
  for n in client lb be1 be2; do
    ip netns add $n
    ip link add v-$n type veth peer name eth0 netns $n
    ip link set v-$n master $BR up
    ip netns exec $n ip link set lo up
    ip netns exec $n ip link set eth0 up
  done
  ip netns exec client ip addr add $SUBNET.1/24 dev eth0
  ip netns exec lb     ip addr add $SUBNET.10/24 dev eth0
  ip netns exec be1    ip addr add $SUBNET.21/24 dev eth0
  ip netns exec be2    ip addr add $SUBNET.22/24 dev eth0
  ip netns exec client ip route add $VIP dev eth0
  # the vip lives on the lb mac from the client's point of view
  ip netns exec client ip neigh add $VIP lladdr "$(mac lb eth0)" dev eth0 nud permanent

  for n in be1 be2; do
    ip netns exec $n bash deploy/backend-setup.sh $VIP >/dev/null
    ip netns exec $n sh -c "echo backend-$n > /tmp/$n.txt; cd /tmp && nohup python3 -m http.server 80 >/dev/null 2>&1 &"
  done

  cat > $CFG <<EOF
interface: eth0
xdp_mode: generic
listen: 127.0.0.1:9100
admin_token_env: XDPSHIELD_TOKEN
encap_src: $SUBNET.10
ddos: {enabled: true, syn_limit_pps: 50, udp_limit_pps: 500, block_ttl: 30s}
health: {enabled: true}
backends:
  - {name: be1, address: $SUBNET.21, mac: "$(mac be1 eth0)"}
  - {name: be2, address: $SUBNET.22, mac: "$(mac be2 eth0)"}
vips:
  - {name: web, address: $VIP, port: 80, backends: [{name: be1}, {name: be2}]}
EOF
  XDPSHIELD_TOKEN=lab ip netns exec lb nohup $BIN -config $CFG >/tmp/xdpshield-lab.log 2>&1 &
  sleep 1
  echo "lab up, log in /tmp/xdpshield-lab.log"
}

test_() {
  echo "--- 20 requests through the vip"
  for i in $(seq 20); do ip netns exec client curl -s --max-time 2 --local-port $((40000+i)) http://$VIP/ || true; done | sort | uniq -c
  echo "--- syn flood from the client (needs hping3)"
  if command -v hping3 >/dev/null; then
    ip netns exec client hping3 -S -p 80 --faster -c 2000 $VIP >/dev/null 2>&1 || true
  fi
  curl -s localhost:9100/api/v1/blocklist; echo
  curl -s localhost:9100/metrics | grep -E 'xdpshield_(dropped|forwarded|sources)' | grep -v ' 0$'
}

down() {
  pkill -f "xdpshield -config $CFG" || true
  for n in client lb be1 be2; do ip netns pids $n 2>/dev/null | xargs -r kill || true; ip netns del $n 2>/dev/null || true; done
  ip link del $BR 2>/dev/null || true
}

case "${1:-}" in
  up) up ;;
  test) test_ ;;
  down) down ;;
  *) echo "usage: $0 up|test|down"; exit 1 ;;
esac
