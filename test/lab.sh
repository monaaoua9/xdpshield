#!/usr/bin/env bash
# One-arm lab on a single linux box: client, lb and two backends in netns, joined by a bridge.
#   sudo test/lab.sh up      build the lab and start xdpshield in the background
#   sudo test/lab.sh test    curl the vip over v4 and v6 from the client, then fire a syn flood
#   sudo test/lab.sh restart restart the daemon (pin_path) and check counters and traffic survive
#   sudo test/lab.sh down
set -euo pipefail

BR=br-lab
SUBNET=10.77.0
VIP=10.77.0.100
SUBNET6=fd77
VIP6=$SUBNET6::100
BIN=${BIN:-bin/xdpshield}
CFG=/tmp/xdpshield-lab.yaml
# not under /sys: "ip netns exec" mounts a fresh sysfs, which hides a bpffs mounted there
BPFFS=/tmp/lab-bpf
PIN=$BPFFS/xdpshield

mac() { ip netns exec "$1" cat /sys/class/net/"$2"/address; }

start() {
  XDPSHIELD_TOKEN=lab ip netns exec lb nohup $BIN -config $CFG >>/tmp/xdpshield-lab.log 2>&1 &
  sleep 1
}

up() {
  mkdir -p $BPFFS && { mountpoint -q $BPFFS || mount -t bpf bpf $BPFFS; }
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
  # nodad: no waiting for duplicate address detection before the first packet
  ip netns exec client ip -6 addr add $SUBNET6::1/64 dev eth0 nodad
  ip netns exec lb     ip -6 addr add $SUBNET6::10/64 dev eth0 nodad
  ip netns exec be1    ip -6 addr add $SUBNET6::21/64 dev eth0 nodad
  ip netns exec be2    ip -6 addr add $SUBNET6::22/64 dev eth0 nodad
  ip netns exec client ip route add $VIP dev eth0
  # the vip lives on the lb mac from the client's point of view
  ip netns exec client ip neigh add $VIP lladdr "$(mac lb eth0)" dev eth0 nud permanent
  ip netns exec client ip -6 neigh add $VIP6 lladdr "$(mac lb eth0)" dev eth0 nud permanent

  for n in be1 be2; do
    ip netns exec $n bash deploy/backend-setup.sh $VIP $VIP6 >/dev/null
    # netns don't isolate the filesystem, so each backend serves its own dir
    mkdir -p /tmp/lab-$n && echo backend-$n > /tmp/lab-$n/index.html
    ip netns exec $n sh -c "cd /tmp/lab-$n && nohup python3 -m http.server 80 --bind :: >/dev/null 2>&1 &"
  done

  cat > $CFG <<EOF
interface: eth0
xdp_mode: generic
listen: 127.0.0.1:9100
pin_path: $PIN
state_file: /tmp/lab-state.json
admin_token_env: XDPSHIELD_TOKEN
encap_src: $SUBNET.10
ddos: {enabled: true, syn_limit_pps: 50, udp_limit_pps: 500, block_ttl: 30s}
health: {enabled: true}
backends:
  - {name: be1, address: $SUBNET.21, mac: "$(mac be1 eth0)"}
  - {name: be2, address: $SUBNET.22, mac: "$(mac be2 eth0)"}
vips:
  - {name: web, address: $VIP, port: 80, backends: [{name: be1}, {name: be2}]}
  - {name: web6, address: "$VIP6", port: 80, backends: [{name: be1}, {name: be2}]}
EOF
  : > /tmp/xdpshield-lab.log
  start
  echo "lab up, log in /tmp/xdpshield-lab.log"
}

test_() {
  echo "--- 40 requests through the vip"
  got=$(for i in $(seq 40); do ip netns exec client curl -s --max-time 2 --local-port $((40000+i)) http://$VIP/ || true; done | sort | uniq -c)
  echo "$got"
  # both backends must have answered, and nothing should have timed out
  [ "$(echo "$got" | grep -c backend-)" = 2 ] || { echo "FAIL: traffic did not reach both backends"; return 1; }
  [ "$(echo "$got" | awk '{s+=$1} END {print s}')" = 40 ] || { echo "FAIL: lost requests"; return 1; }

  echo "--- 40 requests through the v6 vip (6in4 to the v4 backends)"
  got6=$(for i in $(seq 40); do ip netns exec client curl -s -g --max-time 2 --local-port $((41000+i)) "http://[$VIP6]/" || true; done | sort | uniq -c)
  echo "$got6"
  [ "$(echo "$got6" | grep -c backend-)" = 2 ] || { echo "FAIL: v6 traffic did not reach both backends"; return 1; }
  [ "$(echo "$got6" | awk '{s+=$1} END {print s}')" = 40 ] || { echo "FAIL: lost v6 requests"; return 1; }

  echo "--- syn flood from the client (needs hping3)"
  if command -v hping3 >/dev/null; then
    ip netns exec client hping3 -S -p 80 --faster -c 2000 $VIP >/dev/null 2>&1 || true
    ip netns exec lb curl -s localhost:9100/api/v1/blocklist | grep -q 10.77.0.1 || { echo "FAIL: flooder not blocked"; return 1; }
  fi
  ip netns exec lb curl -s localhost:9100/api/v1/blocklist; echo
  ip netns exec lb curl -s localhost:9100/metrics | grep -E 'xdpshield_(dropped|forwarded|sources)' | grep -v ' 0$'
}

counter() { ip netns exec lb curl -s localhost:9100/metrics | awk -v m="$1" '$1 == m {print int($2)}'; }

restart() {
  # the flood in 'test' left the client on the blocklist
  ip netns exec lb curl -s -X DELETE -H "Authorization: Bearer lab" localhost:9100/api/v1/blocklist/$SUBNET.1 >/dev/null
  before=$(counter xdpshield_conntrack_new_flows_total)
  echo "--- conntrack new flows before restart: $before"
  [ "${before:-0}" -gt 0 ] || { echo "FAIL: run 'test' first"; return 1; }

  pkill -TERM -f "xdpshield -config $CFG" || { echo "FAIL: daemon is not running"; return 1; }
  sleep 1
  # the daemon is gone but the program stays attached to eth0 and keeps forwarding from its pinned maps
  ip netns exec client curl -s --max-time 2 http://$VIP/ | grep -q backend- || { echo "FAIL: traffic stopped while the daemon was down"; return 1; }
  start

  after=$(counter xdpshield_conntrack_new_flows_total)
  echo "--- after restart: $after"
  [ "$after" -ge "$before" ] || { echo "FAIL: counters reset, maps were not reused"; return 1; }
  ip netns exec client curl -s --max-time 2 http://$VIP/ | grep -q backend- || { echo "FAIL: no traffic after restart"; return 1; }
  ip netns exec client curl -s -g --max-time 2 "http://[$VIP6]/" | grep -q backend- || { echo "FAIL: no v6 traffic after restart"; return 1; }
  grep -q 'pinned run' /tmp/xdpshield-lab.log && grep 'pinned run' /tmp/xdpshield-lab.log | tail -1
  echo "restart ok"
}

down() {
  pkill -f "xdpshield -config $CFG" || true
  ip netns exec lb $BIN -config $CFG -unpin 2>/dev/null || true
  rm -f /tmp/lab-state.json
  for n in client lb be1 be2; do ip netns pids $n 2>/dev/null | xargs -r kill || true; ip netns del $n 2>/dev/null || true; done
  ip link del $BR 2>/dev/null || true
  mountpoint -q $BPFFS && umount $BPFFS || true
}

case "${1:-}" in
  up) up ;;
  test) test_ ;;
  restart) restart ;;
  down) down ;;
  *) echo "usage: $0 up|test|restart|down"; exit 1 ;;
esac
