#!/usr/bin/env bash
# run as root on the box you want to deploy on: test/hw-check.sh eth0
# prints what matters for xdpshield and tries a native attach/detach on the nic
iface=${1:?usage: hw-check.sh <iface>}
bin=${BIN:-bin/xdpshield}
ok() { printf 'ok    %s\n' "$*"; }
bad() { printf 'FAIL  %s\n' "$*"; rc=1; }
rc=0

echo "kernel $(uname -r)"
maj=$(uname -r | cut -d. -f1); min=$(uname -r | cut -d. -f2)
if [ "$maj" -gt 5 ] || { [ "$maj" -eq 5 ] && [ "$min" -ge 9 ]; }; then ok "kernel >= 5.9 (ring buffer, link update)"; else bad "kernel < 5.9"; fi

[ "$(id -u)" = 0 ] && ok root || bad "not root"
mount | grep -q 'type bpf' && ok "bpffs mounted" || bad "bpffs not mounted (mount -t bpf bpf /sys/fs/bpf)"

echo "--- nic"
if command -v ethtool >/dev/null; then
  ethtool -i "$iface" | grep -E 'driver|version'
  ethtool -l "$iface" 2>/dev/null | sed -n '/Current/,$p'
  ethtool -k "$iface" | grep -E 'generic-receive-offload|large-receive-offload'
else
  echo "(no ethtool)"
fi
echo "mtu $(cat /sys/class/net/$iface/mtu)  (backends need mtu >= this + 20, or 40 with v6 backends)"

echo "--- config"
if [ -n "${CFG:-}" ]; then
  "$bin" -check -config "$CFG" && ok "config parses" || bad "config rejected"
else
  echo "(set CFG=/path/to/config.yaml to validate it too)"
fi

echo "--- native attach"
# a throwaway xdp_pass-less attach through the real program: needs a config with this iface
if [ -n "${CFG:-}" ]; then
  tmp=$(mktemp -d)
  sed -e "s/^interface:.*/interface: $iface/" -e "s/^xdp_mode:.*/xdp_mode: native/" -e '/^pin_path:/d' -e '/^state_file:/d' -e 's/^listen:.*/listen: 127.0.0.1:19100/' "$CFG" > "$tmp/c.yaml"
  "$bin" -config "$tmp/c.yaml" >"$tmp/log" 2>&1 &
  pid=$!
  sleep 3
  if kill -0 $pid 2>/dev/null && ip -d link show "$iface" | grep -q 'prog/xdp'; then
    ok "native xdp attached on $iface"
    ip -d link show "$iface" | grep -E 'xdp|prog'
    curl -s localhost:19100/healthz | grep -q ok && ok "admin api answers"
  else
    bad "native attach failed:"; tail -5 "$tmp/log"
  fi
  kill $pid 2>/dev/null; wait $pid 2>/dev/null
  ip -d link show "$iface" | grep -q 'prog/xdp' && bad "program still attached after exit" || ok "detached on exit"
  rm -rf "$tmp"
fi

echo "--- systemd"
if [ -f deploy/xdpshield.service ] && command -v systemd-analyze >/dev/null; then
  systemd-analyze verify deploy/xdpshield.service 2>&1 | grep -v 'Command .* is not executable' || true
fi

exit $rc
