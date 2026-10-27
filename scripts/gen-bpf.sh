#!/usr/bin/env bash
# regenerates internal/dataplane/shield_bpfel.{go,o}. needs clang (or set BPF2GO_CC), llvm-strip, libbpf headers.
set -euo pipefail
cd "$(dirname "$0")/../internal/dataplane"
export GOPACKAGE=dataplane
# debian/ubuntu keep asm/ under the multiarch dir
arch_inc=/usr/include/$(uname -m)-linux-gnu
[ -d "$arch_inc" ] && extra="-I$arch_inc" || extra=
go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel \
  -type global_cfg -type vip_key -type vip_val -type backend -type block_val \
  -type block_event -type traffic_stat -type lpm_key -type lpm_val -type flow_key -type flow_val -type rate_val \
  Shield ../../bpf/xdp_shield.c -- -O2 -g -Wall -Werror -I../../bpf $extra
