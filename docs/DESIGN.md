# xdpshield: design decisions

The short list of choices behind the load balancer and DDoS filter. Packet flow, map table, controller and known gaps: [ARCHITECTURE.md](ARCHITECTURE.md). Verifier notes: [VERIFIER.md](VERIFIER.md).

## Scope

One XDP program that drops attack traffic and load balances VIP traffic, plus a Go controller that owns every map. IPv4 only, one-arm.

## Decisions

**The datapath never decides policy.** Thresholds, backend sets, weights and lists all arrive through BPF maps from the controller, so a config change is a map write, not a program reload. The kernel side stays small and has no syscalls, allocations or userspace round trip per packet.

**Detection and enforcement both live in XDP.** The packet that crosses the rate threshold creates the blocklist entry, and the next packet from that source dies after one hash lookup. The controller hears about it afterwards through a ring buffer, so a slow or dead controller can't stall mitigation.

**IPIP encapsulation with direct server return, `XDP_TX` on the same interface.** The balancer only sees client-to-server packets; responses skip it, and that's where most of the bytes are. It never tracks TCP state beyond "which backend did this flow go to". Katran does the same. The cost: backends need a tunnel interface and an MSS clamp, and they must be reachable at L2 from the LB interface.

**Maglev for TCP, weighted round robin for UDP and stateless traffic, and connection tracking on top.** Maglev gives every LB node the same backend for the same flow when they share the backend set and hash seed, so ECMP in front of several LBs works and a restart doesn't reshuffle connections. Connection tracking handles the other case: when the backend set changes, existing flows stay where they are and only new flows use the new table. WRR is for when you want exact proportions and don't need stickiness (cursors are per CPU, so short runs are only approximately proportional).

**Tables are built in userspace and swapped atomically.** The datapath does one array lookup. Weights, health and minimal-disruption logic live in Go, where they're unit tested (`internal/maglev`). Each VIP has its own inner map in an `ARRAY_OF_MAPS`; an update builds and fills a new inner map and replaces the outer slot with one syscall, so a packet sees the old table or the new one, never a half-written one.

**Every map the datapath grows is an LRU.** Under attack, old entries get evicted instead of inserts failing.

**Don't trust the packet.** Every read is bounds-checked against `data_end`, and pointers are reloaded after `bpf_xdp_adjust_head`. The one verifier rejection on the first run against a real 6.6 kernel was an unbounded `tot_len` after the byte swap; it's fixed with an `asm volatile` mask because clang folds a plain C mask away (details in VERIFIER.md).

**Source IPs are not metric labels.** During an attack that would be unbounded cardinality. They go to the log and an in-memory list of the last 256 events instead.

**If every backend of a VIP fails its health checks, the table is built from all of them.** Dropping everything is worse than trying.

## How it's checked

Unit tests for Maglev, config, the controller (against a fake dataplane), health and metrics. An integration suite loads the real program and runs crafted packets through `BPF_PROG_TEST_RUN`: encapsulation headers and checksum, flow stickiness, Maglev spread, WRR ratio, flood blocking and unblocking, allow/deny lists, bad TCP flags, malformed frames, fragments, MTU drops and the ICMP frag-needed reply. A network-namespace lab (`test/lab.sh`) ran on a 6.6 kernel (WSL2) in generic XDP mode.

## What hasn't been tried

Native XDP on a real NIC, and kernels other than 6.6. The numbers in BENCHMARKS.md are program cost only, not NIC throughput.

## Known gaps

IPv4 only. No SYN cookies, so per-source rate limits do nothing against a spoofed-source flood spread over millions of addresses; pair with upstream scrubbing. Rate windows are fixed 1 s and roll over without a lock, so counts can be off by a few packets at the boundary. VLAN-tagged frames are passed to the host.
