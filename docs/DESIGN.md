# xdpshield: design decisions

The short list of choices behind the load balancer and DDoS filter. Packet flow, map table, controller and known gaps: [ARCHITECTURE.md](ARCHITECTURE.md). Verifier notes: [VERIFIER.md](VERIFIER.md).

## Scope

One XDP program that drops attack traffic and load balances VIP traffic, plus a Go controller that owns every map. IPv4 and IPv6, one-arm.

## Decisions

**The datapath never decides policy.** Thresholds, backend sets, weights and lists all arrive through BPF maps from the controller, so a config change is a map write, not a program reload. The kernel side stays small and has no syscalls, allocations or userspace round trip per packet.

**Detection and enforcement both live in XDP.** The packet that crosses the rate threshold creates the blocklist entry, and the next packet from that source dies after one hash lookup. The controller hears about it afterwards through a ring buffer, so a slow or dead controller can't stall mitigation.

**IP-in-IP encapsulation with direct server return, `XDP_TX` on the same interface.** The balancer only sees client-to-server packets; responses skip it, and that's where most of the bytes are. It never tracks TCP state beyond "which backend did this flow go to". Katran does the same. The outer header follows the backend, not the client: IPIP, 6in4, IPIP6 or IP6IP6 depending on the family pair, so a v6 VIP can sit in front of v4 backends and the other way round. The cost: backends need a tunnel interface and an MSS clamp, and they must be reachable at L2 from the LB interface.

**Maglev for TCP, weighted round robin for UDP and stateless traffic, and connection tracking on top.** Maglev gives every LB node the same backend for the same flow when they share the backend set and hash seed, so ECMP in front of several LBs works and a restart doesn't reshuffle connections. Connection tracking handles the other case: when the backend set changes, existing flows stay where they are and only new flows use the new table. WRR is for when you want exact proportions and don't need stickiness (cursors are per CPU, so short runs are only approximately proportional).

**Tables are built in userspace and swapped atomically.** The datapath does one array lookup. Weights, health and minimal-disruption logic live in Go, where they're unit tested (`internal/maglev`). Each VIP has its own inner map in an `ARRAY_OF_MAPS`; an update builds and fills a new inner map and replaces the outer slot with one syscall, so a packet sees the old table or the new one, never a half-written one.

**Every map the datapath grows is an LRU.** Under attack, old entries get evicted instead of inserts failing.

**Rate limits are a GCRA token bucket, one timestamp per source and protocol.** Rate is the limit, burst is one second of it. It replaced fixed one second windows, which let a burst through at every boundary and needed a counter plus a window start. Updates are not locked, so two CPUs racing on one source can admit a few extra packets.

**State survives a daemon restart when `pin_path` is set.** Maps and the XDP link are pinned on bpffs and the new process swaps its program into the live link, so the datapath keeps forwarding while the daemon is down. Conntrack holds backend ids, so the controller saves name to id mappings in a state file outside bpffs and restores them before the first apply. A changed map layout is refused with a pointer to `-unpin`.

**Cheap checks skip work they can't need.** The clock is read once per packet and only after the early drops, and the allow/deny trie lookups are skipped while those lists are empty (the controller sets flags in the config map). Both were measured, see BENCHMARKS.md.

**Optional strictness is opt-in.** `drop_orphan_tcp` drops non-SYN TCP with no tracked flow. It stops ACK/RST floods at the price of dropping flows that land on a node that never saw their SYN, so it is off by default and documented as a failover trade-off.

**Don't trust the packet.** Every read is bounds-checked against `data_end`, and pointers are reloaded after `bpf_xdp_adjust_head`. The one verifier rejection on the first run against a real 6.6 kernel was an unbounded `tot_len` after the byte swap; it's fixed with an `asm volatile` mask because clang folds a plain C mask away (details in VERIFIER.md).

**Source IPs are not metric labels.** During an attack that would be unbounded cardinality. They go to the log and an in-memory list of the last 256 events instead.

**If every backend of a VIP fails its health checks, the table is built from all of them.** Dropping everything is worse than trying.

## How it's checked

Unit tests for Maglev, config, the controller (against a fake dataplane), health, metrics, admin and the CLI. An integration suite loads the real program and runs crafted packets through `BPF_PROG_TEST_RUN`: encapsulation headers and checksum for all four tunnel types, flow stickiness, Maglev spread, WRR ratio, flood blocking and unblocking, allow/deny lists, amplification, draining, pinning, strict TCP, bad TCP flags, malformed frames, fragments, MTU drops and the ICMP and ICMPv6 replies, plus a fuzz target that feeds random frames to the program. A network-namespace lab (`test/lab.sh`) covers a dual-stack setup end to end, a live reload and a daemon restart. The systemd unit and the keepalived example were run on the same 6.6 kernel (WSL2), and native XDP attach and detach on a veth pair; CI runs the integration suite on a second kernel (Ubuntu runner).

## What hasn't been tried

Native XDP on a real NIC driver and its throughput, and kernels other than 6.6 and the CI runner's. `test/hw-check.sh <iface>` does the preflight and a native attach on a real box. The numbers in BENCHMARKS.md are program cost only, taken on a noisy laptop, not NIC throughput.

## Known gaps

No SYN cookies, so per-source rate limits do nothing against a spoofed-source flood spread over millions of addresses; pair with upstream scrubbing (and DSR means a validated ACK would reach a backend that has no connection, which is why a cookie proxy isn't here). IPv6 extension headers are not walked: only the fragment header is recognised. Rate state updates are not locked, so counts can be off by a few packets under contention. VLAN-tagged frames are passed to the host.
