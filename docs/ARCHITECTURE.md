# Architecture

xdpshield is two programs that share a set of BPF maps:

- **datapath** (`bpf/`, C): one XDP program on the NIC. Drops attack traffic and load balances VIP traffic. No syscalls, no allocations, no userspace round trip per packet.
- **controller** (`cmd/`, `internal/`, Go): loads the program, owns every map, reacts to config changes and health checks, and exports metrics.

The datapath never decides policy. Thresholds, backend sets, weights and lists all come from the controller through maps, so a config change is a map write, not a reload of the program.

## Packet flow

```
 client ──► NIC rx ring
              │   (driver hands the raw frame to XDP before an skb exists)
              ▼
        ┌─────────────────────────── xdp_shield ───────────────────────────┐
        │ 1 parse eth + ipv4 (bounds checked), sanity: version, ihl, tot_len │
        │     martian source (0/8, 127/8, 224/4, 255.255.255.255) ─► DROP    │
        │     ipv6: same steps 2-7 on its own maps (v6 suffix)               │
        │     not ip (arp, vlan) ─────────────────────────────────► PASS    │
        │                                                                    │
        │ 2 dyn_blocklist[src]  hit and not expired ──────────────► DROP     │
        │   deny_cidr (LPM)     hit ──────────────────────────────► DROP     │
        │                                                                    │
        │ 3 fragment?  dst is a vip address ─► DROP, otherwise ───► PASS     │
        │   parse tcp/udp header (bad doff, port 0)  ─────────────► DROP     │
        │   vip_map[dst ip, dst port, proto] miss ─ host traffic ─► PASS     │
        │                                                                    │
        │ 4 ddos (vip traffic only, skipped for allow_cidr sources)          │
        │     bad tcp flags (null, xmas, syn+fin, syn+rst, fin w/o ack) DROP │
        │     syn  : rate_state[src].syn > limit ─► blocklist + event  DROP  │
        │     udp  : rate_state[src].udp > limit ─► blocklist + event  DROP  │
        │                                                                    │
        │ 5 mtu: tot_len + 20 > max_ip_len  DF ─► icmp frag needed ─► TX     │
        │                                  no DF ─► DROP                    │
        │                                                                    │
        │ 6 backend selection                                                │
        │     conn_track[5-tuple] hit and backend active ─► use it           │
        │     else maglev: table[jhash(5-tuple) % M]  or  wrr: table[cursor++]│
        │          └─ lb_tables[vip_id] (array of maps, swapped atomically)  │
        │          └─ remember the choice in conn_track                      │
        │                                                                    │
        │ 7 bpf_xdp_adjust_head(-20), write eth + outer ipv4 (ipip, DF),     │
        │   recompute header checksum ─────────────────────────────► XDP_TX │
        └────────────────────────────────────────────────────────────────────┘
              │
              ▼
         same NIC tx ring ──► backend (decapsulates on tunl0, replies directly to the client: DSR)

   side outputs
     stats (percpu array) ──────────────► controller, read on each /metrics scrape
     events (ring buffer, new blocks) ──► controller ─► log, recent list, counters
```

### Why these choices

**IPIP + DSR.** The balancer only sees client-to-server packets. Responses skip it, which is where most of the bytes are, and it never has to track TCP state beyond "which backend did this flow go to". Katran does the same. The cost is that backends need a tunnel interface and an MSS clamp (`deploy/backend-setup.sh`).

**XDP_TX, one-arm.** Packets leave on the interface they came in on. No routing lookup per packet; the backend's next-hop MAC comes from the config. This keeps the datapath small but means backends (or the gateway to them) have to be reachable at L2 from the LB interface.

**Maglev for TCP, WRR for UDP/stateless.** Maglev gives every LB node the same backend for the same flow if they share the backend set and `hash_seed`, so ECMP in front of several LBs works and a node restart doesn't reshuffle connections. Connection tracking on top handles the other case: when the backend set changes, existing flows stay where they are and only new flows use the new table. WRR is there for traffic where you want exact proportions and don't care about flow stickiness.

**Tables are built in userspace.** The datapath does one array lookup. Weights, health and minimal-disruption logic live in Go where they can be unit tested (`internal/maglev`). Each VIP has its own inner map inside an `ARRAY_OF_MAPS`; an update builds a new inner map, fills it, and replaces the outer slot with one syscall, so a packet sees the old table or the new one, never a half-written one.

**Blocklist in the kernel.** Detection and enforcement are both in XDP: the packet that crosses the threshold creates the blocklist entry, and the next packet from that source dies after a single hash lookup. The controller is only told about it afterwards through the ring buffer, so a slow or dead controller can't stall mitigation.

## Maps

| map | type | owner | purpose |
|---|---|---|---|
| `config_map` | array(1) | controller | thresholds, ttl, encap source, mtu, hash seed |
| `vip_map` | hash | controller | (addr, port, proto) → vip id, algorithm, table length |
| `vip_addrs` | hash | controller | vip addresses, used to drop fragments |
| `backend_map` | array | controller | id → addr, next-hop mac, active flag |
| `lb_tables` | array of maps | controller | per-vip maglev or wrr table |
| `rr_cursor` | percpu array | datapath | wrr position per vip |
| `conn_track` | LRU hash | datapath | 5-tuple → backend id |
| `rate_state` | LRU hash | datapath | per-source syn/udp counters in a 1s window |
| `dyn_blocklist` | LRU hash | datapath (+ admin api) | source → expiry, reason |
| `deny_cidr`, `allow_cidr` | LPM trie | controller | permanent lists |
| `stats`, `vip_stats`, `backend_stats` | percpu array | datapath | counters |
| `events` | ring buffer | datapath | block events |

All maps that the datapath grows by itself are LRU, so under attack they evict old entries instead of failing inserts.

## Controller

```
config.yaml ──► config.Load (strict parse, validation)
                    │            ▲
        fsnotify / SIGHUP        │ rejected reload keeps the old state
                    ▼            │
              controller.Apply ──┴─► dataplane: backends → lists → vip tables → removals
                    ▲
        health.Manager (tcp probes, fall/rise) ──► SetHealth ──► rebuild affected tables
```

- Backends are written before any table that references them, and removed after the last table stops using them.
- Backend and VIP ids are never reused until the id space wraps, so stale conntrack entries can't send a flow to a different backend.
- If every backend of a VIP fails health checks the table is built from all of them. Dropping everything is worse than trying.
- A table identical to the one already installed is not rewritten.

## Observability

- `/metrics` (Prometheus): counters are read from the kernel on scrape, there is no polling loop. Drops are one metric with a `reason` label. Per-VIP and per-backend traffic, backend health.
- `xdpshield_block_events_total{reason}` and `/api/v1/events` come from the ring buffer. Source IPs are deliberately not metric labels; during an attack that would be unbounded cardinality. They go to the log and the in-memory recent list (last 256).
- `/api/v1/status`, `/api/v1/blocklist` (GET open, POST/DELETE need the bearer token).

## Limits and known gaps

- IPv6 VIPs work, but backends must be IPv4: a v6 client packet is wrapped in an IPv4 header with protocol 41 (6in4) and unwrapped on the backend's `sit0`. There is no ip6ip6 path.
- IPv6 extension headers are not walked. Only the fragment header is recognised (dropped when aimed at a VIP); anything else that isn't TCP or UDP right after the fixed header is passed to the host, including hop-by-hop and routing headers on VIP traffic.
- No SYN cookies; SYN floods are handled by per-source rate limits, which does nothing against a spoofed-source flood spread over millions of addresses. Pair with upstream scrubbing for volumetric attacks.
- Rate windows are fixed 1s and roll over without a lock, so counts can be off by a few packets around the boundary.
- A v6 packet that would exceed the MTU after the 20 byte 6in4 wrapper gets ICMPv6 packet too big (type 2, advertised mtu = `mtu - 20`) from the VIP, 110 bytes, built in place and sent with `XDP_TX`.
- A DF packet that would exceed the MTU after encapsulation gets an ICMP "fragmentation needed" (type 3 code 4, advertised mtu = `mtu - 20`) sent back from the VIP, 70 bytes, built in place and sent with `XDP_TX`. Without DF the packet is dropped. Clamp MSS on the backends anyway.
- WRR cursors are per CPU, so short runs are only approximately proportional.
- Single VLAN-untagged Ethernet only; tagged frames are passed to the host.
