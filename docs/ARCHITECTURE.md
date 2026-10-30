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
| `rate_state` | LRU hash | datapath | per-source syn/udp token bucket timestamps |
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

## Orphan TCP (drop_orphan_tcp)

Off by default. With it on (and `ddos.enabled`), a TCP packet to a VIP that is not a plain SYN and has no conntrack entry is dropped (`drop_no_flow`) instead of being hashed to a backend. That kills ACK/RST floods at the VIP for the price of one map lookup. The trade-off is the same one HA relies on: a flow that arrives at a node which never saw its SYN (failover, ECMP rehash, a restart without `pin_path`) is dropped too, so the client has to reconnect. Leave it off for active/active setups unless connections are short.

## Restarts (pin_path)

With `pin_path: /sys/fs/bpf/xdpshield` every map is pinned there by name and the XDP link is pinned as `xdp_link`. On the next start the loader reuses the pinned maps (conntrack, rate state, blocklist, counters, tables) instead of creating new ones and calls `Update` on the pinned link, which replaces the program atomically (linux 5.9+). When the process exits the datapath keeps forwarding with the last tables.

Ids are the catch: conntrack entries hold backend ids, and ids are handed out by the controller. It writes `state_file` (default `/var/lib/xdpshield/state.json`; bpffs cannot hold regular files, so it does not live next to the pins) after every successful config apply and reads it back before the first apply, so names keep their ids and entries the new config dropped are removed as usual. Health starts out "all up" again.

If a new build changes a map layout the loader refuses the old pins and says to run `xdpshield -unpin` first (that drops conntrack). Changing `interface`, `xdp_mode` or `pin_path` needs `-unpin` too, the pinned link stays on the old interface. An unpinned run behaves as before: exit detaches.

## Prefix list files

`ddos.deny_lists` / `allow_lists` name files with one prefix or bare address per line (`#` and `;` start comments). They are read on every config load, relative to the config file, merged with the inline lists, deduplicated and pushed into the same LPM tries, so a country zone file or a Spamhaus DROP dump is enough for coarse geo or reputation blocking. Each trie holds 16384 prefixes per family and the loader rejects bigger sets. The files are not watched: after refreshing them send `SIGHUP`, or touch the config.

There is deliberately no MaxMind/ASN reader in the daemon; turn the database into prefix files with whatever tool you trust and drop the result in.

## Draining

`drain: true` on a backend removes it from every Maglev/WRR table but leaves it `active` in `backend_map`, so conntrack hits keep going to it. Flows end on their own or age out of the LRU. If every backend of a VIP is drained or down the VIP falls back to using all of them rather than blackholing. After removing the backend from the config, its remaining flows rehash to somewhere else.

## Amplification filter

`ddos.amplification.ports` lists UDP source ports used by reflection attacks. A UDP packet whose source port is in that list, aimed at one of our VIP addresses but matching no VIP (the destination port is a random victim port), is dropped when its UDP length is at least `min_size`. Nothing behind the balancer sent a query, so there is nothing legitimate to lose, unless a backend itself resolves through the VIP address: allowlist those. A VIP that really serves one of the ports (DNS on 53) is untouched because the VIP lookup happens first. Packets for addresses that aren't VIPs go to the host stack as before. Counted as `drop_amplification`.

## Observability

- `/metrics` (Prometheus): counters are read from the kernel on scrape, there is no polling loop. Drops are one metric with a `reason` label. Per-VIP and per-backend traffic, backend health.
- `xdpshield_block_events_total{reason}` and `/api/v1/events` come from the ring buffer. Source IPs are deliberately not metric labels; during an attack that would be unbounded cardinality. They go to the log and the in-memory recent list (last 256).
- `/api/v1/status`, `/api/v1/blocklist` (GET open, POST/DELETE need the bearer token).

## Limits and known gaps

- Backends can be IPv4 or IPv6, independent of the VIP family. The outer header follows the backend: IPv4 backends get IPIP (inner v4) or 6in4 (protocol 41, inner v6, decap on `sit0`), IPv6 backends get IPIP6 (next header 4) or IP6IP6 (next header 41), decapsulated on `ip6tnl0`. `encap_src` is needed with any v4 backend, `encap_src6` with any v6 one. The tunnel overhead used for the MTU check is 40 bytes as soon as one backend is v6 (it is checked before a backend is picked), so a pure-v4 setup keeps the 20 byte limit.
- IPv6 extension headers are not walked. Only the fragment header is recognised (dropped when aimed at a VIP); anything else that isn't TCP or UDP right after the fixed header is passed to the host, including hop-by-hop and routing headers on VIP traffic.
- No SYN cookies; SYN floods are handled by per-source rate limits, which does nothing against a spoofed-source flood spread over millions of addresses. Pair with upstream scrubbing for volumetric attacks.
- Rate limits are a GCRA token bucket per source (rate = limit, burst = one second of it), kept as one timestamp per protocol. Updates are not locked, so two cpus racing on the same source can admit a few extra packets.
- A v6 packet that would exceed the MTU after the 20 byte 6in4 wrapper gets ICMPv6 packet too big (type 2, advertised mtu = `mtu - 20`) from the VIP, 110 bytes, built in place and sent with `XDP_TX`.
- A DF packet that would exceed the MTU after encapsulation gets an ICMP "fragmentation needed" (type 3 code 4, advertised mtu = `mtu - 20`) sent back from the VIP, 70 bytes, built in place and sent with `XDP_TX`. Without DF the packet is dropped. Clamp MSS on the backends anyway.
- WRR cursors are per CPU, so short runs are only approximately proportional.
- Single VLAN-untagged Ethernet only; tagged frames are passed to the host.
