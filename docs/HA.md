# Running two or more balancers

There is no connection state sync between nodes. What makes failover work anyway:

- Maglev gives the same backend for the same flow on every node as long as the nodes share `hash_seed`, the backend list (names, weights, order irrelevant) and the health view. A flow that lands on the surviving node is hashed to the backend it was already using.
- Conntrack only matters for flows that were placed *before* a backend set change (a backend went down or came back, a weight changed, `drain`). Those flows, and only those, can move when the node serving them disappears. Plan maintenance with `drain: true` so there is nothing pinned to a stale choice.
- WRR vips (`algorithm: wrr`) are per-CPU round robin with no flow hashing. After a failover every flow on such a vip is re-placed. Use maglev for anything with long-lived connections.

## Active/passive with VRRP

Both nodes run the same `config.yaml` (same `hash_seed`, same backends) so the standby has its tables loaded and a failover is only an address move. The VIP is configured on the lb interface of whoever is master; XDP sees the packets before the stack does, the address on the host only exists to answer ARP/ND.

`deploy/keepalived.conf` is a starting point. It tracks `/healthz` so a dead daemon gives up the VIP. With `pin_path` set a daemon restart does not detach the datapath, so a plain restart doesn't need a failover at all.

```
node A:  keepalived (MASTER, prio 150)  xdpshield  config.yaml
node B:  keepalived (BACKUP, prio 100)  xdpshield  config.yaml (identical)
```

Things to check on your own network:

- The next hop MACs in `backends[].mac` must be reachable at L2 from both nodes' interfaces.
- `encap_src` / `encap_src6` can differ per node, the backends don't care who the outer source is as long as their rp_filter and firewall let both through.
- Gratuitous ARP on failover (`garp_master_delay` in keepalived) so clients and the gateway relearn the VIP's MAC.

## Active/active with ECMP

Put the nodes behind a router that hashes flows (ECMP, 5-tuple) and announce the VIP from both, with BGP or static routes. Because placement is a pure function of the 5-tuple and the shared config, either node can serve any flow. When a node leaves, the router rehashes some flows to the others, and those flows keep their backend by the same argument as above.

Caveats:

- Resilient hashing on the router keeps flows from moving when nodes join or leave; without it, more flows change node and rely on the Maglev equality.
- Rate limits and blocklists are per node. An attacker spread over two nodes gets twice the limit, and a source blocked on one node is not blocked on the other until it trips the limit there. Push manual blocks to every node (`xdpshieldctl block` against each admin address).
- Health checks run per node; a transient disagreement briefly gives different tables. Keep `fall`/`rise` identical.

## What is not covered

Conntrack sync, shared blocklists and a built-in BGP speaker are not implemented. If you need exact connection survival across arbitrary backend changes, that needs a state replication design that depends on your network, and it is a separate piece of work.
