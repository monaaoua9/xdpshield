# xdpshield

[![ci](https://github.com/monaaoua9/xdpshield/actions/workflows/ci.yml/badge.svg)](https://github.com/monaaoua9/xdpshield/actions/workflows/ci.yml)

An XDP load balancer and DDoS filter. A C/eBPF program runs on the NIC receive path and drops attack traffic or forwards VIP traffic to backends over IPIP, before the kernel allocates an skb. A Go controller owns the BPF maps, applies config changes live, health checks backends and exports Prometheus metrics.

```
client ─► NIC ─► [ XDP: validate ─► blocklist ─► rate limit ─► maglev/wrr ─► ipip encap ] ─► XDP_TX ─► backend ─► client (DSR)
                        │                                  ▲
                        └─ stats, ring buffer ─► controller ─► /metrics, admin api, logs
```

- **Dual stack**: IPv4 and IPv6 VIPs, blocklists, CIDR lists and backends, any mix. The tunnel is IPIP, 6in4, IPIP6 or IP6IP6 depending on the pair; oversized packets get ICMP frag-needed or ICMPv6 packet too big.
- **Load balancing in the kernel**: Maglev consistent hashing or smooth weighted round robin per VIP, LRU connection tracking so established flows survive backend changes, DSR so responses bypass the balancer.
- **DDoS**: malformed and martian packets, invalid TCP flag combinations, fragments to VIPs, reflected UDP answers (DNS, NTP, memcached...) aimed at a VIP address, per-source SYN and UDP token-bucket rate limits with automatic TTL blocklisting, permanent allow/deny CIDRs (inline or from prefix list files such as country zones). The packet that trips a limit creates the block; the controller is informed asynchronously.
- **Restarts without losing state**: with `pin_path` set, maps (conntrack, blocklists, counters) and the XDP link are pinned on bpffs. A restart reuses them and swaps the program inside the live link, so flows survive and there is no gap. `xdpshield -unpin` detaches for good.
- **Live control**: YAML config, applied on file change or `SIGHUP`, diffed into map writes. VIP tables are swapped atomically via array-of-maps. Rejected configs leave the running state alone.
- **Health checks**: TCP or HTTP (`health_check: http`, 2xx/3xx on `health_path`) probes with fall/rise thresholds; unhealthy backends leave the table without touching other flows, and `drain: true` stops new flows to a backend while tracked ones finish.
- **Observability**: Prometheus counters read from per-CPU maps on scrape, ring buffer for block events, small admin API.

Design details are in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) (shorter version: [docs/DESIGN.md](docs/DESIGN.md)), verifier notes in [docs/VERIFIER.md](docs/VERIFIER.md), running several nodes in [docs/HA.md](docs/HA.md).

## Layout

```
bpf/                    datapath
  xdp_shield.c            program
  include/common.h        shared structs, constants, stat ids
  include/maps.h          map definitions
  include/parsing.h       bounds-checked header parsing
cmd/xdpshield/          main
cmd/xdpshieldctl/       cli for the admin api
internal/
  config/                 yaml, defaults, validation
  controller/             config -> map writes, ids, health reactions
  dataplane/              bpf2go output + map operations (linux only)
  maglev/                 table generation (maglev, smooth wrr)
  health/                 tcp health checks
  metrics/                prometheus collector, ring buffer consumer
  admin/                  http api
  statdef/                stat names, checked against common.h by a test
configs/example.yaml
deploy/                 Dockerfile, systemd unit, backend setup script
test/lab.sh             netns lab
```

## Requirements

Linux 5.8+ (ring buffer; 5.9+ for XDP bpf_link), `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_PERFMON`. Go 1.26. To rebuild the BPF object: clang, llvm-strip, libbpf headers. The generated object is committed, so building the binary needs only Go.

## Build and run

```sh
git clone https://github.com/monaaoua9/xdpshield && cd xdpshield
make build
bin/xdpshield -check -config configs/example.yaml
sudo XDPSHIELD_TOKEN=changeme bin/xdpshield -config configs/example.yaml
# -log-format json -log-level debug for a log shipper or a noisy night

make generate            # after touching bpf/*.c or bpf/include/*.h
```

Backends must decapsulate the tunnel and answer from the VIP: `deploy/backend-setup.sh <vip>`.

```sh
curl localhost:9100/metrics | grep xdpshield_
curl localhost:9100/api/v1/status
curl -H "Authorization: Bearer $XDPSHIELD_TOKEN" -d '{"ip":"203.0.113.77","ttl":"1h"}' localhost:9100/api/v1/blocklist
kill -HUP $(pidof xdpshield)     # or just edit the file
curl -X POST -H "Authorization: Bearer $XDPSHIELD_TOKEN" localhost:9100/api/v1/reload   # same, but tells you if the config was rejected

bin/xdpshieldctl status          # vips, backends, health
bin/xdpshieldctl blocked
bin/xdpshieldctl block 203.0.113.77 1h    # token from $XDPSHIELD_TOKEN or -token
bin/xdpshieldctl reload                   # POST /api/v1/reload, prints the validation error on failure
bin/xdpshieldctl events 20
bin/xdpshieldctl stats
bin/xdpshieldctl top                      # live pps, drops by reason, backend health
```

## Tests

```sh
make test-unit            # maglev, config, controller (fake dataplane), health, metrics, admin
make test-integration     # root, linux: loads the real program and runs crafted packets through it
test/lab.sh up && test/lab.sh test    # end to end with network namespaces: v4 and v6 vips, syn flood
test/lab.sh reload                     # drain a backend through a live config reload and undo it
test/lab.sh restart                    # kill the daemon, traffic keeps flowing, restart picks the pins up
```

The integration suite covers encapsulation (headers, checksum, MACs), flow stickiness, Maglev spread, WRR ratio, SYN/UDP flood blocking and unblocking, ring buffer events, allow/deny lists, bad flags, malformed frames, fragments, MTU drops and the ICMP frag-needed reply.

## Performance

Program cost only, measured with `BPF_PROG_TEST_RUN` (3M runs per case, kernel-side timing): no driver, no DMA, no skb. Intel i5-8365U @ 1.6 GHz, 2 vCPUs, WSL2 kernel 6.6, single core. The table is the median of three runs; ranges and the exact commands are in [docs/BENCHMARKS.md](docs/BENCHMARKS.md). Reproduce with `sudo go test -tags integration -run xxx -bench XDP ./internal/dataplane/`.

| path | ns/pkt | Mpps/core |
|---|---|---|
| non-IP, passed to the stack | 50 | 20.0 |
| host traffic (not a VIP), passed | 132 | 7.6 |
| dropped by deny CIDR (LPM) | 92 | 10.9 |
| dropped by dynamic blocklist | ~100 (unstable, see doc) | ~10 |
| dropped, bad TCP flags | 225 | 4.4 |
| LB, established TCP flow (conntrack hit, ipip encap) | 93 | 10.8 |
| LB, TCP SYN (rate check, hash, encap) | 79 | 12.7 |
| LB, UDP weighted round robin | 76 | 13.2 |
| IPv6 LB, established TCP flow (6in4 encap) | 77 | 13.0 |
| IPv6 LB, TCP SYN | 78 | 12.8 |

These are ceilings for the program on a slow laptop core, not NIC throughput: a real run adds driver and memory costs, and native XDP on a 10G NIC was not tried. For scale, a blocklisted source costs about 100 ns at best per packet before the kernel allocates anything.

## Status

Unit tests pass. The program loads under the verifier of a 6.6 kernel (WSL2, clang 21) and the `BPF_PROG_TEST_RUN` integration tests (v4, v6, amplification, drain, rate limits) pass. The first load was rejected for an unbounded `tot_len` after the byte swap; that is fixed in `parsing.h`. `test/lab.sh` also ran on that kernel (generic XDP, netns): 20 requests to the VIP were answered through the IPIP path and the SYN flood got the client blocked. The lab backends share one /tmp, so it can't show the split between them; the integration tests cover that. Other kernels and NIC drivers (native XDP) have not been tried; CI runs the integration suite on every push.

Known gaps are listed at the end of the architecture doc: no SYN cookies, no IPv6 extension header walking.

## License

Go code: MIT. BPF programs: GPL-2.0-only OR BSD-2-Clause (the kernel needs a GPL-compatible license string to allow some helpers).
