# xdpshield

[![ci](https://github.com/monaaoua9/xdpshield/actions/workflows/ci.yml/badge.svg)](https://github.com/monaaoua9/xdpshield/actions/workflows/ci.yml)

An XDP load balancer and DDoS filter. A C/eBPF program runs on the NIC receive path and drops attack traffic or forwards VIP traffic to backends over IPIP, before the kernel allocates an skb. A Go controller owns the BPF maps, applies config changes live, health checks backends and exports Prometheus metrics.

```
client ─► NIC ─► [ XDP: validate ─► blocklist ─► rate limit ─► maglev/wrr ─► ipip encap ] ─► XDP_TX ─► backend ─► client (DSR)
                        │                                  ▲
                        └─ stats, ring buffer ─► controller ─► /metrics, admin api, logs
```

- **Dual stack**: IPv4 and IPv6 VIPs, blocklists and CIDR lists. IPv6 clients are carried to the (IPv4) backends in 6in4 and get ICMPv6 packet too big when they overshoot the MTU.
- **Load balancing in the kernel**: Maglev consistent hashing or smooth weighted round robin per VIP, LRU connection tracking so established flows survive backend changes, DSR so responses bypass the balancer.
- **DDoS**: malformed and martian packets, invalid TCP flag combinations, fragments to VIPs, reflected UDP answers (DNS, NTP, memcached...) aimed at a VIP address, per-source SYN and UDP rate limits with automatic TTL blocklisting, permanent allow/deny CIDRs. The packet that trips a limit creates the block; the controller is informed asynchronously.
- **Live control**: YAML config, applied on file change or `SIGHUP`, diffed into map writes. VIP tables are swapped atomically via array-of-maps. Rejected configs leave the running state alone.
- **Health checks**: TCP or HTTP (`health_check: http`, 2xx/3xx on `health_path`) probes with fall/rise thresholds; unhealthy backends leave the table without touching other flows, and `drain: true` stops new flows to a backend while tracked ones finish.
- **Observability**: Prometheus counters read from per-CPU maps on scrape, ring buffer for block events, small admin API.

Design details are in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), verifier notes in [docs/VERIFIER.md](docs/VERIFIER.md).

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

make generate            # after touching bpf/*.c or bpf/include/*.h
```

Backends must decapsulate the tunnel and answer from the VIP: `deploy/backend-setup.sh <vip>`.

```sh
curl localhost:9100/metrics | grep xdpshield_
curl localhost:9100/api/v1/status
curl -H "Authorization: Bearer $XDPSHIELD_TOKEN" -d '{"ip":"203.0.113.77","ttl":"1h"}' localhost:9100/api/v1/blocklist
kill -HUP $(pidof xdpshield)     # or just edit the file

bin/xdpshieldctl status          # vips, backends, health
bin/xdpshieldctl blocked
bin/xdpshieldctl block 203.0.113.77 1h    # token from $XDPSHIELD_TOKEN or -token
bin/xdpshieldctl events 20
bin/xdpshieldctl stats
```

## Tests

```sh
make test-unit            # maglev, config, controller (fake dataplane), health, metrics, admin
make test-integration     # root, linux: loads the real program and runs crafted packets through it
test/lab.sh up && test/lab.sh test    # end to end with network namespaces
```

The integration suite covers encapsulation (headers, checksum, MACs), flow stickiness, Maglev spread, WRR ratio, SYN/UDP flood blocking and unblocking, ring buffer events, allow/deny lists, bad flags, malformed frames, fragments, MTU drops and the ICMP frag-needed reply.

## Performance

Program cost only, measured with `BPF_PROG_TEST_RUN` (3M runs per case, kernel-side timing): no driver, no DMA, no skb. Intel i5-8365U @ 1.6 GHz, 2 vCPUs, WSL2 kernel 6.6, single core. Reproduce with `sudo go test -tags integration -run xxx -bench XDP ./internal/dataplane/`.

| path | ns/pkt | Mpps/core |
|---|---|---|
| non-IP, passed to the stack | 80 | 12.5 |
| host traffic (not a VIP), passed | 279 | 3.6 |
| dropped by deny CIDR (LPM) | 225 | 4.4 |
| dropped by dynamic blocklist | 217 | 4.6 |
| dropped, bad TCP flags | 311 | 3.2 |
| LB, established TCP flow (conntrack hit, ipip encap) | 213 | 4.7 |
| LB, TCP SYN (rate check, hash, encap) | 189 | 5.3 |
| LB, UDP weighted round robin | 183 | 5.5 |

These are ceilings for the program on a slow laptop core, not NIC throughput: a real run adds driver and memory costs, and native XDP on a 10G NIC was not tried. For scale, a blocklisted source costs about 220 ns per packet before the kernel allocates anything.

## Status

Unit tests pass. The program loads under the verifier of a 6.6 kernel (WSL2, clang 21) and all twelve `BPF_PROG_TEST_RUN` integration tests pass. The first load was rejected for an unbounded `tot_len` after the byte swap; that is fixed in `parsing.h`. `test/lab.sh` also ran on that kernel (generic XDP, netns): 20 requests to the VIP were answered through the IPIP path and the SYN flood got the client blocked. The lab backends share one /tmp, so it can't show the split between them; the integration tests cover that. Other kernels and NIC drivers (native XDP) have not been tried; CI runs the integration suite on every push.

Known gaps are listed at the end of the architecture doc: v6 backends (v6 clients are tunnelled to v4 backends over 6in4), no SYN cookies.

## License

Go code: MIT. BPF programs: GPL-2.0-only OR BSD-2-Clause (the kernel needs a GPL-compatible license string to allow some helpers).
