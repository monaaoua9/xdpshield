# xdpshield: benchmarks

Measured 2026-10-30, after the IPv6, token bucket and clock-read changes (six repetitions; the table taken earlier the same day used three and a slower phase of the core, it is not kept).

| | |
|---|---|
| CPU | Intel i5-8365U, 1.6 GHz, 2 vCPUs given to WSL2, one core used |
| Kernel | 6.6.87.2 (WSL2); the program is run by `BPF_PROG_TEST_RUN`, no real NIC |
| Toolchain | Go 1.27.0 (cross-compiled on Windows), BPF object from the repo |

## Measurement environment

The machine is a low-spec laptop with 8 GB of RAM, running Windows 11 with WSL2 limited to 2 vCPUs. While measuring it usually had about six terminals open and the C: drive was nearly full. All of that adds noise: timings varied 2-5x between runs, and the core alternates between a fast and a roughly 6x slower phase. So single runs mean nothing here. Old-vs-new comparisons are done interleaved in one session and read as best-of or medians, and every table says how it was taken. Treat absolute numbers as indicative only.

## What is measured

The cost of the XDP program itself, using `BPF_PROG_TEST_RUN`: the kernel runs the program on a crafted packet N times and reports its own timing. No driver, no DMA, no skb, no packet generation. These are ceilings for the program on a slow laptop core, not NIC throughput.

```
GOOS=linux GOARCH=amd64 go test -c -tags integration -o xdp.test ./internal/dataplane
# inside WSL as root, from internal/dataplane:
./xdp.test -test.run xxx -test.bench XDP -test.benchtime 3000000x -test.count 3
```

3,000,000 runs per case, three repetitions; median with min–max in brackets. The program's own time per packet:

| path | ns/pkt | Mpps/core |
|---|---:|---:|
| non-IP, passed to the stack | 50 (42 – 66) | 20.0 |
| host traffic (not a VIP), passed | 132 (113 – 148) | 7.6 |
| dropped by deny CIDR (LPM) | 92 (88 – 113) | 10.9 |
| dropped by dynamic blocklist | 101 best of 6 (101 – 608) | ~10 |
| dropped, bad TCP flags | 225 (158 – 616) | 4.4 |
| LB, established TCP flow (conntrack hit, IPIP encap) | 93 (81 – 113) | 10.8 |
| LB, TCP SYN (rate check, hash, encap) | 79 (74 – 91) | 12.7 |
| LB, UDP weighted round robin | 76 (73 – 85) | 13.2 |
| LB, allowlisted source | 76 (73 – 82) | 13.2 |
| IPv6, dropped by deny CIDR | 82 (77 – 88) | 12.2 |
| IPv6 LB, established TCP flow (6in4 encap) | 77 (76 – 79) | 13.0 |
| IPv6 LB, TCP SYN | 78 (75 – 86) | 12.8 |

## Reading these numbers

- The WSL2 core alternates between a fast and a roughly 6x slower phase between runs. This table was taken in a fast phase; an earlier run the same day gave 130-250 ns for the same paths. Compare rows within one table, not across tables.
- The two drop rows that read a map entry written by userspace (dynamic blocklist) and the bad-flags row are the noisy ones: six runs spread from 101 to 608 ns and 158 to 616 ns. I report the best run for the blocklist and the median for bad flags, and I don't know why they vary more than the LB paths.
- Against the pre-change build in the same session, the LB, drop and IPv6 paths were 15-30% faster (one clock read per packet instead of two, trie lookups skipped while the list is empty). Non-IP and bad-flags did not change.
- IPv6 paths now cost about the same as IPv4 ones here; the earlier gap in the first table was the slow phase, not the program.

## What has not been measured

Native XDP on a real NIC, other kernels, multi-core scaling, and end-to-end behaviour under an actual flood. The network-namespace lab (`test/lab.sh`) checks correctness, not speed. This file compares xdpshield with no other balancer.
