# xdpshield: benchmarks

Measured 2026-10-29.

| | |
|---|---|
| CPU | Intel i5-8365U, 1.6 GHz, 2 vCPUs given to WSL2, one core used |
| Kernel | 6.6.87.2 (WSL2), generic XDP, no real NIC |
| Toolchain | Go 1.27.0 (cross-compiled on Windows), BPF object from the repo |

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
| non-IP, passed to the stack | 72 (52 – 76) | 13.9 |
| host traffic (not a VIP), passed | 123 (118 – 128) | 8.1 |
| dropped by deny CIDR (LPM) | 106 (99 – 111) | 9.4 |
| dropped by dynamic blocklist | 91 (88 – 125) | 11.0 |
| dropped, bad TCP flags | 169 (148 – 170) | 5.9 |
| LB, established TCP flow (conntrack hit, IPIP encap) | 138 (119 – 148) | 7.2 |
| LB, TCP SYN (rate check, hash, encap) | 119 (112 – 125) | 8.4 |
| LB, UDP weighted round robin | 124 (124 – 130) | 8.1 |
| LB, allowlisted source | 106 (106 – 117) | 9.4 |

## Reading these numbers

- A blocklisted source costs about 90 ns before the kernel allocates anything. The drop paths are the cheap ones, which is the point of doing them in XDP.
- The load-balancing paths (header rewrite, checksum, IPIP encapsulation) cost roughly 20–50 ns more than the cheapest drop.
- The "bad TCP flags" drop is the slowest case here (about 170 ns), slower than the LB paths even though it does less. I haven't looked into why.
- Every figure is lower than the README's, for example the established-flow LB path at 138 ns against 213 ns. Per-packet times at this scale move with the core's clock, so I haven't tried to explain the gap. Use ratios between rows, not absolute values across days.

## What has not been measured

Native XDP on a real NIC, other kernels, multi-core scaling, and end-to-end behaviour under an actual flood. The network-namespace lab (`test/lab.sh`) checks correctness, not speed. This file compares xdpshield with no other balancer.
