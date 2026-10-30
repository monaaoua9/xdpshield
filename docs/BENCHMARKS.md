# xdpshield: benchmarks

Measured 2026-10-30, after the IPv6 and token bucket work.

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
| non-IP, passed to the stack | 72 (72 – 76) | 13.9 |
| host traffic (not a VIP), passed | 169 (166 – 209) | 5.9 |
| dropped by deny CIDR (LPM) | 135 (127 – 163) | 7.4 |
| dropped by dynamic blocklist | 121 (117 – 122) | 8.3 |
| dropped, bad TCP flags | 169 (166 – 197) | 5.9 |
| LB, established TCP flow (conntrack hit, IPIP encap) | 135 (135 – 148) | 7.4 |
| LB, TCP SYN (rate check, hash, encap) | 130 (126 – 132) | 7.7 |
| LB, UDP weighted round robin | 131 (124 – 135) | 7.6 |
| LB, allowlisted source | 141 (129 – 144) | 7.1 |
| IPv6, dropped by deny CIDR | 185 (138 – 247) | 5.4 |
| IPv6 LB, established TCP flow (6in4 encap) | 267 (243 – 338) | 3.7 |
| IPv6 LB, TCP SYN | 148 (148 – 213) | 6.8 |

## Reading these numbers

- A blocklisted source costs about 90 ns before the kernel allocates anything. The drop paths are the cheap ones, which is the point of doing them in XDP.
- The load-balancing paths (header rewrite, checksum, IPIP encapsulation) cost roughly 20–50 ns more than the cheapest drop.
- The "bad TCP flags" drop is the slowest case here (about 170 ns), slower than the LB paths even though it does less. I haven't looked into why.
- The IPv6 rows are noisier than the v4 ones (the established flow ranges 243 – 338 ns) and I only ran three repetitions, so treat them as a rough range. The established v6 flow is the slowest path here, which is plausible given the 16-byte keys and the larger outer header, but I haven't profiled it.
- These numbers are higher than the previous run's for the same v4 paths (established LB flow 135 ns against 138 ns, host traffic 169 against 123). The program changed in between (dual stack, token bucket), but the core's clock also moves between days, so use ratios between rows, not absolute values across days.

## What has not been measured

Native XDP on a real NIC, other kernels, multi-core scaling, and end-to-end behaviour under an actual flood. The network-namespace lab (`test/lab.sh`) checks correctness, not speed. This file compares xdpshield with no other balancer.
