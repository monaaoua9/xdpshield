# Writing for the verifier

Notes on how `bpf/xdp_shield.c` is kept acceptable to the kernel verifier, and what to keep doing when you change it.

## Packet bounds

Every read of packet memory is preceded by a comparison against `data_end` for exactly the bytes being read.

```c
if ((void *)(eth + 1) > p->end) return PARSE_BAD;
ip = (void *)(eth + 1);
if ((void *)(ip + 1) > p->end) return PARSE_BAD;
```

Variable-length parts are bounded before use. `ihl * 4` is checked against `tot_len` and `tot_len` against `data_end` before the L4 pointer is derived, and the L4 header gets its own `(hdr + 1) > end` check. `tot_len` is at most 65535, which keeps the pointer range inside what the verifier will track.

`bpf_ntohs()` on a loaded field gives the verifier an unbounded scalar, and adding that to a packet pointer is refused ("math between pkt pointer and register with unbounded min value"). `parse_l3` masks `tot` with an `asm volatile` and 0xffff because clang folds a plain C mask away. This was the one rejection on the first run against a real kernel (6.6).

Never trust a length field from the packet by itself: `tot_len < hlen` and `ip + tot_len > data_end` are both rejected as malformed.

## Pointers die after `bpf_xdp_adjust_head`

The call invalidates every packet pointer. `encap_ipip` copies what it needs (inner `tot_len`, `tos`, the MAC the frame was addressed to) into locals first, then reloads `data`/`data_end` from the context and re-checks bounds before writing. Nothing after the call touches the old `struct pkt`.

The outer IP header overlaps the old Ethernet header in memory. That is intentional and safe because the old MACs were copied out beforehand.

## Map values

Every `bpf_map_lookup_elem` result is null-checked before dereference, including the stats helpers. Map value pointers are only used inside the block that checked them.

`lb_tables` is an array of maps; the inner lookup (`bpf_map_lookup_elem(tbl, &idx)`) is also null-checked, which covers an index past the end of the inner array without the program having to know its size.

## Loops

The only loop is the 10 iteration checksum, marked `#pragma unroll`. Everything else is straight-line code, so the verifier's instruction budget is not a concern (about 900 instructions).

`% vip->table_len` can't divide by zero: the code returns early when `table_len == 0`, and BPF defines division by zero as 0 anyway.

## Atomics

The program targets `-mcpu=v1`. `__sync_fetch_and_add` compiles to `xadd`, which has **no return value** at that level, so counters are bumped and then read back instead of using the result. Using the return value fails at compile time with "Invalid usage of the XADD return value".

## Races we accept

- Window rollover in `rate_bump` is not atomic. Worst case two CPUs both reset the window.
- `conn_track` updates can overwrite each other when two packets of a new flow race on different CPUs. Both pick the same backend (same hash), so the result is the same.
- `last_seen_ns` in conntrack is informational; eviction is LRU, not time based.

None of these can corrupt memory or make the program unsafe, only make a counter slightly off.

## Defence against the program's own state

- Maps the datapath inserts into are `LRU_HASH`, so a flood of unique sources evicts old entries and never makes `bpf_map_update_elem` fail.
- Blocklist entries carry an expiry; expired ones are deleted lazily on the next hit.
- Ring buffer reserve failures are counted (`event_lost`) instead of ignored.

## How it is checked

1. `bpf2go` compiles with `-Wall -Werror`.
2. `go test -tags integration ./internal/dataplane/` loads the program (the verifier runs at load time; a rejection prints the full log) and pushes crafted frames through `BPF_PROG_TEST_RUN`: truncated frames, lying `tot_len`, fragments, martians, bad flag combinations, floods, oversize packets, and checks the output frames byte by byte, including the outer header checksum.
3. CI runs both on a real kernel.

When changing the C: rebuild, run the integration tests as root, and read the verifier log if it fails. The usual causes are a missing bounds check after pointer arithmetic, using a packet pointer after `adjust_head`, or a stack object that grew past 512 bytes.
