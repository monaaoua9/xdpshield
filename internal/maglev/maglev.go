// Package maglev builds lookup tables for the xdp datapath. The datapath only
// does table[hash % len]; everything about weights and consistency lives here.
package maglev

import (
	"errors"
	"hash/fnv"
	"sort"
)

// must match MAGLEV_M in bpf/include/common.h
const TableSize = 65537

type Backend struct {
	Name   string
	ID     uint32
	Weight uint32
}

var ErrNoBackends = errors.New("no backends with weight > 0")

// Build returns TableSize slots holding backend ids. Permutations are seeded
// from the backend *name*, not its position, so every lb node that sees the
// same set produces the same table and removing one backend only moves its
// own share (plus a little churn).
func Build(bs []Backend) ([]uint32, error) {
	bs = active(bs)
	if len(bs) == 0 {
		return nil, ErrNoBackends
	}

	n := len(bs)
	offset := make([]uint64, n)
	skip := make([]uint64, n)
	next := make([]uint64, n)
	credit := make([]uint64, n)
	var maxW uint64
	for i, b := range bs {
		offset[i] = hashName(b.Name, 0xa5) % TableSize
		skip[i] = hashName(b.Name, 0x5a)%(TableSize-1) + 1
		if uint64(b.Weight) > maxW {
			maxW = uint64(b.Weight)
		}
	}

	table := make([]uint32, TableSize)
	filled := make([]bool, TableSize)
	count := 0

	for count < TableSize {
		for i, b := range bs {
			// weights: a backend with half the max weight gets a turn every other round
			credit[i] += uint64(b.Weight)
			for credit[i] >= maxW && count < TableSize {
				credit[i] -= maxW
				c := (offset[i] + next[i]*skip[i]) % TableSize
				for filled[c] {
					next[i]++
					c = (offset[i] + next[i]*skip[i]) % TableSize
				}
				table[c] = b.ID
				filled[c] = true
				next[i]++
				count++
			}
		}
	}
	return table, nil
}

// BuildWRR returns one cycle of smooth weighted round robin (same algorithm
// nginx uses), so heavy backends are spread out instead of bunched up.
// The datapath indexes it with a per-cpu counter, so the split is approximate
// across cpus but exact over a long run.
func BuildWRR(bs []Backend) ([]uint32, error) {
	bs = active(bs)
	if len(bs) == 0 {
		return nil, ErrNoBackends
	}

	g := uint32(0)
	for _, b := range bs {
		g = gcd(g, b.Weight)
	}
	var total int64
	w := make([]int64, len(bs))
	for i, b := range bs {
		w[i] = int64(b.Weight / g)
		total += w[i]
	}
	// the cycle has to fit in the inner map
	if total > TableSize {
		return nil, errors.New("wrr weights too large, reduce them")
	}

	cur := make([]int64, len(bs))
	out := make([]uint32, 0, total)
	for k := int64(0); k < total; k++ {
		best := 0
		for i := range bs {
			cur[i] += w[i]
			if cur[i] > cur[best] {
				best = i
			}
		}
		cur[best] -= total
		out = append(out, bs[best].ID)
	}
	return out, nil
}

func active(bs []Backend) []Backend {
	out := make([]Backend, 0, len(bs))
	for _, b := range bs {
		if b.Weight > 0 {
			out = append(out, b)
		}
	}
	// input order shouldn't matter
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func hashName(s string, salt byte) uint64 {
	h := fnv.New64a()
	h.Write([]byte{salt})
	h.Write([]byte(s))
	return h.Sum64()
}

func gcd(a, b uint32) uint32 {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}
