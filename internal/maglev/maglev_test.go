package maglev

import (
	"math"
	"testing"
)

func share(t []uint32) map[uint32]int {
	m := map[uint32]int{}
	for _, id := range t {
		m[id]++
	}
	return m
}

func TestBuildFillsEverySlot(t *testing.T) {
	tbl, err := Build([]Backend{{"a", 0, 1}, {"b", 1, 1}, {"c", 2, 1}})
	if err != nil {
		t.Fatal(err)
	}
	if len(tbl) != TableSize {
		t.Fatalf("len %d", len(tbl))
	}
	total := 0
	for _, n := range share(tbl) {
		total += n
	}
	if total != TableSize {
		t.Fatalf("lost slots: %d", total)
	}
}

func TestBuildEvenSplit(t *testing.T) {
	tbl, _ := Build([]Backend{{"a", 0, 1}, {"b", 1, 1}, {"c", 2, 1}, {"d", 3, 1}})
	want := float64(TableSize) / 4
	for id, n := range share(tbl) {
		if math.Abs(float64(n)-want)/want > 0.01 {
			t.Errorf("backend %d got %d, want ~%.0f", id, n, want)
		}
	}
}

func TestBuildWeighted(t *testing.T) {
	tbl, _ := Build([]Backend{{"a", 0, 300}, {"b", 1, 100}})
	s := share(tbl)
	ratio := float64(s[0]) / float64(s[1])
	if math.Abs(ratio-3) > 0.05 {
		t.Fatalf("ratio %.3f, want 3", ratio)
	}
}

func TestBuildDeterministicAcrossOrder(t *testing.T) {
	a, _ := Build([]Backend{{"x", 0, 1}, {"y", 1, 1}, {"z", 2, 1}})
	b, _ := Build([]Backend{{"z", 2, 1}, {"x", 0, 1}, {"y", 1, 1}})
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("tables differ at %d", i)
		}
	}
}

func TestBuildMinimalDisruption(t *testing.T) {
	bs := []Backend{}
	for i, n := range []string{"b0", "b1", "b2", "b3", "b4", "b5", "b6", "b7", "b8", "b9"} {
		bs = append(bs, Backend{n, uint32(i), 1})
	}
	before, _ := Build(bs)
	after, _ := Build(bs[:9]) // drop b9

	moved := 0
	for i := range before {
		// slots that belonged to a surviving backend should mostly stay put
		if before[i] != 9 && before[i] != after[i] {
			moved++
		}
	}
	// maglev isn't perfect, google's paper shows a few percent
	if frac := float64(moved) / TableSize; frac > 0.08 {
		t.Fatalf("%.1f%% of surviving slots moved", frac*100)
	}
}

func TestZeroWeightIgnored(t *testing.T) {
	tbl, _ := Build([]Backend{{"a", 0, 1}, {"b", 1, 0}})
	for _, id := range tbl {
		if id != 0 {
			t.Fatal("zero weight backend got traffic")
		}
	}
	if _, err := Build([]Backend{{"a", 0, 0}}); err != ErrNoBackends {
		t.Fatalf("got %v", err)
	}
}

func TestWRRSmoothAndProportional(t *testing.T) {
	seq, err := BuildWRR([]Backend{{"a", 0, 5}, {"b", 1, 1}, {"c", 2, 1}})
	if err != nil {
		t.Fatal(err)
	}
	if len(seq) != 7 {
		t.Fatalf("cycle len %d", len(seq))
	}
	s := share(seq)
	if s[0] != 5 || s[1] != 1 || s[2] != 1 {
		t.Fatalf("share %v", s)
	}
	// nginx's example: a a b a c a a, never five a in a row
	run, best := 0, 0
	for _, id := range seq {
		if id == 0 {
			run++
		} else {
			run = 0
		}
		if run > best {
			best = run
		}
	}
	if best > 2 {
		t.Fatalf("heavy backend bunched up: %v", seq)
	}
}

func TestWRRReducesWeights(t *testing.T) {
	seq, _ := BuildWRR([]Backend{{"a", 0, 100}, {"b", 1, 200}})
	if len(seq) != 3 {
		t.Fatalf("cycle len %d, want 3", len(seq))
	}
}
