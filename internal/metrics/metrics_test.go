package metrics

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/monaaoua9/xdpshield/internal/controller"
	"github.com/monaaoua9/xdpshield/internal/statdef"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

type fakeSrc struct{}

func (fakeSrc) Counters() ([]uint64, error) {
	v := make([]uint64, len(statdef.Names))
	for i, n := range statdef.Names {
		if n == "drop_syn_flood" {
			v[i] = 42
		}
		if n == "rx_pkts" {
			v[i] = 7
		}
	}
	return v, nil
}
func (fakeSrc) BackendTraffic(uint32) (statdef.Traffic, error) {
	return statdef.Traffic{Pkts: 5, Bytes: 500}, nil
}
func (fakeSrc) VIPTraffic(uint32) (statdef.Traffic, error) {
	return statdef.Traffic{Pkts: 9, Bytes: 900}, nil
}

type fakeTopo struct{}

func (fakeTopo) Snapshot() ([]controller.VIPInfo, []controller.BackendInfo) {
	return []controller.VIPInfo{{Name: "web", ID: 0}}, []controller.BackendInfo{{Name: "a", ID: 0, Healthy: true}}
}

func TestCollect(t *testing.T) {
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(NewCollector(fakeSrc{}, fakeTopo{}))

	got, err := testutil.GatherAndCount(reg, "xdpshield_dropped_packets_total")
	if err != nil || got != 11 {
		t.Fatalf("drop series: %d, %v", got, err)
	}

	n, err := testutil.GatherAndCount(reg)
	if err != nil {
		t.Fatal(err)
	}
	if n < 20 {
		t.Fatalf("only %d series", n)
	}
}

type scripted struct{ evs []statdef.BlockEvent }

var errDone = errors.New("done")

func (s *scripted) Next() (statdef.BlockEvent, error) {
	if len(s.evs) == 0 {
		return statdef.BlockEvent{}, errDone
	}
	e := s.evs[0]
	s.evs = s.evs[1:]
	return e, nil
}

func TestEventsRecentNewestFirst(t *testing.T) {
	reg := prometheus.NewRegistry()
	e := NewEvents(reg)
	src := &scripted{}
	for i := 0; i < keep+10; i++ {
		src.evs = append(src.evs, statdef.BlockEvent{At: time.Unix(int64(i), 0), Reason: "syn_flood", PPS: uint32(i)})
	}
	e.Run(context.Background(), src, errDone)

	got := e.Recent(3)
	if len(got) != 3 || got[0].PPS != keep+9 || got[2].PPS != keep+7 {
		t.Fatalf("recent: %+v", got)
	}
	if len(e.Recent(0)) != keep {
		t.Fatal("ring should cap at keep")
	}
	if c := testutil.ToFloat64(e.byReason.WithLabelValues("syn_flood")); c != keep+10 {
		t.Fatalf("counter %v", c)
	}
}
