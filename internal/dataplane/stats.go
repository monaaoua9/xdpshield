//go:build linux

package dataplane

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/monaaoua9/xdpshield/internal/statdef"
)

type (
	Traffic    = statdef.Traffic
	BlockEvent = statdef.BlockEvent
)

// Counters sums the per-cpu stat slots, indexed like statdef.Names
func (p *Plane) Counters() ([]uint64, error) {
	out := make([]uint64, len(statdef.Names))
	for i := range out {
		var percpu []uint64
		if err := p.objs.Stats.Lookup(uint32(i), &percpu); err != nil {
			return nil, fmt.Errorf("stat %s: %w", statdef.Names[i], err)
		}
		for _, v := range percpu {
			out[i] += v
		}
	}
	return out, nil
}

func (p *Plane) BackendTraffic(id uint32) (Traffic, error) {
	var percpu []ShieldTrafficStat
	if err := p.objs.BackendStats.Lookup(id, &percpu); err != nil {
		return Traffic{}, err
	}
	return sum(percpu), nil
}

func (p *Plane) VIPTraffic(id uint32) (Traffic, error) {
	var percpu []ShieldTrafficStat
	if err := p.objs.VipStats.Lookup(id, &percpu); err != nil {
		return Traffic{}, err
	}
	return sum(percpu), nil
}

func sum(in []ShieldTrafficStat) (t Traffic) {
	for _, s := range in {
		t.Pkts += s.Pkts
		t.Bytes += s.Bytes
	}
	return
}

// TrackedFlows is a rough count, iterating a 500k entry lru isn't free so
// callers shouldn't hit this on every scrape
func (p *Plane) TrackedFlows() (n int) {
	var k ShieldFlowKey
	var v ShieldFlowVal
	it := p.objs.ConnTrack.Iterate()
	for it.Next(&k, &v) {
		n++
	}
	var k6 ShieldFlowKey6
	it = p.objs.ConnTrack6.Iterate()
	for it.Next(&k6, &v) {
		n++
	}
	return
}

type EventReader struct {
	rd   *ringbuf.Reader
	boot time.Time
}

func (p *Plane) Events() (*EventReader, error) {
	rd, err := ringbuf.NewReader(p.objs.Events)
	if err != nil {
		return nil, err
	}
	// bpf timestamps are monotonic ns, remember where that clock is now
	boot := time.Now().Add(-time.Duration(nowMonotonic()))
	return &EventReader{rd: rd, boot: boot}, nil
}

var ErrClosed = errors.New("event reader closed")

func (r *EventReader) Next() (BlockEvent, error) {
	for {
		rec, err := r.rd.Read()
		if errors.Is(err, ringbuf.ErrClosed) {
			return BlockEvent{}, ErrClosed
		}
		if err != nil {
			return BlockEvent{}, err
		}

		var raw ShieldBlockEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.NativeEndian, &raw); err != nil {
			continue // short sample, skip it
		}
		src := fromAddr32(raw.Src)
		if raw.Family == 6 {
			src = netip.AddrFrom16(raw.Src6.B)
		}
		return BlockEvent{
			At:     r.boot.Add(time.Duration(raw.TsNs)),
			Src:    src.String(),
			Reason: statdef.ReasonName(raw.Reason),
			PPS:    raw.ObservedPps,
		}, nil
	}
}

func (r *EventReader) Close() error { return r.rd.Close() }
