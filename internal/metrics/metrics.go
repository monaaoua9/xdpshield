package metrics

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"

	"github.com/monaaoua9/xdpshield/internal/controller"
	"github.com/monaaoua9/xdpshield/internal/statdef"
	"github.com/prometheus/client_golang/prometheus"
)

// Source is the read side of the datapath
type Source interface {
	Counters() ([]uint64, error)
	BackendTraffic(id uint32) (statdef.Traffic, error)
	VIPTraffic(id uint32) (statdef.Traffic, error)
}

type Topology interface {
	Snapshot() ([]controller.VIPInfo, []controller.BackendInfo)
}

// Collector reads kernel counters on scrape, nothing is polled in the background
type Collector struct {
	src  Source
	topo Topology

	counters map[string]*prometheus.Desc
	dropped  *prometheus.Desc
	vipPkts  *prometheus.Desc
	vipBytes *prometheus.Desc
	bePkts   *prometheus.Desc
	beBytes  *prometheus.Desc
	beUp     *prometheus.Desc
}

var simple = map[string]string{
	"rx_pkts":      "xdpshield_rx_packets_total",
	"rx_bytes":     "xdpshield_rx_bytes_total",
	"pass":         "xdpshield_passed_packets_total",
	"lb_fwd":       "xdpshield_forwarded_packets_total",
	"lb_fwd_bytes": "xdpshield_forwarded_bytes_total",
	"ct_hit":       "xdpshield_conntrack_hits_total",
	"ct_new":       "xdpshield_conntrack_new_flows_total",
	"allowlisted":  "xdpshield_allowlisted_packets_total",
	"block_added":  "xdpshield_sources_blocked_total",
	"event_lost":   "xdpshield_events_lost_total",

	"icmp_frag_needed": "xdpshield_icmp_frag_needed_total",
	"icmp6_too_big":    "xdpshield_icmp6_too_big_total",
}

func NewCollector(src Source, topo Topology) *Collector {
	c := &Collector{src: src, topo: topo, counters: map[string]*prometheus.Desc{}}
	for stat, name := range simple {
		c.counters[stat] = prometheus.NewDesc(name, "datapath counter "+stat, nil, nil)
	}
	c.dropped = prometheus.NewDesc("xdpshield_dropped_packets_total", "packets dropped in XDP", []string{"reason"}, nil)
	c.vipPkts = prometheus.NewDesc("xdpshield_vip_packets_total", "packets balanced per vip", []string{"vip"}, nil)
	c.vipBytes = prometheus.NewDesc("xdpshield_vip_bytes_total", "bytes balanced per vip", []string{"vip"}, nil)
	c.bePkts = prometheus.NewDesc("xdpshield_backend_packets_total", "packets sent to backend", []string{"backend"}, nil)
	c.beBytes = prometheus.NewDesc("xdpshield_backend_bytes_total", "bytes sent to backend", []string{"backend"}, nil)
	c.beUp = prometheus.NewDesc("xdpshield_backend_up", "1 if the backend passes health checks", []string{"backend"}, nil)
	return c
}

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range c.counters {
		ch <- d
	}
	for _, d := range []*prometheus.Desc{c.dropped, c.vipPkts, c.vipBytes, c.bePkts, c.beBytes, c.beUp} {
		ch <- d
	}
}

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	vals, err := c.src.Counters()
	if err != nil {
		slog.Error("read counters", "err", err)
		return
	}
	for i, name := range statdef.Names {
		if d, ok := c.counters[name]; ok {
			ch <- prometheus.MustNewConstMetric(d, prometheus.CounterValue, float64(vals[i]))
		} else if reason, ok := strings.CutPrefix(name, "drop_"); ok {
			ch <- prometheus.MustNewConstMetric(c.dropped, prometheus.CounterValue, float64(vals[i]), reason)
		}
	}

	vips, bes := c.topo.Snapshot()
	for _, v := range vips {
		if t, err := c.src.VIPTraffic(v.ID); err == nil {
			ch <- prometheus.MustNewConstMetric(c.vipPkts, prometheus.CounterValue, float64(t.Pkts), v.Name)
			ch <- prometheus.MustNewConstMetric(c.vipBytes, prometheus.CounterValue, float64(t.Bytes), v.Name)
		}
	}
	for _, b := range bes {
		up := 0.0
		if b.Healthy {
			up = 1
		}
		ch <- prometheus.MustNewConstMetric(c.beUp, prometheus.GaugeValue, up, b.Name)
		if t, err := c.src.BackendTraffic(b.ID); err == nil {
			ch <- prometheus.MustNewConstMetric(c.bePkts, prometheus.CounterValue, float64(t.Pkts), b.Name)
			ch <- prometheus.MustNewConstMetric(c.beBytes, prometheus.CounterValue, float64(t.Bytes), b.Name)
		}
	}
}

// Events drains the ring buffer. Per-ip labels would blow up cardinality
// during an attack, so ips only go to the log and the recent list.
type EventSource interface {
	Next() (statdef.BlockEvent, error)
}

type Events struct {
	byReason *prometheus.CounterVec

	mu     sync.Mutex
	recent []statdef.BlockEvent
	pos    int
	full   bool
}

const keep = 256

func NewEvents(reg prometheus.Registerer) *Events {
	e := &Events{
		byReason: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "xdpshield_block_events_total",
			Help: "block events received from the kernel ring buffer",
		}, []string{"reason"}),
		recent: make([]statdef.BlockEvent, keep),
	}
	reg.MustRegister(e.byReason)
	return e
}

// Run returns when the source is closed or ctx is done
func (e *Events) Run(ctx context.Context, src EventSource, closed error) {
	for ctx.Err() == nil {
		ev, err := src.Next()
		if errors.Is(err, closed) {
			return
		}
		if err != nil {
			slog.Error("ring buffer read", "err", err)
			continue
		}
		e.byReason.WithLabelValues(ev.Reason).Inc()
		slog.Warn("source blocked", "src", ev.Src, "reason", ev.Reason, "pps", ev.PPS)

		e.mu.Lock()
		e.recent[e.pos] = ev
		e.pos = (e.pos + 1) % keep
		if e.pos == 0 {
			e.full = true
		}
		e.mu.Unlock()
	}
}

// Recent returns newest first
func (e *Events) Recent(limit int) []statdef.BlockEvent {
	e.mu.Lock()
	defer e.mu.Unlock()

	n := e.pos
	if e.full {
		n = keep
	}
	if limit <= 0 || limit > n {
		limit = n
	}
	out := make([]statdef.BlockEvent, 0, limit)
	for i := 1; i <= limit; i++ {
		out = append(out, e.recent[(e.pos-i+keep)%keep])
	}
	return out
}
