package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

type sample struct {
	at  time.Time
	val map[string]float64 // full series name incl. labels
}

func parseMetrics(raw []byte) map[string]float64 {
	out := map[string]float64{}
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "xdpshield_") {
			continue
		}
		i := strings.LastIndexByte(line, ' ')
		if i < 0 {
			continue
		}
		if v, err := strconv.ParseFloat(line[i+1:], 64); err == nil {
			out[line[:i]] = v
		}
	}
	return out
}

// rate per second between two samples, 0 if the counter went backwards (restart)
func rate(prev, cur *sample, series string) float64 {
	dt := cur.at.Sub(prev.at).Seconds()
	d := cur.val[series] - prev.val[series]
	if dt <= 0 || d < 0 {
		return 0
	}
	return d / dt
}

func render(prev, cur *sample, backends []topBackend, events []topEvent) string {
	var sb strings.Builder
	w := tabwriter.NewWriter(&sb, 0, 4, 2, ' ', 0)

	fmt.Fprintf(w, "xdpshield   %s\n\n", cur.at.Format("15:04:05"))
	fmt.Fprintf(w, "rx\t%s pps\t%s bit/s\n", human(rate(prev, cur, "xdpshield_rx_packets_total")),
		human(rate(prev, cur, "xdpshield_rx_bytes_total")*8))
	fmt.Fprintf(w, "forwarded\t%s pps\t%s bit/s\n", human(rate(prev, cur, "xdpshield_forwarded_packets_total")),
		human(rate(prev, cur, "xdpshield_forwarded_bytes_total")*8))
	fmt.Fprintf(w, "passed to host\t%s pps\n", human(rate(prev, cur, "xdpshield_passed_packets_total")))
	fmt.Fprintf(w, "new flows\t%s /s\t(conntrack hits %s /s)\n", human(rate(prev, cur, "xdpshield_conntrack_new_flows_total")),
		human(rate(prev, cur, "xdpshield_conntrack_hits_total")))
	fmt.Fprintf(w, "sources blocked\t%s total\n\n", human(cur.val["xdpshield_sources_blocked_total"]))

	type kv struct {
		reason string
		pps    float64
	}
	var drops []kv
	for series := range cur.val {
		if r, ok := strings.CutPrefix(series, `xdpshield_dropped_packets_total{reason="`); ok {
			r = strings.TrimSuffix(r, `"}`)
			drops = append(drops, kv{r, rate(prev, cur, series)})
		}
	}
	sort.Slice(drops, func(i, j int) bool {
		if drops[i].pps != drops[j].pps {
			return drops[i].pps > drops[j].pps
		}
		return drops[i].reason < drops[j].reason
	})
	fmt.Fprintln(w, "DROPS\tPPS")
	shown := 0
	for _, d := range drops {
		if d.pps == 0 {
			continue
		}
		fmt.Fprintf(w, "%s\t%s\n", d.reason, human(d.pps))
		shown++
	}
	if shown == 0 {
		fmt.Fprintln(w, "-\t0")
	}

	fmt.Fprintln(w, "\nBACKEND\tHEALTH\tPPS")
	for _, b := range backends {
		h := "up"
		if !b.Healthy {
			h = "DOWN"
		}
		series := fmt.Sprintf(`xdpshield_backend_packets_total{backend=%q}`, b.Name)
		fmt.Fprintf(w, "%s\t%s\t%s\n", b.Name, h, human(rate(prev, cur, series)))
	}

	if len(events) > 0 {
		fmt.Fprintln(w, "\nRECENT BLOCKS\tREASON\tPPS")
		for _, e := range events {
			fmt.Fprintf(w, "%s %s\t%s\t%d\n", e.At.Local().Format("15:04:05"), e.Src, e.Reason, e.PPS)
		}
	}
	w.Flush()
	return sb.String()
}

type topBackend struct {
	Name    string `json:"name"`
	Healthy bool   `json:"healthy"`
}

type topEvent struct {
	At     time.Time `json:"at"`
	Src    string    `json:"src"`
	Reason string    `json:"reason"`
	PPS    uint32    `json:"observed_pps"`
}

func (c *client) take() (*sample, error) {
	raw, err := c.do("GET", "/metrics", nil)
	if err != nil {
		return nil, err
	}
	return &sample{at: time.Now(), val: parseMetrics(raw)}, nil
}

func (c *client) top(out io.Writer, every time.Duration) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	prev, err := c.take()
	if err != nil {
		return err
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
		cur, err := c.take()
		if err != nil {
			return err
		}

		var st struct {
			Backends []topBackend `json:"backends"`
		}
		var evs []topEvent
		if err := c.get("/api/v1/status", &st); err != nil {
			return err
		}
		if err := c.get("/api/v1/events?limit=5", &evs); err != nil {
			return err
		}
		fmt.Fprint(out, "\x1b[H\x1b[2J", render(prev, cur, st.Backends, evs))
		prev = cur
	}
}
