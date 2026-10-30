//go:build linux && integration

// sudo go test -tags integration -run xxx -bench . ./internal/dataplane/
// ns/pkt is the kernel's own average over Repeat runs of BPF_PROG_TEST_RUN, so it
// is the program cost only: no driver, no dma, no skb.

package dataplane

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/monaaoua9/xdpshield/internal/config"
	"github.com/monaaoua9/xdpshield/internal/controller"
)

func benchPlane(b *testing.B) *Plane {
	b.Helper()
	p, err := Load()
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { p.Close() })

	raw := strings.NewReplacer(
		"syn_limit_pps: 5", "syn_limit_pps: 2000000000",
		"udp_limit_pps: 5", "udp_limit_pps: 2000000000",
		"deny: [198.51.100.0/24]", "deny: [198.51.100.0/24, 2001:db8:dead::/48]",
		"vips:\n", "vips:\n  - {name: web6, address: \"2001:db8:100::10\", port: 443, backends: [{name: a}, {name: b}, {name: c}]}\n",
	).Replace(testCfg)
	cfg, err := config.Parse([]byte(raw))
	if err != nil {
		b.Fatal(err)
	}
	if err := controller.New(p).Apply(cfg); err != nil {
		b.Fatal(err)
	}
	return p
}

func BenchmarkXDP(b *testing.B) {
	p := benchPlane(b)
	if err := p.Block(netip.MustParseAddr("100.100.0.9"), time.Hour); err != nil {
		b.Fatal(err)
	}

	arp := append(append(append([]byte{}, lbMAC...), cliMAC...), 0x08, 0x06)
	arp = append(arp, make([]byte, 50)...)
	hostTCP := frame(ipPkt(6, netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("10.9.9.9"), 0, tcpHdr(1000, 80, ack)))

	cases := []struct {
		name string
		pkt  []byte
	}{
		{"pass_non_ip", arp},
		{"pass_host_traffic", hostTCP},
		{"drop_denylist", tcpFrame("198.51.100.7", 1234, syn)},
		{"drop_dyn_blocklist", tcpFrame("100.100.0.9", 1234, syn)},
		{"drop_bad_flags", tcpFrame("1.1.1.1", 1234, 0)},
		{"lb_tcp_established", tcpFrame("1.1.1.1", 40000, ack)},
		{"lb_tcp_syn", tcpFrame("1.1.1.2", 40001, syn)},
		{"lb_udp_wrr", udpFrame("1.1.1.3", 5000)},
		{"allowlisted_lb", tcpFrame("192.0.2.5", 40000, ack)},
		{"v6_drop_denylist", tcp6("2001:db8:dead::5", 1234, syn)},
		{"v6_lb_tcp_established", tcp6("2001:db8:1::1", 40000, ack)},
		{"v6_lb_tcp_syn", tcp6("2001:db8:1::2", 40001, syn)},
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			// prime conntrack so the flow cases measure the steady state
			if _, _, err := p.objs.XdpShield.Test(c.pkt); err != nil {
				b.Fatal(err)
			}
			_, d, err := p.objs.XdpShield.Benchmark(c.pkt, b.N, nil)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportMetric(float64(d.Nanoseconds()), "ns/pkt")
			b.ReportMetric(1e3/float64(d.Nanoseconds()), "Mpps/core")
		})
	}
}
