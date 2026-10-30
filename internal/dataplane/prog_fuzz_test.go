//go:build linux && integration

package dataplane

import (
	"net/netip"
	"testing"

	"github.com/monaaoua9/xdpshield/internal/config"
	"github.com/monaaoua9/xdpshield/internal/controller"
)

// not much to assert on random bytes except that the kernel accepts the run
// and the verdict is one we know. mostly here to shake out out-of-bounds
// reads the verifier can't see (it only proves the accesses are checked).
func FuzzXDP(f *testing.F) {
	p, err := Load()
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { p.Close() })

	raw := testCfg6 // v6 lab plus a v4 vip below
	cfg, err := config.Parse([]byte(raw + "  - {name: web4, address: 203.0.113.10, port: 443, backends: [{name: a}, {name: b}]}\n"))
	if err != nil {
		f.Fatal(err)
	}
	if err := controller.New(p).Apply(cfg); err != nil {
		f.Fatal(err)
	}

	cli4, cli6 := netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2001:db8:1::1")
	for _, seed := range [][]byte{
		frame(ipPkt(6, cli4, vipIP, 0, tcpHdr(4000, 443, syn))),
		frame(ipPkt(17, cli4, vipIP, 0, udpHdr(4000, 53))),
		frame(ipPkt(6, cli4, vipIP, 0x2000, tcpHdr(4000, 443, ack))),
		frame6(ip6Pkt(6, cli6, vip6, tcpHdr(4000, 443, syn))),
		frame6(ip6Pkt(17, cli6, vip6, udpHdr(4000, 53))),
		frame6(ip6Pkt(44, cli6, vip6, make([]byte, 28))),
		frame6(ip6Pkt(17, cli6, vip6, make([]byte, 1500))),
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, pkt []byte) {
		if len(pkt) < 14 {
			t.Skip() // BPF_PROG_TEST_RUN refuses runs shorter than an ethernet header
		}
		ret, _, err := p.objs.XdpShield.Test(pkt)
		if err != nil {
			t.Fatal(err)
		}
		if ret != xdpDrop && ret != xdpPass && ret != xdpTX {
			t.Fatalf("verdict %d", ret)
		}
	})
}
