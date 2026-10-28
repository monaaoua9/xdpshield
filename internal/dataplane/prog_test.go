//go:build linux && integration

// Runs the real program in the kernel through BPF_PROG_TEST_RUN, no nic needed.
// Needs root: sudo go test -tags integration ./internal/dataplane/

package dataplane

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/monaaoua9/xdpshield/internal/config"
	"github.com/monaaoua9/xdpshield/internal/controller"
	"github.com/monaaoua9/xdpshield/internal/statdef"
)

const (
	xdpDrop = 1
	xdpPass = 2
	xdpTX   = 3

	fin = 1
	syn = 2
	rst = 4
	psh = 8
	ack = 16
	urg = 32
)

var (
	lbMAC  = []byte{0x02, 0xaa, 0, 0, 0, 1}
	cliMAC = []byte{0x02, 0xcc, 0, 0, 0, 2}
	vipIP  = netip.MustParseAddr("203.0.113.10")
)

func csum(b []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return ^uint16(s)
}

func ipPkt(proto byte, src, dst netip.Addr, fragField uint16, l4 []byte) []byte {
	h := make([]byte, 20)
	h[0] = 0x45
	binary.BigEndian.PutUint16(h[2:], uint16(20+len(l4)))
	binary.BigEndian.PutUint16(h[6:], fragField)
	h[8] = 64
	h[9] = proto
	s, d := src.As4(), dst.As4()
	copy(h[12:], s[:])
	copy(h[16:], d[:])
	binary.BigEndian.PutUint16(h[10:], csum(h))
	return append(h, l4...)
}

func tcpHdr(sport, dport uint16, flags byte) []byte {
	h := make([]byte, 20)
	binary.BigEndian.PutUint16(h[0:], sport)
	binary.BigEndian.PutUint16(h[2:], dport)
	h[12] = 5 << 4
	h[13] = flags
	return h
}

func udpHdr(sport, dport uint16) []byte {
	h := make([]byte, 8+16)
	binary.BigEndian.PutUint16(h[0:], sport)
	binary.BigEndian.PutUint16(h[2:], dport)
	binary.BigEndian.PutUint16(h[4:], uint16(len(h)))
	return h
}

func frame(ip []byte) []byte {
	f := append(append([]byte{}, lbMAC...), cliMAC...)
	f = append(f, 0x08, 0x00)
	f = append(f, ip...)
	for len(f) < 64 {
		f = append(f, 0)
	}
	return f
}

func tcpFrame(src string, sport uint16, flags byte) []byte {
	return frame(ipPkt(6, netip.MustParseAddr(src), vipIP, 0, tcpHdr(sport, 443, flags)))
}

func udpFrame(src string, sport uint16) []byte {
	return frame(ipPkt(17, netip.MustParseAddr(src), vipIP, 0, udpHdr(sport, 53)))
}

const testCfg = `
interface: lo
encap_src: 10.0.0.1
mtu: 1500
ddos:
  enabled: true
  syn_limit_pps: 5
  udp_limit_pps: 5
  allow: [192.0.2.0/24]
  deny: [198.51.100.0/24]
backends:
  - {name: a, address: 10.0.1.1, mac: "02:00:00:00:01:01"}
  - {name: b, address: 10.0.1.2, mac: "02:00:00:00:01:02"}
  - {name: c, address: 10.0.1.3, mac: "02:00:00:00:01:03"}
vips:
  - name: web
    address: 203.0.113.10
    port: 443
    backends: [{name: a}, {name: b}, {name: c}]
  - name: dns
    address: 203.0.113.10
    port: 53
    proto: udp
    algorithm: wrr
    backends: [{name: a, weight: 3}, {name: b, weight: 1}]
`

func setup(t *testing.T) *Plane {
	t.Helper()
	p, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })

	cfg, err := config.Parse([]byte(testCfg))
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.New(p).Apply(cfg); err != nil {
		t.Fatal(err)
	}
	return p
}

func run(t *testing.T, p *Plane, pkt []byte) (uint32, []byte) {
	t.Helper()
	ret, out, err := p.objs.XdpShield.Test(pkt)
	if err != nil {
		t.Fatal(err)
	}
	return ret, out
}

// backend ip out of an ipip frame, after checking the outer header is sane
func outerDst(t *testing.T, out []byte, inner []byte) netip.Addr {
	t.Helper()
	if len(out) < len(inner)+20 {
		t.Fatalf("short output: %d", len(out))
	}
	oip := out[14:34]
	if oip[0] != 0x45 || oip[9] != 4 {
		t.Fatalf("outer header: % x", oip)
	}
	if csum(oip) != 0 {
		t.Fatalf("outer checksum wrong: % x", oip)
	}
	innerLen := binary.BigEndian.Uint16(inner[16:])
	if got := binary.BigEndian.Uint16(oip[2:]); got != innerLen+20 {
		t.Fatalf("outer tot_len %d, inner %d", got, innerLen)
	}
	if !bytes.Equal(out[34:34+20], inner[14:34]) {
		t.Fatalf("inner ip header changed")
	}
	return netip.AddrFrom4([4]byte(oip[16:20]))
}

func counter(t *testing.T, p *Plane, name string) uint64 {
	t.Helper()
	c, err := p.Counters()
	if err != nil {
		t.Fatal(err)
	}
	for i, n := range statdef.Names {
		if n == name {
			return c[i]
		}
	}
	t.Fatalf("no stat %s", name)
	return 0
}

func TestNonIPv4Passes(t *testing.T) {
	p := setup(t)
	arp := append(append(append([]byte{}, lbMAC...), cliMAC...), 0x08, 0x06)
	arp = append(arp, make([]byte, 50)...)
	if ret, _ := run(t, p, arp); ret != xdpPass {
		t.Fatalf("got %d", ret)
	}
}

func TestUnknownDestinationPasses(t *testing.T) {
	p := setup(t)
	pkt := frame(ipPkt(6, netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("10.9.9.9"), 0, tcpHdr(1000, 80, syn)))
	if ret, _ := run(t, p, pkt); ret != xdpPass {
		t.Fatalf("got %d", ret)
	}
}

func TestVIPIsEncapsulatedAndSticky(t *testing.T) {
	p := setup(t)
	pkt := tcpFrame("1.1.1.1", 40000, ack)

	ret, out := run(t, p, pkt)
	if ret != xdpTX {
		t.Fatalf("got %d", ret)
	}
	first := outerDst(t, out, pkt)
	if !bytes.Equal(out[0:6], []byte{0x02, 0, 0, 0, 1, first.As4()[3]}) {
		t.Fatalf("dst mac % x for %s", out[0:6], first)
	}
	if !bytes.Equal(out[6:12], lbMAC) {
		t.Fatalf("src mac % x", out[6:12])
	}

	for i := 0; i < 20; i++ {
		_, out := run(t, p, pkt)
		if got := outerDst(t, out, pkt); got != first {
			t.Fatalf("flow moved from %s to %s", first, got)
		}
	}
	if counter(t, p, "ct_hit") < 20 {
		t.Fatal("conntrack not used")
	}
}

func TestMaglevSpreadsFlows(t *testing.T) {
	p := setup(t)
	seen := map[netip.Addr]int{}
	for i := 0; i < 600; i++ {
		src := netip.AddrFrom4([4]byte{100, 64, byte(i >> 8), byte(i)}).String()
		pkt := tcpFrame(src, uint16(2000+i), ack)
		ret, out := run(t, p, pkt)
		if ret != xdpTX {
			t.Fatalf("flow %d: %d", i, ret)
		}
		seen[outerDst(t, out, pkt)]++
	}
	if len(seen) != 3 {
		t.Fatalf("only %v", seen)
	}
	for ip, n := range seen {
		if n < 120 || n > 280 {
			t.Errorf("%s got %d of 600", ip, n)
		}
	}
}

func TestWRRRatio(t *testing.T) {
	p := setup(t)
	// the cursor is per cpu, test_run executes on whatever cpu we're on, so
	// use distinct flows and just check the overall ratio
	seen := map[netip.Addr]int{}
	for i := 0; i < 400; i++ {
		src := netip.AddrFrom4([4]byte{100, 65, byte(i >> 8), byte(i)}).String()
		pkt := udpFrame(src, uint16(3000+i))
		ret, out := run(t, p, pkt)
		if ret != xdpTX {
			t.Fatalf("got %d", ret)
		}
		seen[outerDst(t, out, pkt)]++
	}
	a, b := seen[netip.MustParseAddr("10.0.1.1")], seen[netip.MustParseAddr("10.0.1.2")]
	if a < 250 || a > 350 || b < 50 || b > 150 {
		t.Fatalf("wrr split %v", seen)
	}
}

func TestSynFloodBlocksSource(t *testing.T) {
	p := setup(t)
	src := "45.9.9.9"

	for i := 0; i < 5; i++ {
		if ret, _ := run(t, p, tcpFrame(src, uint16(5000+i), syn)); ret != xdpTX {
			t.Fatalf("syn %d dropped early: %d", i, ret)
		}
	}
	if ret, _ := run(t, p, tcpFrame(src, 5006, syn)); ret != xdpDrop {
		t.Fatalf("flood not dropped: %d", ret)
	}
	// once blocked, everything from that source dies in the first lookup
	if ret, _ := run(t, p, tcpFrame(src, 5000, ack)); ret != xdpDrop {
		t.Fatalf("established-looking packet got through: %d", ret)
	}
	if counter(t, p, "drop_syn_flood") != 1 || counter(t, p, "drop_blocked") != 1 {
		t.Fatal("counters off")
	}

	list, err := p.Blocked()
	if err != nil || len(list) != 1 || list[0].Addr.String() != src {
		t.Fatalf("blocked list: %v %v", list, err)
	}

	rd, err := p.Events()
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()
	ev, err := rd.Next()
	if err != nil || ev.Src != src || ev.Reason != "syn_flood" {
		t.Fatalf("event %+v %v", ev, err)
	}

	// other sources are untouched
	if ret, _ := run(t, p, tcpFrame("45.9.9.10", 1234, syn)); ret != xdpTX {
		t.Fatal("innocent source affected")
	}

	if err := p.Unblock(netip.MustParseAddr(src)); err != nil {
		t.Fatal(err)
	}
	if ret, _ := run(t, p, tcpFrame(src, 5000, ack)); ret != xdpTX {
		t.Fatal("unblock didn't work")
	}
}

func TestUDPFlood(t *testing.T) {
	p := setup(t)
	var dropped int
	for i := 0; i < 20; i++ {
		if ret, _ := run(t, p, udpFrame("45.8.8.8", uint16(7000+i))); ret == xdpDrop {
			dropped++
		}
	}
	if dropped != 15 { // 5 pass, the 6th trips the block and the other 14 hit the blocklist
		t.Fatalf("dropped %d of 20", dropped)
	}
}

func TestAllowlistSkipsRateLimit(t *testing.T) {
	p := setup(t)
	for i := 0; i < 50; i++ {
		if ret, _ := run(t, p, tcpFrame("192.0.2.7", uint16(9000+i), syn)); ret != xdpTX {
			t.Fatalf("allowlisted source dropped at %d", i)
		}
	}
}

func TestDenylist(t *testing.T) {
	p := setup(t)
	if ret, _ := run(t, p, tcpFrame("198.51.100.4", 1234, syn)); ret != xdpDrop {
		t.Fatal("denied source passed")
	}
	if counter(t, p, "drop_denylist") != 1 {
		t.Fatal("counter")
	}
}

func TestBadTCPFlags(t *testing.T) {
	p := setup(t)
	for name, f := range map[string]byte{
		"null":    0,
		"xmas":    fin | psh | urg,
		"synfin":  syn | fin,
		"synrst":  syn | rst,
		"finonly": fin,
	} {
		if ret, _ := run(t, p, tcpFrame("77.7.7.7", 4444, f)); ret != xdpDrop {
			t.Errorf("%s: got %d", name, ret)
		}
	}
}

func TestMalformedAndFragments(t *testing.T) {
	p := setup(t)

	// martian source
	if ret, _ := run(t, p, tcpFrame("127.0.0.1", 1111, syn)); ret != xdpDrop {
		t.Error("loopback source passed")
	}
	// tot_len bigger than the frame
	bad := tcpFrame("8.8.4.4", 1111, syn)
	binary.BigEndian.PutUint16(bad[16:], 1400)
	if ret, _ := run(t, p, bad); ret != xdpDrop {
		t.Error("lying tot_len passed")
	}
	// fragment aimed at the vip
	frag := frame(ipPkt(17, netip.MustParseAddr("8.8.4.4"), vipIP, 0x2000, udpHdr(1, 53)))
	if ret, _ := run(t, p, frag); ret != xdpDrop {
		t.Error("fragment passed")
	}
	// source port 0
	if ret, _ := run(t, p, tcpFrame("8.8.4.4", 0, ack)); ret != xdpDrop {
		t.Error("port 0 passed")
	}
}

func TestOversizeDFGetsFragNeeded(t *testing.T) {
	p := setup(t)
	client := netip.MustParseAddr("8.8.8.8")
	big := frame(ipPkt(6, client, vipIP, 0x4000, append(tcpHdr(1234, 443, ack), make([]byte, 1460)...)))

	ret, out := run(t, p, big)
	if ret != xdpTX {
		t.Fatalf("got %d", ret)
	}
	if len(out) != 70 {
		t.Fatalf("reply is %d bytes", len(out))
	}
	// macs swapped back to the sender
	if !bytes.Equal(out[0:6], cliMAC) || !bytes.Equal(out[6:12], lbMAC) {
		t.Fatalf("macs % x / % x", out[0:6], out[6:12])
	}
	ip, ic := out[14:34], out[34:]
	if csum(ip) != 0 || csum(ic) != 0 {
		t.Fatal("bad checksum")
	}
	if ip[9] != 1 || netip.AddrFrom4([4]byte(ip[12:16])) != vipIP || netip.AddrFrom4([4]byte(ip[16:20])) != client {
		t.Fatalf("ip header % x", ip)
	}
	if ic[0] != 3 || ic[1] != 4 {
		t.Fatalf("icmp type/code %d/%d", ic[0], ic[1])
	}
	if mtu := binary.BigEndian.Uint16(ic[6:]); mtu != 1480 {
		t.Fatalf("advertised mtu %d", mtu)
	}
	if !bytes.Equal(ic[8:], big[14:42]) {
		t.Fatal("quoted packet differs from the original")
	}
	if counter(t, p, "icmp_frag_needed") != 1 || counter(t, p, "drop_mtu") != 1 {
		t.Fatal("counters")
	}
}

func TestOversizeDropped(t *testing.T) {
	p := setup(t)
	big := frame(ipPkt(17, netip.MustParseAddr("8.8.8.8"), vipIP, 0, make([]byte, 1475)))
	// ipPkt wrote tot_len = 20+1475 = 1495, +20 for the tunnel > 1500? no: 1515 > 1500
	// udp header inside is zeros so this has port 0 -> fix ports first
	binary.BigEndian.PutUint16(big[34:], 1234)
	binary.BigEndian.PutUint16(big[36:], 53)
	if ret, _ := run(t, p, big); ret != xdpDrop {
		t.Fatalf("got %d", ret)
	}
	if counter(t, p, "drop_mtu") != 1 {
		t.Fatal("not counted as mtu drop")
	}
}
