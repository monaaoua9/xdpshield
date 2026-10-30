//go:build linux && integration

package dataplane

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/monaaoua9/xdpshield/internal/config"
	"github.com/monaaoua9/xdpshield/internal/controller"
)

var vip6 = netip.MustParseAddr("2001:db8:100::10")

const testCfg6 = `
interface: lo
encap_src: 10.0.0.1
mtu: 1500
ddos:
  enabled: true
  syn_limit_pps: 5
  udp_limit_pps: 5
  allow: [2001:db8:a110::/48]
  deny: [2001:db8:dead::/48]
backends:
  - {name: a, address: 10.0.1.1, mac: "02:00:00:00:01:01"}
  - {name: b, address: 10.0.1.2, mac: "02:00:00:00:01:02"}
  - {name: c, address: 10.0.1.3, mac: "02:00:00:00:01:03"}
vips:
  - name: web6
    address: 2001:db8:100::10
    port: 443
    backends: [{name: a}, {name: b}, {name: c}]
  - name: dns6
    address: 2001:db8:100::10
    port: 53
    proto: udp
    backends: [{name: a}, {name: b}]
`

func setup6(t *testing.T) *Plane {
	t.Helper()
	p, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })

	cfg, err := config.Parse([]byte(testCfg6))
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.New(p).Apply(cfg); err != nil {
		t.Fatal(err)
	}
	return p
}

func ip6Pkt(next byte, src, dst netip.Addr, l4 []byte) []byte {
	h := make([]byte, 40)
	h[0] = 0x60
	binary.BigEndian.PutUint16(h[4:], uint16(len(l4)))
	h[6] = next
	h[7] = 64
	s, d := src.As16(), dst.As16()
	copy(h[8:], s[:])
	copy(h[24:], d[:])
	return append(h, l4...)
}

func frame6(ip []byte) []byte {
	f := append(append([]byte{}, lbMAC...), cliMAC...)
	f = append(f, 0x86, 0xdd)
	f = append(f, ip...)
	for len(f) < 80 {
		f = append(f, 0)
	}
	return f
}

func tcp6(src string, sport uint16, flags byte) []byte {
	return frame6(ip6Pkt(6, netip.MustParseAddr(src), vip6, tcpHdr(sport, 443, flags)))
}

func udp6(src string, sport uint16) []byte {
	return frame6(ip6Pkt(17, netip.MustParseAddr(src), vip6, udpHdr(sport, 53)))
}

// checks the 6in4 wrapper and returns the backend it was sent to
func sixInFourDst(t *testing.T, out, in []byte) netip.Addr {
	t.Helper()
	if len(out) < len(in)+20 {
		t.Fatalf("short output: %d", len(out))
	}
	oip := out[14:34]
	if oip[0] != 0x45 || oip[9] != 41 {
		t.Fatalf("outer header: % x", oip)
	}
	if csum(oip) != 0 {
		t.Fatalf("outer checksum wrong: % x", oip)
	}
	plen := binary.BigEndian.Uint16(in[18:])
	if got := binary.BigEndian.Uint16(oip[2:]); got != 40+plen+20 {
		t.Fatalf("outer tot_len %d, inner payload %d", got, plen)
	}
	if !bytes.Equal(out[34:74], in[14:54]) {
		t.Fatal("inner ipv6 header changed")
	}
	if out[12] != 0x08 || out[13] != 0x00 {
		t.Fatalf("ethertype % x", out[12:14])
	}
	return netip.AddrFrom4([4]byte(oip[16:20]))
}

func TestV6VIPIsTunnelledAndSticky(t *testing.T) {
	p := setup6(t)
	pkt := tcp6("2001:db8:1::1", 40000, ack)

	ret, out := run(t, p, pkt)
	if ret != xdpTX {
		t.Fatalf("got %d", ret)
	}
	first := sixInFourDst(t, out, pkt)
	if !bytes.Equal(out[0:6], []byte{0x02, 0, 0, 0, 1, first.As4()[3]}) {
		t.Fatalf("dst mac % x for %s", out[0:6], first)
	}
	if !bytes.Equal(out[6:12], lbMAC) {
		t.Fatalf("src mac % x", out[6:12])
	}

	for i := 0; i < 20; i++ {
		_, out := run(t, p, pkt)
		if got := sixInFourDst(t, out, pkt); got != first {
			t.Fatalf("flow moved from %s to %s", first, got)
		}
	}
	if counter(t, p, "ct_hit") < 20 {
		t.Fatal("conntrack not used")
	}
}

func TestV6SpreadsAcrossBackends(t *testing.T) {
	p := setup6(t)
	seen := map[netip.Addr]int{}
	for i := 0; i < 300; i++ {
		src := netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, byte(i >> 8), byte(i)})
		pkt := tcp6(src.String(), uint16(30000+i), ack)
		_, out := run(t, p, pkt)
		seen[sixInFourDst(t, out, pkt)]++
	}
	if len(seen) != 3 {
		t.Fatalf("only reached %v", seen)
	}
	for be, n := range seen {
		if n < 50 {
			t.Fatalf("%s got %d of 300", be, n)
		}
	}
}

func TestV6OtherTrafficPasses(t *testing.T) {
	p := setup6(t)
	other := netip.MustParseAddr("2001:db8:100::99")

	// not a vip address
	pkt := frame6(ip6Pkt(6, netip.MustParseAddr("2001:db8:1::1"), other, tcpHdr(1000, 443, syn)))
	if ret, _ := run(t, p, pkt); ret != xdpPass {
		t.Fatalf("unknown dst: %d", ret)
	}
	// right address, no vip on that port
	pkt = frame6(ip6Pkt(6, netip.MustParseAddr("2001:db8:1::1"), vip6, tcpHdr(1000, 8080, syn)))
	if ret, _ := run(t, p, pkt); ret != xdpPass {
		t.Fatalf("unknown port: %d", ret)
	}
	// icmpv6 neighbour solicitation and friends must reach the host
	pkt = frame6(ip6Pkt(58, netip.MustParseAddr("fe80::1"), vip6, make([]byte, 32)))
	if ret, _ := run(t, p, pkt); ret != xdpPass {
		t.Fatalf("icmpv6: %d", ret)
	}
}

func TestV6Malformed(t *testing.T) {
	p := setup6(t)
	src := netip.MustParseAddr("2001:db8:1::1")

	for name, pkt := range map[string][]byte{
		"unspecified src": frame6(ip6Pkt(6, netip.IPv6Unspecified(), vip6, tcpHdr(1, 443, syn))),
		"multicast src":   frame6(ip6Pkt(6, netip.MustParseAddr("ff02::1"), vip6, tcpHdr(1, 443, syn))),
		"loopback src":    frame6(ip6Pkt(6, netip.IPv6Loopback(), vip6, tcpHdr(1, 443, syn))),
		"zero port":       frame6(ip6Pkt(6, src, vip6, tcpHdr(0, 443, syn))),
	} {
		if ret, _ := run(t, p, pkt); ret != xdpDrop {
			t.Errorf("%s: got %d", name, ret)
		}
	}

	// payload_len claims more than the frame carries
	bad := ip6Pkt(6, src, vip6, tcpHdr(1000, 443, ack))
	binary.BigEndian.PutUint16(bad[4:], 4000)
	if ret, _ := run(t, p, frame6(bad)); ret != xdpDrop {
		t.Errorf("long payload_len: got %d", ret)
	}
	if got := counter(t, p, "drop_malformed"); got != 5 {
		t.Errorf("drop_malformed = %d", got)
	}
}

func TestV6FragmentsToVIPDropped(t *testing.T) {
	p := setup6(t)
	// fragment header: next=tcp, offset 0, more fragments
	fh := []byte{6, 0, 0, 1, 0, 0, 0, 1}
	to := frame6(ip6Pkt(44, netip.MustParseAddr("2001:db8:1::1"), vip6, append(fh, tcpHdr(1, 443, ack)...)))
	if ret, _ := run(t, p, to); ret != xdpDrop {
		t.Fatalf("frag to vip: %d", ret)
	}
	other := frame6(ip6Pkt(44, netip.MustParseAddr("2001:db8:1::1"), netip.MustParseAddr("2001:db8:100::99"), append(fh, tcpHdr(1, 443, ack)...)))
	if ret, _ := run(t, p, other); ret != xdpPass {
		t.Fatalf("frag elsewhere: %d", ret)
	}
}

func TestV6DenyAndAllowLists(t *testing.T) {
	p := setup6(t)
	if ret, _ := run(t, p, tcp6("2001:db8:dead::5", 1234, ack)); ret != xdpDrop {
		t.Fatalf("denied: %d", ret)
	}
	if counter(t, p, "drop_denylist") != 1 {
		t.Fatal("denylist counter")
	}

	// allowlisted sources skip rate limits entirely
	for i := 0; i < 50; i++ {
		if ret, _ := run(t, p, tcp6("2001:db8:a110::7", uint16(2000+i), syn)); ret != xdpTX {
			t.Fatalf("allowlisted syn %d: %d", i, ret)
		}
	}
	if counter(t, p, "allowlisted") != 50 {
		t.Fatalf("allowlisted = %d", counter(t, p, "allowlisted"))
	}
}

func TestV6SynFloodBlocksAndUnblocks(t *testing.T) {
	p := setup6(t)
	src := "2001:db8:bad::1"

	var ret uint32
	for i := 0; i < 8; i++ {
		ret, _ = run(t, p, tcp6(src, uint16(5000+i), syn))
	}
	if ret != xdpDrop {
		t.Fatalf("flood not dropped: %d", ret)
	}
	if counter(t, p, "drop_syn_flood") == 0 || counter(t, p, "block_added") != 1 {
		t.Fatal("flood counters")
	}

	// now on the blocklist, even a plain ack from the same source goes
	if ret, _ := run(t, p, tcp6(src, 5000, ack)); ret != xdpDrop {
		t.Fatalf("blocked source passed: %d", ret)
	}
	if counter(t, p, "drop_blocked") == 0 {
		t.Fatal("drop_blocked")
	}

	list, err := p.Blocked()
	if err != nil || len(list) != 1 || list[0].Addr != netip.MustParseAddr(src) {
		t.Fatalf("blocked list %v %v", list, err)
	}

	if err := p.Unblock(netip.MustParseAddr(src)); err != nil {
		t.Fatal(err)
	}
	if ret, _ := run(t, p, tcp6(src, 5000, ack)); ret != xdpTX {
		t.Fatalf("after unblock: %d", ret)
	}
}

func TestV6BlockEventCarriesAddress(t *testing.T) {
	p := setup6(t)
	rd, err := p.Events()
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()

	src := "2001:db8:bad::2"
	for i := 0; i < 8; i++ {
		run(t, p, udp6(src, uint16(7000+i)))
	}
	ev, err := rd.Next()
	if err != nil {
		t.Fatal(err)
	}
	if ev.Src != src || ev.Reason != "udp_flood" {
		t.Fatalf("event %+v", ev)
	}
}

func TestV6TooBigGetsICMPv6Reply(t *testing.T) {
	p := setup6(t)
	cli := netip.MustParseAddr("2001:db8:1::1")
	// 40 + 1450 + 20 > 1500
	big := ip6Pkt(17, cli, vip6, append(udpHdr(1000, 53), make([]byte, 1450-24)...))
	ret, out := run(t, p, frame6(big))
	if ret != xdpTX {
		t.Fatalf("got %d", ret)
	}
	if len(out) != 110 {
		t.Fatalf("reply is %d bytes", len(out))
	}
	if counter(t, p, "drop_mtu") != 1 || counter(t, p, "icmp6_too_big") != 1 {
		t.Fatal("counters")
	}

	// macs swapped, from the vip back to the client
	if !bytes.Equal(out[0:6], cliMAC) || !bytes.Equal(out[6:12], lbMAC) {
		t.Fatalf("macs % x / % x", out[0:6], out[6:12])
	}
	ip := out[14:54]
	if ip[0]>>4 != 6 || ip[6] != 58 || binary.BigEndian.Uint16(ip[4:]) != 56 {
		t.Fatalf("ip6 header % x", ip)
	}
	if netip.AddrFrom16([16]byte(ip[8:24])) != vip6 || netip.AddrFrom16([16]byte(ip[24:40])) != cli {
		t.Fatalf("addresses % x", ip[8:40])
	}

	ic := out[54:]
	if ic[0] != 2 || ic[1] != 0 {
		t.Fatalf("icmp type/code %d/%d", ic[0], ic[1])
	}
	if mtu := binary.BigEndian.Uint32(ic[4:]); mtu != 1480 {
		t.Fatalf("advertised mtu %d", mtu)
	}
	if !bytes.Equal(ic[8:], big[:48]) {
		t.Fatal("quote doesn't match the original header")
	}

	// icmpv6 checksum covers the pseudo header too; summing all of it must give 0
	pseudo := append(append([]byte{}, ip[8:40]...), 0, 0, 0, byte(len(ic)), 0, 0, 0, 58)
	if csum(append(pseudo, ic...)) != 0 {
		t.Fatal("icmpv6 checksum wrong")
	}
}

func TestV6MTUBoundary(t *testing.T) {
	p := setup6(t)
	// just fits
	ok := ip6Pkt(17, netip.MustParseAddr("2001:db8:1::1"), vip6, append(udpHdr(1000, 53), make([]byte, 1440-24)...))
	if ret, _ := run(t, p, frame6(ok)); ret != xdpTX {
		t.Fatalf("max size: %d", ret)
	}
}

func TestV6CIDRSyncRemovesStale(t *testing.T) {
	p := setup6(t)
	if err := p.SetCIDRs(controller.Deny, []netip.Prefix{netip.MustParsePrefix("2001:db8:beef::/48")}); err != nil {
		t.Fatal(err)
	}
	if ret, _ := run(t, p, tcp6("2001:db8:dead::5", 1234, ack)); ret != xdpTX {
		t.Fatalf("old deny entry still active: %d", ret)
	}
	if ret, _ := run(t, p, tcp6("2001:db8:beef::5", 1234, ack)); ret != xdpDrop {
		t.Fatalf("new deny entry missing: %d", ret)
	}
}
