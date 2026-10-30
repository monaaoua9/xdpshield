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

const testCfgV6BE = `
interface: lo
encap_src6: 2001:db8:ee::1
mtu: 1500
backends:
  - {name: a, address: "2001:db8:b::1", mac: "02:00:00:00:02:01"}
  - {name: b, address: "2001:db8:b::2", mac: "02:00:00:00:02:02"}
vips:
  - name: web4
    address: 203.0.113.10
    port: 443
    backends: [{name: a}, {name: b}]
  - name: web6
    address: 2001:db8:100::10
    port: 443
    backends: [{name: a}, {name: b}]
`

func setupV6BE(t *testing.T) *Plane {
	t.Helper()
	p, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	cfg, err := config.Parse([]byte(testCfgV6BE))
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.New(p).Apply(cfg); err != nil {
		t.Fatal(err)
	}
	return p
}

// checks the ipv6 wrapper and hands back the backend it points at
func checkOuter6(t *testing.T, out []byte, next byte, innerLen int) netip.Addr {
	t.Helper()
	if out[12] != 0x86 || out[13] != 0xdd {
		t.Fatalf("ethertype % x", out[12:14])
	}
	h := out[14:54]
	if h[0]>>4 != 6 || h[6] != next || h[7] != 64 {
		t.Fatalf("outer header % x", h)
	}
	if got := int(binary.BigEndian.Uint16(h[4:])); got != innerLen {
		t.Fatalf("payload_len %d, want %d", got, innerLen)
	}
	if netip.AddrFrom16([16]byte(h[8:24])) != netip.MustParseAddr("2001:db8:ee::1") {
		t.Fatalf("outer src % x", h[8:24])
	}
	return netip.AddrFrom16([16]byte(h[24:40]))
}

func TestV4ClientToV6Backend(t *testing.T) {
	p := setupV6BE(t)
	pkt := tcpFrame("1.1.1.1", 40000, ack)

	ret, out := run(t, p, pkt)
	if ret != xdpTX {
		t.Fatalf("got %d", ret)
	}
	innerLen := int(binary.BigEndian.Uint16(pkt[16:]))
	be := checkOuter6(t, out, 4, innerLen)
	if be.String() != "2001:db8:b::1" && be.String() != "2001:db8:b::2" {
		t.Fatalf("backend %s", be)
	}
	if !bytes.Equal(out[0:6], []byte{0x02, 0, 0, 0, 2, be.As16()[15]}) || !bytes.Equal(out[6:12], lbMAC) {
		t.Fatalf("macs % x / % x", out[0:6], out[6:12])
	}
	if !bytes.Equal(out[54:74], pkt[14:34]) {
		t.Fatal("inner ipv4 header changed")
	}

	for i := 0; i < 10; i++ {
		_, again := run(t, p, pkt)
		if got := checkOuter6(t, again, 4, innerLen); got != be {
			t.Fatalf("flow moved from %s to %s", be, got)
		}
	}
}

func TestV6ClientToV6Backend(t *testing.T) {
	p := setupV6BE(t)
	pkt := tcp6("2001:db8:1::1", 40000, ack)

	ret, out := run(t, p, pkt)
	if ret != xdpTX {
		t.Fatalf("got %d", ret)
	}
	plen := int(binary.BigEndian.Uint16(pkt[18:]))
	be := checkOuter6(t, out, 41, 40+plen)
	if be.Is4() {
		t.Fatalf("backend %s", be)
	}
	if !bytes.Equal(out[54:94], pkt[14:54]) {
		t.Fatal("inner ipv6 header changed")
	}
}

func TestV6BackendsSpread(t *testing.T) {
	p := setupV6BE(t)
	seen := map[netip.Addr]int{}
	for i := 0; i < 200; i++ {
		src := netip.AddrFrom4([4]byte{9, 9, byte(i), 1})
		pkt := frame(ipPkt(6, src, vipIP, 0, tcpHdr(5000, 443, ack)))
		_, out := run(t, p, pkt)
		seen[checkOuter6(t, out, 4, int(binary.BigEndian.Uint16(pkt[16:])))]++
	}
	if len(seen) != 2 {
		t.Fatalf("reached %v", seen)
	}
}

// with a v6 backend the tunnel adds 40 bytes, so the limits move by 20
func TestV6BackendOverheadShowsInMTU(t *testing.T) {
	p := setupV6BE(t)

	fits := ipPkt(6, netip.MustParseAddr("1.1.1.1"), vipIP, 0x4000, append(tcpHdr(1, 443, ack), make([]byte, 1460-20)...))
	if ret, _ := run(t, p, frame(fits)); ret != xdpTX {
		t.Fatalf("1460 should fit: %d", ret)
	}

	big := ipPkt(6, netip.MustParseAddr("1.1.1.1"), vipIP, 0x4000, append(tcpHdr(1, 443, ack), make([]byte, 1470-20)...))
	ret, out := run(t, p, frame(big))
	if ret != xdpTX || out[14+20] != 3 || out[14+21] != 4 {
		t.Fatalf("expected frag-needed, got %d", ret)
	}
	if mtu := binary.BigEndian.Uint16(out[14+20+6:]); mtu != 1460 {
		t.Fatalf("advertised mtu %d, want 1460", mtu)
	}

	big6 := ip6Pkt(6, netip.MustParseAddr("2001:db8:1::1"), vip6, append(tcpHdr(1000, 443, ack), make([]byte, 1450-20)...))
	ret, out = run(t, p, frame6(big6))
	if ret != xdpTX || out[54] != 2 {
		t.Fatalf("expected packet too big, got %d", ret)
	}
	if mtu := binary.BigEndian.Uint32(out[54+4:]); mtu != 1460 {
		t.Fatalf("advertised v6 mtu %d, want 1460", mtu)
	}
}
