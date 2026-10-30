//go:build linux && integration

package dataplane

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"

	"github.com/monaaoua9/xdpshield/internal/config"
	"github.com/monaaoua9/xdpshield/internal/controller"
)

func udpSized(sport, dport uint16, n int) []byte {
	h := make([]byte, n)
	binary.BigEndian.PutUint16(h[0:], sport)
	binary.BigEndian.PutUint16(h[2:], dport)
	binary.BigEndian.PutUint16(h[4:], uint16(n))
	return h
}

func setupAmp(t *testing.T) *Plane {
	t.Helper()
	p, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })

	raw := strings.Replace(testCfg, "enabled: true", "enabled: true\n  amplification: {ports: [53, 123], min_size: 100}", 1)
	raw = strings.Replace(raw, "allow: [192.0.2.0/24]", "allow: [192.0.2.0/24, 2001:db8:a110::/48]", 1)
	raw = strings.Replace(raw, "vips:\n", "vips:\n  - {name: web6, address: \"2001:db8:100::10\", port: 443, backends: [{name: a}]}\n", 1)
	cfg, err := config.Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.New(p).Apply(cfg); err != nil {
		t.Fatal(err)
	}
	return p
}

func ampV4(src string, sport, dport uint16, n int) []byte {
	return frame(ipPkt(17, netip.MustParseAddr(src), vipIP, 0, udpSized(sport, dport, n)))
}

func ampV6(src string, sport, dport uint16, n int) []byte {
	return frame6(ip6Pkt(17, netip.MustParseAddr(src), vip6, udpSized(sport, dport, n)))
}

func TestAmplificationV4(t *testing.T) {
	p := setupAmp(t)

	if ret, _ := run(t, p, ampV4("1.1.1.1", 53, 40000, 120)); ret != xdpDrop {
		t.Fatalf("big dns answer: %d", ret)
	}
	if counter(t, p, "drop_amplification") != 1 {
		t.Fatal("counter")
	}

	for name, pkt := range map[string][]byte{
		"under min_size":   ampV4("1.1.1.1", 53, 40000, 60),
		"other src port":   ampV4("1.1.1.1", 8080, 40000, 120),
		"allowlisted":      ampV4("192.0.2.9", 53, 40000, 120),
		"to a vip service": ampV4("1.1.1.1", 53, 53, 120),
	} {
		ret, _ := run(t, p, pkt)
		want := uint32(xdpPass)
		if name == "to a vip service" {
			want = xdpTX
		}
		if ret != want {
			t.Errorf("%s: got %d, want %d", name, ret, want)
		}
	}

	// reply to the host itself, not to a vip address
	host := frame(ipPkt(17, netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("10.9.9.9"), 0, udpSized(53, 40000, 120)))
	if ret, _ := run(t, p, host); ret != xdpPass {
		t.Errorf("non-vip destination: %d", ret)
	}
}

func TestAmplificationV6(t *testing.T) {
	p := setupAmp(t)

	if ret, _ := run(t, p, ampV6("2001:db8:1::1", 123, 40000, 120)); ret != xdpDrop {
		t.Fatalf("big ntp answer: %d", ret)
	}
	if ret, _ := run(t, p, ampV6("2001:db8:1::1", 123, 40000, 60)); ret != xdpPass {
		t.Errorf("small: %d", ret)
	}
	if ret, _ := run(t, p, ampV6("2001:db8:a110::5", 123, 40000, 120)); ret != xdpPass {
		t.Errorf("allowlisted: %d", ret)
	}
	if counter(t, p, "drop_amplification") != 1 {
		t.Fatal("counter")
	}
}

func TestAmplificationPortsAreReplaced(t *testing.T) {
	p := setupAmp(t)
	if err := p.SetAmplification([]uint16{11211}, 0); err != nil {
		t.Fatal(err)
	}
	if ret, _ := run(t, p, ampV4("1.1.1.1", 53, 40000, 120)); ret != xdpPass {
		t.Fatalf("53 should be gone: %d", ret)
	}
	if ret, _ := run(t, p, ampV4("1.1.1.1", 11211, 40000, 20)); ret != xdpDrop {
		t.Fatalf("memcached: %d", ret)
	}
	if err := p.SetAmplification(nil, 0); err != nil {
		t.Fatal(err)
	}
	if ret, _ := run(t, p, ampV4("1.1.1.1", 11211, 40000, 120)); ret != xdpPass {
		t.Fatalf("empty list should disable: %d", ret)
	}
}
