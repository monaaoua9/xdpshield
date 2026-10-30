//go:build linux && integration

package dataplane

import (
	"strings"
	"testing"

	"github.com/monaaoua9/xdpshield/internal/config"
	"github.com/monaaoua9/xdpshield/internal/controller"
)

func setupStrict(t *testing.T) *Plane {
	t.Helper()
	p, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })

	raw := strings.Replace(testCfg, "enabled: true", "enabled: true\n  drop_orphan_tcp: true", 1)
	raw = strings.Replace(raw, "vips:\n", "vips:\n  - {name: web6, address: \"2001:db8:100::10\", port: 443, backends: [{name: a}, {name: b}]}\n", 1)
	cfg, err := config.Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.New(p).Apply(cfg); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestOrphanTCPDropped(t *testing.T) {
	p := setupStrict(t)

	// ack flood shape: no syn ever seen for this flow
	if ret, _ := run(t, p, tcpFrame("1.1.1.1", 40000, ack)); ret != xdpDrop {
		t.Fatalf("orphan ack: %d", ret)
	}
	if ret, _ := run(t, p, tcpFrame("1.1.1.1", 40000, rst|ack)); ret != xdpDrop {
		t.Fatalf("orphan rst: %d", ret)
	}
	if counter(t, p, "drop_no_flow") != 2 {
		t.Fatalf("drop_no_flow = %d", counter(t, p, "drop_no_flow"))
	}

	// a real handshake creates the entry and the rest of the flow goes through
	if ret, _ := run(t, p, tcpFrame("1.1.1.1", 40001, syn)); ret != xdpTX {
		t.Fatalf("syn: %d", ret)
	}
	for _, fl := range []byte{ack, ack | psh, fin | ack} {
		if ret, _ := run(t, p, tcpFrame("1.1.1.1", 40001, fl)); ret != xdpTX {
			t.Fatalf("tracked flow, flags %#x: %d", fl, ret)
		}
	}

	// udp and traffic that isn't for a vip are unaffected
	if ret, _ := run(t, p, udpFrame("1.1.1.1", 5000)); ret != xdpTX {
		t.Fatalf("udp: %d", ret)
	}
}

func TestOrphanTCPDroppedV6(t *testing.T) {
	p := setupStrict(t)
	if ret, _ := run(t, p, tcp6("2001:db8:1::1", 40000, ack)); ret != xdpDrop {
		t.Fatalf("orphan ack v6: %d", ret)
	}
	if ret, _ := run(t, p, tcp6("2001:db8:1::1", 40001, syn)); ret != xdpTX {
		t.Fatalf("syn v6: %d", ret)
	}
	if ret, _ := run(t, p, tcp6("2001:db8:1::1", 40001, ack)); ret != xdpTX {
		t.Fatalf("tracked v6: %d", ret)
	}
}

// off by default: an ack with no entry is hashed like always, that is what
// makes failover between nodes with the same config work
func TestOrphanTCPAllowedByDefault(t *testing.T) {
	p := setup(t)
	if ret, _ := run(t, p, tcpFrame("1.1.1.1", 40000, ack)); ret != xdpTX {
		t.Fatalf("got %d", ret)
	}
	if counter(t, p, "drop_no_flow") != 0 {
		t.Fatal("counter moved")
	}
}
