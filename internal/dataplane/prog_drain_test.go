//go:build linux && integration

package dataplane

import (
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"github.com/monaaoua9/xdpshield/internal/config"
	"github.com/monaaoua9/xdpshield/internal/controller"
)

func TestDrainedBackendKeepsTrackedFlows(t *testing.T) {
	p, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	ctl := controller.New(p)
	apply := func(raw string) {
		t.Helper()
		cfg, err := config.Parse([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		if err := ctl.Apply(cfg); err != nil {
			t.Fatal(err)
		}
	}
	apply(testCfg)

	// find a flow that lands on b and remember it
	b := netip.MustParseAddr("10.0.1.2")
	var onB []byte
	for sport := uint16(30000); sport < 30200 && onB == nil; sport++ {
		pkt := tcpFrame("1.1.1.1", sport, ack)
		_, out := run(t, p, pkt)
		if outerDst(t, out, pkt) == b {
			onB = pkt
		}
	}
	if onB == nil {
		t.Fatal("no flow reached b")
	}

	apply(strings.Replace(testCfg, "address: 10.0.1.2,", "address: 10.0.1.2, drain: true,", 1))

	if ret, out := run(t, p, onB); ret != xdpTX || outerDst(t, out, onB) != b {
		t.Fatalf("tracked flow moved after drain (ret %d)", ret)
	}
	// one source per flow, the syn limit in testCfg is 5/s
	for i := 0; i < 200; i++ {
		pkt := tcpFrame("2.2."+strconv.Itoa(i)+".9", 40000, syn)
		_, out := run(t, p, pkt)
		if outerDst(t, out, pkt) == b {
			t.Fatalf("new flow %d went to the drained backend", i)
		}
	}
}
