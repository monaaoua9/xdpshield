//go:build linux && integration

package dataplane

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/monaaoua9/xdpshield/internal/config"
	"github.com/monaaoua9/xdpshield/internal/controller"
)

// a country-sized list: 12k v4 and 3k v6 prefixes
func TestLargeDenyList(t *testing.T) {
	p := setup(t)

	var want []netip.Prefix
	for i := 0; i < 12000; i++ {
		want = append(want, netip.PrefixFrom(netip.AddrFrom4([4]byte{100, byte(i >> 8), byte(i), 0}), 24))
	}
	for i := 0; i < 3000; i++ {
		a := [16]byte{0x20, 0x01, 0x0d, 0xb8, byte(i >> 8), byte(i)}
		want = append(want, netip.PrefixFrom(netip.AddrFrom16(a), 48))
	}
	if err := p.SetCIDRs(controller.Deny, want); err != nil {
		t.Fatal(err)
	}

	if ret, _ := run(t, p, tcpFrame("100.5.200.77", 1234, ack)); ret != xdpDrop {
		t.Fatalf("inside the list: %d", ret)
	}
	if ret, _ := run(t, p, tcpFrame("101.0.0.1", 1234, ack)); ret != xdpTX {
		t.Fatalf("outside the list: %d", ret)
	}

	// shrink back, the stale 14999 entries must go
	if err := p.SetCIDRs(controller.Deny, want[:1]); err != nil {
		t.Fatal(err)
	}
	if ret, _ := run(t, p, tcpFrame("100.5.200.77", 1234, ack)); ret != xdpTX {
		t.Fatalf("stale entry survived: %d", ret)
	}
}

// the datapath skips the trie lookups while a list is empty, so the flags
// have to follow config changes in both directions
func TestListFlagsFollowConfig(t *testing.T) {
	p, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	ctl := controller.New(p)

	apply := func(raw string) {
		cfg, err := config.Parse([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		if err := ctl.Apply(cfg); err != nil {
			t.Fatal(err)
		}
	}
	noLists := strings.NewReplacer("deny: [198.51.100.0/24]", "deny: []", "allow: [192.0.2.0/24]", "allow: []").Replace(testCfg)
	if noLists == testCfg {
		t.Fatal("testCfg lists changed, fix the replacer")
	}

	apply(noLists)
	if ret, _ := run(t, p, tcpFrame("198.51.100.7", 1234, ack)); ret != xdpTX {
		t.Fatalf("no deny list but dropped: %d", ret)
	}

	apply(testCfg)
	if ret, _ := run(t, p, tcpFrame("198.51.100.7", 1234, ack)); ret != xdpDrop {
		t.Fatalf("deny list added, not enforced: %d", ret)
	}

	apply(noLists)
	if ret, _ := run(t, p, tcpFrame("198.51.100.7", 1234, ack)); ret != xdpTX {
		t.Fatalf("deny list removed, still enforced: %d", ret)
	}
}
