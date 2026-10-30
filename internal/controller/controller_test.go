package controller

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/monaaoua9/xdpshield/internal/config"
)

type fakeDP struct {
	global   Global
	backends map[uint32]bool // id -> active
	vips     map[VIPKey]uint32
	tables   map[uint32][]uint32
	setVIPs  int
	allow    []netip.Prefix
	deny     []netip.Prefix
	ampPorts []uint16
	ampMin   uint16
	order    []string
}

func newFake() *fakeDP {
	return &fakeDP{backends: map[uint32]bool{}, vips: map[VIPKey]uint32{}, tables: map[uint32][]uint32{}}
}

func (f *fakeDP) SetGlobal(g Global) error { f.global = g; return nil }
func (f *fakeDP) SetBackend(id uint32, _ netip.Addr, _ [6]byte, active bool) error {
	f.order = append(f.order, "backend")
	f.backends[id] = active
	return nil
}
func (f *fakeDP) DelBackend(id uint32) error { delete(f.backends, id); return nil }
func (f *fakeDP) SetVIP(id uint32, k VIPKey, _ uint32, t []uint32) error {
	f.order = append(f.order, "vip")
	f.setVIPs++
	f.vips[k] = id
	f.tables[id] = t
	return nil
}
func (f *fakeDP) DelVIP(id uint32, k VIPKey) error {
	delete(f.vips, k)
	delete(f.tables, id)
	return nil
}
func (f *fakeDP) SetCIDRs(k CIDRKind, w []netip.Prefix) error {
	if k == Allow {
		f.allow = w
	} else {
		f.deny = w
	}
	return nil
}

func (f *fakeDP) SetAmplification(ports []uint16, min uint16) error {
	f.ampPorts, f.ampMin = ports, min
	return nil
}
func (f *fakeDP) Block(netip.Addr, time.Duration) error { return nil }
func (f *fakeDP) Unblock(netip.Addr) error              { return nil }
func (f *fakeDP) Blocked() ([]BlockedEntry, error)      { return nil, nil }

const base = `
interface: eth0
encap_src: 10.0.0.1
ddos:
  enabled: true
  allow: [10.9.0.0/16]
backends:
  - {name: a, address: 10.0.1.1, mac: "02:00:00:00:00:01"}
  - {name: b, address: 10.0.1.2, mac: "02:00:00:00:00:02"}
  - {name: c, address: 10.0.1.3, mac: "02:00:00:00:00:03"}
vips:
  - name: web
    address: 203.0.113.10
    port: 443
    backends: [{name: a}, {name: b}]
`

func mustCfg(t *testing.T, raw string) *config.Config {
	t.Helper()
	c, err := config.Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestApplyProgramsEverything(t *testing.T) {
	fp := newFake()
	c := New(fp)
	if err := c.Apply(mustCfg(t, base)); err != nil {
		t.Fatal(err)
	}
	if !fp.global.DDoS || fp.global.SynLimitPPS != 200 {
		t.Fatalf("global: %+v", fp.global)
	}
	if len(fp.backends) != 3 || len(fp.vips) != 1 || len(fp.allow) != 1 {
		t.Fatalf("state: %+v", fp)
	}
	// every backend must be written before the first vip so no table dangles
	if i := slices.Index(fp.order, "vip"); i != 3 {
		t.Fatalf("bad order %v", fp.order)
	}
}

func TestAmplificationPushed(t *testing.T) {
	fp := newFake()
	raw := strings.Replace(base, "enabled: true", "enabled: true\n  amplification: {ports: [53, 123], min_size: 120}", 1)
	if err := New(fp).Apply(mustCfg(t, raw)); err != nil {
		t.Fatal(err)
	}
	if len(fp.ampPorts) != 2 || fp.ampMin != 120 {
		t.Fatalf("got %v / %d", fp.ampPorts, fp.ampMin)
	}
}

func TestApplyIsIdempotent(t *testing.T) {
	fp := newFake()
	c := New(fp)
	cfg := mustCfg(t, base)
	c.Apply(cfg)
	c.Apply(cfg)
	if fp.setVIPs != 1 {
		t.Fatalf("table rewritten %d times", fp.setVIPs)
	}
}

func TestHealthRebuildsTable(t *testing.T) {
	fp := newFake()
	c := New(fp)
	c.Apply(mustCfg(t, base))

	if err := c.SetHealth("b", false); err != nil {
		t.Fatal(err)
	}
	idA, _ := c.beIDs.lookup("a")
	idB, _ := c.beIDs.lookup("b")
	if fp.backends[idB] {
		t.Fatal("b should be inactive")
	}
	for _, id := range fp.tables[0] {
		if id != idA {
			t.Fatalf("table still routes to %d", id)
		}
	}

	c.SetHealth("b", true)
	seen := map[uint32]bool{}
	for _, id := range fp.tables[0] {
		seen[id] = true
	}
	if !seen[idB] {
		t.Fatal("b never came back")
	}
}

func TestAllDownFailsOpen(t *testing.T) {
	fp := newFake()
	c := New(fp)
	c.Apply(mustCfg(t, base))
	c.SetHealth("a", false)
	c.SetHealth("b", false)
	if len(fp.tables[0]) == 0 {
		t.Fatal("vip lost its table")
	}
}

func TestRemovals(t *testing.T) {
	fp := newFake()
	c := New(fp)
	c.Apply(mustCfg(t, base))

	smaller := `
interface: eth0
encap_src: 10.0.0.1
backends:
  - {name: a, address: 10.0.1.1, mac: "02:00:00:00:00:01"}
vips: []
`
	if err := c.Apply(mustCfg(t, smaller)); err != nil {
		t.Fatal(err)
	}
	if len(fp.vips) != 0 || len(fp.backends) != 1 || len(fp.allow) != 0 {
		t.Fatalf("leftovers: vips=%d backends=%d allow=%d", len(fp.vips), len(fp.backends), len(fp.allow))
	}
}

func TestIDsNotReusedImmediately(t *testing.T) {
	p := newIDPool(4)
	a, _ := p.get("a")
	p.release("a")
	b, _ := p.get("b")
	if a == b {
		t.Fatal("id reused right away")
	}
	for _, n := range []string{"c", "d"} {
		p.get(n)
	}
	// pool of 4 is now used up except for the freed one
	e, err := p.get("e")
	if err != nil || e != a {
		t.Fatalf("got %d,%v want %d", e, err, a)
	}
	if _, err := p.get("f"); err == nil {
		t.Fatal("expected exhaustion")
	}
}
