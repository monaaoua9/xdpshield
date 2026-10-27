package controller

import (
	"fmt"
	"hash/fnv"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/monaaoua9/xdpshield/internal/config"
	"github.com/monaaoua9/xdpshield/internal/maglev"
	"github.com/monaaoua9/xdpshield/internal/statdef"
)

type CIDRKind int

const (
	Allow CIDRKind = iota
	Deny
)

type Global struct {
	DDoS        bool
	SynLimitPPS uint32
	UDPLimitPPS uint32
	BlockTTL    time.Duration
	EncapSrc    netip.Addr
	MTU         int
	HashSeed    uint32
}

type VIPKey struct {
	Addr netip.Addr
	Port uint16
	UDP  bool
}

type BlockedEntry struct {
	Addr      netip.Addr
	Reason    uint32
	ExpiresIn time.Duration
}

// Dataplane is what the controller needs from the kernel side. The real one
// lives in internal/dataplane (linux only), tests use a fake.
type Dataplane interface {
	SetGlobal(Global) error
	SetBackend(id uint32, ip netip.Addr, mac [6]byte, active bool) error
	DelBackend(id uint32) error
	SetVIP(id uint32, k VIPKey, algo uint32, table []uint32) error
	DelVIP(id uint32, k VIPKey) error
	SetCIDRs(kind CIDRKind, want []netip.Prefix) error
	Block(ip netip.Addr, ttl time.Duration) error
	Unblock(ip netip.Addr) error
	Blocked() ([]BlockedEntry, error)
}

type Controller struct {
	dp Dataplane

	mu     sync.Mutex
	cfg    *config.Config
	up     map[string]bool // health, missing = up
	beIDs  idPool
	vipIDs idPool
	vips   map[string]vipState // by vip name
	bes    map[string]bool     // backends currently programmed
}

type vipState struct {
	id    uint32
	key   VIPKey
	table uint64 // fnv of the last table we pushed, skips identical rewrites
}

func New(dp Dataplane) *Controller {
	return &Controller{
		dp:     dp,
		up:     map[string]bool{},
		beIDs:  newIDPool(config.MaxBackends),
		vipIDs: newIDPool(config.MaxVIPs),
		vips:   map[string]vipState{},
		bes:    map[string]bool{},
	}
}

func (c *Controller) Apply(cfg *config.Config) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cfg = cfg
	return c.reconcile()
}

// SetHealth is called by the health checker on state transitions
func (c *Controller) SetHealth(backend string, up bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if prev, ok := c.up[backend]; ok && prev == up {
		return nil
	}
	c.up[backend] = up
	if c.cfg == nil {
		return nil
	}
	return c.reconcile()
}

func (c *Controller) healthy(name string) bool {
	up, ok := c.up[name]
	return !ok || up
}

func (c *Controller) reconcile() error {
	cfg := c.cfg

	g := Global{
		DDoS:        cfg.DDoS.Enabled,
		SynLimitPPS: cfg.DDoS.SynLimitPPS,
		UDPLimitPPS: cfg.DDoS.UDPLimitPPS,
		BlockTTL:    cfg.DDoS.BlockTTL,
		EncapSrc:    cfg.EncapSrc,
		MTU:         cfg.MTU,
		HashSeed:    cfg.HashSeed,
	}
	if err := c.dp.SetGlobal(g); err != nil {
		return fmt.Errorf("global config: %w", err)
	}

	// backends first, a table must never point at an id the datapath doesn't know
	want := map[string]bool{}
	for _, b := range cfg.Backends {
		want[b.Name] = true
		id, err := c.beIDs.get(b.Name)
		if err != nil {
			return err
		}
		mac, _ := net.ParseMAC(b.MAC) // validated on load
		var m [6]byte
		copy(m[:], mac)
		if err := c.dp.SetBackend(id, b.Address, m, c.healthy(b.Name)); err != nil {
			return fmt.Errorf("backend %s: %w", b.Name, err)
		}
		c.bes[b.Name] = true
	}

	if err := c.dp.SetCIDRs(Allow, cfg.DDoS.Allow); err != nil {
		return fmt.Errorf("allow list: %w", err)
	}
	if err := c.dp.SetCIDRs(Deny, cfg.DDoS.Deny); err != nil {
		return fmt.Errorf("deny list: %w", err)
	}

	seen := map[string]bool{}
	for _, v := range cfg.VIPs {
		seen[v.Name] = true
		if err := c.syncVIP(v); err != nil {
			return fmt.Errorf("vip %s: %w", v.Name, err)
		}
	}

	// removals last so existing traffic keeps flowing during the swap
	for name, st := range c.vips {
		if seen[name] {
			continue
		}
		if err := c.dp.DelVIP(st.id, st.key); err != nil {
			return fmt.Errorf("remove vip %s: %w", name, err)
		}
		c.vipIDs.release(name)
		delete(c.vips, name)
	}
	for name := range c.bes {
		if want[name] {
			continue
		}
		id, ok := c.beIDs.lookup(name)
		if ok {
			if err := c.dp.DelBackend(id); err != nil {
				return fmt.Errorf("remove backend %s: %w", name, err)
			}
		}
		c.beIDs.release(name)
		delete(c.bes, name)
		delete(c.up, name)
	}
	return nil
}

func (c *Controller) syncVIP(v config.VIP) error {
	id, err := c.vipIDs.get(v.Name)
	if err != nil {
		return err
	}

	members := func(onlyHealthy bool) []maglev.Backend {
		var out []maglev.Backend
		for _, m := range v.Backends {
			if onlyHealthy && !c.healthy(m.Name) {
				continue
			}
			bid, _ := c.beIDs.lookup(m.Name)
			out = append(out, maglev.Backend{Name: m.Name, ID: bid, Weight: m.Weight})
		}
		return out
	}

	bs := members(true)
	if len(bs) == 0 {
		// everything is down: better to try them all than blackhole the vip
		bs = members(false)
	}

	algo := uint32(statdef.AlgoMaglev)
	build := maglev.Build
	if v.Algorithm == "wrr" {
		algo = statdef.AlgoWRR
		build = maglev.BuildWRR
	}
	table, err := build(bs)
	if err != nil {
		return err
	}

	key := VIPKey{Addr: v.Address, Port: v.Port, UDP: v.Proto == "udp"}
	sum := tableSum(algo, table)
	if st, ok := c.vips[v.Name]; ok && st.key == key && st.table == sum {
		return nil
	}
	if old, ok := c.vips[v.Name]; ok && old.key != key {
		// vip moved to another addr/port, drop the old key
		if err := c.dp.DelVIP(old.id, old.key); err != nil {
			return err
		}
	}
	if err := c.dp.SetVIP(id, key, algo, table); err != nil {
		return err
	}
	c.vips[v.Name] = vipState{id: id, key: key, table: sum}
	return nil
}

func tableSum(algo uint32, t []uint32) uint64 {
	h := fnv.New64a()
	h.Write([]byte{byte(algo)})
	var b [4]byte
	for _, v := range t {
		b[0], b[1], b[2], b[3] = byte(v), byte(v>>8), byte(v>>16), byte(v>>24)
		h.Write(b[:])
	}
	return h.Sum64()
}

type BackendInfo struct {
	Name    string `json:"name"`
	ID      uint32 `json:"id"`
	Address string `json:"address"`
	Healthy bool   `json:"healthy"`
}

type VIPInfo struct {
	Name string `json:"name"`
	ID   uint32 `json:"id"`
	Addr string `json:"address"`
	Port uint16 `json:"port"`
	UDP  bool   `json:"udp"`
}

func (c *Controller) Snapshot() ([]VIPInfo, []BackendInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var vs []VIPInfo
	for name, st := range c.vips {
		vs = append(vs, VIPInfo{name, st.id, st.key.Addr.String(), st.key.Port, st.key.UDP})
	}
	slices.SortFunc(vs, func(a, b VIPInfo) int { return int(a.ID) - int(b.ID) })

	var bs []BackendInfo
	if c.cfg != nil {
		for _, b := range c.cfg.Backends {
			id, _ := c.beIDs.lookup(b.Name)
			bs = append(bs, BackendInfo{b.Name, id, b.Address.String(), c.healthy(b.Name)})
		}
	}
	return vs, bs
}

func (c *Controller) Block(ip netip.Addr, ttl time.Duration) error { return c.dp.Block(ip, ttl) }
func (c *Controller) Unblock(ip netip.Addr) error                  { return c.dp.Unblock(ip) }
func (c *Controller) Blocked() ([]BlockedEntry, error)             { return c.dp.Blocked() }
