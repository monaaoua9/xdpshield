//go:build linux

package dataplane

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/cilium/ebpf"
	"github.com/monaaoua9/xdpshield/internal/controller"
	"github.com/monaaoua9/xdpshield/internal/maglev"
)

var _ controller.Dataplane = (*Plane)(nil)

// addresses go into maps in network byte order, which on the wire-facing
// side of the struct is just the 4 raw bytes read as a native u32
func addr32(a netip.Addr) uint32 {
	b := a.As4()
	return binary.NativeEndian.Uint32(b[:])
}

func fromAddr32(v uint32) netip.Addr {
	var b [4]byte
	binary.NativeEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b)
}

func addr6(a netip.Addr) ShieldAddr6 {
	return ShieldAddr6{B: a.As16()}
}

func port16(p uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], p)
	return binary.NativeEndian.Uint16(b[:])
}

func (p *Plane) SetGlobal(g controller.Global) error {
	var flags uint32
	if g.DDoS {
		flags |= 1
	}
	v := ShieldGlobalCfg{
		Flags:       flags,
		SynLimitPps: g.SynLimitPPS,
		UdpLimitPps: g.UDPLimitPPS,
		BlockTtlSec: uint32(g.BlockTTL / time.Second),
		EncapSrc:    addr32(g.EncapSrc),
		MaxIpLen:    uint32(g.MTU),
		HashSeed:    g.HashSeed,
	}
	return p.objs.ConfigMap.Put(uint32(0), &v)
}

func (p *Plane) SetBackend(id uint32, ip netip.Addr, mac [6]byte, active bool) error {
	b := ShieldBackend{Addr: addr32(ip), Mac: mac}
	if active {
		b.Active = 1
	}
	return p.objs.BackendMap.Put(id, &b)
}

func (p *Plane) DelBackend(id uint32) error {
	// array maps can't delete, zero it so active=0
	return p.objs.BackendMap.Put(id, &ShieldBackend{})
}

func protoNum(udp bool) uint8 {
	if udp {
		return 17
	}
	return 6
}

func vipKey(k controller.VIPKey) ShieldVipKey {
	return ShieldVipKey{Addr: addr32(k.Addr), Port: port16(k.Port), Proto: protoNum(k.UDP)}
}

func vipKey6(k controller.VIPKey) ShieldVipKey6 {
	return ShieldVipKey6{Addr: addr6(k.Addr), Port: port16(k.Port), Proto: protoNum(k.UDP)}
}

// SetVIP builds a fresh inner table, swaps it into the outer map and only then
// publishes the vip, so a packet never finds a vip whose table isn't there yet.
func (p *Plane) SetVIP(id uint32, k controller.VIPKey, algo uint32, table []uint32) error {
	if len(table) == 0 || len(table) > maglev.TableSize {
		return fmt.Errorf("table size %d", len(table))
	}

	inner, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: maglev.TableSize,
	})
	if err != nil {
		return fmt.Errorf("inner map: %w", err)
	}
	defer inner.Close() // outer map holds its own reference

	if err := fillTable(inner, table); err != nil {
		return err
	}
	if err := p.objs.LbTables.Put(id, uint32(inner.FD())); err != nil {
		return fmt.Errorf("swap table: %w", err)
	}

	val := ShieldVipVal{Id: id, Algo: algo, TableLen: uint32(len(table))}
	if k.Addr.Is6() {
		if err := p.objs.Vip6Map.Put(vipKey6(k), &val); err != nil {
			return err
		}
		return p.objs.Vip6Addrs.Put(addr6(k.Addr), uint8(1))
	}
	if err := p.objs.VipMap.Put(vipKey(k), &val); err != nil {
		return err
	}
	return p.objs.VipAddrs.Put(addr32(k.Addr), uint8(1))
}

func fillTable(m *ebpf.Map, table []uint32) error {
	keys := make([]uint32, len(table))
	for i := range keys {
		keys[i] = uint32(i)
	}
	_, err := m.BatchUpdate(keys, table, nil)
	if err == nil {
		return nil
	}
	if !errors.Is(err, ebpf.ErrNotSupported) {
		return fmt.Errorf("fill table: %w", err)
	}
	for i, v := range table {
		if err := m.Put(uint32(i), v); err != nil {
			return fmt.Errorf("fill table[%d]: %w", i, err)
		}
	}
	return nil
}

func (p *Plane) DelVIP(id uint32, k controller.VIPKey) error {
	if k.Addr.Is6() {
		if err := p.delVIP6(k); err != nil {
			return err
		}
	} else if err := p.delVIP4(k); err != nil {
		return err
	}

	if err := p.objs.LbTables.Delete(id); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	return nil
}

func (p *Plane) delVIP4(k controller.VIPKey) error {
	if err := p.objs.VipMap.Delete(vipKey(k)); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}

	// drop the address from the fragment filter if no other vip uses it
	still := false
	var key ShieldVipKey
	var val ShieldVipVal
	it := p.objs.VipMap.Iterate()
	for it.Next(&key, &val) {
		if key.Addr == addr32(k.Addr) {
			still = true
			break
		}
	}
	if !still {
		p.objs.VipAddrs.Delete(addr32(k.Addr))
	}
	return nil
}

func (p *Plane) delVIP6(k controller.VIPKey) error {
	if err := p.objs.Vip6Map.Delete(vipKey6(k)); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}

	still := false
	var key ShieldVipKey6
	var val ShieldVipVal
	it := p.objs.Vip6Map.Iterate()
	for it.Next(&key, &val) {
		if key.Addr == addr6(k.Addr) {
			still = true
			break
		}
	}
	if !still {
		p.objs.Vip6Addrs.Delete(addr6(k.Addr))
	}
	return nil
}

func (p *Plane) cidrMaps(kind controller.CIDRKind) (v4, v6 *ebpf.Map) {
	if kind == controller.Allow {
		return p.objs.AllowCidr, p.objs.AllowCidr6
	}
	return p.objs.DenyCidr, p.objs.DenyCidr6
}

// SetCIDRs makes the tries match want exactly
func (p *Plane) SetCIDRs(kind controller.CIDRKind, want []netip.Prefix) error {
	var k4 []ShieldLpmKey
	var k6 []ShieldLpmKey6
	for _, w := range want {
		w = w.Masked()
		if w.Addr().Is4() {
			k4 = append(k4, ShieldLpmKey{Prefixlen: uint32(w.Bits()), Addr: addr32(w.Addr())})
		} else {
			k6 = append(k6, ShieldLpmKey6{Prefixlen: uint32(w.Bits()), Addr: addr6(w.Addr())})
		}
	}

	m4, m6 := p.cidrMaps(kind)
	if err := syncTrie(m4, k4); err != nil {
		return err
	}
	return syncTrie(m6, k6)
}

func syncTrie[K comparable](m *ebpf.Map, want []K) error {
	wanted := map[K]bool{}
	for i := range want {
		wanted[want[i]] = true
		if err := m.Put(&want[i], &ShieldLpmVal{Flags: 1}); err != nil {
			return fmt.Errorf("add cidr: %w", err)
		}
	}

	var stale []K
	var k K
	var v ShieldLpmVal
	it := m.Iterate()
	for it.Next(&k, &v) {
		if !wanted[k] {
			stale = append(stale, k)
		}
	}
	if err := it.Err(); err != nil {
		return err
	}
	for i := range stale {
		if err := m.Delete(&stale[i]); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
	}
	return nil
}

func (p *Plane) Block(ip netip.Addr, ttl time.Duration) error {
	v := ShieldBlockVal{
		ExpiresNs: nowMonotonic() + uint64(ttl),
		Reason:    3,
	}
	if ip.Is6() {
		return p.objs.DynBlocklist6.Put(addr6(ip), &v)
	}
	return p.objs.DynBlocklist.Put(addr32(ip), &v)
}

func (p *Plane) Unblock(ip netip.Addr) error {
	var err error
	if ip.Is6() {
		err = p.objs.DynBlocklist6.Delete(addr6(ip))
	} else {
		err = p.objs.DynBlocklist.Delete(addr32(ip))
	}
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return err
}

func (p *Plane) Blocked() ([]controller.BlockedEntry, error) {
	now := nowMonotonic()
	var out []controller.BlockedEntry

	var k uint32
	var v ShieldBlockVal
	it := p.objs.DynBlocklist.Iterate()
	for it.Next(&k, &v) {
		if v.ExpiresNs <= now {
			continue
		}
		out = append(out, controller.BlockedEntry{
			Addr:      fromAddr32(k),
			Reason:    v.Reason,
			ExpiresIn: time.Duration(v.ExpiresNs - now),
		})
	}
	if err := it.Err(); err != nil {
		return nil, err
	}

	var k6 ShieldAddr6
	it = p.objs.DynBlocklist6.Iterate()
	for it.Next(&k6, &v) {
		if v.ExpiresNs <= now {
			continue
		}
		out = append(out, controller.BlockedEntry{
			Addr:      netip.AddrFrom16(k6.B),
			Reason:    v.Reason,
			ExpiresIn: time.Duration(v.ExpiresNs - now),
		})
	}
	return out, it.Err()
}
