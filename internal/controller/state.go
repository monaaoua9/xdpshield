package controller

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
)

// State is what a restarted process needs to pick up the maps a previous run
// left pinned: which id belongs to which backend/vip. Without it ids would be
// handed out in config order again and conntrack entries could point at the
// wrong backend.
type State struct {
	Backends map[string]uint32   `json:"backends"`
	VIPs     map[string]VIPEntry `json:"vips"`
}

type VIPEntry struct {
	ID   uint32     `json:"id"`
	Addr netip.Addr `json:"addr"`
	Port uint16     `json:"port"`
	UDP  bool       `json:"udp"`
}

func (c *Controller) State() State {
	c.mu.Lock()
	defer c.mu.Unlock()

	s := State{Backends: map[string]uint32{}, VIPs: map[string]VIPEntry{}}
	for name := range c.bes {
		if id, ok := c.beIDs.lookup(name); ok {
			s.Backends[name] = id
		}
	}
	for name, v := range c.vips {
		s.VIPs[name] = VIPEntry{ID: v.id, Addr: v.key.Addr, Port: v.key.Port, UDP: v.key.UDP}
	}
	return s
}

// Restore has to run before the first Apply. The vips are marked as having an
// unknown table so Apply rewrites them, and anything the new config no longer
// mentions gets removed like any other stale entry.
func (c *Controller) Restore(s State) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for name, id := range s.Backends {
		c.beIDs.adopt(name, id)
		c.bes[name] = true
	}
	for name, v := range s.VIPs {
		c.vipIDs.adopt(name, v.ID)
		c.vips[name] = vipState{id: v.ID, key: VIPKey{Addr: v.Addr, Port: v.Port, UDP: v.UDP}}
	}
}

func SaveState(path string, s State) error {
	raw, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// a missing file is fine, it just means a first start
func LoadState(path string) (State, error) {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return State{}, nil
	}
	if err != nil {
		return State{}, err
	}
	var s State
	return s, json.Unmarshal(raw, &s)
}
