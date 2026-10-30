package config

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	MaxVIPs     = 64
	MaxBackends = 1024
	MaxAmpPorts = 64
)

type Config struct {
	Interface string `yaml:"interface"`
	XDPMode   string `yaml:"xdp_mode"` // auto, native, generic
	Listen    string `yaml:"listen"`
	// name of the env var holding the admin bearer token, empty = mutating admin routes disabled
	AdminTokenEnv string `yaml:"admin_token_env"`

	EncapSrc netip.Addr `yaml:"encap_src"`
	MTU      int        `yaml:"mtu"`
	HashSeed uint32     `yaml:"hash_seed"`

	DDoS     DDoS      `yaml:"ddos"`
	Health   Health    `yaml:"health"`
	Backends []Backend `yaml:"backends"`
	VIPs     []VIP     `yaml:"vips"`
}

type DDoS struct {
	Enabled     bool           `yaml:"enabled"`
	SynLimitPPS uint32         `yaml:"syn_limit_pps"`
	UDPLimitPPS uint32         `yaml:"udp_limit_pps"`
	BlockTTL    time.Duration  `yaml:"block_ttl"`
	Allow       []netip.Prefix `yaml:"allow"`
	Deny        []netip.Prefix `yaml:"deny"`
	// files of prefixes (country zones, drop lists...) merged into allow/deny on load
	AllowLists []string `yaml:"allow_lists"`
	DenyLists  []string `yaml:"deny_lists"`

	Amplification Amplification `yaml:"amplification"`
}

// Amplification drops reflected udp answers (source port in Ports) that land on
// a vip address without matching any vip. empty Ports = off.
type Amplification struct {
	Ports   []uint16 `yaml:"ports"`
	MinSize uint16   `yaml:"min_size"` // smallest udp length (header included) to drop, 0 = any
}

type Health struct {
	Enabled  bool          `yaml:"enabled"`
	Interval time.Duration `yaml:"interval"`
	Timeout  time.Duration `yaml:"timeout"`
	Fall     int           `yaml:"fall"`
	Rise     int           `yaml:"rise"`
}

type Backend struct {
	Name       string     `yaml:"name"`
	Address    netip.Addr `yaml:"address"`
	MAC        string     `yaml:"mac"` // next hop mac on the lb's interface
	HealthPort uint16     `yaml:"health_port"`
	// tcp (default) or http; http wants a 2xx/3xx from health_path (default /)
	HealthCheck string `yaml:"health_check"`
	HealthPath  string `yaml:"health_path"`
	// no new flows, tracked ones keep going until they end or age out
	Drain bool `yaml:"drain"`
}

type VIP struct {
	Name      string      `yaml:"name"`
	Address   netip.Addr  `yaml:"address"`
	Port      uint16      `yaml:"port"`
	Proto     string      `yaml:"proto"`
	Algorithm string      `yaml:"algorithm"` // maglev, wrr
	Backends  []VIPMember `yaml:"backends"`
}

type VIPMember struct {
	Name   string `yaml:"name"`
	Weight uint32 `yaml:"weight"`
}

func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	if err := c.expandLists(filepath.Dir(path)); err != nil {
		return nil, fmt.Errorf("cidr lists: %w", err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func Parse(raw []byte) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	c.defaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) defaults() {
	if c.XDPMode == "" {
		c.XDPMode = "auto"
	}
	if c.Listen == "" {
		c.Listen = "127.0.0.1:9100"
	}
	if c.MTU == 0 {
		c.MTU = 1500
	}
	if c.HashSeed == 0 {
		c.HashSeed = 0x5eed
	}
	d := &c.DDoS
	if d.SynLimitPPS == 0 {
		d.SynLimitPPS = 200
	}
	if d.UDPLimitPPS == 0 {
		d.UDPLimitPPS = 2000
	}
	if d.BlockTTL == 0 {
		d.BlockTTL = 60 * time.Second
	}
	h := &c.Health
	if h.Interval == 0 {
		h.Interval = 2 * time.Second
	}
	if h.Timeout == 0 {
		h.Timeout = 500 * time.Millisecond
	}
	if h.Fall == 0 {
		h.Fall = 3
	}
	if h.Rise == 0 {
		h.Rise = 2
	}
	for i := range c.Backends {
		b := &c.Backends[i]
		if b.HealthCheck == "" {
			b.HealthCheck = "tcp"
		}
		if b.HealthCheck == "http" && b.HealthPath == "" {
			b.HealthPath = "/"
		}
	}
	for i := range c.VIPs {
		v := &c.VIPs[i]
		if v.Proto == "" {
			v.Proto = "tcp"
		}
		if v.Algorithm == "" {
			v.Algorithm = "maglev"
		}
		for j := range v.Backends {
			if v.Backends[j].Weight == 0 {
				v.Backends[j].Weight = 1
			}
		}
	}
}

func (c *Config) Validate() error {
	if c.Interface == "" {
		return fmt.Errorf("interface is required")
	}
	switch c.XDPMode {
	case "auto", "native", "generic":
	default:
		return fmt.Errorf("xdp_mode %q: want auto, native or generic", c.XDPMode)
	}
	if !c.EncapSrc.Is4() {
		return fmt.Errorf("encap_src must be an ipv4 address")
	}
	if c.MTU < 576 || c.MTU > 9216 {
		return fmt.Errorf("mtu %d out of range", c.MTU)
	}
	if len(c.VIPs) > MaxVIPs {
		return fmt.Errorf("too many vips (%d > %d)", len(c.VIPs), MaxVIPs)
	}
	if len(c.Backends) > MaxBackends {
		return fmt.Errorf("too many backends (%d > %d)", len(c.Backends), MaxBackends)
	}

	for _, p := range append(append([]netip.Prefix{}, c.DDoS.Allow...), c.DDoS.Deny...) {
		if !p.IsValid() || p.Addr().Is4In6() {
			return fmt.Errorf("cidr %s: use a plain ipv4 or ipv6 prefix", p)
		}
	}

	if err := checkCIDRCount("allow", c.DDoS.Allow); err != nil {
		return err
	}
	if err := checkCIDRCount("deny", c.DDoS.Deny); err != nil {
		return err
	}

	amp := c.DDoS.Amplification
	if len(amp.Ports) > MaxAmpPorts {
		return fmt.Errorf("too many amplification ports (%d > %d)", len(amp.Ports), MaxAmpPorts)
	}
	ampSeen := map[uint16]bool{}
	for _, p := range amp.Ports {
		if p == 0 || ampSeen[p] {
			return fmt.Errorf("amplification port %d is zero or listed twice", p)
		}
		ampSeen[p] = true
	}

	bes := map[string]Backend{}
	addrs := map[netip.Addr]string{}
	for _, b := range c.Backends {
		if b.Name == "" {
			return fmt.Errorf("backend without a name")
		}
		if _, dup := bes[b.Name]; dup {
			return fmt.Errorf("duplicate backend %q", b.Name)
		}
		if !b.Address.Is4() {
			// v6 clients reach v4 backends over 6in4, there is no ip6ip6 path yet
			return fmt.Errorf("backend %s: address must be ipv4", b.Name)
		}
		if other, dup := addrs[b.Address]; dup {
			return fmt.Errorf("backend %s and %s share address %s", b.Name, other, b.Address)
		}
		if b.HealthCheck != "tcp" && b.HealthCheck != "http" {
			return fmt.Errorf("backend %s: health_check %q, want tcp or http", b.Name, b.HealthCheck)
		}
		if b.HealthCheck == "http" && !strings.HasPrefix(b.HealthPath, "/") {
			return fmt.Errorf("backend %s: health_path must start with /", b.Name)
		}
		if _, err := net.ParseMAC(b.MAC); err != nil {
			return fmt.Errorf("backend %s: bad mac: %w", b.Name, err)
		}
		bes[b.Name] = b
		addrs[b.Address] = b.Name
	}

	type key struct {
		a netip.Addr
		p uint16
		t string
	}
	seen := map[key]bool{}
	names := map[string]bool{}
	for _, v := range c.VIPs {
		if v.Name == "" || names[v.Name] {
			return fmt.Errorf("vip name %q missing or duplicated", v.Name)
		}
		names[v.Name] = true
		if !v.Address.IsValid() || v.Address.Is4In6() {
			return fmt.Errorf("vip %s: address must be plain ipv4 or ipv6", v.Name)
		}
		if v.Port == 0 {
			return fmt.Errorf("vip %s: port is required", v.Name)
		}
		if v.Proto != "tcp" && v.Proto != "udp" {
			return fmt.Errorf("vip %s: proto %q", v.Name, v.Proto)
		}
		if v.Algorithm != "maglev" && v.Algorithm != "wrr" {
			return fmt.Errorf("vip %s: algorithm %q", v.Name, v.Algorithm)
		}
		k := key{v.Address, v.Port, v.Proto}
		if seen[k] {
			return fmt.Errorf("vip %s duplicates another vip", v.Name)
		}
		seen[k] = true
		if len(v.Backends) == 0 {
			return fmt.Errorf("vip %s has no backends", v.Name)
		}
		for _, m := range v.Backends {
			if _, ok := bes[m.Name]; !ok {
				return fmt.Errorf("vip %s references unknown backend %q", v.Name, m.Name)
			}
		}
	}
	return nil
}

// HealthPortFor falls back to the port of the first tcp vip using the backend.
// 0 means we have nothing to probe.
func (c *Config) HealthPortFor(b Backend) uint16 {
	if b.HealthPort != 0 {
		return b.HealthPort
	}
	for _, v := range c.VIPs {
		if v.Proto != "tcp" {
			continue
		}
		for _, m := range v.Backends {
			if m.Name == b.Name {
				return v.Port
			}
		}
	}
	return 0
}
