package config

import (
	"strings"
	"testing"
)

const good = `
interface: eth0
encap_src: 10.0.0.1
ddos:
  allow: [10.9.0.0/16]
backends:
  - {name: a, address: 10.0.1.1, mac: "02:00:00:00:00:01"}
  - {name: b, address: 10.0.1.2, mac: "02:00:00:00:00:02"}
vips:
  - name: web
    address: 203.0.113.10
    port: 443
    backends:
      - {name: a, weight: 3}
      - {name: b}
`

func TestParseDefaults(t *testing.T) {
	c, err := Parse([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	if c.MTU != 1500 || c.XDPMode != "auto" || c.DDoS.SynLimitPPS == 0 {
		t.Fatalf("defaults not applied: %+v", c)
	}
	v := c.VIPs[0]
	if v.Proto != "tcp" || v.Algorithm != "maglev" || v.Backends[1].Weight != 1 {
		t.Fatalf("vip defaults: %+v", v)
	}
	if p := c.HealthPortFor(c.Backends[0]); p != 443 {
		t.Fatalf("health port %d", p)
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string]string{
		"unknown field":   good + "\nbogus: 1\n",
		"unknown backend": strings.Replace(good, "{name: b}", "{name: nope}", 1),
		"bad mac":         strings.Replace(good, "02:00:00:00:00:02", "zz", 1),
		"ipv6 vip":        strings.Replace(good, "203.0.113.10", "2001:db8::1", 1),
		"dup backend ip":  strings.Replace(good, "10.0.1.2", "10.0.1.1", 1),
		"no iface":        strings.Replace(good, "interface: eth0", "", 1),
		"bad algo":        strings.Replace(good, "port: 443", "port: 443\n    algorithm: random", 1),
	}
	for name, raw := range cases {
		if _, err := Parse([]byte(raw)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestExampleConfigIsValid(t *testing.T) {
	if _, err := Load("../../configs/example.yaml"); err != nil {
		t.Fatal(err)
	}
}
