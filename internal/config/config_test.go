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
		"unknown field":             good + "\nbogus: 1\n",
		"unknown backend":           strings.Replace(good, "{name: b}", "{name: nope}", 1),
		"bad mac":                   strings.Replace(good, "02:00:00:00:00:02", "zz", 1),
		"v6 backend, no encap_src6": strings.Replace(good, "10.0.1.2", "2001:db8::2", 1),
		"encap_src6 is v4":          strings.Replace(good, "encap_src: 10.0.0.1", "encap_src: 10.0.0.1\nencap_src6: 10.0.0.9", 1),
		"mapped vip":                strings.Replace(good, "203.0.113.10", "::ffff:203.0.113.10", 1),
		"dup backend ip":            strings.Replace(good, "10.0.1.2", "10.0.1.1", 1),
		"no iface":                  strings.Replace(good, "interface: eth0", "", 1),
		"bad algo":                  strings.Replace(good, "port: 443", "port: 443\n    algorithm: random", 1),
	}
	for name, raw := range cases {
		if _, err := Parse([]byte(raw)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestIPv6VIPAndCIDRs(t *testing.T) {
	raw := strings.Replace(good, "203.0.113.10", "2001:db8::1", 1)
	raw = strings.Replace(raw, "ddos:\n", "ddos:\n  deny: [2001:db8:bad::/48]\n", 1)
	c, err := Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if !c.VIPs[0].Address.Is6() {
		t.Fatalf("vip addr %s", c.VIPs[0].Address)
	}
}

func TestAmplificationValidation(t *testing.T) {
	with := func(list string) string {
		return strings.Replace(good, "ddos:\n", "ddos:\n  amplification: {ports: "+list+", min_size: 200}\n", 1)
	}
	c, err := Parse([]byte(with("[53, 123, 11211]")))
	if err != nil {
		t.Fatal(err)
	}
	if a := c.DDoS.Amplification; len(a.Ports) != 3 || a.MinSize != 200 {
		t.Fatalf("got %+v", a)
	}
	for _, bad := range []string{"[53, 53]", "[0]"} {
		if _, err := Parse([]byte(with(bad))); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestHealthCheckKinds(t *testing.T) {
	c, err := Parse([]byte(strings.Replace(good, `address: 10.0.1.1,`, `address: 10.0.1.1, health_check: http,`, 1)))
	if err != nil {
		t.Fatal(err)
	}
	if b := c.Backends[0]; b.HealthCheck != "http" || b.HealthPath != "/" {
		t.Fatalf("got %+v", b)
	}
	if c.Backends[1].HealthCheck != "tcp" {
		t.Fatalf("default is %q", c.Backends[1].HealthCheck)
	}
	for _, bad := range []string{`health_check: icmp,`, `health_check: http, health_path: ready,`} {
		if _, err := Parse([]byte(strings.Replace(good, `address: 10.0.1.1,`, `address: 10.0.1.1, `+bad, 1))); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestIPv6Backend(t *testing.T) {
	raw := strings.Replace(good, "10.0.1.2", "2001:db8::2", 1)
	raw = strings.Replace(raw, "encap_src: 10.0.0.1", "encap_src: 10.0.0.1\nencap_src6: 2001:db8::1", 1)
	c, err := Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if !c.Backends[1].Address.Is6() || !c.EncapSrc6.Is6() {
		t.Fatalf("got %+v", c.Backends[1])
	}

	// all-v6 deployment doesn't need an ipv4 encap_src
	only6 := strings.Replace(raw, "encap_src: 10.0.0.1\n", "", 1)
	only6 = strings.Replace(only6, "10.0.1.1", "2001:db8::3", 1)
	if _, err := Parse([]byte(only6)); err != nil {
		t.Fatal(err)
	}
}

func TestExampleConfigIsValid(t *testing.T) {
	if _, err := Load("../../configs/example.yaml"); err != nil {
		t.Fatal(err)
	}
}
