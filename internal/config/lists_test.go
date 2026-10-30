package config

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadMergesPrefixLists(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "cn.zone", "# country zone\n1.0.1.0/24\n1.0.2.0/23 ; trailing comment\n\n2001:db8:77::/48\n198.51.100.7\n")
	writeFile(t, dir, "ok.txt", "10.20.0.0/16\n")

	raw := strings.Replace(good, "ddos:\n  allow: [10.9.0.0/16]\n",
		"ddos:\n  allow: [10.9.0.0/16]\n  allow_lists: [ok.txt]\n  deny: [1.0.1.0/24]\n  deny_lists: [cn.zone]\n", 1)
	writeFile(t, dir, "config.yaml", raw)

	c, err := Load(filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.DDoS.Allow) != 2 {
		t.Fatalf("allow %v", c.DDoS.Allow)
	}
	// 1.0.1.0/24 is in both the inline list and the file, only one copy
	if len(c.DDoS.Deny) != 4 {
		t.Fatalf("deny %v", c.DDoS.Deny)
	}
	want := netip.MustParsePrefix("198.51.100.7/32")
	found := false
	for _, p := range c.DDoS.Deny {
		found = found || p == want
	}
	if !found {
		t.Fatalf("bare address not turned into a host route: %v", c.DDoS.Deny)
	}
}

func TestPrefixListErrors(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"garbage":  "1.2.3.0/24\nnot-an-ip\n",
		"mapped":   "::ffff:1.2.3.4\n",
		"too big":  strings.Repeat("10.1.2.3\n", 1) + bigList(MaxCIDRs+1),
		"no slash": "1.2.3.4/33\n",
	}
	for name, body := range cases {
		writeFile(t, dir, "bad.txt", body)
		raw := strings.Replace(good, "ddos:\n", "ddos:\n  deny_lists: [bad.txt]\n", 1)
		writeFile(t, dir, "config.yaml", raw)
		if _, err := Load(filepath.Join(dir, "config.yaml")); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}

	writeFile(t, dir, "config.yaml", strings.Replace(good, "ddos:\n", "ddos:\n  deny_lists: [missing.txt]\n", 1))
	if _, err := Load(filepath.Join(dir, "config.yaml")); err == nil {
		t.Error("missing file accepted")
	}
}

func bigList(n int) string {
	var sb strings.Builder
	for i := 0; i < n; i++ {
		sb.WriteString(netip.AddrFrom4([4]byte{11, byte(i >> 8), byte(i), 0}).String() + "/24\n")
	}
	return sb.String()
}
