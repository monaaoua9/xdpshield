package config

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

const MaxCIDRs = 16384 // per family and per list kind, same as CIDR_MAX in the bpf headers

// one prefix per line, '#' or ';' start a comment, a bare address counts as a
// host route. fits country zone files, spamhaus drop and plain ip dumps.
func readPrefixes(path string) ([]netip.Prefix, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []netip.Prefix
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		p, err := netip.ParsePrefix(line)
		if err != nil {
			a, aerr := netip.ParseAddr(line)
			if aerr != nil {
				return nil, fmt.Errorf("%s:%d: %q is not a prefix or address", path, n, line)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		if p.Addr().Is4In6() || p.Addr().Zone() != "" {
			return nil, fmt.Errorf("%s:%d: use a plain ipv4 or ipv6 prefix", path, n)
		}
		out = append(out, p.Masked())
	}
	return out, sc.Err()
}

// expandLists folds the files named in allow_lists/deny_lists into Allow and
// Deny. relative paths are relative to the config file.
func (c *Config) expandLists(dir string) error {
	fold := func(files []string, dst *[]netip.Prefix) error {
		seen := map[netip.Prefix]bool{}
		for _, p := range *dst {
			seen[p.Masked()] = true
		}
		for _, f := range files {
			if !filepath.IsAbs(f) {
				f = filepath.Join(dir, f)
			}
			ps, err := readPrefixes(f)
			if err != nil {
				return err
			}
			for _, p := range ps {
				if !seen[p] {
					seen[p] = true
					*dst = append(*dst, p)
				}
			}
		}
		return nil
	}
	if err := fold(c.DDoS.AllowLists, &c.DDoS.Allow); err != nil {
		return err
	}
	return fold(c.DDoS.DenyLists, &c.DDoS.Deny)
}

func checkCIDRCount(kind string, ps []netip.Prefix) error {
	var v4, v6 int
	for _, p := range ps {
		if p.Addr().Is4() {
			v4++
		} else {
			v6++
		}
	}
	if v4 > MaxCIDRs || v6 > MaxCIDRs {
		return fmt.Errorf("%s list too big: %d ipv4 and %d ipv6 prefixes, limit is %d each", kind, v4, v6, MaxCIDRs)
	}
	return nil
}
