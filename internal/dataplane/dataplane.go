//go:build linux

package dataplane

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

type Plane struct {
	objs ShieldObjects
	lnk  link.Link
}

// Load puts the program and maps in the kernel without attaching anything.
// Tests use it with BPF_PROG_TEST_RUN.
func Load() (*Plane, error) {
	return LoadPinned("")
}

// LoadPinned is Load, but with pinPath set (a directory on bpffs) every map
// is pinned there by name and reused if a previous run left it behind. That
// is what keeps conntrack, blocklists and counters across a restart.
func LoadPinned(pinPath string) (*Plane, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("memlock: %w", err)
	}

	spec, err := LoadShield()
	if err != nil {
		return nil, fmt.Errorf("load bpf spec: %w", err)
	}

	var opts *ebpf.CollectionOptions
	if pinPath != "" {
		if err := os.MkdirAll(pinPath, 0o700); err != nil {
			return nil, err
		}
		for name, m := range spec.Maps {
			// .rodata and friends are per-load, nothing to carry over
			if !strings.HasPrefix(name, ".") {
				m.Pinning = ebpf.PinByName
			}
		}
		opts = &ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: pinPath}}
	}

	p := &Plane{}
	if err := spec.LoadAndAssign(&p.objs, opts); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			// the full log is the only useful part when the verifier says no
			return nil, fmt.Errorf("verifier rejected program:\n%+v", ve)
		}
		if errors.Is(err, ebpf.ErrMapIncompatible) {
			return nil, fmt.Errorf("maps pinned in %s don't match this build, run xdpshield -unpin first: %w", pinPath, err)
		}
		return nil, fmt.Errorf("load bpf: %w", err)
	}
	return p, nil
}

const linkPin = "xdp_link"

// Open loads the program and attaches it. With pinPath set the xdp link is
// pinned as well: a later Open swaps the program inside the existing link, so
// packets never see a gap, and Close leaves the datapath running.
func Open(ifname, mode, pinPath string) (*Plane, error) {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, err
	}
	p, err := LoadPinned(pinPath)
	if err != nil {
		return nil, err
	}

	if pinPath != "" {
		if l, err := link.LoadPinnedLink(filepath.Join(pinPath, linkPin), nil); err == nil {
			if err := l.Update(p.objs.XdpShield); err != nil {
				l.Close()
				p.objs.Close()
				return nil, fmt.Errorf("swap program in pinned link (needs linux 5.9+): %w", err)
			}
			p.lnk = l
			return p, nil
		}
	}

	var flags link.XDPAttachFlags
	switch mode {
	case "native":
		flags = link.XDPDriverMode
	case "generic":
		flags = link.XDPGenericMode
	}

	p.lnk, err = link.AttachXDP(link.XDPOptions{
		Program:   p.objs.XdpShield,
		Interface: iface.Index,
		Flags:     flags,
	})
	if err != nil {
		p.objs.Close()
		return nil, fmt.Errorf("attach xdp to %s (%s): %w", ifname, mode, err)
	}
	if pinPath != "" {
		if err := p.lnk.Pin(filepath.Join(pinPath, linkPin)); err != nil {
			p.Close()
			return nil, fmt.Errorf("pin link: %w", err)
		}
	}
	return p, nil
}

// Detach removes what a pinned run left behind: the xdp link (so traffic goes
// back to the normal stack) and every pinned map.
func Detach(pinPath string) error {
	l, err := link.LoadPinnedLink(filepath.Join(pinPath, linkPin), nil)
	if err == nil {
		if err := l.Unpin(); err != nil {
			l.Close()
			return err
		}
		l.Close() // last reference, the kernel detaches
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.RemoveAll(pinPath)
}

func (p *Plane) Close() error {
	// closing an unpinned link detaches the program, traffic goes back to the normal stack.
	// a pinned one keeps running, only our file descriptors go away
	var errs []error
	if p.lnk != nil {
		errs = append(errs, p.lnk.Close())
	}
	errs = append(errs, p.objs.Close())
	return errors.Join(errs...)
}

func nowMonotonic() uint64 {
	var ts unix.Timespec
	unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return uint64(ts.Sec)*1e9 + uint64(ts.Nsec)
}
