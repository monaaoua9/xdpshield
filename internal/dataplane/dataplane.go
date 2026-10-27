//go:build linux

package dataplane

import (
	"errors"
	"fmt"
	"net"

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
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("memlock: %w", err)
	}

	p := &Plane{}
	if err := LoadShieldObjects(&p.objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			// the full log is the only useful part when the verifier says no
			return nil, fmt.Errorf("verifier rejected program:\n%+v", ve)
		}
		return nil, fmt.Errorf("load bpf: %w", err)
	}
	return p, nil
}

func Open(ifname, mode string) (*Plane, error) {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, err
	}
	p, err := Load()
	if err != nil {
		return nil, err
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
	return p, nil
}

func (p *Plane) Close() error {
	// closing the link detaches the program, traffic goes back to the normal stack
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
