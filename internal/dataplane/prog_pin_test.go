//go:build linux && integration

package dataplane

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/monaaoua9/xdpshield/internal/config"
	"github.com/monaaoua9/xdpshield/internal/controller"
	"golang.org/x/sys/unix"
)

// each test gets its own bpffs, the host one may not even be mounted
func bpffs(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := unix.Mount("bpf", dir, "bpf", 0, ""); err != nil {
		t.Skipf("can't mount bpffs: %v", err)
	}
	t.Cleanup(func() { unix.Unmount(dir, unix.MNT_DETACH) })
	return filepath.Join(dir, "xdpshield")
}

func TestPinnedMapsSurviveRestart(t *testing.T) {
	pin := bpffs(t)
	cfg, err := config.Parse([]byte(testCfg))
	if err != nil {
		t.Fatal(err)
	}

	p1, err := LoadPinned(pin)
	if err != nil {
		t.Fatal(err)
	}
	c1 := controller.New(p1)
	if err := c1.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	pkt := tcpFrame("1.1.1.1", 40001, ack)
	_, out := run(t, p1, pkt)
	be := outerDst(t, out, pkt)
	state := c1.State()
	p1.Close()

	// "restart": fresh objects over the same pins
	p2, err := LoadPinned(pin)
	if err != nil {
		t.Fatal(err)
	}
	defer p2.Close()
	c2 := controller.New(p2)
	c2.Restore(state)
	if err := c2.Apply(cfg); err != nil {
		t.Fatal(err)
	}

	_, out = run(t, p2, pkt)
	if got := outerDst(t, out, pkt); got != be {
		t.Fatalf("flow moved from %s to %s across restart", be, got)
	}
	if counter(t, p2, "ct_new") != 1 || counter(t, p2, "ct_hit") != 1 {
		t.Fatalf("conntrack entry lost: new=%d hit=%d", counter(t, p2, "ct_new"), counter(t, p2, "ct_hit"))
	}
}

func TestPinnedLinkIsReusedAndDetached(t *testing.T) {
	pin := bpffs(t)

	p1, err := Open("lo", "generic", pin)
	if err != nil {
		t.Skipf("can't attach xdp to lo: %v", err)
	}
	if _, err := os.Stat(filepath.Join(pin, linkPin)); err != nil {
		t.Fatalf("link not pinned: %v", err)
	}
	p1.Close() // pinned: stays attached

	p2, err := Open("lo", "generic", pin)
	if err != nil {
		t.Fatalf("second open should swap the program in the pinned link: %v", err)
	}
	p2.Close()

	if err := Detach(pin); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(pin); !os.IsNotExist(err) {
		t.Fatalf("pin dir still there: %v", err)
	}

	// and nothing is left attached: a fresh unpinned open works again
	p3, err := Open("lo", "generic", "")
	if err != nil {
		t.Fatalf("lo still occupied: %v", err)
	}
	p3.Close()
}
