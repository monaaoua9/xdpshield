package health

import (
	"net"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/monaaoua9/xdpshield/internal/config"
)

func TestFlapsDownAndUp(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	var mu sync.Mutex
	var events []bool
	m := New(func(_ string, up bool) {
		mu.Lock()
		events = append(events, up)
		mu.Unlock()
	})
	defer m.Stop()

	cfg := &config.Config{
		Health: config.Health{Enabled: true, Interval: 20 * time.Millisecond, Timeout: 100 * time.Millisecond, Fall: 2, Rise: 2},
		Backends: []config.Backend{
			{Name: "x", Address: netip.MustParseAddr("127.0.0.1"), HealthPort: port},
		},
	}
	m.Update(cfg)

	waitFor := func(n int) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			mu.Lock()
			got := len(events)
			mu.Unlock()
			if got >= n {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("timed out waiting for event %d", n)
	}

	ln.Close()
	waitFor(1)
	ln2, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
	if err != nil {
		t.Skip("port taken, can't test recovery")
	}
	defer ln2.Close()
	go func() {
		for {
			c, err := ln2.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	waitFor(2)

	mu.Lock()
	defer mu.Unlock()
	if events[0] != false || events[1] != true {
		t.Fatalf("events %v", events)
	}
}
