package health

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/monaaoua9/xdpshield/internal/config"
)

type Manager struct {
	onChange func(name string, up bool)

	mu     sync.Mutex
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func New(onChange func(name string, up bool)) *Manager {
	return &Manager{onChange: onChange}
}

// Update restarts all probes with the new config. Probe state resets, so a
// backend is assumed up again until it fails `fall` times.
func (m *Manager) Update(cfg *config.Config) {
	m.Stop()
	if !cfg.Health.Enabled {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel

	for _, b := range cfg.Backends {
		port := cfg.HealthPortFor(b)
		if port == 0 {
			continue
		}
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			m.probe(ctx, b.Name, b.Address, port, cfg.Health)
		}()
	}
}

func (m *Manager) Stop() {
	m.mu.Lock()
	cancel := m.cancel
	m.cancel = nil
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	m.wg.Wait()
}

func (m *Manager) probe(ctx context.Context, name string, ip netip.Addr, port uint16, h config.Health) {
	addr := net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
	up := true
	fails, oks := 0, 0

	t := time.NewTicker(h.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}

		ok := check(ctx, addr, h.Timeout)
		if ok {
			oks++
			fails = 0
		} else {
			fails++
			oks = 0
		}

		switch {
		case up && fails >= h.Fall:
			up = false
		case !up && oks >= h.Rise:
			up = true
		default:
			continue
		}
		slog.Warn("backend health changed", "backend", name, "up", up)
		m.onChange(name, up)
	}
}

func check(ctx context.Context, addr string, timeout time.Duration) bool {
	d := net.Dialer{Timeout: timeout}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	c.Close()
	return true
}
