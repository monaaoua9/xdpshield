package health

import (
	"context"
	"log/slog"
	"net"
	"net/http"
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
			m.probe(ctx, b, port, cfg.Health)
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

func (m *Manager) probe(ctx context.Context, b config.Backend, port uint16, h config.Health) {
	name := b.Name
	addr := net.JoinHostPort(b.Address.String(), strconv.Itoa(int(port)))
	chk := func() bool { return check(ctx, addr, h.Timeout) }
	if b.HealthCheck == "http" {
		chk = httpCheck(ctx, addr, b.HealthPath, h.Timeout)
	}
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

		if chk() {
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

func httpCheck(ctx context.Context, addr, path string, timeout time.Duration) func() bool {
	cl := &http.Client{
		Timeout: timeout,
		// a redirect to a login page shouldn't count as healthy or unhealthy by itself
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	url := "http://" + addr + path
	return func() bool {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return false
		}
		resp, err := cl.Do(req)
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode >= 200 && resp.StatusCode < 400
	}
}
