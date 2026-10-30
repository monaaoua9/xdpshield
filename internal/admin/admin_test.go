package admin

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/monaaoua9/xdpshield/internal/controller"
	"github.com/monaaoua9/xdpshield/internal/statdef"
	"github.com/prometheus/client_golang/prometheus"
)

type fakeCtl struct{ blocked map[netip.Addr]bool }

func (f *fakeCtl) Snapshot() ([]controller.VIPInfo, []controller.BackendInfo) { return nil, nil }
func (f *fakeCtl) Block(ip netip.Addr, _ time.Duration) error                 { f.blocked[ip] = true; return nil }
func (f *fakeCtl) Unblock(ip netip.Addr) error                                { delete(f.blocked, ip); return nil }
func (f *fakeCtl) Blocked() ([]controller.BlockedEntry, error) {
	var out []controller.BlockedEntry
	for ip := range f.blocked {
		out = append(out, controller.BlockedEntry{Addr: ip, Reason: 3, ExpiresIn: time.Minute})
	}
	return out, nil
}

type noEvents struct{}

func (noEvents) Recent(int) []statdef.BlockEvent { return nil }

func do(h http.Handler, method, path, body, auth string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if auth != "" {
		r.Header.Set("Authorization", auth)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestBlockFlow(t *testing.T) {
	ctl := &fakeCtl{blocked: map[netip.Addr]bool{}}
	h := New(ctl, noEvents{}, prometheus.NewRegistry(), "s3cret").Handler()

	if w := do(h, "POST", "/api/v1/blocklist", `{"ip":"1.2.3.4"}`, ""); w.Code != 401 {
		t.Fatalf("no token: %d", w.Code)
	}
	if w := do(h, "POST", "/api/v1/blocklist", `{"ip":"1.2.3.4"}`, "Bearer wrong"); w.Code != 401 {
		t.Fatalf("wrong token: %d", w.Code)
	}
	if w := do(h, "POST", "/api/v1/blocklist", `{"ip":"::ffff:1.2.3.4"}`, "Bearer s3cret"); w.Code != 400 {
		t.Fatalf("mapped: %d", w.Code)
	}
	if w := do(h, "POST", "/api/v1/blocklist", `{"ip":"2001:db8::7"}`, "Bearer s3cret"); w.Code != 201 {
		t.Fatalf("ipv6: %d", w.Code)
	}
	if w := do(h, "POST", "/api/v1/blocklist", `{"ip":"1.2.3.4","ttl":"999h"}`, "Bearer s3cret"); w.Code != 400 {
		t.Fatalf("ttl: %d", w.Code)
	}
	if w := do(h, "POST", "/api/v1/blocklist", `{"ip":"1.2.3.4","ttl":"5m"}`, "Bearer s3cret"); w.Code != 201 {
		t.Fatalf("block: %d %s", w.Code, w.Body)
	}
	w := do(h, "GET", "/api/v1/blocklist", "", "")
	if !strings.Contains(w.Body.String(), "1.2.3.4") {
		t.Fatalf("list: %s", w.Body)
	}
	if w := do(h, "DELETE", "/api/v1/blocklist/1.2.3.4", "", "Bearer s3cret"); w.Code != 204 {
		t.Fatalf("unblock: %d", w.Code)
	}
	if w := do(h, "DELETE", "/api/v1/blocklist/2001:db8::7", "", "Bearer s3cret"); w.Code != 204 {
		t.Fatalf("unblock v6: %d", w.Code)
	}
	if len(ctl.blocked) != 0 {
		t.Fatal("still blocked")
	}
}

func TestMutationsDisabledWithoutToken(t *testing.T) {
	h := New(&fakeCtl{blocked: map[netip.Addr]bool{}}, noEvents{}, prometheus.NewRegistry(), "").Handler()
	if w := do(h, "POST", "/api/v1/blocklist", `{"ip":"1.2.3.4"}`, "Bearer "); w.Code != 403 {
		t.Fatalf("got %d", w.Code)
	}
	if w := do(h, "GET", "/healthz", "", ""); w.Code != 200 {
		t.Fatalf("healthz %d", w.Code)
	}
}

func TestReload(t *testing.T) {
	s := New(&fakeCtl{blocked: map[netip.Addr]bool{}}, noEvents{}, prometheus.NewRegistry(), "s3cret")
	h := s.Handler()

	if w := do(h, "POST", "/api/v1/reload", "", ""); w.Code != 401 {
		t.Fatalf("no token: %d", w.Code)
	}
	if w := do(h, "POST", "/api/v1/reload", "", "Bearer s3cret"); w.Code != 501 {
		t.Fatalf("unwired: %d", w.Code)
	}

	calls := 0
	s.Reload = func() error { calls++; return nil }
	if w := do(h, "POST", "/api/v1/reload", "", "Bearer s3cret"); w.Code != 200 || calls != 1 {
		t.Fatalf("ok path: %d, calls %d", w.Code, calls)
	}

	s.Reload = func() error { return errors.New("vips[0]: bad port") }
	w := do(h, "POST", "/api/v1/reload", "", "Bearer s3cret")
	if w.Code != 422 || !strings.Contains(w.Body.String(), "bad port") {
		t.Fatalf("rejected: %d %s", w.Code, w.Body)
	}
}
