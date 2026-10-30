package admin

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/monaaoua9/xdpshield/internal/controller"
	"github.com/monaaoua9/xdpshield/internal/statdef"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Ctl interface {
	Snapshot() ([]controller.VIPInfo, []controller.BackendInfo)
	Block(ip netip.Addr, ttl time.Duration) error
	Unblock(ip netip.Addr) error
	Blocked() ([]controller.BlockedEntry, error)
}

type Recent interface {
	Recent(limit int) []statdef.BlockEvent
}

type Server struct {
	ctl    Ctl
	events Recent
	token  string
	gather prometheus.Gatherer

	// nil means the endpoint answers 501
	Reload func() error
}

func New(ctl Ctl, ev Recent, g prometheus.Gatherer, token string) *Server {
	return &Server{ctl: ctl, events: ev, token: token, gather: g}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok\n")) })
	mux.Handle("GET /metrics", promhttp.HandlerFor(s.gather, promhttp.HandlerOpts{}))
	mux.HandleFunc("GET /api/v1/status", s.status)
	mux.HandleFunc("GET /api/v1/blocklist", s.listBlocked)
	mux.HandleFunc("POST /api/v1/blocklist", s.auth(s.block))
	mux.HandleFunc("DELETE /api/v1/blocklist/{ip}", s.auth(s.unblock))
	mux.HandleFunc("GET /api/v1/events", s.recent)
	mux.HandleFunc("POST /api/v1/reload", s.auth(s.reload))
	return mux
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.token == "" {
			fail(w, 403, "ADMIN_DISABLED", "no admin token configured")
			return
		}
		got := r.Header.Get("Authorization")
		want := "Bearer " + s.token
		if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			fail(w, 401, "UNAUTHORIZED", "bad or missing bearer token")
			return
		}
		next(w, r)
	}
}

func (s *Server) status(w http.ResponseWriter, _ *http.Request) {
	vips, bes := s.ctl.Snapshot()
	ok(w, map[string]any{"vips": vips, "backends": bes}, nil)
}

type blockedJSON struct {
	Addr      string `json:"addr"`
	Reason    string `json:"reason"`
	ExpiresIn string `json:"expires_in"`
}

func (s *Server) listBlocked(w http.ResponseWriter, _ *http.Request) {
	list, err := s.ctl.Blocked()
	if err != nil {
		fail(w, 500, "INTERNAL", err.Error())
		return
	}
	out := make([]blockedJSON, 0, len(list))
	for _, e := range list {
		out = append(out, blockedJSON{e.Addr.String(), statdef.ReasonName(e.Reason), e.ExpiresIn.Round(time.Second).String()})
	}
	ok(w, out, map[string]any{"count": len(out)})
}

func (s *Server) block(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IP  string `json:"ip"`
		TTL string `json:"ttl"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		fail(w, 400, "INVALID_BODY", "expected {ip, ttl}")
		return
	}
	ip, err := netip.ParseAddr(req.IP)
	if err != nil || ip.Is4In6() || ip.Zone() != "" {
		fail(w, 400, "INVALID_IP", "ipv4 or ipv6 address required")
		return
	}
	ttl := 10 * time.Minute
	if req.TTL != "" {
		if ttl, err = time.ParseDuration(req.TTL); err != nil || ttl <= 0 || ttl > 24*time.Hour {
			fail(w, 400, "INVALID_TTL", "ttl must be a duration up to 24h")
			return
		}
	}
	if err := s.ctl.Block(ip, ttl); err != nil {
		fail(w, 500, "INTERNAL", err.Error())
		return
	}
	w.WriteHeader(http.StatusCreated)
	ok(w, map[string]string{"ip": ip.String(), "ttl": ttl.String()}, nil)
}

func (s *Server) unblock(w http.ResponseWriter, r *http.Request) {
	ip, err := netip.ParseAddr(r.PathValue("ip"))
	if err != nil || ip.Is4In6() || ip.Zone() != "" {
		fail(w, 400, "INVALID_IP", "ipv4 or ipv6 address required")
		return
	}
	if err := s.ctl.Unblock(ip); err != nil {
		fail(w, 500, "INTERNAL", err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) reload(w http.ResponseWriter, _ *http.Request) {
	if s.Reload == nil {
		fail(w, 501, "NOT_SUPPORTED", "reload is not wired up")
		return
	}
	if err := s.Reload(); err != nil {
		fail(w, 422, "RELOAD_REJECTED", err.Error())
		return
	}
	ok(w, map[string]string{"result": "applied"}, nil)
}

func (s *Server) recent(w http.ResponseWriter, r *http.Request) {
	n, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	ev := s.events.Recent(n)
	ok(w, ev, map[string]any{"count": len(ev)})
}

func ok(w http.ResponseWriter, data, meta any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"data": data, "meta": meta})
}

func fail(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": msg}})
}
