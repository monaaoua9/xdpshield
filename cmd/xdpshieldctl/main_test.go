package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func fakeAPI(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/status", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"data":{"vips":[{"name":"web","id":0,"address":"2001:db8::1","port":443,"udp":false}],
			"backends":[{"name":"a","id":0,"address":"10.0.1.1","healthy":true},{"name":"b","id":1,"address":"10.0.1.2","healthy":false}]},"meta":null}`))
	})
	mux.HandleFunc("GET /api/v1/blocklist", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"data":[{"addr":"1.2.3.4","reason":"syn_flood","expires_in":"59s"}],"meta":{"count":1}}`))
	})
	mux.HandleFunc("POST /api/v1/blocklist", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(401)
			w.Write([]byte(`{"error":{"code":"UNAUTHORIZED","message":"bad or missing bearer token"}}`))
			return
		}
		w.WriteHeader(201)
		w.Write([]byte(`{"data":{},"meta":null}`))
	})
	mux.HandleFunc("DELETE /api/v1/blocklist/{ip}", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("ip") != "1.2.3.4" {
			t.Errorf("unblock path %q", r.PathValue("ip"))
		}
		w.WriteHeader(204)
	})
	mux.HandleFunc("GET /api/v1/events", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("limit") != "5" {
			t.Errorf("limit %q", r.URL.RawQuery)
		}
		w.Write([]byte(`{"data":[{"at":"2026-01-02T03:04:05Z","src":"1.2.3.4","reason":"udp_flood","observed_pps":2300}],"meta":{"count":1}}`))
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("# HELP x y\nxdpshield_rx_packets_total 12345678\nxdpshield_dropped_packets_total{reason=\"mtu\"} 7\nother_metric 1\n"))
	})
	return httptest.NewServer(mux)
}

func ctl(t *testing.T, srv *httptest.Server, args ...string) (int, string, string) {
	t.Helper()
	var out, errw bytes.Buffer
	code := run(append([]string{"-addr", srv.URL, "-token", "tok"}, args...), &out, &errw)
	return code, out.String(), errw.String()
}

func TestStatus(t *testing.T) {
	srv := fakeAPI(t)
	defer srv.Close()
	code, out, _ := ctl(t, srv, "status")
	if code != 0 {
		t.Fatal(code)
	}
	for _, want := range []string{"[2001:db8::1]:443", "tcp", "DOWN", "10.0.1.2"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
}

func TestBlockedAndEvents(t *testing.T) {
	srv := fakeAPI(t)
	defer srv.Close()
	if _, out, _ := ctl(t, srv, "blocked"); !strings.Contains(out, "syn_flood") {
		t.Errorf("blocked:\n%s", out)
	}
	if _, out, _ := ctl(t, srv, "events", "5"); !strings.Contains(out, "udp_flood") || !strings.Contains(out, "2300") {
		t.Errorf("events:\n%s", out)
	}
}

func TestBlockUnblock(t *testing.T) {
	srv := fakeAPI(t)
	defer srv.Close()
	if code, out, _ := ctl(t, srv, "block", "1.2.3.4", "5m"); code != 0 || !strings.Contains(out, "blocked") {
		t.Errorf("block: %d %q", code, out)
	}
	if code, _, _ := ctl(t, srv, "unblock", "1.2.3.4"); code != 0 {
		t.Errorf("unblock: %d", code)
	}

	// wrong token surfaces the api error code
	var out, errw bytes.Buffer
	code := run([]string{"-addr", srv.URL, "-token", "nope", "block", "1.2.3.4"}, &out, &errw)
	if code != 1 || !strings.Contains(errw.String(), "UNAUTHORIZED") {
		t.Errorf("bad token: %d %q", code, errw.String())
	}
}

func TestStats(t *testing.T) {
	srv := fakeAPI(t)
	defer srv.Close()
	_, out, _ := ctl(t, srv, "stats")
	if !strings.Contains(out, "rx_packets_total") || !strings.Contains(out, "12.35M") {
		t.Errorf("stats:\n%s", out)
	}
	if strings.Contains(out, "other_metric") {
		t.Error("foreign metric leaked")
	}
}

func TestUsageErrors(t *testing.T) {
	srv := fakeAPI(t)
	defer srv.Close()
	for _, args := range [][]string{{}, {"nope"}, {"block"}, {"unblock", "a", "b"}, {"events", "x"}} {
		if code, _, _ := ctl(t, srv, args...); code != 2 {
			t.Errorf("%v: exit %d", args, code)
		}
	}
}

func TestRenderRates(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	prev := &sample{at: t0, val: parseMetrics([]byte(
		"xdpshield_rx_packets_total 1000\n" +
			"xdpshield_dropped_packets_total{reason=\"syn_flood\"} 0\n" +
			"xdpshield_dropped_packets_total{reason=\"mtu\"} 5\n" +
			"xdpshield_backend_packets_total{backend=\"a\"} 100\n"))}
	cur := &sample{at: t0.Add(2 * time.Second), val: parseMetrics([]byte(
		"xdpshield_rx_packets_total 21000\n" +
			"xdpshield_dropped_packets_total{reason=\"syn_flood\"} 4000\n" +
			"xdpshield_dropped_packets_total{reason=\"mtu\"} 5\n" +
			"xdpshield_backend_packets_total{backend=\"a\"} 300\n"))}

	got := render(prev, cur,
		[]topBackend{{"a", true}, {"b", false}},
		[]topEvent{{t0, "1.2.3.4", "syn_flood", 900}})

	for _, want := range []string{"10.0k pps", "syn_flood", "2000", "DOWN", "1.2.3.4"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	if strings.Contains(got, "\nmtu") {
		t.Errorf("idle drop reason shown:\n%s", got)
	}
}

func TestRateIgnoresCounterReset(t *testing.T) {
	t0 := time.Now()
	prev := &sample{at: t0, val: map[string]float64{"x": 500}}
	cur := &sample{at: t0.Add(time.Second), val: map[string]float64{"x": 10}}
	if r := rate(prev, cur, "x"); r != 0 {
		t.Fatalf("got %v", r)
	}
}
