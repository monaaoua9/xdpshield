package metrics

import (
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestLifecycle(t *testing.T) {
	reg := prometheus.NewRegistry()
	l := NewLifecycle(reg, "v1.2.3")

	l.Reloaded(nil)
	l.Reloaded(errors.New("bad yaml"))
	l.Reloaded(errors.New("bad yaml"))

	if got := testutil.ToFloat64(l.reloads.WithLabelValues("ok")); got != 1 {
		t.Errorf("ok = %v", got)
	}
	if got := testutil.ToFloat64(l.reloads.WithLabelValues("error")); got != 2 {
		t.Errorf("error = %v", got)
	}

	n, err := testutil.GatherAndCount(reg, "xdpshield_build_info", "xdpshield_start_time_seconds")
	if err != nil || n != 2 {
		t.Errorf("count = %d, err = %v", n, err)
	}
}
