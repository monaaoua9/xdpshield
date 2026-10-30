package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type Lifecycle struct {
	reloads *prometheus.CounterVec
	lastOK  prometheus.Gauge
}

func NewLifecycle(reg prometheus.Registerer, version string) *Lifecycle {
	l := &Lifecycle{
		reloads: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "xdpshield_config_reloads_total",
			Help: "config reload attempts by result",
		}, []string{"result"}),
		lastOK: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "xdpshield_config_last_success_timestamp_seconds",
			Help: "unix time of the last config that was applied",
		}),
	}
	// both series exist from the start so rate() works on the first failure
	l.reloads.WithLabelValues("ok")
	l.reloads.WithLabelValues("error")

	info := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "xdpshield_build_info",
		Help: "constant 1, the version is in the label",
	}, []string{"version"})
	info.WithLabelValues(version).Set(1)

	start := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "xdpshield_start_time_seconds",
		Help: "unix time the daemon started",
	})
	now := float64(time.Now().Unix())
	start.Set(now)
	l.lastOK.Set(now) // the initial apply counts

	reg.MustRegister(l.reloads, l.lastOK, info, start)
	return l
}

func (l *Lifecycle) Reloaded(err error) {
	if err != nil {
		l.reloads.WithLabelValues("error").Inc()
		return
	}
	l.reloads.WithLabelValues("ok").Inc()
	l.lastOK.Set(float64(time.Now().Unix()))
}
