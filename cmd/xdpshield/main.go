//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/monaaoua9/xdpshield/internal/admin"
	"github.com/monaaoua9/xdpshield/internal/config"
	"github.com/monaaoua9/xdpshield/internal/controller"
	"github.com/monaaoua9/xdpshield/internal/dataplane"
	"github.com/monaaoua9/xdpshield/internal/health"
	"github.com/monaaoua9/xdpshield/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

var version = "dev"

func main() {
	cfgPath := flag.String("config", "/etc/xdpshield/config.yaml", "config file")
	check := flag.Bool("check", false, "validate the config and exit")
	showVer := flag.Bool("version", false, "print version and exit")
	unpin := flag.Bool("unpin", false, "detach a pinned run (pin_path) and delete its maps, then exit")
	flag.Parse()

	if *showVer {
		fmt.Println(version)
		return
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		os.Exit(2)
	}
	if *check {
		fmt.Println("config ok")
		return
	}
	if *unpin {
		if cfg.PinPath == "" {
			fmt.Fprintln(os.Stderr, "pin_path is not set in the config, nothing to do")
			os.Exit(2)
		}
		if err := dataplane.Detach(cfg.PinPath); err != nil {
			fmt.Fprintln(os.Stderr, "unpin:", err)
			os.Exit(1)
		}
		os.Remove(cfg.StateFile) // ids of maps that no longer exist are worthless
		fmt.Println("detached and removed", cfg.PinPath)
		return
	}

	if err := run(*cfgPath, cfg); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(path string, cfg *config.Config) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	plane, err := dataplane.Open(cfg.Interface, cfg.XDPMode, cfg.PinPath)
	if err != nil {
		return err
	}
	defer plane.Close()
	slog.Info("xdp attached", "iface", cfg.Interface, "mode", cfg.XDPMode, "version", version)

	ctl := controller.New(plane)
	if cfg.PinPath != "" {
		st, err := controller.LoadState(cfg.StateFile)
		if err != nil {
			return fmt.Errorf("read saved state: %w", err)
		}
		ctl.Restore(st)
		slog.Info("pinned run", "path", cfg.PinPath, "restored_vips", len(st.VIPs), "restored_backends", len(st.Backends))
	}
	persist := func() {
		if cfg.PinPath == "" {
			return
		}
		if err := controller.SaveState(cfg.StateFile, ctl.State()); err != nil {
			slog.Error("save state", "err", err)
		}
	}
	if err := ctl.Apply(cfg); err != nil {
		return fmt.Errorf("initial apply: %w", err)
	}
	persist()

	hc := health.New(func(name string, up bool) {
		if err := ctl.SetHealth(name, up); err != nil {
			slog.Error("apply health change", "backend", name, "err", err)
		}
	})
	hc.Update(cfg)
	defer hc.Stop()

	reg := prometheus.NewRegistry()
	reg.MustRegister(metrics.NewCollector(plane, ctl))
	events := metrics.NewEvents(reg)

	rd, err := plane.Events()
	if err != nil {
		return fmt.Errorf("ring buffer: %w", err)
	}
	go events.Run(ctx, rd, dataplane.ErrClosed)
	defer rd.Close()

	token := ""
	if cfg.AdminTokenEnv != "" {
		token = os.Getenv(cfg.AdminTokenEnv)
	}
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           admin.New(ctl, events, reg, token).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("http server", "err", err)
			stop()
		}
	}()
	slog.Info("listening", "addr", cfg.Listen, "admin_writes", token != "")

	reload := func(why string) {
		next, err := config.Load(path)
		if err != nil {
			slog.Error("reload rejected, keeping old config", "why", why, "err", err)
			return
		}
		if next.Interface != cfg.Interface || next.XDPMode != cfg.XDPMode || next.Listen != cfg.Listen || next.PinPath != cfg.PinPath {
			slog.Warn("interface, xdp_mode, listen and pin_path need a restart, ignoring them")
		}
		if err := ctl.Apply(next); err != nil {
			slog.Error("reload failed", "why", why, "err", err)
			return
		}
		persist()
		hc.Update(next)
		slog.Info("config reloaded", "why", why, "vips", len(next.VIPs), "backends", len(next.Backends))
	}

	watch(ctx, path, reload)

	<-ctx.Done()
	if cfg.PinPath != "" {
		slog.Info("shutting down, datapath stays attached (pin_path), use -unpin to remove it")
	} else {
		slog.Info("shutting down")
	}
	sctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return srv.Shutdown(sctx)
}

// watch reloads on SIGHUP and on file changes. We watch the directory because
// editors and configmap mounts replace the file instead of writing to it.
func watch(ctx context.Context, path string, reload func(string)) {
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)

	w, err := fsnotify.NewWatcher()
	if err == nil {
		err = w.Add(filepath.Dir(path))
	}
	if err != nil {
		slog.Warn("file watch disabled, use SIGHUP", "err", err)
		w = nil
	}

	go func() {
		var debounce <-chan time.Time
		var events <-chan fsnotify.Event
		if w != nil {
			defer w.Close()
			events = w.Events
		}
		base := filepath.Base(path)
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				reload("sighup")
			case ev := <-events:
				// configmap updates swap a ..data symlink, so don't filter too hard
				if filepath.Base(ev.Name) == base || filepath.Base(ev.Name) == "..data" {
					debounce = time.After(300 * time.Millisecond)
				}
			case <-debounce:
				debounce = nil
				reload("file change")
			}
		}
	}()
}
