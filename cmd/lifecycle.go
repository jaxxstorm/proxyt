package cmd

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	log "github.com/jaxxstorm/log"
)

// proxyRuntime owns work independently of net/http, which relinquishes ownership
// of a connection on Hijack. Admission and drain share a lock: no Add can race a
// shutdown Wait, including in the interval before a connection is hijacked.
type proxyRuntime struct {
	config       runtimeConfig
	metrics      *proxyMetrics
	log          *log.Logger
	mu           sync.Mutex
	drainAt      time.Time
	jobs         map[*proxyWork]struct{}
	idle         chan struct{}
	idleOnce     sync.Once
	shutdownOnce sync.Once
	stopped      chan struct{}
	ctx          context.Context
	cancel       context.CancelFunc
	workers      sync.WaitGroup
	dial         func(context.Context, string, string, *tls.Config) (net.Conn, error)
}

type workContextKey struct{}

type proxyWork struct {
	runtime *proxyRuntime
	cancel  context.CancelFunc
	mu      sync.Mutex
	conns   []net.Conn
	closed  bool
	tunnel  bool
	done    sync.Once
}

func newProxyRuntime(config runtimeConfig, metrics *proxyMetrics) *proxyRuntime {
	ctx, cancel := context.WithCancel(context.Background())
	return &proxyRuntime{config: config, metrics: metrics, log: logger, jobs: make(map[*proxyWork]struct{}), idle: make(chan struct{}), stopped: make(chan struct{}), ctx: ctx, cancel: cancel, dial: dialControlPlane}
}

func (rt *proxyRuntime) draining() bool {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return !rt.drainAt.IsZero()
}

func (rt *proxyRuntime) beginDrain() time.Time {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.drainAt.IsZero() {
		rt.drainAt = time.Now()
		rt.metrics.draining.Set(1)
		rt.log.Info("Replica draining", log.String("deadline", rt.drainAt.Add(rt.config.shutdownDelay+rt.config.shutdownTimeout).Format(time.RFC3339Nano)))
		if len(rt.jobs) == 0 {
			rt.idleOnce.Do(func() { close(rt.idle) })
		}
	}
	return rt.drainAt
}

func (rt *proxyRuntime) admit(ctx context.Context) (*proxyWork, context.Context) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if !rt.drainAt.IsZero() {
		return nil, ctx
	}
	ctx, cancel := context.WithCancel(ctx)
	work := &proxyWork{runtime: rt, cancel: cancel}
	rt.jobs[work] = struct{}{}
	return work, context.WithValue(ctx, workContextKey{}, work)
}

func (work *proxyWork) add(conn net.Conn, tunnel bool) bool {
	work.mu.Lock()
	defer work.mu.Unlock()
	if work.closed {
		conn.Close()
		return false
	}
	work.conns = append(work.conns, conn)
	work.tunnel = work.tunnel || tunnel
	return true
}

func (work *proxyWork) close(forced bool) {
	work.mu.Lock()
	if work.closed {
		work.mu.Unlock()
		return
	}
	work.closed = true
	conns := work.conns
	if forced && work.tunnel {
		work.runtime.metrics.forcedTunnels.Inc()
	}
	work.mu.Unlock()
	work.cancel()
	for _, conn := range conns {
		if forced {
			// Avoid serial TLS close-notify waits during forced cleanup.
			_ = conn.SetDeadline(time.Now())
		}
		conn.Close()
	}
}

func (work *proxyWork) finish() {
	work.done.Do(func() {
		work.close(false)
		rt := work.runtime
		rt.mu.Lock()
		defer rt.mu.Unlock()
		delete(rt.jobs, work)
		if !rt.drainAt.IsZero() && len(rt.jobs) == 0 {
			rt.idleOnce.Do(func() { close(rt.idle) })
		}
	})
}

func (rt *proxyRuntime) handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health", "/ready", "/metrics":
			next.ServeHTTP(w, r)
			return
		}
		work, ctx := rt.admit(r.Context())
		if work == nil {
			instrumentHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "ProxyT is draining", http.StatusServiceUnavailable)
			}), rt.metrics).ServeHTTP(w, r)
			return
		}
		defer work.finish()
		next.ServeHTTP(&workResponseWriter{ResponseWriter: w, work: work}, r.WithContext(ctx))
	})
}

type workResponseWriter struct {
	http.ResponseWriter
	work *proxyWork
}

func (w *workResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *workResponseWriter) Flush()                      { _ = http.NewResponseController(w.ResponseWriter).Flush() }
func (w *workResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, rw, err := http.NewResponseController(w.ResponseWriter).Hijack()
	if err != nil {
		return nil, nil, err
	}
	if !w.work.add(conn, true) {
		return nil, nil, fmt.Errorf("replica stopped during hijack")
	}
	return conn, rw, nil
}

func (rt *proxyRuntime) shutdown(servers []*http.Server) {
	rt.shutdownOnce.Do(func() {
		defer close(rt.stopped)
		start := rt.beginDrain()
		timer := time.NewTimer(time.Until(start.Add(rt.config.shutdownDelay)))
		<-timer.C
		ctx, cancel := context.WithDeadline(context.Background(), start.Add(rt.config.shutdownDelay+rt.config.shutdownTimeout))
		defer cancel()
		var serversWG sync.WaitGroup
		for _, srv := range servers {
			serversWG.Add(1)
			go func() { defer serversWG.Done(); _ = srv.Shutdown(ctx) }()
		}
		serversDone := make(chan struct{})
		go func() { serversWG.Wait(); close(serversDone) }()
		select {
		case <-rt.idle:
		case <-ctx.Done():
		}
		select {
		case <-serversDone:
		case <-ctx.Done():
		}
		rt.cancel()
		rt.mu.Lock()
		pending := make([]*proxyWork, 0, len(rt.jobs))
		for work := range rt.jobs {
			pending = append(pending, work)
		}
		rt.mu.Unlock()
		for _, work := range pending {
			work.close(true)
		}
		for _, srv := range servers {
			_ = srv.Close()
		}
		<-serversDone
		<-rt.idle
		rt.workers.Wait()
		rt.log.Info("Replica stopped", log.Int("forced_work", len(pending)))
	})
	<-rt.stopped
}

// Install before serving so a signal cannot be missed during startup. Repeated
// signals are ignored without restarting or shortening the drain schedule.
func terminationSignals() (<-chan os.Signal, func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	return ch, func() { signal.Stop(ch) }
}
