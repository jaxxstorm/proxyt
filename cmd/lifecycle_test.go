package cmd

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func metricValue(t *testing.T, metric prometheus.Metric) float64 {
	t.Helper()
	m := new(dto.Metric)
	if err := metric.Write(m); err != nil {
		t.Fatal(err)
	}
	if m.Gauge != nil {
		return m.Gauge.GetValue()
	}
	return m.Counter.GetValue()
}

func await(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for completion")
	}
}

func testRuntime(t *testing.T) *proxyRuntime {
	t.Helper()
	c := defaultRuntimeConfig()
	c.shutdownDelay = 0
	c.shutdownTimeout = 50 * time.Millisecond
	c.connectTimeout = 100 * time.Millisecond
	return newProxyRuntime(c, newProxyMetrics())
}

func readyTransport() http.RoundTripper {
	return roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
	})
}

// Echo opaque bytes after parsing a real upgrade. Every fixture worker is joined
// so it cannot outlive the runtime or mutate test state after cleanup.
func echoDial(t *testing.T) func(context.Context, string, string, *tls.Config) (net.Conn, error) {
	t.Helper()
	var wg sync.WaitGroup
	t.Cleanup(wg.Wait)
	return func(ctx context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
		client, server := net.Pipe()
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer server.Close()
			reader := bufio.NewReader(server)
			req, err := http.ReadRequest(reader)
			if err != nil {
				return
			}
			io.Copy(io.Discard, req.Body)
			req.Body.Close()
			if _, err := io.WriteString(server, "HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: tailscale-control-protocol\r\n\r\n"); err != nil {
				return
			}
			io.Copy(server, reader)
		}()
		return client, nil
	}
}

func runtimeServer(t *testing.T, rt *proxyRuntime, transport http.RoundTripper) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(buildRuntimeHandler(transport, nil, rt))
	t.Cleanup(func() { rt.shutdown([]*http.Server{s.Config}); s.Close() })
	return s
}

func openTunnel(t *testing.T, address string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	return upgradeConn(t, conn)
}

func upgradeConn(t *testing.T, conn net.Conn) (net.Conn, *bufio.Reader) {
	t.Helper()
	_, err := io.WriteString(conn, "POST /ts2021 HTTP/1.1\r\nHost: proxy.example.com\r\nConnection: upgrade\r\nUpgrade: tailscale-control-protocol\r\nContent-Length: 0\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(conn)
	resp, err := http.ReadResponse(r, &http.Request{Method: "POST"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 101 {
		t.Fatalf("upgrade status = %d", resp.StatusCode)
	}
	return conn, r
}

func exchange(t *testing.T, conn net.Conn, reader io.Reader) {
	t.Helper()
	if _, err := io.WriteString(conn, "opaque"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 6)
	if _, err := io.ReadFull(reader, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "opaque" {
		t.Fatalf("payload = %q", buf)
	}
}

func status(t *testing.T, client *http.Client, url string, want int) {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != want {
		t.Fatalf("%s = %d, want %d", url, resp.StatusCode, want)
	}
}

func TestReplicaDrainAndReconnect(t *testing.T) {
	withProxyTestGlobals(t)
	rt := testRuntime(t)
	rt.config.shutdownDelay = 50 * time.Millisecond
	rt.dial = echoDial(t)
	s := runtimeServer(t, rt, readyTransport())
	second := testRuntime(t)
	second.dial = echoDial(t)
	s2 := runtimeServer(t, second, readyTransport())
	conn, reader := openTunnel(t, s.Listener.Addr().String())
	exchange(t, conn, reader)
	// Keep one ordinary connection alive across admission closure.
	status(t, s.Client(), s.URL+"/health", 200)
	at := rt.beginDrain()
	if rt.beginDrain() != at {
		t.Fatal("drain reset its schedule")
	}
	status(t, s.Client(), s.URL+"/key", 503)
	status(t, s.Client(), s.URL+"/ready", 503)
	status(t, s.Client(), s.URL+"/health", 200)
	status(t, s.Client(), s.URL+"/metrics", 200)
	exchange(t, conn, reader)
	done := make(chan struct{})
	go func() { rt.shutdown([]*http.Server{s.Config}); close(done) }()
	await(t, done)
	if _, err := reader.ReadByte(); err == nil {
		t.Fatal("tunnel survived forced shutdown")
	}
	if got := metricValue(t, rt.metrics.forcedTunnels); got != 1 {
		t.Fatalf("forced = %v", got)
	}
	if got := metricValue(t, rt.metrics.activeTunnels); got != 0 {
		t.Fatalf("active = %v", got)
	}
	rt.shutdown([]*http.Server{s.Config})
	if got := metricValue(t, rt.metrics.forcedTunnels); got != 1 {
		t.Fatal("shutdown counted twice")
	}
	other, otherReader := openTunnel(t, s2.Listener.Addr().String())
	exchange(t, other, otherReader)
}

func TestNaturalDrainAndLateRegistration(t *testing.T) {
	withProxyTestGlobals(t)
	t.Run("natural completion", func(t *testing.T) {
		rt := testRuntime(t)
		rt.config.shutdownTimeout = time.Hour
		work, _ := rt.admit(context.Background())
		done := make(chan struct{})
		rt.beginDrain()
		go func() { rt.shutdown(nil); close(done) }()
		work.finish()
		work.finish()
		await(t, done)
		if got := metricValue(t, rt.metrics.forcedTunnels); got != 0 {
			t.Fatal(got)
		}
	})
	t.Run("registration after forced close", func(t *testing.T) {
		rt := testRuntime(t)
		work, _ := rt.admit(context.Background())
		work.close(true)
		a, b := net.Pipe()
		defer b.Close()
		if work.add(a, true) {
			t.Fatal("registered connection after closure")
		}
		if _, err := b.Write([]byte("x")); err == nil {
			t.Fatal("late socket leaked")
		}
		work.finish()
		rt.shutdown(nil)
	})
}

func TestReadinessDrainRace(t *testing.T) {
	withProxyTestGlobals(t)
	rt := testRuntime(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	handler := buildRuntimeHandler(roundTripperFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		close(entered)
		<-release
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(""))}, nil
	}), nil, rt)
	done := make(chan struct{})
	response := httptest.NewRecorder()
	go func() { handler.ServeHTTP(response, httptest.NewRequest("GET", "/ready", nil)); close(done) }()
	await(t, entered)
	rt.beginDrain()
	close(release)
	await(t, done)
	if response.Code != 503 {
		t.Fatal(response.Code)
	}
	for path, want := range map[string]int{"/ready": 503, "/health": 200, "/key": 503} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != want {
			t.Fatalf("%s = %d", path, w.Code)
		}
	}
	if calls.Load() != 1 {
		t.Fatal("draining replica queried upstream")
	}
	rt.shutdown(nil)
}

func TestSetupTimeoutAndCancellation(t *testing.T) {
	withProxyTestGlobals(t)
	for _, stage := range []string{"dial", "tls", "write", "headers", "body"} {
		t.Run(stage, func(t *testing.T) {
			rt := testRuntime(t)
			rt.config.connectTimeout = 30 * time.Millisecond
			var calls atomic.Int32
			peerDone := make(chan struct{})
			rt.dial = func(ctx context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
				calls.Add(1)
				if stage == "dial" {
					defer close(peerDone)
					<-ctx.Done()
					return nil, ctx.Err()
				}
				client, peer := net.Pipe()
				go func() {
					defer close(peerDone)
					defer peer.Close()
					if stage == "headers" || stage == "body" {
						_, _ = http.ReadRequest(bufio.NewReader(peer))
					}
					<-ctx.Done()
				}()
				if stage == "tls" {
					conn := tls.Client(client, &tls.Config{InsecureSkipVerify: true})
					if err := conn.HandshakeContext(ctx); err != nil {
						client.Close()
						return nil, err
					}
				}
				return client, nil
			}
			s := runtimeServer(t, rt, readyTransport())
			conn, err := net.Dial("tcp", s.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(2 * time.Second))
			length := 0
			if stage == "body" {
				length = 100
			}
			fmt.Fprintf(conn, "POST /ts2021 HTTP/1.1\r\nHost: proxy.example.com\r\nConnection: upgrade\r\nUpgrade: tailscale-control-protocol\r\nContent-Length: %d\r\n\r\n", length)
			// An incomplete client body can preclude an HTTP response. The
			// connection must nevertheless terminate and release its work.
			_, _ = http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: "POST"})
			await(t, peerDone)
			rt.beginDrain()
			await(t, rt.idle)
			if calls.Load() != 1 {
				t.Fatalf("attempts = %d", calls.Load())
			}
		})
	}
	t.Run("request cancellation", func(t *testing.T) {
		rt := testRuntime(t)
		rt.config.connectTimeout = time.Hour
		entered := make(chan struct{})
		rt.dial = func(ctx context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
			close(entered)
			<-ctx.Done()
			return nil, ctx.Err()
		}
		s := runtimeServer(t, rt, readyTransport())
		ctx, cancel := context.WithCancel(context.Background())
		req, _ := http.NewRequestWithContext(ctx, "POST", s.URL+"/ts2021", nil)
		done := make(chan struct{})
		go func() {
			resp, _ := s.Client().Do(req)
			if resp != nil {
				resp.Body.Close()
			}
			close(done)
		}()
		await(t, entered)
		cancel()
		await(t, done)
		rt.beginDrain()
		await(t, rt.idle)
	})
}

func TestTunnelOutlivesSetupDeadline(t *testing.T) {
	withProxyTestGlobals(t)
	rt := testRuntime(t)
	rt.config.connectTimeout = 40 * time.Millisecond
	rt.dial = echoDial(t)
	s := runtimeServer(t, rt, readyTransport())
	conn, reader := openTunnel(t, s.Listener.Addr().String())
	time.Sleep(2 * rt.config.connectTimeout)
	exchange(t, conn, reader)
}

func TestGenericUpgradesShareShutdownBudget(t *testing.T) {
	withProxyTestGlobals(t)
	rt := testRuntime(t)
	var peers sync.WaitGroup
	t.Cleanup(peers.Wait)
	transport := roundTripperFunc(func(*http.Request) (*http.Response, error) {
		a, b := net.Pipe()
		peers.Add(1)
		go func() { defer peers.Done(); defer b.Close(); io.Copy(b, b) }()
		return &http.Response{StatusCode: 101, Header: http.Header{"Connection": {"upgrade"}, "Upgrade": {"test-stream"}}, Body: a}, nil
	})
	s1 := runtimeServer(t, rt, transport)
	s2 := runtimeServer(t, rt, transport)
	for _, server := range []*httptest.Server{s1, s2} {
		conn, err := net.Dial("tcp", server.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		conn.SetDeadline(time.Now().Add(time.Second))
		io.WriteString(conn, "GET /socket HTTP/1.1\r\nHost: proxy.example.com\r\nConnection: upgrade\r\nUpgrade: test-stream\r\n\r\n")
		reader := bufio.NewReader(conn)
		resp, err := http.ReadResponse(reader, &http.Request{Method: "GET"})
		if err != nil || resp.StatusCode != 101 {
			t.Fatalf("upgrade: %v, %v", resp, err)
		}
		exchange(t, conn, reader)
	}
	done := make(chan struct{})
	go func() { rt.shutdown([]*http.Server{s1.Config, s2.Config}); close(done) }()
	await(t, done)
	if got := metricValue(t, rt.metrics.forcedTunnels); got != 2 {
		t.Fatalf("forced = %v", got)
	}
}

type gatedHijacker struct {
	http.ResponseWriter
	entered chan struct{}
	release <-chan struct{}
}

func (w gatedHijacker) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w gatedHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, rw, err := http.NewResponseController(w.ResponseWriter).Hijack()
	close(w.entered)
	<-w.release
	return conn, rw, err
}

func TestShutdownDuringHijack(t *testing.T) {
	withProxyTestGlobals(t)
	rt := testRuntime(t)
	rt.dial = echoDial(t)
	entered := make(chan struct{})
	handler := buildRuntimeHandler(readyTransport(), nil, rt)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(gatedHijacker{w, entered, rt.ctx.Done()}, r)
	}))
	t.Cleanup(s.Close)
	conn, err := net.Dial("tcp", s.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Second))
	io.WriteString(conn, "POST /ts2021 HTTP/1.1\r\nHost: proxy.example.com\r\nConnection: upgrade\r\nUpgrade: tailscale-control-protocol\r\nContent-Length: 0\r\n\r\n")
	await(t, entered)
	done := make(chan struct{})
	go func() { rt.shutdown([]*http.Server{s.Config}); close(done) }()
	await(t, done)
	_, err = io.ReadAll(conn)
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("hijacked connection escaped shutdown")
	}
}
