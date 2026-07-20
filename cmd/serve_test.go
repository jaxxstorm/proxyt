package cmd

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestGetTailscaleTarget(t *testing.T) {
	withProxyTestGlobals(t)

	tests := []struct {
		name   string
		path   string
		ua     string
		auth   string
		target string
	}{
		{name: "control protocol", path: "/ts2021", target: "controlplane.tailscale.com"},
		{name: "api route", path: "/api/v2/tailnet", target: "controlplane.tailscale.com"},
		{name: "machine route", path: "/machine/register", target: "controlplane.tailscale.com"},
		{name: "derp route", path: "/derp/map", target: "derp.tailscale.com"},
		{name: "web login route", path: "/login", target: "login.tailscale.com"},
		{name: "tailscale auth request", path: "/auth", ua: "tailscale/1.0", target: "login.tailscale.com"},
		{name: "tailscale authenticated request", path: "/device", ua: "tailscale/1.0", auth: "Bearer token", target: "controlplane.tailscale.com"},
		{name: "default web route", path: "/", ua: "Mozilla/5.0", target: "login.tailscale.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			if tt.ua != "" {
				req.Header.Set("User-Agent", tt.ua)
			}
			if tt.auth != "" {
				req.Header.Set("Authorization", tt.auth)
			}

			if got := getTailscaleTarget(req); got != tt.target {
				t.Fatalf("target = %q, want %q", got, tt.target)
			}
		})
	}
}

func TestRewriteTailscaleURL(t *testing.T) {
	withProxyTestGlobals(t)
	domain = "proxy.example.com"

	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "login https",
			in:   "https://login.tailscale.com/welcome",
			want: "https://proxy.example.com/welcome",
		},
		{
			name: "controlplane http",
			in:   "http://controlplane.tailscale.com/key",
			want: "https://proxy.example.com/key",
		},
		{
			name: "protocol relative",
			in:   "//login.tailscale.com/bootstrap",
			want: "//proxy.example.com/bootstrap",
		},
		{
			name: "non tailscale unchanged",
			in:   "https://example.com/keep",
			want: "https://example.com/keep",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := rewriteTailscaleURL(tt.in); got != tt.want {
				t.Fatalf("rewriteTailscaleURL(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestRewriteTailscaleURLsInBody(t *testing.T) {
	withProxyTestGlobals(t)
	domain = "proxy.example.com"

	body := strings.Join([]string{
		`{"login":"https://login.tailscale.com/start"}`,
		`"https://controlplane.tailscale.com/key"`,
		`//login.tailscale.com/bootstrap`,
		`https://example.com/unchanged`,
	}, "\n")

	got := rewriteTailscaleURLsInBody(body)
	for _, want := range []string{
		"https://proxy.example.com/start",
		"https://proxy.example.com/key",
		"//proxy.example.com/bootstrap",
		"https://example.com/unchanged",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("rewritten body missing %q: %s", want, got)
		}
	}
}

func TestSetupXForwardedHeaders(t *testing.T) {
	t.Run("adds headers in http only mode", func(t *testing.T) {
		withProxyTestGlobals(t)
		httpOnly = true

		req := httptest.NewRequest(http.MethodGet, "http://proxy.example.com/key", nil)
		req.Host = "proxy.example.com"
		req.RemoteAddr = "203.0.113.10:12345"

		setupXForwardedHeaders(req)

		if got := req.Header.Get("X-Forwarded-For"); got != "203.0.113.10" {
			t.Fatalf("X-Forwarded-For = %q, want %q", got, "203.0.113.10")
		}
		if got := req.Header.Get("X-Forwarded-Proto"); got != "https" {
			t.Fatalf("X-Forwarded-Proto = %q, want https", got)
		}
		if got := req.Header.Get("X-Forwarded-Host"); got != "proxy.example.com" {
			t.Fatalf("X-Forwarded-Host = %q, want proxy.example.com", got)
		}
	})

	t.Run("preserves preexisting forwarded headers", func(t *testing.T) {
		withProxyTestGlobals(t)
		httpOnly = true

		req := httptest.NewRequest(http.MethodGet, "http://proxy.example.com/key", nil)
		req.Host = "proxy.example.com"
		req.RemoteAddr = "203.0.113.10:12345"
		req.Header.Set("X-Forwarded-For", "198.51.100.10")
		req.Header.Set("X-Forwarded-Proto", "http")
		req.Header.Set("X-Forwarded-Host", "existing.example.com")

		setupXForwardedHeaders(req)

		if got := req.Header.Get("X-Forwarded-For"); got != "198.51.100.10" {
			t.Fatalf("X-Forwarded-For = %q, want preserved value", got)
		}
		if got := req.Header.Get("X-Forwarded-Proto"); got != "http" {
			t.Fatalf("X-Forwarded-Proto = %q, want preserved value", got)
		}
		if got := req.Header.Get("X-Forwarded-Host"); got != "existing.example.com" {
			t.Fatalf("X-Forwarded-Host = %q, want preserved value", got)
		}
	})
}

func TestBuildMainHandlerRoutesRequests(t *testing.T) {
	withProxyTestGlobals(t)
	domain = "proxy.example.com"
	httpOnly = true

	loginUpstream := newRecordedUpstream(t, "login", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("login"))
	})
	controlplaneUpstream := newRecordedUpstream(t, "controlplane", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("controlplane"))
	})
	derpUpstream := newRecordedUpstream(t, "derp", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("derp"))
	})

	resolveProxyTarget = func(target string) *url.URL {
		switch target {
		case "login.tailscale.com":
			return mustParseURL(t, loginUpstream.server.URL)
		case "controlplane.tailscale.com":
			return mustParseURL(t, controlplaneUpstream.server.URL)
		case "derp.tailscale.com":
			return mustParseURL(t, derpUpstream.server.URL)
		default:
			t.Fatalf("unexpected target %q", target)
			return nil
		}
	}

	proxy := httptest.NewServer(buildMainHandler(nil))
	t.Cleanup(proxy.Close)

	client := proxy.Client()

	resp, err := client.Get(proxy.URL + "/health")
	if err != nil {
		t.Fatalf("health request: %v", err)
	}
	body := readBody(t, resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(body, "Tailscale Proxy is running") {
		t.Fatalf("unexpected health body %q", body)
	}
	if loginUpstream.count() != 0 || controlplaneUpstream.count() != 0 || derpUpstream.count() != 0 {
		t.Fatalf("health request should not hit upstreams")
	}

	assertProxyResponseBody(t, client, proxy.URL+"/key", "controlplane")
	assertProxyResponseBody(t, client, proxy.URL+"/login", "login")
	assertProxyResponseBody(t, client, proxy.URL+"/derp/map", "derp")
	assertProxyResponseBody(t, client, proxy.URL+"/docs", "login")

	controlReq := controlplaneUpstream.lastRequest()
	if controlReq.Path != "/key" {
		t.Fatalf("controlplane path = %q, want /key", controlReq.Path)
	}
	if controlReq.ForwardedProto != "https" {
		t.Fatalf("X-Forwarded-Proto = %q, want https", controlReq.ForwardedProto)
	}
	if controlReq.ForwardedHost == "" {
		t.Fatal("expected X-Forwarded-Host to be populated")
	}
	if controlReq.ForwardedFor == "" {
		t.Fatal("expected X-Forwarded-For to be populated")
	}
}

func TestBuildMainHandlerRewritesResponses(t *testing.T) {
	withProxyTestGlobals(t)
	domain = "proxy.example.com"

	upstream := newRecordedUpstream(t, "controlplane", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Location", "https://login.tailscale.com/welcome")
		_, _ = w.Write([]byte(`{"login":"https://controlplane.tailscale.com/key","bootstrap":"//login.tailscale.com/bootstrap"}`))
	})

	resolveProxyTarget = func(target string) *url.URL {
		return mustParseURL(t, upstream.server.URL)
	}

	proxy := httptest.NewServer(buildMainHandler(nil))
	t.Cleanup(proxy.Close)

	resp, err := proxy.Client().Get(proxy.URL + "/key")
	if err != nil {
		t.Fatalf("proxy request: %v", err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get("Location"); got != "https://proxy.example.com/welcome" {
		t.Fatalf("Location = %q, want rewritten location", got)
	}

	body := readBody(t, resp.Body)
	for _, want := range []string{
		"https://proxy.example.com/key",
		"//proxy.example.com/bootstrap",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("rewritten body missing %q: %s", want, body)
		}
	}
}

func TestRuntimeObservabilityEndpointsAndMetrics(t *testing.T) {
	withProxyTestGlobals(t)

	expiry := time.Date(2030, time.January, 1, 0, 0, 0, 0, time.UTC)
	transport := roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodHead && request.URL.Host == "controlplane.tailscale.com" {
			return &http.Response{
				StatusCode: http.StatusNoContent,
				Body:       io.NopCloser(strings.NewReader("")),
				Header:     make(http.Header),
			}, nil
		}
		return nil, errors.New("upstream unavailable")
	})
	handler, _ := buildMainHandlerWithMetrics(transport, func() (*tls.Certificate, error) {
		return &tls.Certificate{Leaf: &x509.Certificate{NotAfter: expiry}}, nil
	})
	proxy := httptest.NewServer(handler)
	t.Cleanup(proxy.Close)

	for _, endpoint := range []string{"/health", "/ready"} {
		response, err := proxy.Client().Get(proxy.URL + endpoint)
		if err != nil {
			t.Fatalf("GET %s: %v", endpoint, err)
		}
		if response.StatusCode != http.StatusOK {
			t.Fatalf("%s status = %d, want 200", endpoint, response.StatusCode)
		}
		_ = response.Body.Close()
	}

	response, err := proxy.Client().Get(proxy.URL + "/key")
	if err != nil {
		t.Fatalf("GET /key: %v", err)
	}
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("/key status = %d, want 503", response.StatusCode)
	}
	_ = response.Body.Close()

	response, err = proxy.Client().Get(proxy.URL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	metricsBody := readBody(t, response.Body)
	for _, want := range []string{
		`proxyt_http_requests_total{method="GET",route="health",status="200"} 1`,
		`proxyt_http_requests_total{method="GET",route="ready",status="200"} 1`,
		`proxyt_http_requests_total{method="GET",route="controlplane.tailscale.com",status="503"} 1`,
		`proxyt_upstream_errors_total{target="controlplane.tailscale.com"} 1`,
		"proxyt_http_request_duration_seconds",
		"proxyt_certificate_expiry_timestamp_seconds " + strconv.FormatFloat(float64(expiry.Unix()), 'g', -1, 64),
	} {
		if !strings.Contains(metricsBody, want) {
			t.Fatalf("metrics missing %q:\n%s", want, metricsBody)
		}
	}
	failingHandler := buildMainHandlerWithObservability(roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("control plane unavailable")
	}), nil)
	failingProxy := httptest.NewServer(failingHandler)
	t.Cleanup(failingProxy.Close)

	response, err = failingProxy.Client().Get(failingProxy.URL + "/health")
	if err != nil {
		t.Fatalf("GET failing /health: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("failing /health status = %d, want 200", response.StatusCode)
	}
	_ = response.Body.Close()

	response, err = failingProxy.Client().Get(failingProxy.URL + "/ready")
	if err != nil {
		t.Fatalf("GET failing /ready: %v", err)
	}
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("failing /ready status = %d, want 503", response.StatusCode)
	}
	_ = response.Body.Close()
}

func TestTS2021HandlerTracksActiveTunnels(t *testing.T) {
	withProxyTestGlobals(t)

	backendReady := make(chan struct{})
	releaseBackend := make(chan struct{})
	backendResult := make(chan error, 1)
	t.Cleanup(func() {
		select {
		case <-releaseBackend:
		default:
			close(releaseBackend)
		}
	})

	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			backendResult <- errors.New("backend response writer does not support hijacking")
			return
		}
		conn, readWriter, err := hijacker.Hijack()
		if err != nil {
			backendResult <- err
			return
		}
		defer conn.Close()
		if _, err := readWriter.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: tailscale-control-protocol\r\n\r\n"); err != nil {
			backendResult <- err
			return
		}
		if err := readWriter.Flush(); err != nil {
			backendResult <- err
			return
		}
		close(backendReady)
		<-releaseBackend
		backendResult <- nil
	}))
	backend.EnableHTTP2 = false
	backend.StartTLS()
	t.Cleanup(backend.Close)

	dialControlPlane = func(network, addr string, config *tls.Config) (net.Conn, error) {
		return tls.Dial(network, strings.TrimPrefix(backend.URL, "https://"), &tls.Config{InsecureSkipVerify: true})
	}
	handler, _ := buildMainHandlerWithMetrics(nil, nil)
	proxy := httptest.NewServer(handler)
	t.Cleanup(proxy.Close)

	clientConn, err := net.Dial("tcp", strings.TrimPrefix(proxy.URL, "http://"))
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer clientConn.Close()
	if err := clientConn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set client deadline: %v", err)
	}
	request := "POST /ts2021 HTTP/1.1\r\nHost: proxy.example.com\r\nConnection: upgrade\r\nUpgrade: tailscale-control-protocol\r\nContent-Length: 0\r\n\r\n"
	if _, err := clientConn.Write([]byte(request)); err != nil {
		t.Fatalf("write upgrade request: %v", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(clientConn), &http.Request{Method: http.MethodPost})
	if err != nil {
		t.Fatalf("read switching response: %v", err)
	}
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", response.StatusCode)
	}
	select {
	case <-backendReady:
	case <-time.After(5 * time.Second):
		t.Fatal("backend did not establish tunnel")
	}
	metricsResponse, err := proxy.Client().Get(proxy.URL + "/metrics")
	if err != nil {
		t.Fatalf("GET active tunnel metrics: %v", err)
	}
	metricsBody := readBody(t, metricsResponse.Body)
	if !strings.Contains(metricsBody, "proxyt_ts2021_active_tunnels 1") {
		t.Fatalf("active tunnel metric missing from:\n%s", metricsBody)
	}

	close(releaseBackend)
	if err := clientConn.Close(); err != nil {
		t.Fatalf("close client connection: %v", err)
	}
	if err := <-backendResult; err != nil {
		t.Fatalf("backend tunnel: %v", err)
	}
	metricsResponse, err = proxy.Client().Get(proxy.URL + "/metrics")
	if err != nil {
		t.Fatalf("GET closed tunnel metrics: %v", err)
	}
	metricsBody = readBody(t, metricsResponse.Body)
	if !strings.Contains(metricsBody, "proxyt_ts2021_active_tunnels 0") {
		t.Fatalf("closed tunnel metric missing from:\n%s", metricsBody)
	}
}

func TestTS2021HandlerPreservesMethodAndUpgradeHeaders(t *testing.T) {
	withProxyTestGlobals(t)

	var receivedMethod string
	var receivedConnection string
	var receivedUpgrade string

	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ts2021" {
			t.Fatalf("backend path = %q, want /ts2021", r.URL.Path)
		}
		receivedMethod = r.Method
		receivedConnection = r.Header.Get("Connection")
		receivedUpgrade = r.Header.Get("Upgrade")
		w.Header().Set("X-Upstream", "local-fake")
		_, _ = w.Write([]byte("controlplane ok"))
	}))
	t.Cleanup(backend.Close)

	dialControlPlane = func(network, addr string, config *tls.Config) (net.Conn, error) {
		return tls.Dial(network, strings.TrimPrefix(backend.URL, "https://"), &tls.Config{
			InsecureSkipVerify: true,
		})
	}

	proxy := httptest.NewServer(buildMainHandler(nil))
	t.Cleanup(proxy.Close)

	req, err := http.NewRequest(http.MethodPost, proxy.URL+"/ts2021", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Connection", "upgrade")
	req.Header.Set("Upgrade", "tailscale-control-protocol")

	resp, err := proxy.Client().Do(req)
	if err != nil {
		t.Fatalf("ts2021 request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Upstream"); got != "local-fake" {
		t.Fatalf("X-Upstream = %q, want local-fake", got)
	}
	if body := readBody(t, resp.Body); body != "controlplane ok" {
		t.Fatalf("body = %q, want controlplane ok", body)
	}
	if receivedMethod != http.MethodPost {
		t.Fatalf("backend method = %q, want POST", receivedMethod)
	}
	if receivedConnection != "upgrade" {
		t.Fatalf("backend Connection = %q, want upgrade", receivedConnection)
	}
	if receivedUpgrade != "tailscale-control-protocol" {
		t.Fatalf("backend Upgrade = %q, want tailscale-control-protocol", receivedUpgrade)
	}
}

func TestTS2021HandlerTunnelsBufferedBytes(t *testing.T) {
	withProxyTestGlobals(t)

	clientPayload := []byte("client-buffered-payload")
	upstreamPayload := []byte("upstream-buffered-payload")
	upstreamReply := []byte("upstream-reply")
	backendResult := make(chan error, 1)

	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			backendResult <- errors.New("backend response writer does not support hijacking")
			return
		}

		conn, readWriter, err := hijacker.Hijack()
		if err != nil {
			backendResult <- err
			return
		}
		defer conn.Close()

		if _, err := readWriter.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: tailscale-control-protocol\r\n\r\n"); err != nil {
			backendResult <- err
			return
		}
		if _, err := readWriter.Write(upstreamPayload); err != nil {
			backendResult <- err
			return
		}
		if err := readWriter.Flush(); err != nil {
			backendResult <- err
			return
		}

		receivedClientPayload := make([]byte, len(clientPayload))
		if _, err := io.ReadFull(readWriter, receivedClientPayload); err != nil {
			backendResult <- err
			return
		}
		if string(receivedClientPayload) != string(clientPayload) {
			backendResult <- errors.New("backend received unexpected client payload")
			return
		}

		_, err = conn.Write(upstreamReply)
		backendResult <- err
	}))
	backend.EnableHTTP2 = false
	backend.StartTLS()
	t.Cleanup(backend.Close)

	dialControlPlane = func(network, addr string, config *tls.Config) (net.Conn, error) {
		return tls.Dial(network, strings.TrimPrefix(backend.URL, "https://"), &tls.Config{
			InsecureSkipVerify: true,
		})
	}

	proxy := httptest.NewServer(buildMainHandler(nil))
	t.Cleanup(proxy.Close)

	clientConn, err := net.Dial("tcp", strings.TrimPrefix(proxy.URL, "http://"))
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer clientConn.Close()
	if err := clientConn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set client deadline: %v", err)
	}

	request := "POST /ts2021 HTTP/1.1\r\nHost: proxy.example.com\r\nConnection: upgrade\r\nUpgrade: tailscale-control-protocol\r\nContent-Length: 0\r\n\r\n"
	if _, err := clientConn.Write(append([]byte(request), clientPayload...)); err != nil {
		t.Fatalf("write upgrade request and payload: %v", err)
	}

	clientReader := bufio.NewReader(clientConn)
	response, err := http.ReadResponse(clientReader, &http.Request{Method: http.MethodPost})
	if err != nil {
		t.Fatalf("read switching response: %v", err)
	}
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", response.StatusCode)
	}

	receivedUpstreamPayload := make([]byte, len(upstreamPayload))
	if _, err := io.ReadFull(clientReader, receivedUpstreamPayload); err != nil {
		t.Fatalf("read buffered upstream payload: %v", err)
	}
	if string(receivedUpstreamPayload) != string(upstreamPayload) {
		t.Fatalf("upstream payload = %q, want %q", receivedUpstreamPayload, upstreamPayload)
	}

	receivedReply := make([]byte, len(upstreamReply))
	if _, err := io.ReadFull(clientReader, receivedReply); err != nil {
		t.Fatalf("read upstream reply: %v", err)
	}
	if string(receivedReply) != string(upstreamReply) {
		t.Fatalf("upstream reply = %q, want %q", receivedReply, upstreamReply)
	}

	if err := <-backendResult; err != nil {
		t.Fatalf("backend tunnel: %v", err)
	}
}

func TestTS2021HandlerReturnsBadGatewayOnDialFailure(t *testing.T) {
	withProxyTestGlobals(t)

	dialControlPlane = func(network, addr string, config *tls.Config) (net.Conn, error) {
		return nil, errors.New("boom")
	}

	proxy := httptest.NewServer(buildMainHandler(nil))
	t.Cleanup(proxy.Close)

	resp, err := proxy.Client().Get(proxy.URL + "/ts2021")
	if err != nil {
		t.Fatalf("ts2021 request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
}

func withProxyTestGlobals(t *testing.T) {
	t.Helper()

	oldDomain := domain
	oldPort := port
	oldHTTPSPort := httpsPort
	oldEmail := email
	oldCertDir := certDir
	oldIssueCerts := issueCerts
	oldDebug := debug
	oldHTTPOnly := httpOnly
	oldBindAddr := bindAddr
	oldLogger := logger
	oldResolveProxyTarget := resolveProxyTarget
	oldDialControlPlane := dialControlPlane

	domain = "proxy.example.com"
	port = "80"
	httpsPort = "443"
	email = ""
	certDir = ""
	issueCerts = false
	debug = false
	httpOnly = false
	bindAddr = "127.0.0.1"
	logger = nil
	resolveProxyTarget = oldResolveProxyTarget
	dialControlPlane = oldDialControlPlane

	t.Cleanup(func() {
		domain = oldDomain
		port = oldPort
		httpsPort = oldHTTPSPort
		email = oldEmail
		certDir = oldCertDir
		issueCerts = oldIssueCerts
		debug = oldDebug
		httpOnly = oldHTTPOnly
		bindAddr = oldBindAddr
		logger = oldLogger
		resolveProxyTarget = oldResolveProxyTarget
		dialControlPlane = oldDialControlPlane
	})
}

func assertProxyResponseBody(t *testing.T, client *http.Client, endpoint, want string) {
	t.Helper()

	resp, err := client.Get(endpoint)
	if err != nil {
		t.Fatalf("GET %s: %v", endpoint, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s status = %d, want 200", endpoint, resp.StatusCode)
	}
	if got := readBody(t, resp.Body); got != want {
		t.Fatalf("%s body = %q, want %q", endpoint, got, want)
	}
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()

	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse url %q: %v", raw, err)
	}

	return parsed
}

func readBody(t *testing.T, body io.ReadCloser) string {
	t.Helper()

	payload, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	return string(payload)
}

type recordedUpstream struct {
	server *httptest.Server

	mu      sync.Mutex
	counts  int
	records []upstreamRequest
}

type upstreamRequest struct {
	Path           string
	Host           string
	ForwardedFor   string
	ForwardedHost  string
	ForwardedProto string
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (fn roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func newRecordedUpstream(t *testing.T, _ string, responder func(http.ResponseWriter, *http.Request)) *recordedUpstream {
	t.Helper()

	upstream := &recordedUpstream{}
	upstream.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstream.mu.Lock()
		upstream.counts++
		upstream.records = append(upstream.records, upstreamRequest{
			Path:           r.URL.Path,
			Host:           r.Host,
			ForwardedFor:   r.Header.Get("X-Forwarded-For"),
			ForwardedHost:  r.Header.Get("X-Forwarded-Host"),
			ForwardedProto: r.Header.Get("X-Forwarded-Proto"),
		})
		upstream.mu.Unlock()

		responder(w, r)
	}))
	t.Cleanup(upstream.server.Close)

	return upstream
}

func (u *recordedUpstream) count() int {
	u.mu.Lock()
	defer u.mu.Unlock()

	return u.counts
}

func (u *recordedUpstream) lastRequest() upstreamRequest {
	u.mu.Lock()
	defer u.mu.Unlock()

	if len(u.records) == 0 {
		return upstreamRequest{}
	}

	return u.records[len(u.records)-1]
}
