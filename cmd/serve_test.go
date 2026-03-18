package cmd

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
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

func TestTS2021HandlerUsesInjectedDialer(t *testing.T) {
	withProxyTestGlobals(t)

	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ts2021" {
			t.Fatalf("backend path = %q, want /ts2021", r.URL.Path)
		}
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

	resp, err := proxy.Client().Get(proxy.URL + "/ts2021")
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
