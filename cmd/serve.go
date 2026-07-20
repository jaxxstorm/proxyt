package cmd

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	log "github.com/jaxxstorm/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"golang.org/x/crypto/acme/autocert"
)

var (
	domain             string
	port               string
	httpsPort          string
	email              string
	certDir            string
	issueCerts         bool
	debug              bool
	httpOnly           bool
	bindAddr           string
	logger             *log.Logger
	resolveProxyTarget = func(target string) *url.URL {
		return &url.URL{
			Scheme: "https",
			Host:   target,
		}
	}
	dialControlPlane = func(network, addr string, config *tls.Config) (net.Conn, error) {
		return tls.Dial(network, addr, config)
	}
)

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the Tailscale login server proxy",
	Long:  `A proxy server to use when Tailscale is blocked on your domain.`,
	Run: func(cmd *cobra.Command, args []string) {
		runProxy()
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)

	serveCmd.Flags().StringVarP(&domain, "domain", "d", "", "Domain name for the proxy (required)")
	serveCmd.Flags().StringVarP(&port, "port", "p", "80", "HTTP port for Let's Encrypt challenges or main port in HTTP-only mode")
	serveCmd.Flags().StringVar(&httpsPort, "https-port", "443", "HTTPS port for the proxy")
	serveCmd.Flags().StringVarP(&email, "email", "e", "", "Email address for Let's Encrypt registration")
	serveCmd.Flags().StringVar(&certDir, "cert-dir", "", "Directory to store/read SSL certificates (required when not using --http-only)")
	serveCmd.Flags().BoolVar(&issueCerts, "issue", true, "Automatically issue Let's Encrypt certificates")
	serveCmd.Flags().BoolVar(&debug, "debug", false, "Enable debug logging for all requests")
	serveCmd.Flags().BoolVar(&httpOnly, "http-only", false, "Run in HTTP-only mode (for use behind HTTPS proxy/load balancer)")
	serveCmd.Flags().StringVar(&bindAddr, "bind", "0.0.0.0", "Address to bind the server to")

	configureServeSettings(settings, serveCmd.Flags())
}

func configureServeSettings(settings *viper.Viper, flags *pflag.FlagSet) {
	settings.SetEnvPrefix("PROXYT")
	settings.AutomaticEnv()
	settings.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	for _, key := range []string{"domain", "port", "https-port", "email", "cert-dir", "issue", "debug", "http-only", "bind"} {
		_ = settings.BindPFlag(key, flags.Lookup(key))
	}
}

func validateServeConfiguration(settings *viper.Viper) error {
	if settings.GetString("domain") == "" {
		return fmt.Errorf("domain is required")
	}
	if !settings.GetBool("http-only") && settings.GetString("cert-dir") == "" {
		return fmt.Errorf("cert-dir is required when not using --http-only mode")
	}
	if !settings.GetBool("http-only") && settings.GetBool("issue") && settings.GetString("email") == "" {
		return fmt.Errorf("email is required when --issue is true for Let's Encrypt registration")
	}
	return nil
}

func runProxy() {
	// Read values from viper (supports both flags and environment variables)
	domain = settings.GetString("domain")
	port = settings.GetString("port")
	httpsPort = settings.GetString("https-port")
	email = settings.GetString("email")
	certDir = settings.GetString("cert-dir")
	issueCerts = settings.GetBool("issue")
	debug = settings.GetBool("debug")
	httpOnly = settings.GetBool("http-only")
	bindAddr = settings.GetString("bind")

	var err error
	logger, err = newRuntimeLogger(debug)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer closeRuntimeLogger(logger)

	logger.Info("Starting Tailscale proxy",
		log.String("domain", domain),
		log.Bool("http_only", httpOnly))

	if debug {
		logger.Info("Debug logging enabled")
	}

	if err := validateServeConfiguration(settings); err != nil {
		logger.Fatal(err.Error())
	}

	var certManager *autocert.Manager
	var tlsConfig *tls.Config

	if !httpOnly && issueCerts {
		// Set up Let's Encrypt certificate manager
		certManager = &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Cache:      autocert.DirCache(certDir),
			HostPolicy: autocert.HostWhitelist(domain),
			Email:      email,
		}

		tlsConfig = &tls.Config{
			GetCertificate: certManager.GetCertificate,
		}

		logger.Info("Automatic certificate issuance enabled", log.String("domain", domain))
	} else if !httpOnly {
		// Check if certificates exist in cert-dir
		certFile := filepath.Join(certDir, domain+".crt")
		keyFile := filepath.Join(certDir, domain+".key")

		if _, err := os.Stat(certFile); os.IsNotExist(err) {
			logger.Fatal("Certificate file not found (required when --issue=false)", log.String("file", certFile))
		}
		if _, err := os.Stat(keyFile); os.IsNotExist(err) {
			logger.Fatal("Key file not found (required when --issue=false)", log.String("file", keyFile))
		}

		// Load existing certificates
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			logger.Fatal("Failed to load certificates", log.Error(err))
		}

		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}

		logger.Info("Using existing certificates", log.String("cert_dir", certDir))
	}

	mainHandler := buildMainHandlerWithObservability(nil, certificateGetter(certManager, tlsConfig))

	var servers []*http.Server

	if httpOnly {
		// HTTP-only mode for use behind HTTPS proxy/load balancer
		httpServer := &http.Server{
			Addr:    bindAddr + ":" + port,
			Handler: mainHandler,
		}
		servers = append(servers, httpServer)

		logger.Info("HTTP-only mode enabled - running behind HTTPS proxy",
			log.String("bind_addr", bindAddr),
			log.String("port", port))
	} else {
		// Full HTTPS mode with optional HTTP for Let's Encrypt

		// Create HTTPS server
		httpsServer := &http.Server{
			Addr:      bindAddr + ":" + httpsPort,
			Handler:   mainHandler,
			TLSConfig: tlsConfig,
		}
		servers = append(servers, httpsServer)

		var httpServer *http.Server

		if issueCerts {
			// Create HTTP server that handles Let's Encrypt challenges
			httpMux := http.NewServeMux()

			// Handle Let's Encrypt challenges
			httpMux.Handle("/.well-known/", certManager.HTTPHandler(nil))

			// Redirect all other HTTP requests to HTTPS
			httpMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				// Don't redirect ACME challenges
				if strings.HasPrefix(r.URL.Path, "/.well-known/") {
					certManager.HTTPHandler(nil).ServeHTTP(w, r)
					return
				}

				// Redirect to HTTPS
				httpsURL := "https://" + r.Host + r.RequestURI
				if httpsPort != "443" {
					httpsURL = "https://" + domain + ":" + httpsPort + r.RequestURI
				}
				http.Redirect(w, r, httpsURL, http.StatusMovedPermanently)
			})

			httpServer = &http.Server{
				Addr:    bindAddr + ":" + port,
				Handler: httpMux,
			}
		} else {
			// Simple HTTP server that redirects to HTTPS
			httpMux := http.NewServeMux()
			httpMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				httpsURL := "https://" + r.Host + r.RequestURI
				if httpsPort != "443" {
					httpsURL = "https://" + domain + ":" + httpsPort + r.RequestURI
				}
				http.Redirect(w, r, httpsURL, http.StatusMovedPermanently)
			})

			httpServer = &http.Server{
				Addr:    bindAddr + ":" + port,
				Handler: httpMux,
			}
		}

		if httpServer != nil {
			servers = append(servers, httpServer)
		}
	}

	// Channel to listen for interrupt signal
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	// Start all servers
	for _, server := range servers {
		go func(srv *http.Server) {
			if srv.TLSConfig != nil {
				// HTTPS server
				logger.Info("Starting HTTPS proxy server",
					log.String("addr", srv.Addr),
					log.String("domain", domain))
				if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
					logger.Fatal("HTTPS server failed", log.Error(err))
				}
			} else {
				// HTTP server
				if httpOnly {
					logger.Info("Starting HTTP proxy server (behind HTTPS proxy)",
						log.String("addr", srv.Addr))
				} else if issueCerts {
					logger.Info("Starting HTTP server for Let's Encrypt challenges and redirects",
						log.String("addr", srv.Addr))
				} else {
					logger.Info("Starting HTTP server for HTTPS redirects",
						log.String("addr", srv.Addr))
				}
				if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					logger.Fatal("HTTP server failed", log.Error(err))
				}
			}
		}(server)
	}

	// Wait for interrupt signal
	<-stop
	logger.Info("Shutting down servers...")

	// Create a context with timeout for graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shutdown all servers
	for _, server := range servers {
		if err := server.Shutdown(ctx); err != nil {
			logger.Error("Server shutdown error", log.String("addr", server.Addr), log.Error(err))
		}
	}

	logger.Info("Servers stopped")
}

const readinessTimeout = 5 * time.Second

type proxyMetrics struct {
	registry          *prometheus.Registry
	requests          *prometheus.CounterVec
	requestDuration   *prometheus.HistogramVec
	upstreamErrors    *prometheus.CounterVec
	certificateExpiry *prometheus.GaugeVec
	activeTunnels     prometheus.Gauge
}

func newProxyMetrics() *proxyMetrics {
	metrics := &proxyMetrics{
		registry: prometheus.NewRegistry(),
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "proxyt_http_requests_total",
			Help: "Total HTTP requests handled by ProxyT.",
		}, []string{"method", "route", "status"}),
		requestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "proxyt_http_request_duration_seconds",
			Help: "Duration of HTTP requests handled by ProxyT.",
		}, []string{"method", "route", "status"}),
		upstreamErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "proxyt_upstream_errors_total",
			Help: "Total upstream connection and proxy errors.",
		}, []string{"target"}),
		certificateExpiry: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "proxyt_certificate_expiry_timestamp_seconds",
			Help: "Expiry time of the certificate managed by ProxyT as a Unix timestamp.",
		}, nil),
		activeTunnels: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "proxyt_ts2021_active_tunnels",
			Help: "Current number of active ts2021 control-protocol tunnels.",
		}),
	}
	metrics.registry.MustRegister(
		metrics.requests,
		metrics.requestDuration,
		metrics.upstreamErrors,
		metrics.certificateExpiry,
		metrics.activeTunnels,
	)
	return metrics
}

type readinessChecker struct {
	transport   http.RoundTripper
	certificate func() (*tls.Certificate, error)
}

func certificateGetter(certManager *autocert.Manager, tlsConfig *tls.Config) func() (*tls.Certificate, error) {
	if httpOnly {
		return nil
	}
	if certManager != nil {
		return func() (*tls.Certificate, error) {
			return certManager.GetCertificate(&tls.ClientHelloInfo{ServerName: domain})
		}
	}
	if tlsConfig != nil && len(tlsConfig.Certificates) > 0 {
		certificate := tlsConfig.Certificates[0]
		return func() (*tls.Certificate, error) {
			return &certificate, nil
		}
	}
	return nil
}

func certificateExpiry(certificate *tls.Certificate) (time.Time, error) {
	if certificate == nil {
		return time.Time{}, fmt.Errorf("certificate is unavailable")
	}
	if certificate.Leaf != nil {
		return certificate.Leaf.NotAfter, nil
	}
	if len(certificate.Certificate) == 0 {
		return time.Time{}, fmt.Errorf("certificate has no leaf")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return time.Time{}, fmt.Errorf("parse certificate: %w", err)
	}
	return leaf.NotAfter, nil
}

func (checker readinessChecker) managedCertificateExpiry() (time.Time, error) {
	if checker.certificate == nil {
		return time.Time{}, nil
	}
	certificate, err := checker.certificate()
	if err != nil {
		return time.Time{}, fmt.Errorf("get certificate: %w", err)
	}
	expiry, err := certificateExpiry(certificate)
	if err != nil {
		return time.Time{}, err
	}
	if !expiry.After(time.Now()) {
		return time.Time{}, fmt.Errorf("certificate expired at %s", expiry.UTC().Format(time.RFC3339))
	}
	return expiry, nil
}

func (checker readinessChecker) check(ctx context.Context) (time.Time, error) {
	expiry, err := checker.managedCertificateExpiry()
	if err != nil {
		return time.Time{}, err
	}

	transport := checker.transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodHead, "https://controlplane.tailscale.com/", nil)
	if err != nil {
		return time.Time{}, err
	}
	response, err := (&http.Client{Transport: transport}).Do(request)
	if err != nil {
		return time.Time{}, fmt.Errorf("reach control plane: %w", err)
	}
	_ = response.Body.Close()
	return expiry, nil
}

func buildMainHandler(transport http.RoundTripper) http.Handler {
	return buildMainHandlerWithObservability(transport, nil)
}

func buildMainHandlerWithObservability(transport http.RoundTripper, certificate func() (*tls.Certificate, error)) http.Handler {
	handler, _ := buildMainHandlerWithMetrics(transport, certificate)
	return handler
}

func buildMainHandlerWithMetrics(transport http.RoundTripper, certificate func() (*tls.Certificate, error)) (http.Handler, *proxyMetrics) {
	metrics := newProxyMetrics()
	readiness := readinessChecker{transport: transport, certificate: certificate}
	reverseProxy := buildReverseProxy(transport, metrics)
	mainHandler := http.NewServeMux()

	mainHandler.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		logger.Info("Health check request", log.String("remote_addr", r.RemoteAddr))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK - Tailscale Proxy is running"))
	})

	mainHandler.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), readinessTimeout)
		defer cancel()

		expiry, err := readiness.check(ctx)
		if err != nil {
			logger.Error("Readiness check failed", log.Error(err))
			http.Error(w, "ProxyT is not ready", http.StatusServiceUnavailable)
			return
		}
		if !expiry.IsZero() {
			metrics.certificateExpiry.WithLabelValues().Set(float64(expiry.Unix()))
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK - Tailscale Proxy is ready"))
	})

	mainHandler.Handle("/metrics", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if expiry, err := readiness.managedCertificateExpiry(); err == nil && !expiry.IsZero() {
			metrics.certificateExpiry.WithLabelValues().Set(float64(expiry.Unix()))
		}
		promhttp.HandlerFor(metrics.registry, promhttp.HandlerOpts{}).ServeHTTP(w, r)
	}))

	mainHandler.HandleFunc("/ts2021", func(w http.ResponseWriter, r *http.Request) {
		handleTailscaleControlProtocol(w, r, metrics)
	})

	mainHandler.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			logger.Info("Health check request", log.String("remote_addr", r.RemoteAddr))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("OK - Tailscale Proxy is running"))
			return
		}

		if strings.HasPrefix(r.URL.Path, "/ts2021") {
			handleTailscaleControlProtocol(w, r, metrics)
			return
		}

		if debug {
			logDebugRequest("MAIN_HANDLER", r)
		}

		logger.Info("Request - proxying",
			log.String("remote_addr", r.RemoteAddr),
			log.String("host", r.Host),
			log.String("path", r.URL.Path))
		reverseProxy.ServeHTTP(w, r)
	})

	return instrumentHandler(mainHandler, metrics), metrics
}

type metricsResponseWriter struct {
	http.ResponseWriter
	status int
}

func (writer *metricsResponseWriter) WriteHeader(status int) {
	if writer.status == 0 {
		writer.status = status
	}
	writer.ResponseWriter.WriteHeader(status)
}

func (writer *metricsResponseWriter) Write(body []byte) (int, error) {
	if writer.status == 0 {
		writer.status = http.StatusOK
	}
	return writer.ResponseWriter.Write(body)
}

func (writer *metricsResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := writer.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("response writer does not support hijacking")
	}
	return hijacker.Hijack()
}

func (writer *metricsResponseWriter) Flush() {
	if flusher, ok := writer.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (writer *metricsResponseWriter) Unwrap() http.ResponseWriter {
	return writer.ResponseWriter
}

func instrumentHandler(next http.Handler, metrics *proxyMetrics) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		writer := &metricsResponseWriter{ResponseWriter: w}
		next.ServeHTTP(writer, r)

		status := writer.status
		if status == 0 {
			status = http.StatusOK
		}
		route := metricRoute(r)
		labels := prometheus.Labels{
			"method": r.Method,
			"route":  route,
			"status": fmt.Sprintf("%d", status),
		}
		metrics.requests.With(labels).Inc()
		metrics.requestDuration.With(labels).Observe(time.Since(start).Seconds())
	})
}

func metricRoute(r *http.Request) string {
	switch {
	case r.URL.Path == "/health":
		return "health"
	case r.URL.Path == "/ready":
		return "ready"
	case r.URL.Path == "/metrics":
		return "metrics"
	case strings.HasPrefix(r.URL.Path, "/ts2021"):
		return "ts2021"
	default:
		return getTailscaleTarget(r)
	}
}

func buildReverseProxy(transport http.RoundTripper, metrics *proxyMetrics) *httputil.ReverseProxy {
	reverseProxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			setupXForwardedHeaders(req)

			target := getTailscaleTarget(req)
			upstream := resolveProxyTarget(target)
			if upstream == nil {
				upstream = &url.URL{
					Scheme: "https",
					Host:   target,
				}
			}

			if debug {
				logDebugRequest("DIRECTOR", req)
			}

			logger.Info("Reverse proxying request",
				log.String("host", req.Host),
				log.String("path", req.URL.Path),
				log.String("target", target))

			req.URL.Scheme = upstream.Scheme
			req.URL.Host = upstream.Host
			req.Host = upstream.Host

			if upgrade := req.Header.Get("Upgrade"); upgrade != "" && debug {
				logger.Debug("Preserving Upgrade header", log.String("upgrade", upgrade))
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			metrics.upstreamErrors.WithLabelValues(getTailscaleTarget(r)).Inc()
			logger.Error("Reverse proxy error", log.String("url", r.URL.String()), log.Error(err))
			if debug {
				logDebugRequest("ERROR", r)
			}
			http.Error(w, "Service temporarily unavailable", http.StatusServiceUnavailable)
		},
		ModifyResponse: func(resp *http.Response) error {
			if debug {
				logger.Debug("Response received",
					log.String("method", resp.Request.Method),
					log.String("path", resp.Request.URL.Path),
					log.String("host", resp.Request.URL.Host),
					log.String("status", resp.Status))

				for name, values := range resp.Header {
					for _, value := range values {
						logger.Debug("Response header", log.String("name", name), log.String("value", value))
					}
				}
			}

			if location := resp.Header.Get("Location"); location != "" {
				if newLocation := rewriteTailscaleURL(location); newLocation != location {
					logger.Info("Rewriting Location header",
						log.String("from", location),
						log.String("to", newLocation))
					resp.Header.Set("Location", newLocation)
				}
			}

			contentType := resp.Header.Get("Content-Type")
			if strings.Contains(contentType, "application/json") ||
				strings.Contains(contentType, "text/html") ||
				strings.Contains(contentType, "text/plain") {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return err
				}
				_ = resp.Body.Close()

				rewrittenBody := rewriteTailscaleURLsInBody(string(body))
				if rewrittenBody != string(body) {
					logger.Info("Rewrote URLs in response body", log.Int("bytes", len(rewrittenBody)))
				}

				resp.Body = io.NopCloser(strings.NewReader(rewrittenBody))
				resp.ContentLength = int64(len(rewrittenBody))
				resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(rewrittenBody)))
			}

			return nil
		},
	}

	if transport != nil {
		reverseProxy.Transport = transport
	}

	return reverseProxy
}

// logDebugRequest logs detailed information about a request when debug mode is enabled
func logDebugRequest(phase string, r *http.Request) {
	logger.Debug("Request details",
		log.String("phase", phase),
		log.String("method", r.Method),
		log.String("url", r.URL.String()),
		log.String("remote_addr", r.RemoteAddr),
		log.String("host", r.Host),
		log.String("proto", r.Proto))

	// Log all headers
	for name, values := range r.Header {
		for _, value := range values {
			logger.Debug("Request header",
				log.String("phase", phase),
				log.String("name", name),
				log.String("value", value))
		}
	}

	// Log query parameters
	if len(r.URL.RawQuery) > 0 {
		logger.Debug("Request query",
			log.String("phase", phase),
			log.String("query", r.URL.RawQuery))
	}
}

// getTailscaleTarget determines which Tailscale service to route to based on the request
func getTailscaleTarget(r *http.Request) string {
	// Check the request path and headers to determine the appropriate Tailscale service
	path := r.URL.Path
	userAgent := r.Header.Get("User-Agent")
	authHeader := r.Header.Get("Authorization")

	if debug {
		logger.Debug("Determining target",
			log.String("path", path),
			log.String("user_agent", userAgent))
		if authHeader != "" {
			logger.Debug("Authorization header present",
				log.String("auth_preview", authHeader[:min(len(authHeader), 20)]+"..."))
		}
	}

	// Route based on path patterns - prioritize API endpoints first
	switch {
	case strings.HasPrefix(path, "/ts2021"):
		// Tailscale control protocol upgrade endpoint
		logger.Info("Tailscale control protocol upgrade request detected, routing to controlplane")
		return "controlplane.tailscale.com"
	case strings.HasPrefix(path, "/key"):
		// Key exchange - always goes to controlplane
		logger.Info("Key exchange request detected, routing to controlplane")
		return "controlplane.tailscale.com"
	case strings.HasPrefix(path, "/api/"):
		// All API calls go to controlplane (including /api/v2/)
		logger.Info("API request detected, routing to controlplane")
		return "controlplane.tailscale.com"
	case strings.HasPrefix(path, "/machine/"):
		// Machine registration and updates
		logger.Info("Machine API request detected, routing to controlplane")
		return "controlplane.tailscale.com"
	case strings.HasPrefix(path, "/derp/"):
		// DERP relay traffic
		logger.Info("DERP request detected, routing to derp")
		return "derp.tailscale.com"
	case strings.HasPrefix(path, "/bootstrap-dns"):
		// DNS bootstrap
		logger.Info("DNS bootstrap request detected, routing to controlplane")
		return "controlplane.tailscale.com"
	case strings.HasPrefix(path, "/register"):
		// Registration requests
		logger.Info("Registration request detected, routing to controlplane")
		return "controlplane.tailscale.com"
	case strings.HasPrefix(path, "/c/"):
		// Control plane endpoints
		logger.Info("Control plane endpoint detected, routing to controlplane")
		return "controlplane.tailscale.com"
	case authHeader != "" && strings.Contains(userAgent, "tailscale"):
		// Tailscale client with auth header (likely auth key flow)
		logger.Info("Authenticated Tailscale client request, routing to controlplane")
		return "controlplane.tailscale.com"
	case strings.Contains(userAgent, "tailscale"):
		// Other Tailscale client requests
		if strings.Contains(path, "login") || strings.Contains(path, "auth") {
			logger.Info("Tailscale client login/auth request, routing to login")
			return "login.tailscale.com"
		}
		// Default to controlplane for other client requests
		logger.Info("Tailscale client request, routing to controlplane")
		return "controlplane.tailscale.com"
	case strings.HasPrefix(path, "/login") || strings.HasPrefix(path, "/auth") || strings.HasPrefix(path, "/a/"):
		// Login/auth web requests
		logger.Info("Web login/auth request, routing to login")
		return "login.tailscale.com"
	default:
		// Default to login for web-based access
		if debug {
			logger.Debug("Default routing to login")
		}
		return "login.tailscale.com"
	}
}

// handleTailscaleControlProtocol handles the /ts2021 endpoint with custom protocol upgrade
func handleTailscaleControlProtocol(w http.ResponseWriter, r *http.Request, metrics *proxyMetrics) {
	if debug {
		logDebugRequest("TS2021_HANDLER", r)
	}

	logger.Info("Handling Tailscale control protocol upgrade request",
		log.String("remote_addr", r.RemoteAddr),
		log.String("method", r.Method),
		log.String("host", r.Host),
		log.String("connection", r.Header.Get("Connection")),
		log.String("upgrade", r.Header.Get("Upgrade")))

	// Check if we can hijack the connection immediately
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		logger.Error("Response writer doesn't support hijacking")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Connect to the backend first
	backendConn, err := dialControlPlane("tcp", "controlplane.tailscale.com:443", &tls.Config{
		ServerName: "controlplane.tailscale.com",
	})
	if err != nil {
		metrics.upstreamErrors.WithLabelValues("controlplane.tailscale.com").Inc()
		logger.Error("Error connecting to backend",
			log.String("method", r.Method),
			log.String("path", r.URL.Path),
			log.String("connection", r.Header.Get("Connection")),
			log.String("upgrade", r.Header.Get("Upgrade")),
			log.Error(err))
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer backendConn.Close()

	// Write the original request to the backend
	err = r.Write(backendConn)
	if err != nil {
		metrics.upstreamErrors.WithLabelValues("controlplane.tailscale.com").Inc()
		logger.Error("Error writing request to backend",
			log.String("method", r.Method),
			log.String("path", r.URL.Path),
			log.Error(err))
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	// Read the response from the backend
	reader := bufio.NewReader(backendConn)
	resp, err := http.ReadResponse(reader, r)
	if err != nil {
		metrics.upstreamErrors.WithLabelValues("controlplane.tailscale.com").Inc()
		logger.Error("Error reading response from backend",
			log.String("method", r.Method),
			log.String("path", r.URL.Path),
			log.Error(err))
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	logger.Info("Received control protocol response from upstream",
		log.String("method", r.Method),
		log.String("path", r.URL.Path),
		log.Int("status_code", resp.StatusCode),
		log.String("status", resp.Status),
		log.String("connection", resp.Header.Get("Connection")),
		log.String("upgrade", resp.Header.Get("Upgrade")))

	// Copy response headers to client
	for name, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}

	// Write the response status
	w.WriteHeader(resp.StatusCode)

	// If it's a protocol switching response, hijack and tunnel
	if resp.StatusCode == http.StatusSwitchingProtocols {
		logger.Info("Protocol switching response received, hijacking connection for tunneling")

		// Hijack the client connection
		clientConn, clientReadWriter, err := hijacker.Hijack()
		if err != nil {
			logger.Error("Error hijacking connection", log.Error(err))
			return
		}
		defer clientConn.Close()
		if err := clientReadWriter.Flush(); err != nil {
			logger.Error("Error flushing protocol switch response", log.Error(err))
			return
		}
		metrics.activeTunnels.Inc()
		defer metrics.activeTunnels.Dec()

		// Start bidirectional copying
		done := make(chan bool, 2)

		// Copy from client to backend
		go func() {
			defer func() { done <- true }()
			io.Copy(backendConn, clientReadWriter)
			logger.Debug("Client to backend copy finished")
		}()

		// Copy from backend to client
		go func() {
			defer func() { done <- true }()
			io.Copy(clientConn, reader)
			logger.Debug("Backend to client copy finished")
		}()

		// Wait for either direction to finish
		<-done
		logger.Debug("Tunneling finished")
		return
	}

	logger.Error("Control protocol upgrade did not switch protocols",
		log.String("method", r.Method),
		log.String("path", r.URL.Path),
		log.Int("status_code", resp.StatusCode),
		log.String("status", resp.Status),
		log.String("connection", resp.Header.Get("Connection")),
		log.String("upgrade", resp.Header.Get("Upgrade")))

	// For non-upgrade responses, copy the body normally
	if resp.Body != nil {
		io.Copy(w, resp.Body)
		resp.Body.Close()
	}
}

// rewriteTailscaleURL rewrites Tailscale URLs to use the custom domain
func rewriteTailscaleURL(url string) string {
	// Replace Tailscale domains with our custom domain
	url = strings.Replace(url, "https://login.tailscale.com", "https://"+domain, -1)
	url = strings.Replace(url, "https://controlplane.tailscale.com", "https://"+domain, -1)
	url = strings.Replace(url, "http://login.tailscale.com", "https://"+domain, -1)
	url = strings.Replace(url, "http://controlplane.tailscale.com", "https://"+domain, -1)

	// Also handle protocol-relative URLs
	url = strings.Replace(url, "//login.tailscale.com", "//"+domain, -1)
	url = strings.Replace(url, "//controlplane.tailscale.com", "//"+domain, -1)

	return url
}

// rewriteTailscaleURLsInBody rewrites Tailscale URLs in response body content
func rewriteTailscaleURLsInBody(body string) string {
	// Use regex to find and replace Tailscale URLs in the body
	tailscaleURLRegex := regexp.MustCompile(`https?://(login|controlplane)\.tailscale\.com`)
	body = tailscaleURLRegex.ReplaceAllStringFunc(body, func(match string) string {
		return rewriteTailscaleURL(match)
	})

	// Also handle protocol-relative URLs
	protocolRelativeRegex := regexp.MustCompile(`//(login|controlplane)\.tailscale\.com`)
	body = protocolRelativeRegex.ReplaceAllStringFunc(body, func(match string) string {
		return "//" + domain
	})

	// Handle quoted URLs in JSON
	quotedURLRegex := regexp.MustCompile(`"https?://(login|controlplane)\.tailscale\.com([^"]*)"`)
	body = quotedURLRegex.ReplaceAllStringFunc(body, func(match string) string {
		return rewriteTailscaleURL(match)
	})

	return body
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// setupXForwardedHeaders sets up X-Forwarded headers when running behind a proxy
func setupXForwardedHeaders(req *http.Request) {
	// If running behind a proxy, preserve the original client information
	if httpOnly {
		// Trust the X-Forwarded-For header if present, otherwise use RemoteAddr
		if xff := req.Header.Get("X-Forwarded-For"); xff == "" {
			// Extract IP from RemoteAddr (format: "IP:port")
			clientIP := req.RemoteAddr
			if idx := strings.LastIndex(clientIP, ":"); idx != -1 {
				clientIP = clientIP[:idx]
			}
			req.Header.Set("X-Forwarded-For", clientIP)
		}

		// Set X-Forwarded-Proto if not already present
		if req.Header.Get("X-Forwarded-Proto") == "" {
			req.Header.Set("X-Forwarded-Proto", "https")
		}

		// Set X-Forwarded-Host if not already present
		if req.Header.Get("X-Forwarded-Host") == "" {
			req.Header.Set("X-Forwarded-Host", req.Host)
		}
	}
}
