package cmd

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/crypto/acme/autocert"
)

var (
	domain     string
	port       string
	httpsPort  string
	email      string
	certDir    string
	issueCerts bool
	debug      bool
	httpOnly   bool
	bindAddr   string
	logger     *zap.Logger
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

	serveCmd.MarkFlagRequired("domain")

	// Bind environment variables
	viper.SetEnvPrefix("PROXYT")
	viper.AutomaticEnv()
	viper.BindPFlag("domain", serveCmd.Flags().Lookup("domain"))
	viper.BindPFlag("port", serveCmd.Flags().Lookup("port"))
	viper.BindPFlag("https-port", serveCmd.Flags().Lookup("https-port"))
	viper.BindPFlag("email", serveCmd.Flags().Lookup("email"))
	viper.BindPFlag("cert-dir", serveCmd.Flags().Lookup("cert-dir"))
	viper.BindPFlag("issue", serveCmd.Flags().Lookup("issue"))
	viper.BindPFlag("debug", serveCmd.Flags().Lookup("debug"))
	viper.BindPFlag("http-only", serveCmd.Flags().Lookup("http-only"))
	viper.BindPFlag("bind", serveCmd.Flags().Lookup("bind"))
}

func runProxy() {
	// Read values from viper (supports both flags and environment variables)
	domain = viper.GetString("domain")
	port = viper.GetString("port")
	httpsPort = viper.GetString("https-port")
	email = viper.GetString("email")
	certDir = viper.GetString("cert-dir")
	issueCerts = viper.GetBool("issue")
	debug = viper.GetBool("debug")
	httpOnly = viper.GetBool("http-only")
	bindAddr = viper.GetString("bind")

	// Initialize zap logger
	var err error
	if debug {
		config := zap.NewDevelopmentConfig()
		config.Level = zap.NewAtomicLevelAt(zapcore.DebugLevel)
		logger, err = config.Build()
	} else {
		config := zap.NewProductionConfig()
		config.Level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
		logger, err = config.Build()
	}
	if err != nil {
		panic(fmt.Sprintf("Failed to initialize logger: %v", err))
	}
	defer logger.Sync()

	logger.Info("Starting Tailscale proxy",
		zap.String("domain", domain),
		zap.Bool("http_only", httpOnly))

	if debug {
		logger.Info("Debug logging enabled")
	}

	// Validate required flags based on mode
	if domain == "" {
		logger.Fatal("domain is required")
	}
	if !httpOnly && certDir == "" {
		logger.Fatal("cert-dir is required when not using --http-only mode")
	}

	var certManager *autocert.Manager
	var tlsConfig *tls.Config

	if !httpOnly && issueCerts {
		// Validate email is required for Let's Encrypt
		if email == "" {
			logger.Fatal("Email is required when --issue is true for Let's Encrypt registration")
		}

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

		logger.Info("Automatic certificate issuance enabled", zap.String("domain", domain))
	} else if !httpOnly {
		// Check if certificates exist in cert-dir
		certFile := filepath.Join(certDir, domain+".crt")
		keyFile := filepath.Join(certDir, domain+".key")

		if _, err := os.Stat(certFile); os.IsNotExist(err) {
			logger.Fatal("Certificate file not found (required when --issue=false)", zap.String("file", certFile))
		}
		if _, err := os.Stat(keyFile); os.IsNotExist(err) {
			logger.Fatal("Key file not found (required when --issue=false)", zap.String("file", keyFile))
		}

		// Load existing certificates
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			logger.Fatal("Failed to load certificates", zap.Error(err))
		}

		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}

		logger.Info("Using existing certificates", zap.String("cert_dir", certDir))
	}

	// Create a reverse proxy handler
	reverseProxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			// Setup X-Forwarded headers when running behind a proxy
			setupXForwardedHeaders(req)

			// Determine the appropriate Tailscale target
			target := getTailscaleTarget(req)

			if debug {
				logDebugRequest("DIRECTOR", req)
			}

			logger.Info("Reverse proxying request",
				zap.String("host", req.Host),
				zap.String("path", req.URL.Path),
				zap.String("target", target))

			// Set the target
			req.URL.Scheme = "https"
			req.URL.Host = target
			req.Host = target

			// Preserve upgrade headers for Tailscale control protocol
			if upgrade := req.Header.Get("Upgrade"); upgrade != "" {
				if debug {
					logger.Debug("Preserving Upgrade header", zap.String("upgrade", upgrade))
				}
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			logger.Error("Reverse proxy error", zap.String("url", r.URL.String()), zap.Error(err))
			if debug {
				logDebugRequest("ERROR", r)
			}
			http.Error(w, "Service temporarily unavailable", http.StatusServiceUnavailable)
		},
		ModifyResponse: func(resp *http.Response) error {
			if debug {
				logger.Debug("Response received",
					zap.String("method", resp.Request.Method),
					zap.String("path", resp.Request.URL.Path),
					zap.String("host", resp.Request.URL.Host),
					zap.String("status", resp.Status))

				for name, values := range resp.Header {
					for _, value := range values {
						logger.Debug("Response header", zap.String("name", name), zap.String("value", value))
					}
				}
			}

			// Rewrite URLs in response headers
			if location := resp.Header.Get("Location"); location != "" {
				if newLocation := rewriteTailscaleURL(location); newLocation != location {
					logger.Info("Rewriting Location header",
						zap.String("from", location),
						zap.String("to", newLocation))
					resp.Header.Set("Location", newLocation)
				}
			}

			// Rewrite URLs in response body for JSON and HTML content
			contentType := resp.Header.Get("Content-Type")
			if strings.Contains(contentType, "application/json") ||
				strings.Contains(contentType, "text/html") ||
				strings.Contains(contentType, "text/plain") {

				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return err
				}
				resp.Body.Close()

				// Rewrite URLs in the response body
				rewrittenBody := rewriteTailscaleURLsInBody(string(body))

				if rewrittenBody != string(body) {
					logger.Info("Rewrote URLs in response body", zap.Int("bytes", len(rewrittenBody)))
				}

				// Create new response body
				resp.Body = io.NopCloser(strings.NewReader(rewrittenBody))
				resp.ContentLength = int64(len(rewrittenBody))
				resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(rewrittenBody)))
			}

			return nil
		},
	}

	// Create the main HTTP handler that will be used in all modes
	mainHandler := http.NewServeMux()

	// Add a health check endpoint
	mainHandler.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		logger.Info("Health check request", zap.String("remote_addr", r.RemoteAddr))
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK - Tailscale Proxy is running"))
	})

	// Handle Tailscale control protocol upgrade specially
	mainHandler.HandleFunc("/ts2021", handleTailscaleControlProtocol)

	// Handle all other requests by proxying them
	mainHandler.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Don't proxy health checks
		if r.URL.Path == "/health" {
			logger.Info("Health check request", zap.String("remote_addr", r.RemoteAddr))
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK - Tailscale Proxy is running"))
			return
		}

		// Handle Tailscale control protocol upgrade specially
		if strings.HasPrefix(r.URL.Path, "/ts2021") {
			handleTailscaleControlProtocol(w, r)
			return
		}

		if debug {
			logDebugRequest("MAIN_HANDLER", r)
		}
		logger.Info("Request - proxying",
			zap.String("remote_addr", r.RemoteAddr),
			zap.String("host", r.Host),
			zap.String("path", r.URL.Path))
		reverseProxy.ServeHTTP(w, r)
	})

	var servers []*http.Server

	if httpOnly {
		// HTTP-only mode for use behind HTTPS proxy/load balancer
		httpServer := &http.Server{
			Addr:    bindAddr + ":" + port,
			Handler: mainHandler,
		}
		servers = append(servers, httpServer)

		logger.Info("HTTP-only mode enabled - running behind HTTPS proxy",
			zap.String("bind_addr", bindAddr),
			zap.String("port", port))
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
					zap.String("addr", srv.Addr),
					zap.String("domain", domain))
				if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
					logger.Fatal("HTTPS server failed", zap.Error(err))
				}
			} else {
				// HTTP server
				if httpOnly {
					logger.Info("Starting HTTP proxy server (behind HTTPS proxy)",
						zap.String("addr", srv.Addr))
				} else if issueCerts {
					logger.Info("Starting HTTP server for Let's Encrypt challenges and redirects",
						zap.String("addr", srv.Addr))
				} else {
					logger.Info("Starting HTTP server for HTTPS redirects",
						zap.String("addr", srv.Addr))
				}
				if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					logger.Fatal("HTTP server failed", zap.Error(err))
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
			logger.Error("Server shutdown error", zap.String("addr", server.Addr), zap.Error(err))
		}
	}

	logger.Info("Servers stopped")
}

// logDebugRequest logs detailed information about a request when debug mode is enabled
func logDebugRequest(phase string, r *http.Request) {
	logger.Debug("Request details",
		zap.String("phase", phase),
		zap.String("method", r.Method),
		zap.String("url", r.URL.String()),
		zap.String("remote_addr", r.RemoteAddr),
		zap.String("host", r.Host),
		zap.String("proto", r.Proto))

	// Log all headers
	for name, values := range r.Header {
		for _, value := range values {
			logger.Debug("Request header",
				zap.String("phase", phase),
				zap.String("name", name),
				zap.String("value", value))
		}
	}

	// Log query parameters
	if len(r.URL.RawQuery) > 0 {
		logger.Debug("Request query",
			zap.String("phase", phase),
			zap.String("query", r.URL.RawQuery))
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
			zap.String("path", path),
			zap.String("user_agent", userAgent))
		if authHeader != "" {
			logger.Debug("Authorization header present",
				zap.String("auth_preview", authHeader[:min(len(authHeader), 20)]+"..."))
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
func handleTailscaleControlProtocol(w http.ResponseWriter, r *http.Request) {
	if debug {
		logDebugRequest("TS2021_HANDLER", r)
	}

	logger.Info("Handling Tailscale control protocol upgrade request", zap.String("remote_addr", r.RemoteAddr))

	// Check if we can hijack the connection immediately
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		logger.Error("Response writer doesn't support hijacking")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Connect to the backend first
	backendConn, err := tls.Dial("tcp", "controlplane.tailscale.com:443", &tls.Config{
		ServerName: "controlplane.tailscale.com",
	})
	if err != nil {
		logger.Error("Error connecting to backend", zap.Error(err))
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer backendConn.Close()

	// Write the original request to the backend
	err = r.Write(backendConn)
	if err != nil {
		logger.Error("Error writing request to backend", zap.Error(err))
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	// Read the response from the backend
	reader := bufio.NewReader(backendConn)
	resp, err := http.ReadResponse(reader, r)
	if err != nil {
		logger.Error("Error reading response from backend", zap.Error(err))
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

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
		clientConn, _, err := hijacker.Hijack()
		if err != nil {
			logger.Error("Error hijacking connection", zap.Error(err))
			return
		}
		defer clientConn.Close()

		// Start bidirectional copying
		done := make(chan bool, 2)

		// Copy from client to backend
		go func() {
			defer func() { done <- true }()
			io.Copy(backendConn, clientConn)
			logger.Debug("Client to backend copy finished")
		}()

		// Copy from backend to client
		go func() {
			defer func() { done <- true }()
			io.Copy(clientConn, backendConn)
			logger.Debug("Backend to client copy finished")
		}()

		// Wait for either direction to finish
		<-done
		logger.Debug("Tunneling finished")
		return
	}

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
