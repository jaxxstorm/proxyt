package cmd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type certificateFiles struct{ cert, key []byte }

func makeCertificate(t *testing.T, host string, start, end time.Time, serial int64) certificateFiles {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), DNSNames: []string{host}, NotBefore: start, NotAfter: end, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return certificateFiles{pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})}
}

func (f certificateFiles) write(t *testing.T, dir string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "proxy.example.com.crt"), f.cert, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "proxy.example.com.key"), f.key, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestExternalCertificateValidation(t *testing.T) {
	withProxyTestGlobals(t)
	now := time.Now()
	valid := makeCertificate(t, "proxy.example.com", now.Add(-time.Hour), now.Add(time.Hour), 1)
	other := makeCertificate(t, "proxy.example.com", now.Add(-time.Hour), now.Add(time.Hour), 2)
	for name, files := range map[string]certificateFiles{
		"mismatch":  {valid.cert, other.key},
		"malformed": {[]byte("broken"), valid.key},
		"expired":   makeCertificate(t, "proxy.example.com", now.Add(-2*time.Hour), now.Add(-time.Hour), 3),
		"future":    makeCertificate(t, "proxy.example.com", now.Add(time.Hour), now.Add(2*time.Hour), 4),
		"hostname":  makeCertificate(t, "other.example.com", now.Add(-time.Hour), now.Add(time.Hour), 5),
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			files.write(t, dir)
			if _, err := newExternalCertificates(dir, "proxy.example.com", newProxyMetrics(), logger); err == nil {
				t.Fatal("accepted invalid certificate")
			}
		})
	}
	dir := t.TempDir()
	if _, err := newExternalCertificates(dir, "proxy.example.com", newProxyMetrics(), logger); err == nil {
		t.Fatal("accepted missing files")
	}
	valid.write(t, dir)
	if err := os.Remove(filepath.Join(dir, "proxy.example.com.key")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "proxy.example.com.key"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := newExternalCertificates(dir, "proxy.example.com", newProxyMetrics(), logger); err == nil {
		t.Fatal("accepted unreadable key")
	}
}

func TestCertificateReloadRecoveryAndMetrics(t *testing.T) {
	withProxyTestGlobals(t)
	var output bytes.Buffer
	log, err := buildRuntimeLogger(false, &output, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { log.Close() })
	now := time.Now()
	a := makeCertificate(t, "proxy.example.com", now.Add(-time.Hour), now.Add(time.Hour), 1)
	b := makeCertificate(t, "proxy.example.com", now.Add(-time.Hour), now.Add(2*time.Hour), 2)
	dir := t.TempDir()
	a.write(t, dir)
	metrics := newProxyMetrics()
	c, err := newExternalCertificates(dir, "proxy.example.com", metrics, log)
	if err != nil {
		t.Fatal(err)
	}
	original, _ := c.get(nil)
	c.reload()
	if got := metricValue(t, metrics.certificateReload.WithLabelValues("success")); got != 0 {
		t.Fatal(got)
	}
	certificateFiles{b.cert, a.key}.write(t, dir)
	c.reload()
	c.reload()
	if got, _ := c.get(nil); got != original {
		t.Fatal("failed reload replaced active certificate")
	}
	if got := metricValue(t, metrics.certificateReload.WithLabelValues("error")); got != 2 {
		t.Fatal(got)
	}
	if count := strings.Count(output.String(), "External certificate reload failed"); count != 1 {
		t.Fatalf("failure log count = %d", count)
	}
	rt := testRuntime(t)
	h := buildRuntimeHandler(readyTransport(), func() (*tls.Certificate, error) { return c.get(nil) }, rt)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/ready", nil))
	if w.Code != 200 {
		t.Fatal("last-known-good readiness failed")
	}
	b.write(t, dir)
	c.reload()
	if got, _ := c.get(nil); got.Leaf.SerialNumber.Int64() != 2 {
		t.Fatal("did not recover")
	}
	if got := metricValue(t, metrics.certificateReload.WithLabelValues("success")); got != 1 {
		t.Fatal(got)
	}
	if !strings.Contains(output.String(), "External certificate reload recovered") {
		t.Fatal("no recovery log")
	}
	if strings.Contains(output.String(), "PRIVATE KEY") || strings.Contains(output.String(), "BEGIN CERTIFICATE") {
		t.Fatal("logged PEM")
	}
	// Simulate passage of time for the active snapshot without sleeping or
	// mutating a snapshot concurrently with readers.
	expired := makeCertificate(t, "proxy.example.com", now.Add(-2*time.Hour), now.Add(-time.Hour), 3)
	pair, err := tls.X509KeyPair(expired.cert, expired.key)
	if err != nil {
		t.Fatal(err)
	}
	c.active.Store(&pair)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/ready", nil))
	if w.Code != 503 {
		t.Fatal("expired certificate was ready")
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	expiry, _ := certificateExpiry(&pair)
	if got := metricValue(t, rt.metrics.certificateExpiry.WithLabelValues()); got != float64(expiry.Unix()) {
		t.Fatalf("expiry = %v", got)
	}
	rt.shutdown(nil)
}

func TestMountedCertificateRotation(t *testing.T) {
	withProxyTestGlobals(t)
	now := time.Now()
	a := makeCertificate(t, "proxy.example.com", now.Add(-time.Hour), now.Add(time.Hour), 1)
	b := makeCertificate(t, "proxy.example.com", now.Add(-time.Hour), now.Add(2*time.Hour), 2)
	root := t.TempDir()
	for name, files := range map[string]certificateFiles{"old": a, "new": b} {
		dir := filepath.Join(root, name)
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		files.write(t, dir)
	}
	mount := filepath.Join(root, "current")
	if err := os.Symlink(filepath.Join(root, "old"), mount); err != nil {
		t.Fatal(err)
	}
	rt := testRuntime(t)
	rt.dial = echoDial(t)
	c, err := newExternalCertificates(mount, "proxy.example.com", rt.metrics, logger)
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewUnstartedServer(buildRuntimeHandler(readyTransport(), func() (*tls.Certificate, error) { return c.get(nil) }, rt))
	s.TLS = &tls.Config{GetCertificate: c.get}
	s.StartTLS()
	s.Client().Transport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	t.Cleanup(func() { rt.shutdown([]*http.Server{s.Config}); s.Close() })
	dial := func() (*tls.Conn, error) {
		return tls.Dial("tcp", s.Listener.Addr().String(), &tls.Config{InsecureSkipVerify: true, ServerName: "proxy.example.com"})
	}
	conn, err := dial()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if conn.ConnectionState().PeerCertificates[0].SerialNumber.Int64() != 1 {
		t.Fatal("wrong initial certificate")
	}
	_, reader := upgradeConn(t, conn)
	exchange(t, conn, reader)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := dial()
			if err == nil {
				serial := conn.ConnectionState().PeerCertificates[0].SerialNumber.Int64()
				if serial != 1 && serial != 2 {
					err = fmt.Errorf("partial certificate: %d", serial)
				}
				conn.Close()
			}
			errs <- err
		}()
	}
	if err := os.Symlink(filepath.Join(root, "new"), filepath.Join(root, "next")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(root, "next"), mount); err != nil {
		t.Fatal(err)
	}
	c.reload()
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	next, err := dial()
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if next.ConnectionState().PeerCertificates[0].SerialNumber.Int64() != 2 {
		t.Fatal("new handshake did not use rotated certificate")
	}
	exchange(t, conn, reader)
	status(t, s.Client(), s.URL+"/ready", 200)
	status(t, s.Client(), s.URL+"/metrics", 200)
	active, _ := c.get(nil)
	if got := metricValue(t, rt.metrics.certificateExpiry.WithLabelValues()); got != float64(active.Leaf.NotAfter.Unix()) {
		t.Fatal("stale expiry metric")
	}
}

func TestCertificatePollerStops(t *testing.T) {
	withProxyTestGlobals(t)
	now := time.Now()
	dir := t.TempDir()
	makeCertificate(t, "proxy.example.com", now.Add(-time.Hour), now.Add(time.Hour), 1).write(t, dir)
	c, err := newExternalCertificates(dir, "proxy.example.com", newProxyMetrics(), logger)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.run(ctx, 5*time.Millisecond); close(done) }()
	makeCertificate(t, "proxy.example.com", now.Add(-time.Hour), now.Add(2*time.Hour), 2).write(t, dir)
	deadline := time.Now().Add(time.Second)
	for c.active.Load().Leaf.SerialNumber.Int64() != 2 {
		if time.Now().After(deadline) {
			cancel()
			await(t, done)
			t.Fatal("poller did not publish replacement")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	await(t, done)
}
