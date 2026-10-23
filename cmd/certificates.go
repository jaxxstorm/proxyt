package cmd

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/jaxxstorm/log"
)

type externalCertificates struct {
	dir, domain string
	active      atomic.Pointer[tls.Certificate]
	mu          sync.Mutex // serialize polls, including their failure/recovery reporting
	fingerprint [32]byte
	lastError   string
	metrics     *proxyMetrics
	log         *log.Logger
	now         func() time.Time
}

func certificateLeaf(cert *tls.Certificate) (*x509.Certificate, error) {
	if cert == nil || len(cert.Certificate) == 0 && cert.Leaf == nil {
		return nil, fmt.Errorf("certificate has no leaf")
	}
	if cert.Leaf != nil {
		return cert.Leaf, nil
	}
	return x509.ParseCertificate(cert.Certificate[0])
}

func newExternalCertificates(dir, domain string, metrics *proxyMetrics, logger *log.Logger) (*externalCertificates, error) {
	c := &externalCertificates{dir: dir, domain: domain, metrics: metrics, log: logger, now: time.Now}
	cert, fingerprint, err := c.load()
	if err != nil {
		return nil, err
	}
	c.active.Store(cert)
	c.fingerprint = fingerprint
	return c, nil
}

func (c *externalCertificates) load() (*tls.Certificate, [32]byte, error) {
	var empty [32]byte
	certPEM, err := os.ReadFile(filepath.Join(c.dir, c.domain+".crt"))
	if err != nil {
		return nil, empty, fmt.Errorf("read external certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(c.dir, c.domain+".key"))
	if err != nil {
		return nil, empty, fmt.Errorf("read external private key: %w", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, empty, fmt.Errorf("load external certificate pair: %w", err)
	}
	leaf, err := certificateLeaf(&cert)
	if err != nil {
		return nil, empty, err
	}
	if now := c.now(); now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return nil, empty, fmt.Errorf("external certificate is outside its validity interval")
	}
	if err := leaf.VerifyHostname(c.domain); err != nil {
		return nil, empty, fmt.Errorf("external certificate hostname: %w", err)
	}
	cert.Leaf = leaf
	return &cert, sha256.Sum256(append(certPEM, keyPEM...)), nil
}

func (c *externalCertificates) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return c.active.Load(), nil
}

func (c *externalCertificates) reload() {
	c.mu.Lock()
	defer c.mu.Unlock()
	cert, fingerprint, err := c.load()
	if err != nil {
		c.metrics.certificateReload.WithLabelValues("error").Inc()
		if c.lastError != err.Error() {
			c.log.Error("External certificate reload failed", log.Error(err))
		}
		c.lastError = err.Error()
		return
	}
	if c.lastError != "" {
		c.log.Info("External certificate reload recovered")
	}
	c.lastError = ""
	if fingerprint == c.fingerprint {
		return
	}
	c.active.Store(cert)
	c.fingerprint = fingerprint
	c.metrics.certificateReload.WithLabelValues("success").Inc()
	c.log.Info("External certificate reloaded", log.String("expires", cert.Leaf.NotAfter.UTC().Format(time.RFC3339)))
}

func (c *externalCertificates) run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.reload()
		}
	}
}
