package cmd

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	log "github.com/jaxxstorm/log"
)

const (
	defaultHACookieName = "__Host-proxyt-ha"
	defaultHACookieTTL  = 12 * time.Hour
	haSessionVersion    = 1
)

var tailscaleCookieDomainRegex = regexp.MustCompile(`(?i)\bDomain=\.?(?:[a-z0-9-]+\.)*tailscale\.com\b`)

type haSessionManager struct {
	cookieName string
	domain     string
	ttl        time.Duration
	secret     []byte
	clock      func() time.Time
	random     io.Reader
}

type haSession struct {
	ID        string
	Domain    string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

type haSessionClaims struct {
	Version   int    `json:"v"`
	SessionID string `json:"sid"`
	Domain    string `json:"dom"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

func newHASessionManager(domain, secret, cookieName string, ttl time.Duration) (*haSessionManager, error) {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return nil, errors.New("domain is required for HA mode")
	}

	secret = strings.TrimSpace(secret)
	if len(secret) < 32 {
		return nil, errors.New("ha-secret must be at least 32 characters")
	}

	if cookieName == "" {
		cookieName = defaultHACookieName
	}

	if ttl <= 0 {
		return nil, errors.New("ha-cookie-ttl must be greater than zero")
	}

	return &haSessionManager{
		cookieName: cookieName,
		domain:     domain,
		ttl:        ttl,
		secret:     []byte(secret),
		clock:      time.Now,
		random:     rand.Reader,
	}, nil
}

func (m *haSessionManager) ensureSession(w http.ResponseWriter, r *http.Request) (*haSession, error) {
	now := m.clock()

	session, err := m.readSession(r, now)
	if err != nil {
		logger.Error("Invalid HA session cookie, issuing replacement",
			log.String("cookie_name", m.cookieName),
			log.Error(err))
	}

	if session == nil {
		session, err = m.newSession(now)
		if err != nil {
			return nil, err
		}

		logger.Info("Created HA session",
			log.String("cookie_name", m.cookieName),
			log.String("ha_session_id", session.ID))
	}

	refreshed := &haSession{
		ID:        session.ID,
		Domain:    m.domain,
		IssuedAt:  session.IssuedAt,
		ExpiresAt: now.Add(m.ttl),
	}

	if err := m.writeSessionCookie(w, r, refreshed); err != nil {
		return nil, err
	}

	return refreshed, nil
}

func (m *haSessionManager) readSession(r *http.Request, now time.Time) (*haSession, error) {
	cookie, err := r.Cookie(m.cookieName)
	if errors.Is(err, http.ErrNoCookie) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return m.decodeSessionValue(cookie.Value, now)
}

func (m *haSessionManager) decodeSessionValue(value string, now time.Time) (*haSession, error) {
	payload, err := m.verifySignedValue(value)
	if err != nil {
		return nil, err
	}

	var claims haSessionClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("decode claims: %w", err)
	}

	if claims.Version != haSessionVersion {
		return nil, fmt.Errorf("unsupported session version %d", claims.Version)
	}
	if claims.Domain != m.domain {
		return nil, fmt.Errorf("session domain %q does not match configured domain %q", claims.Domain, m.domain)
	}
	if claims.SessionID == "" {
		return nil, errors.New("session id is required")
	}
	if now.Unix() >= claims.ExpiresAt {
		return nil, errors.New("session expired")
	}

	return &haSession{
		ID:        claims.SessionID,
		Domain:    claims.Domain,
		IssuedAt:  time.Unix(claims.IssuedAt, 0).UTC(),
		ExpiresAt: time.Unix(claims.ExpiresAt, 0).UTC(),
	}, nil
}

func (m *haSessionManager) newSession(now time.Time) (*haSession, error) {
	randomBytes := make([]byte, 16)
	if _, err := io.ReadFull(m.random, randomBytes); err != nil {
		return nil, fmt.Errorf("generate session id: %w", err)
	}

	return &haSession{
		ID:        hex.EncodeToString(randomBytes),
		Domain:    m.domain,
		IssuedAt:  now.UTC(),
		ExpiresAt: now.Add(m.ttl).UTC(),
	}, nil
}

func (m *haSessionManager) writeSessionCookie(w http.ResponseWriter, r *http.Request, session *haSession) error {
	value, err := m.encodeSessionValue(session)
	if err != nil {
		return err
	}

	maxAge := int(time.Until(session.ExpiresAt).Seconds())
	if maxAge <= 0 {
		maxAge = 1
	}

	http.SetCookie(w, &http.Cookie{
		Name:     m.cookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   requestUsesHTTPS(r),
		SameSite: http.SameSiteLaxMode,
		Expires:  session.ExpiresAt,
		MaxAge:   maxAge,
	})

	return nil
}

func (m *haSessionManager) encodeSessionValue(session *haSession) (string, error) {
	claims := haSessionClaims{
		Version:   haSessionVersion,
		SessionID: session.ID,
		Domain:    session.Domain,
		IssuedAt:  session.IssuedAt.UTC().Unix(),
		ExpiresAt: session.ExpiresAt.UTC().Unix(),
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}

	signature := m.sign(payload)

	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func (m *haSessionManager) verifySignedValue(value string) ([]byte, error) {
	parts := strings.Split(value, ".")
	if len(parts) != 2 {
		return nil, errors.New("invalid session format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}

	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}

	if !hmac.Equal(signature, m.sign(payload)) {
		return nil, errors.New("invalid session signature")
	}

	return payload, nil
}

func (m *haSessionManager) sign(payload []byte) []byte {
	mac := hmac.New(sha256.New, m.secret)
	_, _ = mac.Write(payload)
	return mac.Sum(nil)
}

func requestUsesHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}

	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func stripNamedCookie(r *http.Request, name string) {
	cookies := r.Cookies()
	if len(cookies) == 0 {
		return
	}

	values := make([]string, 0, len(cookies))
	removed := false
	for _, cookie := range cookies {
		if cookie.Name == name {
			removed = true
			continue
		}

		values = append(values, cookie.Name+"="+cookie.Value)
	}

	if !removed {
		return
	}

	r.Header.Del("Cookie")
	if len(values) > 0 {
		r.Header.Set("Cookie", strings.Join(values, "; "))
	}
}

func rewriteSetCookieHeader(value string) string {
	if domain == "" {
		return value
	}

	return tailscaleCookieDomainRegex.ReplaceAllString(value, "Domain="+domain)
}
