package cmd

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestNewHASessionManagerValidation(t *testing.T) {
	t.Run("requires domain", func(t *testing.T) {
		_, err := newHASessionManager("", strings.Repeat("a", 32), "", time.Hour)
		if err == nil || !strings.Contains(err.Error(), "domain") {
			t.Fatalf("expected domain validation error, got %v", err)
		}
	})

	t.Run("requires sufficiently long secret", func(t *testing.T) {
		_, err := newHASessionManager("proxy.example.com", "short", "", time.Hour)
		if err == nil || !strings.Contains(err.Error(), "ha-secret") {
			t.Fatalf("expected secret validation error, got %v", err)
		}
	})

	t.Run("requires positive ttl", func(t *testing.T) {
		_, err := newHASessionManager("proxy.example.com", strings.Repeat("a", 32), "", 0)
		if err == nil || !strings.Contains(err.Error(), "ha-cookie-ttl") {
			t.Fatalf("expected ttl validation error, got %v", err)
		}
	})

	t.Run("uses default cookie name", func(t *testing.T) {
		manager, err := newHASessionManager("proxy.example.com", strings.Repeat("a", 32), "", time.Hour)
		if err != nil {
			t.Fatalf("newHASessionManager: %v", err)
		}
		if manager.cookieName != defaultHACookieName {
			t.Fatalf("cookie name = %q, want %q", manager.cookieName, defaultHACookieName)
		}
	})
}

func TestHASessionRoundTripAndCookieStripping(t *testing.T) {
	manager, err := newHASessionManager("proxy.example.com", strings.Repeat("a", 32), defaultHACookieName, time.Hour)
	if err != nil {
		t.Fatalf("newHASessionManager: %v", err)
	}

	now := time.Unix(1_700_000_000, 0).UTC()
	manager.clock = func() time.Time { return now }
	manager.random = strings.NewReader("0123456789abcdef")

	session, err := manager.newSession(now)
	if err != nil {
		t.Fatalf("newSession: %v", err)
	}

	value, err := manager.encodeSessionValue(session)
	if err != nil {
		t.Fatalf("encodeSessionValue: %v", err)
	}

	decoded, err := manager.decodeSessionValue(value, now.Add(10*time.Minute))
	if err != nil {
		t.Fatalf("decodeSessionValue: %v", err)
	}
	if decoded.ID != session.ID {
		t.Fatalf("decoded session id = %q, want %q", decoded.ID, session.ID)
	}

	tampered := value[:len(value)-1] + "A"
	if _, err := manager.decodeSessionValue(tampered, now.Add(10*time.Minute)); err == nil {
		t.Fatal("expected tampered session value to fail validation")
	}

	req := httptest.NewRequest(http.MethodGet, "https://proxy.example.com/login", nil)
	req.AddCookie(&http.Cookie{Name: manager.cookieName, Value: value})
	req.AddCookie(&http.Cookie{Name: "ts-session", Value: "keep-me"})

	stripNamedCookie(req, manager.cookieName)

	if got := req.Header.Get("Cookie"); got != "ts-session=keep-me" {
		t.Fatalf("Cookie header = %q, want proxyt cookie removed", got)
	}
}

func TestRewriteSetCookieHeader(t *testing.T) {
	withProxyTestGlobals(t)
	domain = "proxy.example.com"

	in := "tail=1; Path=/; Domain=login.tailscale.com; HttpOnly; Secure"
	got := rewriteSetCookieHeader(in)

	if !strings.Contains(got, "Domain=proxy.example.com") {
		t.Fatalf("rewritten cookie = %q, want proxyt domain", got)
	}
	if strings.Contains(got, "tailscale.com") {
		t.Fatalf("rewritten cookie should not leak tailscale domain: %q", got)
	}
}

func TestBuildMainHandlerHACrossReplicas(t *testing.T) {
	withProxyTestGlobals(t)
	domain = "proxy.example.com"
	httpOnly = true
	haEnabled = true

	manager, err := newHASessionManager(domain, strings.Repeat("a", 32), defaultHACookieName, time.Hour)
	if err != nil {
		t.Fatalf("newHASessionManager: %v", err)
	}
	haSessions = manager

	upstream := newRecordedUpstream(t, "login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "tail=1; Path=/; Domain=login.tailscale.com; HttpOnly; Secure")
		_, _ = w.Write([]byte("login"))
	})

	resolveProxyTarget = func(target string) *url.URL {
		return mustParseURL(t, upstream.server.URL)
	}

	replicaA := httptest.NewServer(buildMainHandler(nil))
	t.Cleanup(replicaA.Close)
	replicaB := httptest.NewServer(buildMainHandler(nil))
	t.Cleanup(replicaB.Close)

	client := &http.Client{}

	firstReq, err := http.NewRequest(http.MethodGet, replicaA.URL+"/login", nil)
	if err != nil {
		t.Fatalf("first request: %v", err)
	}
	firstReq.Host = domain
	firstReq.Header.Set("X-Forwarded-Proto", "https")

	firstResp, err := client.Do(firstReq)
	if err != nil {
		t.Fatalf("first request failed: %v", err)
	}
	defer firstResp.Body.Close()

	firstCookie := findCookieByName(t, firstResp.Cookies(), defaultHACookieName)
	firstSession, err := manager.decodeSessionValue(firstCookie.Value, time.Now())
	if err != nil {
		t.Fatalf("decode first HA session: %v", err)
	}

	if raw := strings.Join(firstResp.Header.Values("Set-Cookie"), "\n"); !strings.Contains(raw, "Domain=proxy.example.com") {
		t.Fatalf("expected rewritten upstream cookie domain, got %q", raw)
	}

	secondReq, err := http.NewRequest(http.MethodGet, replicaB.URL+"/auth", nil)
	if err != nil {
		t.Fatalf("second request: %v", err)
	}
	secondReq.Host = domain
	secondReq.Header.Set("X-Forwarded-Proto", "https")
	secondReq.AddCookie(firstCookie)

	secondResp, err := client.Do(secondReq)
	if err != nil {
		t.Fatalf("second request failed: %v", err)
	}
	defer secondResp.Body.Close()

	secondCookie := findCookieByName(t, secondResp.Cookies(), defaultHACookieName)
	secondSession, err := manager.decodeSessionValue(secondCookie.Value, time.Now())
	if err != nil {
		t.Fatalf("decode second HA session: %v", err)
	}

	if firstSession.ID != secondSession.ID {
		t.Fatalf("session id changed across replicas: %q != %q", firstSession.ID, secondSession.ID)
	}

	lastUpstreamReq := upstream.lastRequest()
	if strings.Contains(lastUpstreamReq.Cookie, defaultHACookieName+"=") {
		t.Fatalf("proxyt HA cookie leaked upstream: %q", lastUpstreamReq.Cookie)
	}
}

func findCookieByName(t *testing.T, cookies []*http.Cookie, name string) *http.Cookie {
	t.Helper()

	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}

	t.Fatalf("cookie %q not found", name)
	return nil
}
