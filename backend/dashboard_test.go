package main

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestDashboardRequiresSession(t *testing.T) {
	tmp := t.TempDir()
	a := &API{
		auth:         newAuthManager(tmp),
		allowedHosts: map[string]struct{}{"router.test": {}},
	}
	r := httptest.NewRequest(http.MethodGet, "http://router.test/dashboard/", nil)
	r.Host = "router.test"
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/" {
		t.Fatalf("unauthenticated dashboard got %d %q", w.Code, w.Header().Get("Location"))
	}
	r = httptest.NewRequest(http.MethodGet, "http://router.test/dashboard/api/version", nil)
	r.Host = "router.test"
	w = httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated Controller proxy got %d", w.Code)
	}
}

func TestDashboardProxyInjectsControllerSecretAndDropsBrowserSecret(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/version" || r.URL.Query().Get("secret") != "" {
			t.Errorf("unexpected upstream request: %s", r.URL.String())
		}
		if got := r.Header.Get("Authorization"); got != "Bearer controller-secret" {
			t.Errorf("Controller authorization = %q", got)
		}
		if r.Header.Get("Cookie") != "" {
			t.Error("application session cookie was forwarded to Mihomo")
		}
		_, _ = io.WriteString(w, `{"version":"v1.19.23"}`)
	}))
	defer upstream.Close()
	_, portText, err := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	auth := newAuthManager(t.TempDir())
	auth.sessions[sessionDigest("session-token")] = time.Now().Add(time.Hour)
	a := &API{
		state:        RuntimeState{ControllerPort: port},
		manager:      &ProcessManager{secret: "controller-secret"},
		auth:         auth,
		logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		allowedHosts: map[string]struct{}{"router.test": {}},
	}
	r := httptest.NewRequest(http.MethodGet, "http://router.test/dashboard/api/version?secret=browser-value", nil)
	r.Host = "router.test"
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: "session-token"})
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "v1.19.23") {
		t.Fatalf("dashboard proxy got %d: %s", w.Code, w.Body.String())
	}
}

func TestDashboardServesBootstrapAndRestrictsConfigChanges(t *testing.T) {
	if !strings.Contains(dashboardBootstrapJS, "hostname: window.location.hostname,") {
		t.Fatal("Zashboard bootstrap must preserve IPv6 host brackets")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<!doctype html><html><head></head><body></body></html>"), 0600); err != nil {
		t.Fatal(err)
	}
	auth := newAuthManager(t.TempDir())
	auth.sessions[sessionDigest("session-token")] = time.Now().Add(time.Hour)
	a := &API{
		auth:         auth,
		dashboardDir: dir,
		allowedHosts: map[string]struct{}{"router.test": {}},
	}
	r := httptest.NewRequest(http.MethodGet, "http://router.test/dashboard/", nil)
	r.Host = "router.test"
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: "session-token"})
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "inextos-clash-bootstrap.js") {
		t.Fatalf("dashboard page did not receive bootstrap: %d %s", w.Code, w.Body.String())
	}
	if !dashboardControllerRequestAllowed(httptest.NewRecorder(), httptest.NewRequest(http.MethodPut, "http://router.test/dashboard/api/configs", strings.NewReader(`{"mode":"rule"}`))) {
		t.Fatal("safe mode update was rejected")
	}
	w = httptest.NewRecorder()
	if dashboardControllerRequestAllowed(w, httptest.NewRequest(http.MethodPut, "http://router.test/dashboard/api/configs", strings.NewReader(`{"tun":{"enable":true}}`))) || w.Code != http.StatusBadRequest {
		t.Fatalf("TUN config update was not rejected: %d", w.Code)
	}
}
