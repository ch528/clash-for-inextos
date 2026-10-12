package main

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testAPI(dir string) *API {
	state := RuntimeState{MixedPort: 17890, ControllerPort: 9091, BackendPort: 18080}
	manager := newProcessManager(filepath.Join(dir, "missing-mihomo"), "", "", dir, "test-secret-long-enough", state)
	auth := newAuthManager(filepath.Join(dir, "state"))
	return &API{
		state: state, manager: manager, stateDir: filepath.Join(dir, "state"),
		subscriptionsDir: filepath.Join(dir, "subscriptions"), webDir: filepath.Join(dir, "web"),
		logger: slog.New(slog.NewJSONHandler(io.Discard, nil)), auth: auth,
		allowedHosts:   map[string]struct{}{"127.0.0.1:18080": {}},
		frameAncestors: []string{"'self'"},
	}
}

func TestAPIRequiresAuthenticationAndKeepsControllerSecretPrivate(t *testing.T) {
	dir := t.TempDir()
	api := testAPI(dir)
	secret := api.manager.secret
	for _, path := range []string{"/api/mihomo/status", "/api/mihomo/config", "/api/remote-access", "/api/events", "/api/support", "/api/backup/export", "/api/backup/preview", "/api/backup/apply", "/api/auth/status", "/api/health"} {
		recorder := httptest.NewRecorder()
		request := apiRequest(http.MethodGet, path, "", "http://127.0.0.1:18080")
		api.Handler().ServeHTTP(recorder, request)
		if path == "/api/mihomo/status" || path == "/api/mihomo/config" || path == "/api/remote-access" {
			if recorder.Code != http.StatusUnauthorized {
				t.Errorf("%s returned %d, want 401", path, recorder.Code)
			}
		}
		if strings.Contains(recorder.Body.String(), secret) {
			t.Fatalf("secret leaked from %s: %s", path, recorder.Body.String())
		}
	}
}

func TestModeEndpointRejectsUnknownValuesAfterAuthentication(t *testing.T) {
	dir := t.TempDir()
	api := testAPI(dir)
	token := "unit-test-session"
	api.auth.sessions[sessionDigest(token)] = time.Now().Add(sessionLifetime)
	recorder := httptest.NewRecorder()
	request := apiRequest(http.MethodPost, "/api/mihomo/mode", `{"mode":"shell"}`, "http://127.0.0.1:18080")
	request.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	api.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("got status %d, want 400", recorder.Code)
	}
}

func TestConfigReportsSavedTunState(t *testing.T) {
	api := testAPI(t.TempDir())
	if err := api.manager.SetTunSettings(true, "system"); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	api.config(recorder, httptest.NewRequest(http.MethodGet, "/api/mihomo/config", nil))
	if !strings.Contains(recorder.Body.String(), `"tun_enabled":true`) {
		t.Fatalf("saved TUN state missing from config response: %s", recorder.Body.String())
	}
}

func TestValidUpdateHours(t *testing.T) {
	for _, hours := range []int{0, 1, 6, 12, 24, 720} {
		if !validUpdateHours(hours) {
			t.Errorf("validUpdateHours(%d) = false", hours)
		}
	}
	for _, hours := range []int{-1, 721} {
		if validUpdateHours(hours) {
			t.Errorf("validUpdateHours(%d) = true", hours)
		}
	}
}

func apiRequest(method, path, body, origin string) *http.Request {
	request := httptest.NewRequest(method, "http://127.0.0.1:18080"+path, strings.NewReader(body))
	if origin != "" {
		request.Header.Set("Origin", origin)
	}
	return request
}
