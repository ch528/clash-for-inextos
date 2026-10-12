package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"log/slog"
)

func publicSetupRequest() *http.Request {
	r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:18080/api/auth/setup", strings.NewReader(`{"username":"user.admin","password":"private-password"}`))
	r.Host = "127.0.0.1:18080"
	r.RemoteAddr = "127.0.0.1:43128"
	r.Header.Set("Origin", "https://router.example")
	r.Header.Set("X-Forwarded-Host", "router.example")
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-For", "198.51.100.12")
	return r
}

func TestPublicSetupRequiresWindowAndClosesItAfterCreation(t *testing.T) {
	stateDir := t.TempDir()
	var events bytes.Buffer
	a := &API{
		auth:         newAuthManager(stateDir),
		allowedHosts: map[string]struct{}{"127.0.0.1:18080": {}},
		logger:       slog.New(slog.NewJSONHandler(&events, nil)),
	}
	request := publicSetupRequest()
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, request)
	if w.Code != http.StatusForbidden {
		t.Fatalf("public setup without window returned %d", w.Code)
	}
	if _, err := os.Stat(filepath.Join(stateDir, adminFile)); !os.IsNotExist(err) {
		t.Fatal("public setup without window created an administrator")
	}
	if _, err := a.auth.setupOpen(); err != nil {
		t.Fatal(err)
	}
	request = publicSetupRequest()
	w = httptest.NewRecorder()
	a.Handler().ServeHTTP(w, request)
	if w.Code != http.StatusCreated {
		t.Fatalf("authorized setup returned %d: %s", w.Code, w.Body.String())
	}
	if _, err := os.Stat(filepath.Join(stateDir, "setup-open")); !os.IsNotExist(err) {
		t.Fatal("successful setup did not close the public setup window")
	}
	if strings.Contains(events.String(), "private-password") {
		t.Fatal("setup event log contains the submitted password")
	}
	var event map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(events.Bytes()), &event); err != nil {
		t.Fatal(err)
	}
	if event["msg"] != "administrator created" || event["username"] != "user.admin" || event["access_scope"] != "public_https" || event["source_ip"] != "198.51.100.12" {
		t.Fatalf("administrator event has unexpected safe fields: %#v", event)
	}
	request = httptest.NewRequest(http.MethodGet, "http://127.0.0.1:18080/api/auth/status", nil)
	request.Host = "127.0.0.1:18080"
	w = httptest.NewRecorder()
	a.Handler().ServeHTTP(w, request)
	var status map[string]bool
	if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if !status["initialized"] || status["setup_allowed"] {
		t.Fatalf("initialized account has incorrect setup status: %#v", status)
	}
	request = publicSetupRequest()
	w = httptest.NewRecorder()
	a.Handler().ServeHTTP(w, request)
	if w.Code != http.StatusConflict {
		t.Fatalf("second administrator setup returned %d", w.Code)
	}
}

func TestLANSetupUsesListenerScopeAndIgnoresForwardedAddress(t *testing.T) {
	stateDir := t.TempDir()
	var events bytes.Buffer
	a := &API{
		auth:         newAuthManager(stateDir),
		allowedHosts: map[string]struct{}{"192.168.100.1:18080": {}},
		logger:       slog.New(slog.NewJSONHandler(&events, nil)),
	}
	r := httptest.NewRequest(http.MethodPost, "http://192.168.100.1:18080/api/auth/setup", strings.NewReader(`{"username":"lan.admin","password":"private-password"}`))
	r.Host = "192.168.100.1:18080"
	r.RemoteAddr = "192.168.100.45:43128"
	r.Header.Set("Origin", "http://192.168.100.1:18080")
	r.Header.Set("X-Forwarded-For", "203.0.113.99")
	w := httptest.NewRecorder()
	handlerForScope("lan", a.Handler()).ServeHTTP(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("LAN setup returned %d: %s", w.Code, w.Body.String())
	}
	var event map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(events.Bytes()), &event); err != nil {
		t.Fatal(err)
	}
	if event["access_scope"] != "lan" || event["source_ip"] != "192.168.100.45" {
		t.Fatalf("LAN setup trusted client forwarded headers: %#v", event)
	}
}
