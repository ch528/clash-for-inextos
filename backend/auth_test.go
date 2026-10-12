package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSetupLoginAndAccount(t *testing.T) {
	dir := t.TempDir()
	api := testAPI(dir)
	if err := os.MkdirAll(api.stateDir, 0700); err != nil {
		t.Fatal(err)
	}
	handler := handlerForScope("loopback", api.Handler())
	setup := apiRequest(http.MethodPost, "/api/auth/setup", `{"username":"Admin","password":"eightword"}`, "http://127.0.0.1:18080")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, setup)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("setup: %d %s", recorder.Code, recorder.Body.String())
	}
	credential, err := api.auth.credential()
	if err != nil {
		t.Fatal(err)
	}
	credentialJSON, marshalErr := json.Marshal(credential)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	if credential.Username != "Admin" || credential.Scheme != "argon2id" || strings.Contains(string(credentialJSON), "eightword") {
		t.Fatal("credential not stored securely")
	}
	for _, username := range []string{"wrong", "ADMIN"} {
		body := `{"username":"` + username + `","password":"eightword"}`
		req := apiRequest(http.MethodPost, "/api/auth/login", body, "http://127.0.0.1:18080")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		expected := http.StatusUnauthorized
		if username == "ADMIN" {
			expected = http.StatusOK
		}
		if rec.Code != expected {
			t.Fatalf("login %q: %d %s", username, rec.Code, rec.Body.String())
		}
	}
	again := apiRequest(http.MethodPost, "/api/auth/setup", `{"username":"other","password":"eightword"}`, "http://127.0.0.1:18080")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, again)
	if rec.Code != http.StatusConflict {
		t.Fatalf("second setup: %d", rec.Code)
	}
	if err := api.auth.resetPassword("newpassword"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := api.auth.login("127.0.0.1", "admin", "newpassword"); err != nil {
		t.Fatal(err)
	}
}

func TestStateChangingRequestsRequireMatchingOrigin(t *testing.T) {
	dir := t.TempDir()
	api := testAPI(dir)
	token := "valid-session"
	api.auth.sessions[sessionDigest(token)] = time.Now().Add(sessionLifetime)
	handler := api.Handler()
	for _, origin := range []string{"", "http://evil.example", "https://127.0.0.1:18080"} {
		request := apiRequest(http.MethodPost, "/api/mihomo/stop", "", origin)
		request.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
		result := httptest.NewRecorder()
		handler.ServeHTTP(result, request)
		if result.Code != http.StatusForbidden {
			t.Errorf("origin %q returned %d, want 403", origin, result.Code)
		}
	}
}

func TestPublicSetupRequiresWindowAndTrustedListener(t *testing.T) {
	dir := t.TempDir()
	api := testAPI(dir)
	if err := os.MkdirAll(api.stateDir, 0700); err != nil {
		t.Fatal(err)
	}
	body := `{"username":"admin","password":"eightword"}`
	req := apiRequest(http.MethodPost, "/api/auth/setup", body, "https://public.example:8844")
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "public.example:8844")
	blocked := httptest.NewRecorder()
	trustedHandler := handlerForScope("loopback", api.Handler())
	trustedHandler.ServeHTTP(blocked, req)
	if blocked.Code != http.StatusForbidden {
		t.Fatalf("public setup without window: %d", blocked.Code)
	}
	if _, err := api.auth.setupOpen(); err != nil {
		t.Fatal(err)
	}
	req = apiRequest(http.MethodPost, "/api/auth/setup", body, "https://public.example:8844")
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "public.example:8844")
	req.Header.Set("X-Forwarded-For", "198.51.100.9")
	allowed := httptest.NewRecorder()
	trustedHandler.ServeHTTP(allowed, req)
	if allowed.Code != http.StatusCreated {
		t.Fatalf("public setup: %d %s", allowed.Code, allowed.Body.String())
	}
	if api.auth.publicSetupAllowed() {
		t.Fatal("window remained open")
	}
	if _, err := api.auth.setupOpen(); err == nil {
		t.Fatal("setup-open succeeded after admin creation")
	}
	spoof := apiRequest(http.MethodPost, "/api/auth/setup", body, "https://public.example:8844")
	spoof.RemoteAddr = "192.168.100.24:40000"
	spoof.Header.Set("X-Forwarded-Proto", "https")
	spoof.Header.Set("X-Forwarded-Host", "public.example:8844")
	rec := httptest.NewRecorder()
	handlerForScope("lan", api.Handler()).ServeHTTP(rec, spoof)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("spoofed forwarded headers from LAN returned %d", rec.Code)
	}
}

func TestLegacyPasswordHashGetsDefaultUsername(t *testing.T) {
	dir := t.TempDir()
	password := "legacy password"
	credential, err := hashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	originalHash := credential.Hash
	b, err := json.Marshal(credential)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, adminFile), b, 0600); err != nil {
		t.Fatal(err)
	}
	auth := newAuthManager(dir)
	if _, _, err := auth.login("127.0.0.1", "ADMIN", password); err != nil {
		t.Fatal(err)
	}
	migrated, err := auth.credential()
	if err != nil {
		t.Fatal(err)
	}
	if migrated.Username != "admin" || migrated.Hash != originalHash {
		t.Fatal("legacy hash or generated username migration failed")
	}
}

func TestLoginRateLimitStartsAfterFiveFailures(t *testing.T) {
	auth := newAuthManager(t.TempDir())
	now := time.Now()
	for range 5 {
		auth.failedLogin("192.0.2.1", now)
	}
	if wait := auth.loginWait("192.0.2.1", now); wait <= 0 {
		t.Fatal("expected a cooldown after five failed attempts")
	}
	if wait := auth.loginWait("192.0.2.1", now.Add(5*time.Minute+time.Second)); wait != 0 {
		t.Fatalf("cooldown persisted past expiry: %s", wait)
	}
	if wait := auth.loginWait("192.0.2.2", now); wait != 0 {
		t.Fatalf("cooldown leaked to another client: %s", wait)
	}
}

func TestExpiredSessionIsRejectedAndRemoved(t *testing.T) {
	auth := newAuthManager(t.TempDir())
	token := "expired-session"
	key := sessionDigest(token)
	auth.sessions[key] = time.Now().Add(-time.Second)
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:18080/api/auth/me", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	if auth.authenticated(request) {
		t.Fatal("expired session was accepted")
	}
	if _, ok := auth.sessions[key]; ok {
		t.Fatal("expired session was not removed")
	}
}
