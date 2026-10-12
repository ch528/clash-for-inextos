package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSupportBundleRequiresAuthenticationAndOmitsSensitiveFields(t *testing.T) {
	api := testAPI(t.TempDir())
	if err := os.MkdirAll(api.stateDir, 0700); err != nil {
		t.Fatal(err)
	}
	logData := strings.Join([]string{
		`{"time":"2026-10-11T00:00:00Z","level":"INFO","msg":"mihomo started","username":"hao","source_ip":"192.0.2.1","controller_secret":"controller-secret","subscription_url":"https://sub.example/path?token=secret-token"}`,
		`{"time":"2026-10-11T00:00:01Z","level":"ERROR","msg":"password=private-password","password_hash":"private-hash","session_cookie":"private-cookie","tls_key":"private-key"}`,
		`{"time":"2026-10-11T00:00:02Z","level":"WARN","msg":"automatic subscription update failed","reason":"https://sub.example/path?token=secret-token"}`,
	}, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(api.stateDir, "backend.log"), []byte(logData), 0600); err != nil {
		t.Fatal(err)
	}
	if err := recordSystemEvent(systemEventsPath(api.stateDir), "subscription_failed", time.Now()); err != nil {
		t.Fatal(err)
	}

	request := apiRequest(http.MethodGet, "/api/support", "", "http://127.0.0.1:18080")
	response := httptest.NewRecorder()
	api.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated support bundle returned %d, want 401", response.Code)
	}

	token := "support-test-session"
	api.auth.sessions[sessionDigest(token)] = time.Now().Add(sessionLifetime)
	request = apiRequest(http.MethodGet, "/api/support", "", "http://127.0.0.1:18080")
	request.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	response = httptest.NewRecorder()
	api.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "application/zip" {
		t.Fatalf("support bundle returned %d (%s): %s", response.Code, response.Header().Get("Content-Type"), response.Body.String())
	}

	archive, err := zip.NewReader(bytes.NewReader(response.Body.Bytes()), int64(response.Body.Len()))
	if err != nil {
		t.Fatal(err)
	}
	files := make(map[string]string)
	for _, file := range archive.File {
		if file.Mode().Perm() != 0600 {
			t.Errorf("%s mode is %o, want 600", file.Name, file.Mode().Perm())
		}
		entry, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, readErr := io.ReadAll(entry)
		_ = entry.Close()
		if readErr != nil {
			t.Fatal(readErr)
		}
		files[file.Name] = string(data)
	}
	for _, name := range []string{"report.json", "events.json", "backend-log.json"} {
		if _, ok := files[name]; !ok {
			t.Errorf("support bundle is missing %s", name)
		}
	}
	contents := strings.Join([]string{files["report.json"], files["events.json"], files["backend-log.json"]}, "\n")
	for _, secret := range []string{"controller-secret", "secret-token", "sub.example", "private-password", "private-hash", "private-cookie", "private-key", "192.0.2.1", `"username"`, `"reason"`} {
		if strings.Contains(contents, secret) {
			t.Errorf("support bundle leaked %q", secret)
		}
	}
	var logs []supportLogEntry
	if err := json.Unmarshal([]byte(files["backend-log.json"]), &logs); err != nil {
		t.Fatal(err)
	}
	if len(logs) != 2 || logs[0].Message != "mihomo started" || logs[1].Message != "automatic subscription update failed" {
		t.Fatalf("unexpected sanitized backend logs: %#v", logs)
	}
}
