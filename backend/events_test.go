package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSystemEventsAreBoundedNewestFirstAndPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.json")
	base := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
	for i := 0; i < maxSystemEvents+5; i++ {
		if err := recordSystemEvent(path, "mihomo_started", base.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	events, err := readSystemEvents(path, maxSystemEvents)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != maxSystemEvents {
		t.Fatalf("stored %d events, want %d", len(events), maxSystemEvents)
	}
	if !events[0].Time.Equal(base.Add(time.Duration(maxSystemEvents+4)*time.Minute)) || !events[len(events)-1].Time.Equal(base.Add(5*time.Minute)) {
		t.Fatalf("events not returned newest-first within retention: first=%s last=%s", events[0].Time, events[len(events)-1].Time)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0660 {
		t.Fatalf("event file mode is %o, want 660 for the shared application group", info.Mode().Perm())
	}
	lockInfo, err := os.Stat(path + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	if lockInfo.Mode().Perm() != 0660 {
		t.Fatalf("event lock mode is %o, want 660 for the shared application group", lockInfo.Mode().Perm())
	}
	if err := recordSystemEvent(path, "mihomo_started\npassword=secret", base); err == nil {
		t.Fatal("unknown event type accepted caller-controlled message content")
	}
}

func TestSystemEventsDeduplicateRepeatedSecurityAlerts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.json")
	now := time.Now().UTC()
	for _, at := range []time.Time{now, now.Add(time.Second), now.Add(3 * time.Minute)} {
		if err := recordSystemEvent(path, "login_security", at); err != nil {
			t.Fatal(err)
		}
	}
	events, err := readSystemEvents(path, maxSystemEvents)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("got %d security events, want 2 after the cooldown", len(events))
	}
}

func TestSystemEventsEndpointRequiresAuthentication(t *testing.T) {
	api := testAPI(t.TempDir())
	if err := recordSystemEvent(systemEventsPath(api.stateDir), "mihomo_started", time.Now()); err != nil {
		t.Fatal(err)
	}
	request := apiRequest(http.MethodGet, "/api/events", "", "http://127.0.0.1:18080")
	response := httptest.NewRecorder()
	api.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated events returned %d, want 401", response.Code)
	}

	token := "events-test-session"
	api.auth.sessions[sessionDigest(token)] = time.Now().Add(sessionLifetime)
	request = apiRequest(http.MethodGet, "/api/events?limit=25", "", "http://127.0.0.1:18080")
	request.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	response = httptest.NewRecorder()
	api.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("authenticated events returned %d: %s", response.Code, response.Body.String())
	}
	var payload struct {
		Events []systemEvent `json:"events"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Events) != 1 || payload.Events[0].Message != "Mihomo 已启动" {
		t.Fatalf("unexpected event payload: %#v", payload.Events)
	}

	request = apiRequest(http.MethodGet, "/api/events?limit=7", "", "http://127.0.0.1:18080")
	request.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	response = httptest.NewRecorder()
	api.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("invalid event limit returned %d, want 400", response.Code)
	}
}
