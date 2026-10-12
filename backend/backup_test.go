package main

import (
	"encoding/json"
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

func TestPortableBackupPreviewAndApply(t *testing.T) {
	dir := t.TempDir()
	api := testAPI(dir)
	api.manager.configFile = filepath.Join(dir, "mihomo.yaml")
	api.manager.runtimeDir = dir
	api.manager.stateDir = api.stateDir
	fakeMihomo := filepath.Join(dir, "mihomo")
	if err := os.WriteFile(fakeMihomo, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	api.manager.bin = fakeMihomo
	if err := os.WriteFile(api.manager.configFile, []byte("previous config\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(api.subscriptionsDir, 0700); err != nil {
		t.Fatal(err)
	}
	old := subscriptionRecord{ID: "aaaaaaaaaaaaaaaa", Name: "Old", URL: "https://old.example/sub", Enabled: true}
	if err := api.saveSubscriptions([]subscriptionRecord{old}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(api.subscriptionsDir, old.ID+".yaml"), []byte("old profile"), 0600); err != nil {
		t.Fatal(err)
	}

	mixedPort := firstAvailablePort(17890, 17920, 18080, func(port int) bool { return portAvailable(port, true) })
	controllerPort := firstAvailablePort(9091, 9120, 18080, func(port int) bool { return portAvailable(port, false) })
	if mixedPort == 0 || controllerPort == 0 {
		t.Skip("no free application test ports")
	}
	bundle := portableBackup{
		Format: portableBackupFormat, SchemaVersion: portableBackupVersion,
		CreatedAt: time.Now().UTC(), Application: "1.0.0",
		Runtime: portableRuntime{
			MixedPort: mixedPort, ControllerPort: controllerPort, Mode: "direct",
			AutoStart: true, RestartOnFailure: false, TunStack: "gvisor",
			TunIPv6:  true,
			LANProxy: LANProxySettings{Enabled: true, Mode: "selected", Clients: []LANClientPolicy{{Name: "TV", IP: "192.168.100.22", MAC: "02:00:00:00:00:22", Action: "proxy"}}},
			DNS:      DNSSettings{Enabled: true, IPv6: true, Mode: "custom", CustomNameservers: []string{"192.168.100.1"}},
		},
		Subscriptions: []portableSubscription{{
			ID: "0123456789abcdef", Name: "Restored", URL: "https://subscription.example/feed?token=private",
			Enabled: true, Current: true, AutoUpdateHours: 12,
			Config: "proxies:\n  - name: Example\n    type: socks5\n    server: proxy.example\n    port: 1080\nsecret: imported-controller-secret\ntun:\n  enable: true\n",
		}},
		Appearance: portableAppearance{Theme: "dark", Density: "compact"},
	}
	body, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	token := "backup-test-session"
	api.auth.sessions[sessionDigest(token)] = time.Now().Add(time.Hour)
	request := func(path string) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		req := apiRequest(http.MethodPost, path, string(body), "http://127.0.0.1:18080")
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
		api.Handler().ServeHTTP(recorder, req)
		return recorder
	}
	preview := request("/api/backup/preview")
	if preview.Code != http.StatusOK || !strings.Contains(preview.Body.String(), `"subscription_count":1`) || !strings.Contains(preview.Body.String(), `"tun_will_remain_disabled":true`) || !strings.Contains(preview.Body.String(), `"theme":"dark"`) {
		t.Fatalf("unexpected restore preview: status=%d body=%s", preview.Code, preview.Body.String())
	}
	if _, err := os.Stat(filepath.Join(api.subscriptionsDir, old.ID+".yaml")); err != nil {
		t.Fatalf("preview modified existing subscription: %v", err)
	}

	applied := request("/api/backup/apply")
	if applied.Code != http.StatusOK || !strings.Contains(applied.Body.String(), `"density":"compact"`) {
		t.Fatalf("restore apply failed: status=%d body=%s", applied.Code, applied.Body.String())
	}
	items, err := api.loadSubscriptions()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].ID != "0123456789abcdef" || !items[0].Current || items[0].NodeCount != 1 || items[0].AutoUpdateHours != 12 {
		t.Fatalf("restored subscription metadata is wrong: %#v", items)
	}
	profile, err := os.ReadFile(filepath.Join(api.subscriptionsDir, items[0].ID+".yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(profile), "imported-controller-secret") || strings.Contains(string(profile), "tun:") {
		t.Fatalf("portable subscription retained excluded settings: %s", profile)
	}
	config, err := os.ReadFile(api.manager.configFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(config), api.manager.secret) || !strings.Contains(string(config), "enable: false") || strings.Contains(string(config), "imported-controller-secret") {
		t.Fatalf("restore did not use the local secret and safe TUN state: %s", config)
	}
	state, err := loadRuntimeState(api.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if state.DesiredRunning || state.TunEnabled || state.LANProxy.Enabled || state.DNS.Enabled || state.TunTestConfirmed || state.Mode != "direct" || state.TunStack != "gvisor" || state.MixedPort != mixedPort || state.ControllerPort != controllerPort || !state.AutoStart || state.RestartOnFailure {
		t.Fatalf("runtime preferences were not safely restored: %#v", state)
	}
	if !state.TunIPv6 || state.LANProxy.Mode != "selected" || len(state.LANProxy.Clients) != 1 || state.DNS.Mode != "custom" || len(state.DNS.CustomNameservers) != 1 {
		t.Fatalf("network preferences were not restored safely: %#v", state)
	}
}

func TestPortableBackupRejectsUnknownSensitiveFields(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/api/backup/preview", strings.NewReader(`{"format":"clash-for-inextos","schema_version":1,"controller_secret":"should-not-restore"}`))
	var bundle portableBackup
	if err := decodeJSON(httptest.NewRecorder(), request, &bundle, maxPortableBackupSize); err == nil {
		t.Fatal("backup with an unknown controller_secret field was accepted")
	}
}

func TestPortableBackupExportOmitsControllerAndNetworkFields(t *testing.T) {
	dir := t.TempDir()
	api := testAPI(dir)
	if err := os.MkdirAll(api.subscriptionsDir, 0700); err != nil {
		t.Fatal(err)
	}
	item := subscriptionRecord{
		ID: "0123456789abcdef", Name: "Main", URL: "https://subscription.example/feed?token=private",
		Enabled: true, Status: "ready", Current: true, NodeCount: 1, AutoUpdateHours: 12,
	}
	if err := api.saveSubscriptions([]subscriptionRecord{item}); err != nil {
		t.Fatal(err)
	}
	profile := []byte("proxies:\n  - name: Example\n    type: socks5\n    server: proxy.example\n    port: 1080\nsecret: provider-secret\nexternal-controller: 0.0.0.0:9091\ntun:\n  enable: true\ndns:\n  enable: true\n")
	if err := os.WriteFile(filepath.Join(api.subscriptionsDir, item.ID+".yaml"), profile, 0600); err != nil {
		t.Fatal(err)
	}
	token := "backup-export-session"
	api.auth.sessions[sessionDigest(token)] = time.Now().Add(time.Hour)
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:18080/api/backup/export", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	recorder := httptest.NewRecorder()
	api.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("backup export failed: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	for _, forbidden := range []string{api.manager.secret, "provider-secret", "external-controller", "tun:", "dns:", "password_hash", "tls_private_key"} {
		if strings.Contains(recorder.Body.String(), forbidden) {
			t.Fatalf("portable backup included excluded field %q", forbidden)
		}
	}
	if !strings.Contains(recorder.Body.String(), "token=private") || !strings.Contains(recorder.Body.String(), "proxy.example") {
		t.Fatal("portable backup omitted requested subscription data")
	}
}

func TestPortableBackupExportRejectsMissingCurrentConfig(t *testing.T) {
	dir := t.TempDir()
	api := testAPI(dir)
	if err := os.MkdirAll(api.subscriptionsDir, 0700); err != nil {
		t.Fatal(err)
	}
	item := subscriptionRecord{
		ID: "0123456789abcdef", Name: "Main", URL: "https://subscription.example/feed",
		Enabled: true, Status: "ready", Current: true, NodeCount: 1, AutoUpdateHours: 12,
	}
	if err := api.saveSubscriptions([]subscriptionRecord{item}); err != nil {
		t.Fatal(err)
	}
	token := "backup-missing-config-session"
	api.auth.sessions[sessionDigest(token)] = time.Now().Add(time.Hour)
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:18080/api/backup/export", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	recorder := httptest.NewRecorder()
	api.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusInternalServerError || !strings.Contains(recorder.Body.String(), "missing saved config") {
		t.Fatalf("export should reject a current subscription without its cached config: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestPortableBackupApplyRollsBackWhenPortIsUnavailable(t *testing.T) {
	dir := t.TempDir()
	api := testAPI(dir)
	api.manager.configFile = filepath.Join(dir, "mihomo.yaml")
	api.manager.runtimeDir = dir
	api.manager.stateDir = api.stateDir
	fakeMihomo := filepath.Join(dir, "mihomo")
	if err := os.WriteFile(fakeMihomo, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	api.manager.bin = fakeMihomo
	oldConfig := []byte("last known config\n")
	if err := os.WriteFile(api.manager.configFile, oldConfig, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(api.subscriptionsDir, 0700); err != nil {
		t.Fatal(err)
	}
	old := subscriptionRecord{ID: "aaaaaaaaaaaaaaaa", Name: "Old", URL: "https://old.example/sub", Enabled: true}
	if err := api.saveSubscriptions([]subscriptionRecord{old}); err != nil {
		t.Fatal(err)
	}
	oldProfile := []byte("old subscription profile")
	if err := os.WriteFile(filepath.Join(api.subscriptionsDir, old.ID+".yaml"), oldProfile, 0600); err != nil {
		t.Fatal(err)
	}
	var blocker net.Listener
	blockedPort := 0
	for port := 17890; port <= 17920; port++ {
		listener, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err == nil {
			blocker = listener
			blockedPort = port
			break
		}
	}
	if blocker == nil {
		t.Skip("no test port is available to reserve")
	}
	defer blocker.Close()
	controllerPort := firstAvailablePort(9091, 9120, 18080, func(port int) bool { return portAvailable(port, false) })
	if controllerPort == 0 {
		t.Skip("no controller test port is available")
	}
	bundle := portableBackup{
		Format: portableBackupFormat, SchemaVersion: portableBackupVersion,
		Runtime:       portableRuntime{MixedPort: blockedPort, ControllerPort: controllerPort, Mode: "rule", TunStack: "system"},
		Subscriptions: []portableSubscription{},
	}
	body, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	token := "backup-rollback-session"
	api.auth.sessions[sessionDigest(token)] = time.Now().Add(time.Hour)
	request := apiRequest(http.MethodPost, "/api/backup/apply", string(body), "http://127.0.0.1:18080")
	request.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	recorder := httptest.NewRecorder()
	api.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("restore should fail on the occupied port: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	items, err := api.loadSubscriptions()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].ID != old.ID {
		t.Fatalf("subscription directory did not roll back: %#v", items)
	}
	profile, err := os.ReadFile(filepath.Join(api.subscriptionsDir, old.ID+".yaml"))
	if err != nil || string(profile) != string(oldProfile) {
		t.Fatalf("previous subscription file was not restored: %q, %v", profile, err)
	}
	config, err := os.ReadFile(api.manager.configFile)
	if err != nil || string(config) != string(oldConfig) {
		t.Fatalf("previous Mihomo config was changed: %q, %v", config, err)
	}
}
