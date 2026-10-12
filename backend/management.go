package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func (a *API) closeAllConnections(w http.ResponseWriter, r *http.Request) {
	if _, err := a.manager.controller(r.Context(), http.MethodDelete, "/connections", nil); err != nil {
		writeError(w, http.StatusServiceUnavailable, "Mihomo could not close connections")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"closed": true})
}

func (a *API) closeConnection(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/mihomo/connections/")
	if id == "" || strings.Contains(id, "/") || len(id) > 128 {
		writeError(w, http.StatusBadRequest, "invalid connection id")
		return
	}
	if _, err := a.manager.controller(r.Context(), http.MethodDelete, "/connections/"+url.PathEscape(id), nil); err != nil {
		writeError(w, http.StatusServiceUnavailable, "Mihomo could not close connection")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"closed": true})
}

func (a *API) delayProxy(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/api/mihomo/delay/")
	if name == "" || strings.Contains(name, "/") {
		writeError(w, http.StatusBadRequest, "invalid proxy name")
		return
	}
	name, err := url.PathUnescape(name)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid proxy name")
		return
	}
	// A semaphore also protects the Controller when several browsers test nodes at once.
	select {
	case delaySlots <- struct{}{}:
		defer func() { <-delaySlots }()
	case <-r.Context().Done():
		return
	}
	path := "/proxies/" + url.PathEscape(name) + "/delay?timeout=5000&url=" + url.QueryEscape("https://www.gstatic.com/generate_204")
	body, err := a.manager.controller(r.Context(), http.MethodGet, path, nil)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "delay test failed")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

var delaySlots = make(chan struct{}, 5)

func (a *API) diagnostics(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.diagnosticsInfo(r.Context()))
}

func (a *API) diagnosticsInfo(ctx context.Context) map[string]any {
	status := a.manager.Status(ctx)
	port := func(host string, number int) bool {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprint(number)), 300*time.Millisecond)
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	}
	items, _ := a.loadSubscriptions()
	configInfo, configErr := os.Stat(a.manager.configFile)
	readySubscriptions := 0
	for _, item := range items {
		if item.Status == "ready" {
			readySubscriptions++
		}
	}
	remote := inspectRemoteAccess()
	tunEnabled, tunStack, desiredRunning, confirmed := a.manager.TunSettings()
	networkState := a.manager.RuntimeConfig()
	helperCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	helper, helperErr := callPrivilegedHelper(helperCtx, "tun-status")
	cancel()
	_, dashboardErr := os.Stat(filepath.Join(a.activeDashboardDirectory(), "index.html"))
	return map[string]any{
		"backend":                     true,
		"mihomo_process":              status.ProcessAlive,
		"mihomo_version":              status.Version,
		"controller_api":              status.ControllerAvailable,
		"zashboard_available":         dashboardErr == nil,
		"zashboard_version":           a.installedDashboardVersion(),
		"backend_port":                port("127.0.0.1", a.state.BackendPort),
		"mixed_port":                  port("127.0.0.1", a.state.MixedPort),
		"controller_port":             port("127.0.0.1", a.state.ControllerPort),
		"config_present":              configErr == nil && configInfo.Size() > 0,
		"subscriptions":               len(items),
		"subscriptions_ready":         readySubscriptions,
		"https_certificate_status":    remote.CertificateStatus,
		"https_certificate_san_match": remote.CertificateSANMatch,
		"tun_enabled":                 tunEnabled,
		"tun_stack":                   tunStack,
		"tun_desired_running":         desiredRunning,
		"tun_test_confirmed":          confirmed,
		"network_capture_active":      networkCaptureActive(networkState),
		"tun_helper_available":        helperErr == nil,
		"tun_supported":               helperErr == nil && helper.Supported,
		"dns_state":                   map[bool]string{true: "enabled", false: "disabled"}[networkState.DNS.Enabled],
		"transparent_proxy_state":     map[bool]string{true: "enabled", false: "disabled"}[networkState.LANProxy.Enabled],
	}
}

type supportLogEntry struct {
	Time    string `json:"time"`
	Level   string `json:"level"`
	Message string `json:"message"`
}

var supportLogMessages = map[string]struct{}{
	"desired Mihomo startup failed": {}, "LAN listener failed": {}, "backend listening": {},
	"backend stopped": {}, "service settings updated": {}, "mihomo start failed": {},
	"mihomo started": {}, "mihomo stopped": {}, "mihomo restart failed": {},
	"mihomo restarted": {}, "mihomo mode changed": {}, "subscription saved": {},
	"dashboard Controller request failed": {}, "automatic subscription update failed": {},
	"Mihomo restart after failure failed": {}, "Mihomo restarted after failure": {},
	"administrator created": {}, "system event could not be stored": {},
}

func sanitizedBackendLogs(path string) ([]supportLogEntry, error) {
	lines, err := readBoundedLines(path, 200)
	if os.IsNotExist(err) {
		return []supportLogEntry{}, nil
	}
	if err != nil {
		return nil, err
	}
	entries := make([]supportLogEntry, 0, len(lines))
	for _, line := range lines {
		var fields map[string]json.RawMessage
		if json.Unmarshal([]byte(line), &fields) != nil {
			continue
		}
		var entry supportLogEntry
		if json.Unmarshal(fields["time"], &entry.Time) != nil || json.Unmarshal(fields["level"], &entry.Level) != nil || json.Unmarshal(fields["msg"], &entry.Message) != nil {
			continue
		}
		if _, ok := supportLogMessages[entry.Message]; !ok || (entry.Level != "INFO" && entry.Level != "WARN" && entry.Level != "ERROR") {
			continue
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func (a *API) supportBundle(w http.ResponseWriter, r *http.Request) {
	events, err := readSystemEvents(systemEventsPath(a.stateDir), maxSystemEvents)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read system events")
		return
	}
	logs, err := sanitizedBackendLogs(filepath.Join(a.stateDir, "backend.log"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read selected application logs")
		return
	}
	report := map[string]any{
		"generated_at": time.Now().UTC(),
		"system":       a.systemInfo(),
		"diagnostics":  a.diagnosticsInfo(r.Context()),
		"privacy":      "No credentials, subscription records, Mihomo configuration, private keys, or log attributes are included.",
	}
	var output bytes.Buffer
	archive := zip.NewWriter(&output)
	for name, value := range map[string]any{"report.json": report, "events.json": events, "backend-log.json": logs} {
		data, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			_ = archive.Close()
			writeError(w, http.StatusInternalServerError, "could not build support report")
			return
		}
		header := &zip.FileHeader{Name: name, Method: zip.Deflate}
		header.SetMode(0600)
		entry, err := archive.CreateHeader(header)
		if err != nil {
			_ = archive.Close()
			writeError(w, http.StatusInternalServerError, "could not build support report")
			return
		}
		if _, err := entry.Write(data); err != nil {
			_ = archive.Close()
			writeError(w, http.StatusInternalServerError, "could not build support report")
			return
		}
	}
	if err := archive.Close(); err != nil {
		writeError(w, http.StatusInternalServerError, "could not finish support report")
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="clash-for-inextos-support.zip"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(output.Bytes())
}

func (a *API) editSubscription(w http.ResponseWriter, r *http.Request) {
	a.subOp.Lock()
	defer a.subOp.Unlock()
	id := strings.TrimPrefix(r.URL.Path, "/api/subscriptions/")
	if !subscriptionID.MatchString(id) {
		writeError(w, http.StatusBadRequest, "invalid subscription id")
		return
	}
	var input struct {
		Name            string `json:"name"`
		Enabled         bool   `json:"enabled"`
		AutoUpdateHours int    `json:"auto_update_hours"`
	}
	if err := decodeJSON(w, r, &input, 4<<10); err != nil || strings.TrimSpace(input.Name) == "" || len(input.Name) > 80 || !validUpdateHours(input.AutoUpdateHours) {
		writeError(w, http.StatusBadRequest, "invalid subscription settings")
		return
	}
	items, err := a.loadSubscriptions()
	if err != nil {
		writeError(w, 500, "could not read subscriptions")
		return
	}
	for i := range items {
		if items[i].ID == id {
			scheduleChanged := items[i].Enabled != input.Enabled || items[i].AutoUpdateHours != input.AutoUpdateHours
			if items[i].Current && !input.Enabled {
				if err := a.activateConfig(r.Context(), []byte(minimalConfig(a.manager.RuntimeConfig(), a.manager.secret))); err != nil {
					writeError(w, 502, err.Error())
					return
				}
				items[i].Current = false
			}
			items[i].Name = strings.TrimSpace(input.Name)
			items[i].Enabled = input.Enabled
			items[i].AutoUpdateHours = input.AutoUpdateHours
			if scheduleChanged {
				if items[i].Enabled && items[i].AutoUpdateHours > 0 {
					items[i].NextUpdate = nil
					if !items[i].LastUpdated.IsZero() {
						next := items[i].LastUpdated.Add(time.Duration(items[i].AutoUpdateHours) * time.Hour).UTC()
						items[i].NextUpdate = &next
					}
				} else {
					items[i].NextUpdate = nil
				}
			}
			if err := a.saveSubscriptions(items); err != nil {
				writeError(w, 500, "could not save subscription")
				return
			}
			writeJSON(w, 200, viewSubscription(items[i]))
			return
		}
	}
	writeError(w, 404, "subscription not found")
}

func validUpdateHours(hours int) bool { return hours == 0 || (hours >= 1 && hours <= 720) }

func (a *API) mihomoLogs(w http.ResponseWriter, r *http.Request) {
	lines, err := readBoundedLines(filepath.Join(a.stateDir, "mihomo.log"), 1000)
	if err != nil && !os.IsNotExist(err) {
		writeError(w, 500, "could not read Mihomo logs")
		return
	}
	if lines == nil {
		lines = []string{}
	}
	writeJSON(w, 200, map[string]any{"lines": lines})
}
