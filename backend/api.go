package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type API struct {
	state               RuntimeState
	manager             *ProcessManager
	stateDir            string
	subscriptionsDir    string
	webDir              string
	dashboardDir        string
	dashboardUpdatesDir string
	logger              *slog.Logger
	auth                *authManager
	allowedHosts        map[string]struct{}
	frameAncestors      []string
	applicationVersion  string
	upstreamRevision    string
	mu                  sync.Mutex
	subOp               sync.Mutex
	mutationMu          sync.RWMutex
}

var errNetworkSettingsConflict = errors.New("请先关闭当前网络接管，再修改 TUN、LAN 代理或 DNS 设置")

func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, http.StatusOK, map[string]bool{"ok": true}) })
	mux.HandleFunc("GET /api/auth/status", a.authStatus)
	mux.HandleFunc("POST /api/auth/setup", a.authSetup)
	mux.HandleFunc("POST /api/auth/login", a.authLogin)
	mux.HandleFunc("GET /api/auth/me", a.authMe)
	mux.HandleFunc("POST /api/auth/account", a.authAccount)
	mux.HandleFunc("POST /api/auth/logout", a.authLogout)
	mux.HandleFunc("GET /api/system", a.system)
	mux.HandleFunc("GET /api/remote-access", a.remoteAccess)
	mux.HandleFunc("GET /api/updates/check", a.checkUpdates)
	mux.HandleFunc("GET /api/updates/app/status", a.applicationUpdateStatus)
	mux.HandleFunc("POST /api/updates/app", a.updateApplication)
	mux.HandleFunc("POST /api/updates/mihomo", a.updateMihomo)
	mux.HandleFunc("POST /api/updates/geo", a.updateGeoData)
	mux.HandleFunc("POST /api/updates/zashboard", a.updateZashboard)
	mux.HandleFunc("POST /api/updates/zashboard/rollback", a.rollbackZashboard)
	mux.HandleFunc("GET /api/settings/behavior", a.getBehaviorSettings)
	mux.HandleFunc("POST /api/settings/behavior", a.setBehaviorSettings)
	mux.HandleFunc("GET /api/backup/export", a.exportBackup)
	mux.HandleFunc("POST /api/backup/preview", a.previewBackup)
	mux.HandleFunc("POST /api/backup/apply", a.applyBackup)
	mux.HandleFunc("GET /api/mihomo/status", a.status)
	mux.HandleFunc("GET /api/mihomo/config", a.config)
	mux.HandleFunc("GET /api/network/status", a.networkStatus)
	mux.HandleFunc("POST /api/network/tun", a.setTun)
	mux.HandleFunc("POST /api/network/settings", a.setNetworkSettings)
	mux.HandleFunc("POST /api/network/confirm", a.confirmTun)
	mux.HandleFunc("POST /api/network/restore", a.restoreNetwork)
	mux.HandleFunc("POST /api/mihomo/start", a.start)
	mux.HandleFunc("POST /api/mihomo/stop", a.stop)
	mux.HandleFunc("POST /api/mihomo/restart", a.restart)
	mux.HandleFunc("GET /api/mihomo/traffic", a.traffic)
	mux.HandleFunc("GET /api/mihomo/connections", a.connections)
	mux.HandleFunc("DELETE /api/mihomo/connections", a.closeAllConnections)
	mux.HandleFunc("DELETE /api/mihomo/connections/", a.closeConnection)
	mux.HandleFunc("GET /api/mihomo/proxies", a.proxies)
	mux.HandleFunc("GET /api/mihomo/groups", a.groups)
	mux.HandleFunc("GET /api/mihomo/mode", a.getMode)
	mux.HandleFunc("POST /api/mihomo/mode", a.setMode)
	mux.HandleFunc("POST /api/mihomo/proxies/", a.selectProxy)
	mux.HandleFunc("GET /api/mihomo/delay/", a.delayProxy)
	mux.HandleFunc("GET /api/diagnostics", a.diagnostics)
	mux.HandleFunc("GET /api/support", a.supportBundle)
	mux.HandleFunc("GET /api/events", a.systemEvents)
	mux.HandleFunc("GET /api/logs", a.logs)
	mux.HandleFunc("GET /api/logs/mihomo", a.mihomoLogs)
	mux.HandleFunc("GET /api/subscriptions", a.subscriptions)
	mux.HandleFunc("POST /api/subscriptions", a.addSubscription)
	mux.HandleFunc("DELETE /api/subscriptions/", a.deleteSubscription)
	mux.HandleFunc("POST /api/subscriptions/", a.updateSubscription)
	mux.HandleFunc("PATCH /api/subscriptions/", a.editSubscription)
	mux.HandleFunc("/dashboard", a.dashboardRoot)
	mux.HandleFunc("/dashboard/", a.dashboard)
	mux.HandleFunc("/dashboard/api/", a.dashboardAPI)
	mux.HandleFunc("/", a.static)
	return a.securityMiddleware(a.serializeUpdateMutations(mux))
}

func (a *API) system(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.systemInfo())
}

func (a *API) systemInfo() map[string]string {
	version := "unknown"
	if b, err := os.ReadFile("/opt/roceos/version.json"); err == nil {
		var data map[string]any
		if json.Unmarshal(b, &data) == nil {
			if v, ok := data["version"].(string); ok {
				version = v
			}
		}
	}
	kernel, _ := os.ReadFile("/proc/sys/kernel/osrelease")
	debian, _ := os.ReadFile("/etc/debian_version")
	return map[string]string{
		"architecture":        "arm64",
		"device":              "FriendlyElec NanoPi R5S",
		"kernel":              strings.TrimSpace(string(kernel)),
		"inextos_version":     version,
		"debian_version":      strings.TrimSpace(string(debian)),
		"application_version": a.applicationVersion,
		"dashboard_version":   dashboardVersion,
		"build_date":          buildDate,
		"upstream_revision":   a.upstreamRevision,
	}
}

func (a *API) status(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.manager.Status(r.Context()))
}

func (a *API) getBehaviorSettings(w http.ResponseWriter, r *http.Request) {
	autoStart, restartOnFailure, _ := a.manager.StartupSettings()
	writeJSON(w, http.StatusOK, map[string]bool{
		"auto_start": autoStart, "restart_on_failure": restartOnFailure,
	})
}

func (a *API) setBehaviorSettings(w http.ResponseWriter, r *http.Request) {
	var input struct {
		AutoStart        bool `json:"auto_start"`
		RestartOnFailure bool `json:"restart_on_failure"`
	}
	if err := decodeJSON(w, r, &input, 1024); err != nil {
		writeError(w, http.StatusBadRequest, "invalid service settings")
		return
	}
	if err := a.manager.SetStartupSettings(input.AutoStart, input.RestartOnFailure); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save service settings")
		return
	}
	a.logger.Info("service settings updated", "auto_start", input.AutoStart, "restart_on_failure", input.RestartOnFailure)
	a.getBehaviorSettings(w, r)
}

func (a *API) networkStatus(w http.ResponseWriter, r *http.Request) {
	state := a.manager.RuntimeConfig()
	clientsCtx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	clients, clientsErr := readLANClients(clientsCtx)
	cancel()
	response, err := callPrivilegedHelper(r.Context(), "tun-status")
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"tun_enabled": state.TunEnabled, "capture_active": networkCaptureActive(state),
			"tun_stack": state.TunStack, "tun_ipv6": state.TunIPv6,
			"tun_auto_redirect": state.TunAutoRedirect, "desired_running": state.DesiredRunning,
			"tun_test_confirmed": state.TunTestConfirmed, "tun_supported": false,
			"helper_status": err.Error(), "tun_stacks": []string{},
			"lan_proxy": state.LANProxy, "dns": state.DNS,
			"lan_clients": clients, "lan_clients_error": safeClientDiscoveryError(clientsErr),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tun_enabled": state.TunEnabled, "capture_active": networkCaptureActive(state),
		"tun_stack": state.TunStack, "tun_ipv6": state.TunIPv6,
		"tun_auto_redirect": state.TunAutoRedirect, "desired_running": state.DesiredRunning,
		"tun_test_confirmed": response.TunTestConfirmed, "tun_supported": response.Supported,
		"helper_status": response.Status, "tun_stacks": response.Stacks,
		"lan_proxy": state.LANProxy, "dns": state.DNS,
		"lan_clients": clients, "lan_clients_error": safeClientDiscoveryError(clientsErr),
	})
}

func (a *API) setTun(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Enabled bool   `json:"enabled"`
		Stack   string `json:"stack"`
	}
	if err := decodeJSON(w, r, &input, 1024); err != nil {
		writeError(w, http.StatusBadRequest, "invalid TUN settings")
		return
	}
	if input.Stack == "" {
		input.Stack = "system"
	}
	if input.Stack != "system" && input.Stack != "gvisor" && input.Stack != "mixed" {
		writeError(w, http.StatusBadRequest, "TUN stack must be system, gvisor, or mixed")
		return
	}
	state := a.manager.RuntimeConfig()
	state.TunEnabled = input.Enabled
	state.TunStack = input.Stack
	if err := a.applyNetworkSettings(r.Context(), state); err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	a.networkStatus(w, r)
}

func (a *API) setNetworkSettings(w http.ResponseWriter, r *http.Request) {
	var input struct {
		TunEnabled      bool             `json:"tun_enabled"`
		TunStack        string           `json:"tun_stack"`
		TunIPv6         bool             `json:"tun_ipv6"`
		TunAutoRedirect bool             `json:"tun_auto_redirect"`
		LANProxy        LANProxySettings `json:"lan_proxy"`
		DNS             DNSSettings      `json:"dns"`
	}
	if err := decodeJSON(w, r, &input, 32<<10); err != nil {
		writeError(w, http.StatusBadRequest, "invalid network settings")
		return
	}
	if input.TunStack == "" {
		input.TunStack = "system"
	}
	state := a.manager.RuntimeConfig()
	state.TunEnabled = input.TunEnabled
	state.TunStack = input.TunStack
	state.TunIPv6 = input.TunIPv6
	state.TunAutoRedirect = input.TunAutoRedirect
	state.LANProxy = input.LANProxy
	state.DNS = input.DNS
	if err := normalizeNetworkSettings(&state); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if state.TunStack != "system" && state.TunStack != "gvisor" && state.TunStack != "mixed" {
		writeError(w, http.StatusBadRequest, "TUN stack must be system, gvisor, or mixed")
		return
	}
	if err := a.applyNetworkSettings(r.Context(), state); err != nil {
		status := http.StatusServiceUnavailable
		if errors.Is(err, errNetworkSettingsConflict) {
			status = http.StatusConflict
		}
		writeError(w, status, err.Error())
		return
	}
	a.networkStatus(w, r)
}

func (a *API) confirmTun(w http.ResponseWriter, r *http.Request) {
	if _, err := callPrivilegedHelper(r.Context(), "network-confirm"); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if err := a.manager.MarkTunTestConfirmed(); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	a.networkStatus(w, r)
}

func (a *API) restoreNetwork(w http.ResponseWriter, r *http.Request) {
	state := a.manager.RuntimeConfig()
	wasActive := networkCaptureActive(state)
	state.TunEnabled = false
	state.LANProxy.Enabled = false
	state.DNS.Enabled = false
	if err := a.applyNetworkSettings(r.Context(), state); err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	if wasActive {
		a.recordEvent("network_rollback")
	}
	a.networkStatus(w, r)
}

func (a *API) applyNetworkSettings(ctx context.Context, candidateState RuntimeState) (resultErr error) {
	a.subOp.Lock()
	defer a.subOp.Unlock()
	oldState := a.manager.RuntimeConfig()
	if err := normalizeNetworkSettings(&oldState); err != nil {
		return fmt.Errorf("saved network settings are invalid: %w", err)
	}
	candidateState.DesiredRunning = oldState.DesiredRunning
	if err := normalizeNetworkSettings(&candidateState); err != nil {
		return err
	}
	if candidateState.TunStack != "system" && candidateState.TunStack != "gvisor" && candidateState.TunStack != "mixed" {
		return errors.New("TUN stack must be system, gvisor, or mixed")
	}
	if sameNetworkSettings(oldState, candidateState) {
		return nil
	}
	oldActive := networkCaptureActive(oldState)
	newActive := networkCaptureActive(candidateState)
	if oldActive && newActive {
		return errNetworkSettingsConflict
	}
	shouldRun := oldState.DesiredRunning
	defer func() {
		if resultErr != nil {
			a.recordEvent("tun_failure")
		} else if !oldActive && newActive {
			a.recordEvent("network_capture_enabled")
		} else if oldActive && !newActive {
			a.recordEvent("network_capture_disabled")
		}
	}()
	oldConfig, err := os.ReadFile(a.manager.configFile)
	if err != nil {
		return err
	}
	candidateFile, err := os.CreateTemp(filepath.Dir(a.manager.configFile), ".network-candidate-*.yaml")
	if err != nil {
		return err
	}
	candidatePath := candidateFile.Name()
	_ = candidateFile.Close()
	defer os.Remove(candidatePath)
	if err := writeStartupConfig(candidatePath, a.subscriptionsDir, candidateState, a.manager.secret); err != nil {
		return err
	}
	candidate, err := os.ReadFile(candidatePath)
	if err != nil {
		return err
	}
	if err := a.testConfig(ctx, candidate); err != nil {
		return err
	}
	newActiveFromDisabled := !oldActive && newActive
	if newActiveFromDisabled {
		if _, err := callPrivilegedHelper(ctx, "network-prepare"); err != nil {
			return err
		}
	}
	wasRunning := a.manager.Status(ctx).ProcessAlive
	if oldActive || wasRunning {
		if err := a.manager.Stop(ctx); err != nil {
			if newActiveFromDisabled {
				_, _ = callPrivilegedHelper(context.Background(), "network-abort")
			}
			return err
		}
	}
	restore := func() {
		if newActive {
			_, _ = callPrivilegedHelper(context.Background(), "mihomo-stop")
		}
		_ = a.manager.SetNetworkSettings(oldState)
		_ = atomicWrite(a.manager.configFile, oldConfig, 0600)
		if shouldRun || wasRunning {
			rollbackCtx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			_ = a.manager.Start(rollbackCtx)
			cancel()
		}
		if newActiveFromDisabled {
			_, _ = callPrivilegedHelper(context.Background(), "network-abort")
		}
	}
	candidateState.TunTestConfirmed = false
	if err := a.manager.SetNetworkSettings(candidateState); err != nil {
		restore()
		return err
	}
	if err := atomicWrite(a.manager.configFile, candidate, 0600); err != nil {
		restore()
		return err
	}
	if shouldRun || wasRunning {
		startCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		err = a.manager.Start(startCtx)
		cancel()
		if err != nil {
			restore()
			return err
		}
	}
	if !newActive {
		_, _ = callPrivilegedHelper(context.Background(), "network-abort")
	}
	return nil
}

func (a *API) config(w http.ResponseWriter, r *http.Request) {
	mode := "rule"
	controllerOK := false
	tunEnabled, _, _, _ := a.manager.TunSettings()
	state := a.manager.RuntimeConfig()
	if body, err := a.manager.controller(r.Context(), http.MethodGet, "/configs", nil); err == nil {
		controllerOK = true
		var current map[string]any
		if json.Unmarshal(body, &current) == nil {
			if value, ok := current["mode"].(string); ok {
				mode = value
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"mode":              mode,
		"mixed_port":        a.state.MixedPort,
		"controller_port":   a.state.ControllerPort,
		"controller_status": controllerOK,
		"backend_port":      a.state.BackendPort,
		"allow_lan":         false,
		"tun_enabled":       tunEnabled,
		"capture_active":    networkCaptureActive(state),
		"lan_proxy_enabled": state.LANProxy.Enabled,
		"dns_enabled":       state.DNS.Enabled,
	})
}

func (a *API) start(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if err := a.manager.Start(ctx); err != nil {
		a.recordEvent("mihomo_start_failed")
		a.logger.Warn("mihomo start failed", "reason", err.Error())
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	a.logger.Info("mihomo started")
	a.recordEvent("mihomo_started")
	writeJSON(w, http.StatusOK, map[string]bool{"running": true})
}

func (a *API) stop(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 7*time.Second)
	defer cancel()
	if err := a.manager.Stop(ctx); err != nil {
		a.recordEvent("mihomo_stop_failed")
		writeError(w, http.StatusServiceUnavailable, "Mihomo did not stop cleanly")
		return
	}
	a.logger.Info("mihomo stopped")
	a.recordEvent("mihomo_stopped")
	writeJSON(w, http.StatusOK, map[string]bool{"running": false})
}

func (a *API) restart(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 18*time.Second)
	defer cancel()
	if err := a.manager.Restart(ctx); err != nil {
		a.recordEvent("mihomo_start_failed")
		a.logger.Warn("mihomo restart failed", "reason", err.Error())
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	a.logger.Info("mihomo restarted")
	a.recordEvent("mihomo_started")
	writeJSON(w, http.StatusOK, map[string]bool{"running": true})
}

func (a *API) controllerJSON(w http.ResponseWriter, r *http.Request, path string) {
	body, err := a.manager.controller(r.Context(), http.MethodGet, path, nil)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "Mihomo Controller is unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (a *API) connections(w http.ResponseWriter, r *http.Request) {
	a.controllerJSON(w, r, "/connections")
}

func (a *API) proxies(w http.ResponseWriter, r *http.Request) {
	a.controllerJSON(w, r, "/proxies")
}

func (a *API) traffic(w http.ResponseWriter, r *http.Request) {
	body, err := a.manager.controller(r.Context(), http.MethodGet, "/connections", nil)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "Mihomo Controller is unavailable")
		return
	}
	var data struct {
		UploadTotal   int64 `json:"uploadTotal"`
		DownloadTotal int64 `json:"downloadTotal"`
		Connections   []struct {
			Upload   int64 `json:"upload"`
			Download int64 `json:"download"`
		} `json:"connections"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		writeError(w, http.StatusBadGateway, "Mihomo returned an invalid connections response")
		return
	}
	var up, down int64
	for _, c := range data.Connections {
		up += c.Upload
		down += c.Download
	}
	writeJSON(w, http.StatusOK, map[string]any{"upload_bytes": up, "download_bytes": down, "total_upload_bytes": data.UploadTotal, "total_download_bytes": data.DownloadTotal, "active_connections": len(data.Connections)})
}

func (a *API) groups(w http.ResponseWriter, r *http.Request) {
	body, err := a.manager.controller(r.Context(), http.MethodGet, "/proxies", nil)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "Mihomo Controller is unavailable")
		return
	}
	var data struct {
		Proxies map[string]map[string]any `json:"proxies"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		writeError(w, http.StatusBadGateway, "Mihomo returned an invalid proxies response")
		return
	}
	result := make([]map[string]any, 0)
	for name, proxy := range data.Proxies {
		typeName, _ := proxy["type"].(string)
		if typeName != "Selector" && typeName != "URLTest" && typeName != "Fallback" && typeName != "LoadBalance" {
			continue
		}
		result = append(result, map[string]any{"name": name, "type": typeName, "now": proxy["now"], "all": proxy["all"], "history": proxy["history"]})
	}
	writeJSON(w, http.StatusOK, result)
}

func (a *API) getMode(w http.ResponseWriter, r *http.Request) {
	body, err := a.manager.controller(r.Context(), http.MethodGet, "/configs", nil)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "Mihomo Controller is unavailable")
		return
	}
	var data struct {
		Mode string `json:"mode"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		writeError(w, http.StatusBadGateway, "Mihomo returned an invalid mode response")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"mode": data.Mode})
}

func (a *API) setMode(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Mode string `json:"mode"`
	}
	if err := decodeJSON(w, r, &input, 1024); err != nil || !validMode(input.Mode) {
		writeError(w, http.StatusBadRequest, "mode must be rule, global, or direct")
		return
	}
	body := strings.NewReader(fmt.Sprintf(`{"mode":%q}`, input.Mode))
	if _, err := a.manager.controller(r.Context(), http.MethodPatch, "/configs", body); err != nil {
		writeError(w, http.StatusServiceUnavailable, "Mihomo Controller rejected the mode change")
		return
	}
	previous := a.state.Mode
	if err := a.manager.SetMode(input.Mode); err != nil {
		rollback := strings.NewReader(fmt.Sprintf(`{"mode":%q}`, previous))
		_, _ = a.manager.controller(context.Background(), http.MethodPatch, "/configs", rollback)
		writeError(w, http.StatusInternalServerError, "could not save Mihomo mode")
		return
	}
	a.state.Mode = input.Mode
	a.logger.Info("mihomo mode changed", "mode", input.Mode)
	writeJSON(w, http.StatusOK, map[string]string{"mode": input.Mode})
}

func validMode(mode string) bool { return mode == "rule" || mode == "global" || mode == "direct" }

func (a *API) selectProxy(w http.ResponseWriter, r *http.Request) {
	group := strings.TrimPrefix(r.URL.Path, "/api/mihomo/proxies/")
	if group == "" || strings.Contains(group, "/") {
		writeError(w, http.StatusBadRequest, "invalid proxy group")
		return
	}
	group, err := url.PathUnescape(group)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid proxy group")
		return
	}
	var input struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(w, r, &input, 2048); err != nil || input.Name == "" {
		writeError(w, http.StatusBadRequest, "proxy name is required")
		return
	}
	body, err := a.manager.controller(r.Context(), http.MethodGet, "/proxies", nil)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "Mihomo Controller is unavailable")
		return
	}
	var data struct {
		Proxies map[string]struct {
			Type string   `json:"type"`
			All  []string `json:"all"`
		} `json:"proxies"`
	}
	if json.Unmarshal(body, &data) != nil {
		writeError(w, http.StatusBadGateway, "Mihomo returned an invalid proxies response")
		return
	}
	available, ok := data.Proxies[group]
	if !ok || (available.Type != "Selector" && available.Type != "URLTest" && available.Type != "Fallback" && available.Type != "LoadBalance") {
		writeError(w, http.StatusBadRequest, "proxy group cannot be selected")
		return
	}
	allowed := false
	for _, candidate := range available.All {
		if candidate == input.Name {
			allowed = true
			break
		}
	}
	if !allowed {
		writeError(w, http.StatusBadRequest, "proxy is not a member of the selected group")
		return
	}
	path := "/proxies/" + url.PathEscape(group)
	if _, err := a.manager.controller(r.Context(), http.MethodPut, path, strings.NewReader(fmt.Sprintf(`{"name":%q}`, input.Name))); err != nil {
		writeError(w, http.StatusServiceUnavailable, "Mihomo Controller rejected the proxy selection")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"group": group, "now": input.Name})
}

func (a *API) logs(w http.ResponseWriter, r *http.Request) {
	n := 200
	if raw := r.URL.Query().Get("n"); raw != "" {
		var err error
		n, err = strconv.Atoi(raw)
		if err != nil || (n != 200 && n != 500 && n != 1000) {
			writeError(w, http.StatusBadRequest, "n must be 200, 500, or 1000")
			return
		}
	}
	lines, err := readBoundedLines(filepath.Join(a.stateDir, "backend.log"), n)
	if errors.Is(err, os.ErrNotExist) {
		lines = []string{}
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read backend logs")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"lines": lines})
}

type subscriptionRecord struct {
	ID              string             `json:"id"`
	Name            string             `json:"name"`
	URL             string             `json:"url"`
	Enabled         bool               `json:"enabled"`
	LastUpdated     time.Time          `json:"last_updated,omitempty"`
	NextUpdate      *time.Time         `json:"next_update,omitempty"`
	Status          string             `json:"status"`
	Current         bool               `json:"current"`
	NodeCount       int                `json:"node_count"`
	AutoUpdateHours int                `json:"auto_update_hours"`
	Usage           *subscriptionUsage `json:"usage,omitempty"`
}

type subscriptionView struct {
	ID              string                 `json:"id"`
	Name            string                 `json:"name"`
	URL             string                 `json:"url"`
	Enabled         bool                   `json:"enabled"`
	LastUpdated     time.Time              `json:"last_updated,omitempty"`
	NextUpdate      *time.Time             `json:"next_update,omitempty"`
	Status          string                 `json:"status"`
	Current         bool                   `json:"current"`
	NodeCount       int                    `json:"node_count"`
	AutoUpdateHours int                    `json:"auto_update_hours"`
	Usage           *subscriptionUsageView `json:"usage,omitempty"`
}

func viewSubscription(item subscriptionRecord) subscriptionView {
	return subscriptionView{ID: item.ID, Name: item.Name, URL: maskURL(item.URL), Enabled: item.Enabled, LastUpdated: item.LastUpdated, NextUpdate: subscriptionNextUpdate(item, time.Now().UTC()), Status: item.Status, Current: item.Current, NodeCount: item.NodeCount, AutoUpdateHours: item.AutoUpdateHours, Usage: viewSubscriptionUsage(item.Usage)}
}

func (a *API) subscriptions(w http.ResponseWriter, r *http.Request) {
	items, err := a.loadSubscriptions()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read subscriptions")
		return
	}
	views := make([]subscriptionView, 0, len(items))
	for _, item := range items {
		views = append(views, viewSubscription(item))
	}
	writeJSON(w, http.StatusOK, views)
}

func (a *API) addSubscription(w http.ResponseWriter, r *http.Request) {
	a.subOp.Lock()
	defer a.subOp.Unlock()
	var input struct {
		Name    string `json:"name"`
		URL     string `json:"url"`
		Enabled bool   `json:"enabled"`
	}
	if err := decodeJSON(w, r, &input, 16<<10); err != nil || strings.TrimSpace(input.Name) == "" || len(input.Name) > 80 {
		writeError(w, http.StatusBadRequest, "subscription name and URL are required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	if err := validateSubscriptionURL(ctx, input.URL, systemResolver{}); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	items, err := a.loadSubscriptions()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read subscriptions")
		return
	}
	rawID := make([]byte, 8)
	if _, err := rand.Read(rawID); err != nil {
		writeError(w, http.StatusInternalServerError, "could not create subscription id")
		return
	}
	item := subscriptionRecord{ID: hex.EncodeToString(rawID), Name: strings.TrimSpace(input.Name), URL: input.URL, Enabled: input.Enabled, Status: "saved; not imported"}
	items = append(items, item)
	if err := a.saveSubscriptions(items); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save subscription")
		return
	}
	a.logger.Info("subscription saved", "id", item.ID)
	writeJSON(w, http.StatusCreated, viewSubscription(item))
}

var subscriptionID = regexp.MustCompile(`^[a-f0-9]{16}$`)

func (a *API) deleteSubscription(w http.ResponseWriter, r *http.Request) {
	a.subOp.Lock()
	defer a.subOp.Unlock()
	id := strings.TrimPrefix(r.URL.Path, "/api/subscriptions/")
	if !subscriptionID.MatchString(id) || strings.Contains(id, "/") {
		writeError(w, http.StatusBadRequest, "invalid subscription id")
		return
	}
	items, err := a.loadSubscriptions()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read subscriptions")
		return
	}
	found := false
	kept := items[:0]
	for _, item := range items {
		if item.ID == id {
			found = true
			if item.Current {
				if err := a.activateConfig(r.Context(), []byte(minimalConfig(a.manager.RuntimeConfig(), a.manager.secret))); err != nil {
					writeError(w, 502, err.Error())
					return
				}
			}
			continue
		}
		kept = append(kept, item)
	}
	if !found {
		writeError(w, http.StatusNotFound, "subscription not found")
		return
	}
	if err := a.saveSubscriptions(kept); err != nil {
		writeError(w, http.StatusInternalServerError, "could not delete subscription")
		return
	}
	_ = os.Remove(filepath.Join(a.subscriptionsDir, id+".yaml"))
	writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}

func (a *API) updateSubscription(w http.ResponseWriter, r *http.Request) {
	tail := strings.TrimPrefix(r.URL.Path, "/api/subscriptions/")
	parts := strings.Split(tail, "/")
	if len(parts) != 2 || !subscriptionID.MatchString(parts[0]) {
		writeError(w, http.StatusBadRequest, "invalid subscription action")
		return
	}
	switch parts[1] {
	case "update":
		a.updateSubscriptionByID(w, r, parts[0])
	case "activate":
		a.activateSubscriptionByID(w, r, parts[0])
	default:
		writeError(w, http.StatusNotFound, "unknown subscription action")
	}
}

func (a *API) loadSubscriptions() ([]subscriptionRecord, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	b, err := os.ReadFile(filepath.Join(a.subscriptionsDir, "subscriptions.json"))
	if errors.Is(err, os.ErrNotExist) {
		return []subscriptionRecord{}, nil
	}
	if err != nil {
		return nil, err
	}
	var items []subscriptionRecord
	if err := json.Unmarshal(b, &items); err != nil {
		return nil, err
	}
	return items, nil
}

func (a *API) saveSubscriptions(items []subscriptionRecord) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	b, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(a.subscriptionsDir, "subscriptions.json"), append(b, '\n'), 0600)
}

func maskURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "(invalid URL)"
	}
	u.User = nil
	parts := strings.Split(u.Path, "/")
	for i, part := range parts {
		if len(part) > 4 {
			parts[i] = part[:2] + "******" + part[len(part)-2:]
		} else if len(part) > 0 {
			parts[i] = "******"
		}
	}
	u.Path = strings.Join(parts, "/")
	u.RawQuery = ""
	u.ForceQuery = false
	u.Fragment = ""
	masked := u.String()
	if strings.Contains(raw, "?") {
		masked += "?******"
	}
	return masked
}

func (a *API) static(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	clean := strings.TrimPrefix(filepath.Clean("/"+r.URL.Path), string(filepath.Separator))
	path := filepath.Join(a.webDir, clean)
	if st, err := os.Stat(path); err == nil && st.Mode().IsRegular() {
		http.ServeFile(w, r, path)
		return
	}
	index := filepath.Join(a.webDir, "index.html")
	if _, err := os.Stat(index); err != nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, `<!doctype html><title>Clash for iNextOS</title><h1>Web UI assets are not installed</h1><p>The local API is available at <a href="/api/health">/api/health</a>.</p>`)
		return
	}
	http.ServeFile(w, r, index)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any, limit int64) error {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return fmt.Errorf("request must contain one JSON value")
	}
	return nil
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
