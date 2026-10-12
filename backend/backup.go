package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

const (
	portableBackupFormat   = "clash-for-inextos"
	portableBackupVersion  = 1
	maxPortableBackupSize  = 64 << 20
	maxBackupSubscriptions = 20
)

var portableBackupID = regexp.MustCompile(`^[a-f0-9]{16}$`)

type portableBackup struct {
	Format        string                 `json:"format"`
	SchemaVersion int                    `json:"schema_version"`
	CreatedAt     time.Time              `json:"created_at"`
	Application   string                 `json:"application,omitempty"`
	Runtime       portableRuntime        `json:"runtime"`
	Subscriptions []portableSubscription `json:"subscriptions"`
	Appearance    portableAppearance     `json:"appearance,omitempty"`
}

type portableRuntime struct {
	MixedPort        int              `json:"mixed_port"`
	ControllerPort   int              `json:"controller_port"`
	Mode             string           `json:"mode"`
	AutoStart        bool             `json:"auto_start"`
	RestartOnFailure bool             `json:"restart_on_failure"`
	TunStack         string           `json:"tun_stack"`
	TunIPv6          bool             `json:"tun_ipv6,omitempty"`
	TunAutoRedirect  bool             `json:"tun_auto_redirect,omitempty"`
	LANProxy         LANProxySettings `json:"lan_proxy,omitempty"`
	DNS              DNSSettings      `json:"dns,omitempty"`
}

type portableSubscription struct {
	ID              string             `json:"id"`
	Name            string             `json:"name"`
	URL             string             `json:"url"`
	Enabled         bool               `json:"enabled"`
	LastUpdated     time.Time          `json:"last_updated,omitempty"`
	NodeCount       int                `json:"node_count"`
	Current         bool               `json:"current"`
	AutoUpdateHours int                `json:"auto_update_hours"`
	Usage           *subscriptionUsage `json:"usage,omitempty"`
	Config          string             `json:"config,omitempty"`
}

type portableAppearance struct {
	Theme   string `json:"theme,omitempty"`
	Density string `json:"density,omitempty"`
}

type portableRestorePlan struct {
	state       RuntimeState
	config      []byte
	records     []subscriptionRecord
	configs     map[string][]byte
	currentName string
	totalNodes  int
	appearance  portableAppearance
}

type portableRestorePreview struct {
	SubscriptionCount int                `json:"subscription_count"`
	CurrentName       string             `json:"current_subscription,omitempty"`
	TotalNodes        int                `json:"total_nodes"`
	Mode              string             `json:"mode"`
	TunStack          string             `json:"tun_stack"`
	AutoStart         bool               `json:"auto_start"`
	RestartOnFailure  bool               `json:"restart_on_failure"`
	Appearance        portableAppearance `json:"appearance"`
	MihomoWillStayOff bool               `json:"mihomo_will_remain_stopped"`
	TunWillStayOff    bool               `json:"tun_will_remain_disabled"`
}

func (a *API) exportBackup(w http.ResponseWriter, r *http.Request) {
	a.subOp.Lock()
	defer a.subOp.Unlock()
	state := a.manager.RuntimeConfig()
	if err := normalizeNetworkSettings(&state); err != nil {
		writeError(w, http.StatusInternalServerError, "stored network preferences are invalid")
		return
	}
	bundle := portableBackup{
		Format: portableBackupFormat, SchemaVersion: portableBackupVersion,
		CreatedAt: time.Now().UTC(), Application: a.applicationVersion,
		Runtime: portableRuntime{
			MixedPort: state.MixedPort, ControllerPort: state.ControllerPort,
			Mode: state.Mode, AutoStart: state.AutoStart,
			RestartOnFailure: state.RestartOnFailure, TunStack: state.TunStack,
			TunIPv6: state.TunIPv6, TunAutoRedirect: state.TunAutoRedirect,
			LANProxy: portableLANProxySettings(state.LANProxy), DNS: portableDNSSettings(state.DNS),
		},
		Subscriptions: []portableSubscription{},
	}
	items, err := a.loadSubscriptions()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read subscriptions")
		return
	}
	if len(items) > maxBackupSubscriptions {
		writeError(w, http.StatusRequestEntityTooLarge, "too many subscriptions for a portable backup")
		return
	}
	seen := make(map[string]struct{}, len(items))
	currentCount := 0
	for _, item := range items {
		if !portableBackupID.MatchString(item.ID) || strings.TrimSpace(item.Name) == "" || len(item.Name) > 80 || !validRuleProviderURL(item.URL) || !validUpdateHours(item.AutoUpdateHours) || (item.Current && !item.Enabled) {
			writeError(w, http.StatusInternalServerError, "stored subscription data is invalid")
			return
		}
		if _, ok := seen[item.ID]; ok {
			writeError(w, http.StatusInternalServerError, "stored subscription data is invalid")
			return
		}
		seen[item.ID] = struct{}{}
		if item.Current {
			currentCount++
		}
		entry := portableSubscription{
			ID: item.ID, Name: item.Name, URL: item.URL, Enabled: item.Enabled,
			LastUpdated: item.LastUpdated, NodeCount: item.NodeCount, Current: item.Current, Usage: item.Usage,
			AutoUpdateHours: item.AutoUpdateHours,
		}
		body, err := os.ReadFile(filepath.Join(a.subscriptionsDir, item.ID+".yaml"))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			writeError(w, http.StatusInternalServerError, "could not read saved subscription config")
			return
		}
		if len(body) > maxSubscriptionBytes {
			writeError(w, http.StatusRequestEntityTooLarge, "saved subscription config is too large for a portable backup")
			return
		}
		if len(body) == 0 && (item.Current || item.NodeCount > 0) {
			writeError(w, http.StatusInternalServerError, "subscription metadata references a missing saved config")
			return
		}
		if len(body) > 0 {
			safeBody, err := sanitizePortableSubscription(body)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "stored subscription config is invalid")
				return
			}
			entry.Config = string(safeBody)
		}
		bundle.Subscriptions = append(bundle.Subscriptions, entry)
	}
	if currentCount > 1 {
		writeError(w, http.StatusInternalServerError, "stored subscription data is invalid")
		return
	}
	body, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil || len(body) > maxPortableBackupSize {
		writeError(w, http.StatusRequestEntityTooLarge, "portable backup exceeds the size limit")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", `attachment; filename="clash-for-inextos-backup.json"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (a *API) previewBackup(w http.ResponseWriter, r *http.Request) {
	var bundle portableBackup
	if err := decodeJSON(w, r, &bundle, maxPortableBackupSize); err != nil {
		writeError(w, http.StatusBadRequest, "invalid portable backup")
		return
	}
	plan, err := a.validatePortableBackup(r.Context(), bundle)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, plan.preview())
}

func (a *API) applyBackup(w http.ResponseWriter, r *http.Request) {
	var bundle portableBackup
	if err := decodeJSON(w, r, &bundle, maxPortableBackupSize); err != nil {
		writeError(w, http.StatusBadRequest, "invalid portable backup")
		return
	}
	a.subOp.Lock()
	defer a.subOp.Unlock()
	status := a.manager.Status(r.Context())
	if status.ProcessAlive || networkCaptureActive(a.manager.RuntimeConfig()) {
		writeError(w, http.StatusConflict, "stop Mihomo and turn off network capture before restoring a backup")
		return
	}
	plan, err := a.validatePortableBackup(r.Context(), bundle)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	parent := filepath.Dir(a.subscriptionsDir)
	stageRoot, err := os.MkdirTemp(parent, ".subscriptions-restore-*")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not prepare restore")
		return
	}
	defer os.RemoveAll(stageRoot)
	stageDir := filepath.Join(stageRoot, "subscriptions")
	if err := writePortableSubscriptions(stageDir, plan.records, plan.configs); err != nil {
		writeError(w, http.StatusInternalServerError, "could not prepare subscription restore")
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	backupDir, err := os.MkdirTemp(parent, ".subscriptions-before-restore-*")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not prepare restore rollback")
		return
	}
	if err := os.Remove(backupDir); err != nil {
		writeError(w, http.StatusInternalServerError, "could not prepare restore rollback")
		return
	}
	hadPrevious := false
	if _, err := os.Stat(a.subscriptionsDir); err == nil {
		if err := os.Rename(a.subscriptionsDir, backupDir); err != nil {
			writeError(w, http.StatusInternalServerError, "could not stage existing subscriptions")
			return
		}
		hadPrevious = true
	} else if !errors.Is(err, os.ErrNotExist) {
		writeError(w, http.StatusInternalServerError, "could not inspect existing subscriptions")
		return
	}
	rollbackSubscriptions := func() {
		_ = os.RemoveAll(a.subscriptionsDir)
		if hadPrevious {
			_ = os.Rename(backupDir, a.subscriptionsDir)
		}
	}
	if err := os.Rename(stageDir, a.subscriptionsDir); err != nil {
		rollbackSubscriptions()
		writeError(w, http.StatusInternalServerError, "could not apply subscription restore")
		return
	}
	if err := a.manager.RestorePortableRuntime(plan.state, plan.config); err != nil {
		rollbackSubscriptions()
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	a.state = plan.state
	if hadPrevious {
		_ = os.RemoveAll(backupDir)
	}
	writeJSON(w, http.StatusOK, plan.preview())
}

func portableLANProxySettings(settings LANProxySettings) LANProxySettings {
	settings.Enabled = false
	return settings
}

func portableDNSSettings(settings DNSSettings) DNSSettings {
	settings.Enabled = false
	return settings
}

func (a *API) validatePortableBackup(ctx context.Context, bundle portableBackup) (portableRestorePlan, error) {
	if bundle.Format != portableBackupFormat || bundle.SchemaVersion != portableBackupVersion {
		return portableRestorePlan{}, errors.New("unsupported portable backup format or version")
	}
	if len(bundle.Subscriptions) > maxBackupSubscriptions {
		return portableRestorePlan{}, errors.New("portable backup contains too many subscriptions")
	}
	if bundle.Appearance.Theme != "" && bundle.Appearance.Theme != "system" && bundle.Appearance.Theme != "light" && bundle.Appearance.Theme != "dark" {
		return portableRestorePlan{}, errors.New("portable backup appearance theme is invalid")
	}
	if bundle.Appearance.Density != "" && bundle.Appearance.Density != "comfortable" && bundle.Appearance.Density != "compact" {
		return portableRestorePlan{}, errors.New("portable backup appearance density is invalid")
	}
	if bundle.Runtime.MixedPort < 17890 || bundle.Runtime.MixedPort > 17920 || bundle.Runtime.ControllerPort < 9091 || bundle.Runtime.ControllerPort > 9120 || bundle.Runtime.MixedPort == bundle.Runtime.ControllerPort || !validMode(bundle.Runtime.Mode) {
		return portableRestorePlan{}, errors.New("portable backup Mihomo settings are invalid")
	}
	if bundle.Runtime.TunStack != "system" && bundle.Runtime.TunStack != "gvisor" && bundle.Runtime.TunStack != "mixed" {
		return portableRestorePlan{}, errors.New("portable backup TUN stack is invalid")
	}
	state := a.manager.RuntimeConfig()
	if bundle.Runtime.MixedPort == state.BackendPort || bundle.Runtime.ControllerPort == state.BackendPort {
		return portableRestorePlan{}, errors.New("portable backup ports conflict with the application")
	}
	state.MixedPort = bundle.Runtime.MixedPort
	state.ControllerPort = bundle.Runtime.ControllerPort
	state.Mode = bundle.Runtime.Mode
	state.AutoStart = bundle.Runtime.AutoStart
	state.RestartOnFailure = bundle.Runtime.RestartOnFailure
	state.TunStack = bundle.Runtime.TunStack
	state.TunIPv6 = bundle.Runtime.TunIPv6
	state.TunAutoRedirect = bundle.Runtime.TunAutoRedirect
	state.LANProxy = bundle.Runtime.LANProxy
	state.LANProxy.Enabled = false
	state.DNS = bundle.Runtime.DNS
	state.DNS.Enabled = false
	if err := normalizeNetworkSettings(&state); err != nil {
		return portableRestorePlan{}, fmt.Errorf("portable backup network preferences are invalid: %w", err)
	}
	state.DesiredRunning = false
	state.TunEnabled = false
	state.TunTestConfirmed = false
	state.PID = 0
	state.StartedAt = time.Time{}

	seen := make(map[string]struct{}, len(bundle.Subscriptions))
	plan := portableRestorePlan{
		state: state, records: make([]subscriptionRecord, 0, len(bundle.Subscriptions)),
		configs: make(map[string][]byte, len(bundle.Subscriptions)), appearance: bundle.Appearance,
	}
	currentCount := 0
	for _, item := range bundle.Subscriptions {
		if !portableBackupID.MatchString(item.ID) || strings.TrimSpace(item.Name) == "" || len(item.Name) > 80 || !validRuleProviderURL(item.URL) || !validUpdateHours(item.AutoUpdateHours) {
			return portableRestorePlan{}, errors.New("portable backup subscription metadata is invalid")
		}
		if _, ok := seen[item.ID]; ok {
			return portableRestorePlan{}, errors.New("portable backup contains duplicate subscription IDs")
		}
		seen[item.ID] = struct{}{}
		if item.Current {
			currentCount++
			if !item.Enabled {
				return portableRestorePlan{}, errors.New("portable backup selects a disabled subscription")
			}
		}
		body := []byte(item.Config)
		if len(body) > maxSubscriptionBytes {
			return portableRestorePlan{}, errors.New("portable backup subscription config is too large")
		}
		record := subscriptionRecord{
			ID: item.ID, Name: strings.TrimSpace(item.Name), URL: item.URL, Enabled: item.Enabled,
			LastUpdated: item.LastUpdated, Current: item.Current, AutoUpdateHours: item.AutoUpdateHours, Usage: item.Usage,
		}
		if len(body) == 0 {
			if item.Current || item.NodeCount > 0 {
				return portableRestorePlan{}, errors.New("subscription metadata references a missing saved config")
			}
			record.Status = "saved; not imported"
		} else {
			safeBody, err := sanitizePortableSubscription(body)
			if err != nil {
				return portableRestorePlan{}, errors.New("portable backup subscription config is invalid")
			}
			body = safeBody
			generated, count, err := renderSubscription(body, state, a.manager.secret)
			if err != nil {
				return portableRestorePlan{}, fmt.Errorf("subscription config is invalid: %w", err)
			}
			if err := a.testConfig(ctx, generated); err != nil {
				return portableRestorePlan{}, err
			}
			record.Status = "ready"
			record.NodeCount = count
			plan.totalNodes += count
			plan.configs[item.ID] = body
			if item.Current {
				plan.config = generated
				plan.currentName = record.Name
			}
		}
		plan.records = append(plan.records, record)
	}
	if currentCount > 1 {
		return portableRestorePlan{}, errors.New("portable backup selects more than one current subscription")
	}
	if len(plan.config) == 0 {
		plan.config = []byte(minimalConfig(state, a.manager.secret))
		if err := a.testConfig(ctx, plan.config); err != nil {
			return portableRestorePlan{}, err
		}
	}
	return plan, nil
}

func sanitizePortableSubscription(body []byte) ([]byte, error) {
	var source map[string]any
	if err := yaml.Unmarshal(body, &source); err != nil {
		return nil, err
	}
	safe := make(map[string]any, 4)
	for _, key := range []string{"proxies", "proxy-groups", "rule-providers", "rules"} {
		if value, ok := source[key]; ok {
			safe[key] = value
		}
	}
	return yaml.Marshal(safe)
}

func (plan portableRestorePlan) preview() portableRestorePreview {
	return portableRestorePreview{
		SubscriptionCount: len(plan.records), CurrentName: plan.currentName,
		TotalNodes: plan.totalNodes, Mode: plan.state.Mode, TunStack: plan.state.TunStack,
		AutoStart: plan.state.AutoStart, RestartOnFailure: plan.state.RestartOnFailure,
		Appearance: plan.appearance, MihomoWillStayOff: true, TunWillStayOff: true,
	}
}

func writePortableSubscriptions(dir string, records []subscriptionRecord, configs map[string][]byte) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return err
	}
	if err := atomicWrite(filepath.Join(dir, "subscriptions.json"), append(data, '\n'), 0600); err != nil {
		return err
	}
	for id, body := range configs {
		if !portableBackupID.MatchString(id) {
			return errors.New("invalid subscription ID")
		}
		if err := atomicWrite(filepath.Join(dir, id+".yaml"), body, 0600); err != nil {
			return err
		}
	}
	return nil
}
