package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"
)

const maxSystemEvents = 200

var systemEventsMu sync.Mutex

type systemEvent struct {
	ID       string    `json:"id"`
	Time     time.Time `json:"time"`
	Type     string    `json:"type"`
	Severity string    `json:"severity"`
	Message  string    `json:"message"`
}

func systemEventDetails(kind string) (string, string, bool) {
	switch kind {
	case "administrator_created":
		return "info", "管理员账户已创建", true
	case "administrator_login":
		return "info", "管理员已登录", true
	case "login_security":
		return "warning", "登录失败次数过多，登录已暂时限制", true
	case "administrator_updated":
		return "info", "管理员账户已更新", true
	case "mihomo_started":
		return "info", "Mihomo 已启动", true
	case "mihomo_stopped":
		return "info", "Mihomo 已停止", true
	case "mihomo_crashed":
		return "error", "Mihomo 意外退出，系统正在恢复", true
	case "mihomo_start_failed":
		return "error", "Mihomo 启动失败", true
	case "mihomo_stop_failed":
		return "error", "Mihomo 未能正常停止", true
	case "mihomo_updated":
		return "info", "Mihomo 更新完成", true
	case "mihomo_update_available":
		return "info", "发现 Mihomo 新版本", true
	case "mihomo_update_failed":
		return "error", "Mihomo 更新失败，请检查更新状态", true
	case "subscription_updated":
		return "info", "订阅已更新", true
	case "subscription_failed":
		return "error", "订阅更新失败", true
	case "config_rollback":
		return "warning", "配置启动失败，已恢复上一个配置", true
	case "zashboard_updated":
		return "info", "Zashboard 更新完成", true
	case "zashboard_update_failed":
		return "error", "Zashboard 更新失败，当前版本仍保留", true
	case "zashboard_update_available":
		return "info", "发现 Zashboard 新版本", true
	case "geo_update_available":
		return "info", "发现 Geo 数据更新", true
	case "zashboard_rollback":
		return "warning", "Zashboard 已恢复到上一个版本", true
	case "zashboard_rollback_failed":
		return "error", "Zashboard 恢复失败，当前版本仍保留", true
	case "tun_enabled":
		return "warning", "TUN 已启用，请确认网络连接正常", true
	case "tun_disabled":
		return "info", "TUN 已关闭", true
	case "network_capture_enabled":
		return "warning", "网络接管已启用，请确认网络连接正常", true
	case "network_capture_disabled":
		return "info", "网络接管已关闭", true
	case "tun_failure":
		return "error", "TUN 设置失败，请检查网络状态", true
	case "network_rollback":
		return "warning", "网络设置已恢复", true
	case "network_rollback_failed":
		return "error", "自动网络恢复未完成，需要检查网络设置", true
	case "certificate_warning":
		return "warning", "公网 HTTPS 证书需要检查", true
	default:
		return "", "", false
	}
}

func recordSystemEvent(path, kind string, now time.Time) error {
	severity, message, ok := systemEventDetails(kind)
	if !ok {
		return errors.New("unknown system event")
	}
	systemEventsMu.Lock()
	defer systemEventsMu.Unlock()
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0660)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := lock.Chmod(0660); err != nil {
		return err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	items, err := readStoredSystemEvents(path)
	if err != nil {
		return err
	}
	if cooldown := systemEventCooldown(kind); cooldown > 0 {
		for i := len(items) - 1; i >= 0 && now.Sub(items[i].Time) < cooldown; i-- {
			if items[i].Type == kind {
				return nil
			}
		}
	}
	items = append(items, systemEvent{
		ID: strconv.FormatInt(now.UnixNano(), 10), Time: now.UTC(), Type: kind, Severity: severity, Message: message,
	})
	if len(items) > maxSystemEvents {
		items = items[len(items)-maxSystemEvents:]
	}
	data, err := json.Marshal(items)
	if err != nil {
		return err
	}
	return atomicWrite(path, data, 0660)
}

func systemEventCooldown(kind string) time.Duration {
	switch kind {
	case "login_security", "mihomo_crashed", "tun_failure", "certificate_warning":
		return 2 * time.Minute
	case "mihomo_update_available", "zashboard_update_available", "geo_update_available":
		return 24 * time.Hour
	default:
		return 0
	}
}

func readSystemEvents(path string, limit int) ([]systemEvent, error) {
	items, err := readStoredSystemEvents(path)
	if err != nil {
		return nil, err
	}
	if limit <= 0 || limit > maxSystemEvents {
		limit = maxSystemEvents
	}
	if len(items) > limit {
		items = items[len(items)-limit:]
	}
	for left, right := 0, len(items)-1; left < right; left, right = left+1, right-1 {
		items[left], items[right] = items[right], items[left]
	}
	return items, nil
}

func readStoredSystemEvents(path string) ([]systemEvent, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return []systemEvent{}, nil
	}
	if err != nil {
		return nil, err
	}
	var items []systemEvent
	if err := json.Unmarshal(data, &items); err != nil {
		return nil, err
	}
	if len(items) > maxSystemEvents {
		items = items[len(items)-maxSystemEvents:]
	}
	return items, nil
}

func systemEventsPath(stateDir string) string {
	return filepath.Join(stateDir, "events.json")
}

func (a *API) recordEvent(kind string) {
	if a.stateDir == "" {
		return
	}
	if err := recordSystemEvent(systemEventsPath(a.stateDir), kind, time.Now()); err != nil && a.logger != nil {
		a.logger.Error("system event could not be stored", "event_type", kind, "reason", err.Error())
	}
}

func (a *API) systemEvents(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || (value != 25 && value != 50 && value != 100 && value != 200) {
			writeError(w, http.StatusBadRequest, "limit must be 25, 50, 100, or 200")
			return
		}
		limit = value
	}
	items, err := readSystemEvents(systemEventsPath(a.stateDir), limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read system events")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": items})
}
