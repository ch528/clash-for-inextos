package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type dashboardInstallation struct {
	Version   string                 `json:"version"`
	Directory string                 `json:"directory"`
	Previous  *dashboardInstallation `json:"previous,omitempty"`
}

func (a *API) dashboardInstallation(name string) (dashboardInstallation, error) {
	var installed dashboardInstallation
	if a.dashboardUpdatesDir == "" {
		return installed, errors.New("dashboard update directory is unavailable")
	}
	data, err := os.ReadFile(filepath.Join(a.dashboardUpdatesDir, "current.json"))
	if err != nil {
		return installed, err
	}
	if err := json.Unmarshal(data, &installed); err != nil {
		return installed, err
	}
	if name == "previous.json" {
		if installed.Previous == nil {
			return dashboardInstallation{}, os.ErrNotExist
		}
		installed = *installed.Previous
	}
	if installed.Version == "" || versionPattern.FindString(installed.Version) != installed.Version {
		return installed, errors.New("invalid dashboard version record")
	}
	if installed.Directory != "" && (filepath.Base(installed.Directory) != installed.Directory || !strings.HasPrefix(installed.Directory, "release-")) {
		return installed, errors.New("invalid dashboard directory record")
	}
	return installed, nil
}

func (a *API) activeDashboardDirectory() string {
	installed, err := a.dashboardInstallation("current.json")
	if err == nil && installed.Directory != "" {
		return filepath.Join(a.dashboardUpdatesDir, installed.Directory)
	}
	return a.dashboardDir
}

func (a *API) installedDashboardVersion() string {
	installed, err := a.dashboardInstallation("current.json")
	if err == nil {
		return installed.Version
	}
	return dashboardVersion
}

func (a *API) commitDashboardCandidate(directory, version string) error {
	if version == "" || versionPattern.FindString(version) != version {
		return errors.New("invalid dashboard candidate version")
	}
	if filepath.Dir(directory) != a.dashboardUpdatesDir || !strings.HasPrefix(filepath.Base(directory), "release-") {
		return errors.New("dashboard candidate is outside the update directory")
	}
	if err := validateDashboardDirectory(directory); err != nil {
		return err
	}
	previous, err := a.dashboardInstallation("current.json")
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		previous = dashboardInstallation{Version: dashboardVersion}
	}
	previous.Previous = nil
	next, _ := json.Marshal(dashboardInstallation{Version: version, Directory: filepath.Base(directory), Previous: &previous})
	return atomicWrite(filepath.Join(a.dashboardUpdatesDir, "current.json"), next, 0600)
}

func (a *API) updateZashboard(w http.ResponseWriter, r *http.Request) {
	updated := false
	defer func() {
		if updated {
			a.recordEvent("zashboard_updated")
		} else {
			a.recordEvent("zashboard_update_failed")
		}
	}()
	if a.dashboardUpdatesDir == "" {
		writeError(w, http.StatusServiceUnavailable, "Zashboard updates are unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 150*time.Second)
	defer cancel()
	client := newSubscriptionClient(nil, nil)
	client.Timeout = 120 * time.Second
	release, err := fetchLatestRelease(ctx, client, "https://api.github.com/repos/Zephyruso/zashboard/releases/latest")
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	asset, err := dashboardReleaseAsset(release)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, asset.URL, nil)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "invalid Zashboard download request")
		return
	}
	request.Header.Set("User-Agent", "Clash-for-iNextOS")
	response, err := client.Do(request)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "Zashboard download failed")
		return
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		writeError(w, http.StatusServiceUnavailable, "Zashboard download did not return HTTP 200")
		return
	}
	archive, err := io.ReadAll(io.LimitReader(response.Body, maxDashboardArchiveBytes+1))
	if err != nil || len(archive) > maxDashboardArchiveBytes || int64(len(archive)) != asset.Size {
		writeError(w, http.StatusServiceUnavailable, "Zashboard download was interrupted or its size is invalid")
		return
	}
	stage, err := os.MkdirTemp(a.dashboardUpdatesDir, "release-")
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "could not create dashboard candidate")
		return
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(stage)
		}
	}()
	if err := extractDashboardArchive(archive, asset.Digest, stage); err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	if err := ctx.Err(); err != nil {
		writeError(w, http.StatusServiceUnavailable, "Zashboard update request expired")
		return
	}
	if err := a.commitDashboardCandidate(stage, release.TagName); err != nil {
		writeError(w, http.StatusServiceUnavailable, "Zashboard activation failed; previous panel remains active")
		return
	}
	committed = true
	updated = true
	writeJSON(w, http.StatusOK, map[string]any{"updated": true, "version": release.TagName})
}

func (a *API) rollbackZashboard(w http.ResponseWriter, r *http.Request) {
	rolledBack := false
	defer func() {
		if rolledBack {
			a.recordEvent("zashboard_rollback")
		} else {
			a.recordEvent("zashboard_rollback_failed")
		}
	}()
	previous, err := a.dashboardInstallation("previous.json")
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "previous Zashboard version is unavailable")
		return
	}
	root := a.dashboardDir
	if previous.Directory != "" {
		root = filepath.Join(a.dashboardUpdatesDir, previous.Directory)
	}
	if err := validateDashboardDirectory(root); err != nil {
		writeError(w, http.StatusServiceUnavailable, "previous Zashboard files failed validation")
		return
	}
	current, err := a.dashboardInstallation("current.json")
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "current Zashboard version record is unavailable")
		return
	}
	current.Previous = nil
	previous.Previous = &current
	data, _ := json.Marshal(previous)
	if err := atomicWrite(filepath.Join(a.dashboardUpdatesDir, "current.json"), data, 0600); err != nil {
		writeError(w, http.StatusServiceUnavailable, "could not restore previous Zashboard version")
		return
	}
	rolledBack = true
	writeJSON(w, http.StatusOK, map[string]any{"rolled_back": true, "version": previous.Version})
}
