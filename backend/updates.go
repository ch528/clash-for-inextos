package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const maxReleaseResponseBytes = 1 << 20

var versionPattern = regexp.MustCompile(`(?i)v?([0-9]+)\.([0-9]+)\.([0-9]+)`)

type latestRelease struct {
	TagName     string         `json:"tag_name"`
	PublishedAt string         `json:"published_at"`
	Draft       bool           `json:"draft"`
	Prerelease  bool           `json:"prerelease"`
	Assets      []releaseAsset `json:"assets"`
}

type updateComponent struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Current         string `json:"current"`
	Latest          string `json:"latest,omitempty"`
	ReleaseDate     string `json:"release_date,omitempty"`
	UpdateAvailable *bool  `json:"update_available,omitempty"`
	Status          string `json:"status"`
}

func (a *API) checkUpdates(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	mihomoVersion := a.manager.version()
	if match := versionPattern.FindStringSubmatch(mihomoVersion); len(match) > 0 {
		mihomoVersion = strings.TrimPrefix(match[0], "v")
	}
	geoCurrent, geoStatus := geoDataStatus(a.manager.configFile, a.manager.runtimeDir, a.stateDir)
	components := []updateComponent{
		{ID: "app", Name: "Clash for iNextOS", Current: a.applicationVersion, Status: "checking"},
		{ID: "mihomo", Name: "Mihomo", Current: mihomoVersion, Status: "checking"},
		{ID: "zashboard", Name: "Zashboard", Current: strings.TrimPrefix(a.installedDashboardVersion(), "v"), Status: "checking"},
		{ID: "geo", Name: "Geo 数据", Current: geoCurrent, Status: geoStatus},
	}
	sources := []struct {
		index int
		url   string
	}{
		{index: 0, url: applicationReleaseURL("")},
		{index: 1, url: "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest"},
		{index: 2, url: "https://api.github.com/repos/Zephyruso/zashboard/releases/latest"},
		{index: 3, url: "https://api.github.com/repos/MetaCubeX/meta-rules-dat/releases/latest"},
	}
	client := newSubscriptionClient(nil, nil)
	client.Timeout = 10 * time.Second
	for _, source := range sources {
		index := source.index
		release, err := fetchLatestRelease(ctx, client, source.url)
		if err != nil {
			components[index].Status = "source_unavailable"
			continue
		}
		components[index].Latest = strings.TrimPrefix(release.TagName, "v")
		components[index].ReleaseDate = release.PublishedAt
		if index == 0 {
			if _, latest, assetErr := applicationReleaseAsset(release); assetErr != nil {
				components[index].Status = "release_invalid"
				continue
			} else {
				components[index].Latest = latest
			}
		}
		if index == 3 {
			if geoStatus == "in_use" {
				metadata, metaErr := loadGeoDataMetadata(a.stateDir)
				published, publishedErr := time.Parse(time.RFC3339, release.PublishedAt)
				available := metaErr != nil || publishedErr != nil || published.After(metadata.PublishedAt)
				components[index].UpdateAvailable = &available
				components[index].Status = "checked"
				if available {
					a.recordEvent("geo_update_available")
				}
			} else if geoStatus == "installed_version_untracked" || geoStatus == "in_use_missing" {
				available := true
				components[index].UpdateAvailable = &available
				components[index].Status = "checked"
				a.recordEvent("geo_update_available")
			}
			continue
		}
		if release.Draft || release.Prerelease {
			components[index].Status = "no_stable_release"
			continue
		}
		relation, ok := versionRelation(components[index].Latest, components[index].Current)
		if index == 0 {
			relation, ok = applicationVersionRelation(components[index].Latest, components[index].Current)
		}
		if !ok {
			components[index].Status = "version_unavailable"
			continue
		}
		available := relation > 0
		components[index].UpdateAvailable = &available
		components[index].Status = "checked"
		if relation < 0 {
			components[index].Status = "local_newer"
		}
		if available {
			if index == 1 {
				a.recordEvent("mihomo_update_available")
			} else {
				a.recordEvent("zashboard_update_available")
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"checked_at": time.Now().UTC(), "components": components})
}

func geoDataStatus(configFile, dataDir, stateDir string) (string, string) {
	config, err := os.ReadFile(configFile)
	if err != nil {
		return "未知", "usage_unknown"
	}
	files, err := geoDataFilesUsed(config)
	if err != nil {
		return "未知", "usage_unknown"
	}
	if len(files) == 0 {
		return "未启用", "not_in_use"
	}
	for _, name := range files {
		info, err := os.Lstat(filepath.Join(dataDir, name))
		if err != nil || !info.Mode().IsRegular() {
			return "未安装", "in_use_missing"
		}
	}
	metadata, err := loadGeoDataMetadata(stateDir)
	if err != nil || !geoDataHashesMatch(dataDir, files, metadata.Files) {
		return "版本未跟踪", "installed_version_untracked"
	}
	return metadata.PublishedAt.Format("2006-01-02"), "in_use"
}

func fetchLatestRelease(ctx context.Context, client *http.Client, source string) (latestRelease, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return latestRelease{}, err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("User-Agent", "Clash-for-iNextOS")
	response, err := client.Do(request)
	if err != nil {
		return latestRelease{}, fmt.Errorf("release source unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return latestRelease{}, fmt.Errorf("release source returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxReleaseResponseBytes+1))
	if err != nil || len(body) > maxReleaseResponseBytes {
		return latestRelease{}, fmt.Errorf("release response is invalid")
	}
	var release latestRelease
	if err := json.Unmarshal(body, &release); err != nil || strings.TrimSpace(release.TagName) == "" || len(release.TagName) > 128 {
		return latestRelease{}, fmt.Errorf("release metadata is invalid")
	}
	if _, err := time.Parse(time.RFC3339, release.PublishedAt); err != nil {
		return latestRelease{}, fmt.Errorf("release date is invalid")
	}
	return release, nil
}

func versionIsNewer(latest, current string) (bool, bool) {
	relation, valid := versionRelation(latest, current)
	return relation > 0, valid
}

func versionRelation(candidate, current string) (int, bool) {
	candidateParts, candidateOK := versionParts(candidate)
	currentParts, currentOK := versionParts(current)
	if !candidateOK || !currentOK {
		return 0, false
	}
	for index := range candidateParts {
		if candidateParts[index] < currentParts[index] {
			return -1, true
		}
		if candidateParts[index] > currentParts[index] {
			return 1, true
		}
	}
	return 0, true
}

func versionParts(version string) ([3]int, bool) {
	match := versionPattern.FindStringSubmatch(version)
	if len(match) != 4 {
		return [3]int{}, false
	}
	var parts [3]int
	for index := range parts {
		value, err := strconv.Atoi(match[index+1])
		if err != nil {
			return [3]int{}, false
		}
		parts[index] = value
	}
	return parts, true
}
