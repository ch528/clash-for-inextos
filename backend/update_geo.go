package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

const (
	maxGeoAssetBytes     = 96 << 20
	maxGeoUpdateBytes    = 160 << 20
	geoUpdateTimeout     = 4 * time.Minute
	geoAssetFetchTimeout = 35 * time.Second
)

var geoAssetNamePattern = regexp.MustCompile(`^[a-z0-9.-]{1,64}$`)
var geoReleaseTagPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

type geoDataMetadata struct {
	Tag         string            `json:"tag"`
	PublishedAt time.Time         `json:"published_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	Files       map[string]string `json:"files"`
}

type geoDataSwap struct {
	dir        string
	stageDir   string
	names      []string
	installed  []string
	movedOld   []string
	rolledBack bool
}

func geoDataFilesUsed(config []byte) ([]string, error) {
	var parsed struct {
		GeodataMode bool     `yaml:"geodata-mode"`
		Rules       []string `yaml:"rules"`
	}
	if err := yaml.Unmarshal(config, &parsed); err != nil {
		return nil, errors.New("Mihomo configuration is invalid")
	}
	needIP, needSite := false, false
	for _, rule := range parsed.Rules {
		kind := strings.ToUpper(strings.TrimSpace(strings.SplitN(rule, ",", 2)[0]))
		needIP = needIP || kind == "GEOIP"
		needSite = needSite || kind == "GEOSITE"
	}
	var files []string
	if needIP {
		if parsed.GeodataMode {
			files = append(files, "geoip.dat")
		} else {
			files = append(files, "geoip.metadb")
		}
	}
	if needSite {
		files = append(files, "geosite.dat")
	}
	sort.Strings(files)
	return files, nil
}

func geoDataMetadataPath(stateDir string) string {
	return filepath.Join(stateDir, "geo-data.json")
}

func loadGeoDataMetadata(stateDir string) (geoDataMetadata, error) {
	var metadata geoDataMetadata
	data, err := os.ReadFile(geoDataMetadataPath(stateDir))
	if err != nil {
		return metadata, err
	}
	if len(data) > 1<<20 || json.Unmarshal(data, &metadata) != nil || metadata.Tag == "" || metadata.PublishedAt.IsZero() || len(metadata.Files) == 0 {
		return geoDataMetadata{}, errors.New("Geo metadata is invalid")
	}
	for name, digest := range metadata.Files {
		if !validGeoAssetName(name) || !validSHA256(digest) {
			return geoDataMetadata{}, errors.New("Geo metadata is invalid")
		}
	}
	return metadata, nil
}

func geoDataHashesMatch(dataDir string, required []string, recorded map[string]string) bool {
	for _, name := range required {
		path := filepath.Join(dataDir, name)
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxGeoAssetBytes {
			return false
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return false
		}
		digest := sha256.Sum256(data)
		if recorded[name] != hex.EncodeToString(digest[:]) {
			return false
		}
	}
	return true
}

func geoDataReleaseAsset(release latestRelease, name string) (releaseAsset, error) {
	if !validGeoAssetName(name) || !geoReleaseTagPattern.MatchString(release.TagName) || release.Draft || release.Prerelease {
		return releaseAsset{}, errors.New("Geo release metadata is invalid")
	}
	expectedURL := "https://github.com/MetaCubeX/meta-rules-dat/releases/download/" + release.TagName + "/" + name
	var selected releaseAsset
	for _, asset := range release.Assets {
		if asset.Name != name {
			continue
		}
		if selected.Name != "" || asset.URL != expectedURL || asset.Size <= 0 || asset.Size > maxGeoAssetBytes || !validSHA256(strings.TrimPrefix(asset.Digest, "sha256:")) || !strings.HasPrefix(asset.Digest, "sha256:") {
			return releaseAsset{}, errors.New("Geo data asset metadata is invalid")
		}
		selected = asset
	}
	if selected.Name == "" {
		return releaseAsset{}, errors.New("Geo release does not contain a required data file")
	}
	return selected, nil
}

func validGeoAssetName(name string) bool {
	switch name {
	case "geoip.dat", "geoip.metadb", "geosite.dat":
		return true
	default:
		return false
	}
}

func validSHA256(value string) bool {
	digest, err := hex.DecodeString(value)
	return err == nil && len(digest) == sha256.Size
}

func geoAssetSources(asset releaseAsset) []string {
	const prefix = "https://github.com/MetaCubeX/meta-rules-dat/releases/download/"
	if !strings.HasPrefix(asset.URL, prefix) {
		return []string{asset.URL}
	}
	return []string{
		"https://gh-proxy.org/" + asset.URL,
		"https://ghfast.top/" + asset.URL,
		"https://ghproxy.net/" + asset.URL,
		asset.URL,
	}
}

func downloadGeoAsset(ctx context.Context, client *http.Client, asset releaseAsset) ([]byte, error) {
	var lastErr error
	for _, source := range geoAssetSources(asset) {
		sourceCtx, cancel := context.WithTimeout(ctx, geoAssetFetchTimeout)
		request, err := http.NewRequestWithContext(sourceCtx, http.MethodGet, source, nil)
		if err != nil {
			cancel()
			return nil, errors.New("invalid Geo data request")
		}
		request.Header.Set("User-Agent", "Clash-for-iNextOS")
		response, err := client.Do(request)
		if err == nil {
			if response.StatusCode != http.StatusOK {
				lastErr = errors.New("Geo data source is unavailable")
				_ = response.Body.Close()
			} else {
				data, readErr := io.ReadAll(io.LimitReader(response.Body, maxGeoAssetBytes+1))
				_ = response.Body.Close()
				cancel()
				if readErr == nil {
					return verifyGeoAsset(data, asset)
				}
				lastErr = errors.New("Geo data download was interrupted")
			}
		} else {
			lastErr = errors.New("Geo data source is unavailable")
		}
		cancel()
		if ctx.Err() != nil {
			break
		}
	}
	if lastErr == nil {
		lastErr = errors.New("Geo data download failed")
	}
	return nil, lastErr
}

func verifyGeoAsset(data []byte, asset releaseAsset) ([]byte, error) {
	if int64(len(data)) != asset.Size || len(data) > maxGeoAssetBytes {
		return nil, fmt.Errorf("Geo data size does not match release metadata")
	}
	expected, err := hex.DecodeString(strings.TrimPrefix(asset.Digest, "sha256:"))
	actual := sha256.Sum256(data)
	if !strings.HasPrefix(asset.Digest, "sha256:") || err != nil || !strings.EqualFold(hex.EncodeToString(actual[:]), hex.EncodeToString(expected)) {
		return nil, errors.New("Geo data SHA-256 verification failed")
	}
	return data, nil
}

func stageGeoData(dataDir string, candidates map[string][]byte) (*geoDataSwap, error) {
	if len(candidates) == 0 {
		return nil, errors.New("no Geo data is required by the active configuration")
	}
	var total int64
	names := make([]string, 0, len(candidates))
	for name, data := range candidates {
		if !validGeoAssetName(name) || len(data) == 0 || len(data) > maxGeoAssetBytes {
			return nil, errors.New("Geo data candidate is invalid")
		}
		total += int64(len(data))
		names = append(names, name)
	}
	if total > maxGeoUpdateBytes {
		return nil, errors.New("Geo data update exceeds the size limit")
	}
	sort.Strings(names)
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, err
	}
	stageDir, err := os.MkdirTemp(dataDir, ".geo-update-")
	if err != nil {
		return nil, err
	}
	stage := &geoDataSwap{dir: dataDir, stageDir: stageDir, names: names}
	candidateDir := filepath.Join(stageDir, "candidate")
	previousDir := filepath.Join(stageDir, "previous")
	if err := os.MkdirAll(candidateDir, 0700); err != nil {
		_ = os.RemoveAll(stageDir)
		return nil, err
	}
	if err := os.MkdirAll(previousDir, 0700); err != nil {
		_ = os.RemoveAll(stageDir)
		return nil, err
	}
	for _, name := range names {
		path := filepath.Join(candidateDir, name)
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			_ = os.RemoveAll(stageDir)
			return nil, err
		}
		written, writeErr := file.Write(candidates[name])
		if writeErr == nil && written != len(candidates[name]) {
			writeErr = io.ErrShortWrite
		}
		syncErr := file.Sync()
		closeErr := file.Close()
		if writeErr != nil || syncErr != nil || closeErr != nil {
			_ = os.RemoveAll(stageDir)
			return nil, errors.New("could not stage Geo data")
		}
	}
	for _, name := range names {
		target := filepath.Join(dataDir, name)
		if info, err := os.Lstat(target); err == nil {
			if !info.Mode().IsRegular() {
				if rollbackErr := stage.rollback(); rollbackErr != nil {
					return nil, fmt.Errorf("Geo staging failed and rollback was incomplete: %w", rollbackErr)
				}
				return nil, errors.New("existing Geo data path is not a regular file")
			}
			if err := os.Rename(target, filepath.Join(previousDir, name)); err != nil {
				if rollbackErr := stage.rollback(); rollbackErr != nil {
					return nil, fmt.Errorf("Geo staging failed and rollback was incomplete: %w", rollbackErr)
				}
				return nil, err
			}
			stage.movedOld = append(stage.movedOld, name)
		} else if !errors.Is(err, os.ErrNotExist) {
			if rollbackErr := stage.rollback(); rollbackErr != nil {
				return nil, fmt.Errorf("Geo staging failed and rollback was incomplete: %w", rollbackErr)
			}
			return nil, err
		}
		if err := os.Rename(filepath.Join(candidateDir, name), target); err != nil {
			if rollbackErr := stage.rollback(); rollbackErr != nil {
				return nil, fmt.Errorf("Geo staging failed and rollback was incomplete: %w", rollbackErr)
			}
			return nil, err
		}
		stage.installed = append(stage.installed, name)
	}
	return stage, nil
}

func (s *geoDataSwap) rollback() error {
	if s == nil || s.rolledBack {
		return nil
	}
	var rollbackErr error
	previous := make(map[string]bool, len(s.movedOld))
	restored := make(map[string]bool, len(s.movedOld))
	for _, name := range s.movedOld {
		previous[name] = true
	}
	for i := len(s.installed) - 1; i >= 0; i-- {
		name := s.installed[i]
		if previous[name] {
			if err := os.Rename(filepath.Join(s.stageDir, "previous", name), filepath.Join(s.dir, name)); err != nil {
				if rollbackErr == nil {
					rollbackErr = err
				}
			} else {
				restored[name] = true
			}
		} else if err := os.Remove(filepath.Join(s.dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) && rollbackErr == nil {
			rollbackErr = err
		}
	}
	for i := len(s.movedOld) - 1; i >= 0; i-- {
		name := s.movedOld[i]
		if restored[name] {
			continue
		}
		if err := os.Rename(filepath.Join(s.stageDir, "previous", name), filepath.Join(s.dir, name)); err != nil && rollbackErr == nil {
			rollbackErr = err
		}
	}
	if rollbackErr == nil {
		rollbackErr = os.RemoveAll(s.stageDir)
	}
	if rollbackErr == nil {
		s.rolledBack = true
	}
	return rollbackErr
}

func (s *geoDataSwap) commit() {
	if s != nil {
		_ = os.RemoveAll(s.stageDir)
	}
}

func (a *API) updateGeoData(w http.ResponseWriter, r *http.Request) {
	a.subOp.Lock()
	defer a.subOp.Unlock()
	ctx, cancel := context.WithTimeout(r.Context(), geoUpdateTimeout)
	defer cancel()
	result, err := a.applyGeoDataUpdate(ctx)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (a *API) applyGeoDataUpdate(ctx context.Context) (map[string]any, error) {
	config, err := os.ReadFile(a.manager.configFile)
	if err != nil {
		return nil, errors.New("Mihomo configuration is unavailable")
	}
	files, err := geoDataFilesUsed(config)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, errors.New("the active configuration does not use Geo data")
	}
	if enabled, _, _, _ := a.manager.TunSettings(); enabled {
		return nil, errors.New("disable TUN before updating Geo data")
	}
	client := newSubscriptionClient(nil, nil)
	client.Timeout = geoAssetFetchTimeout
	release, err := fetchLatestRelease(ctx, client, "https://api.github.com/repos/MetaCubeX/meta-rules-dat/releases/latest")
	if err != nil {
		return nil, errors.New("Geo release metadata is unavailable")
	}
	candidates := make(map[string][]byte, len(files))
	var total int64
	for _, name := range files {
		asset, err := geoDataReleaseAsset(release, name)
		if err != nil {
			return nil, err
		}
		data, err := downloadGeoAsset(ctx, client, asset)
		if err != nil {
			return nil, err
		}
		total += int64(len(data))
		if total > maxGeoUpdateBytes {
			return nil, errors.New("Geo data update exceeds the size limit")
		}
		candidates[name] = data
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	status := a.manager.Status(ctx)
	wasRunning := status.ProcessAlive || status.DesiredRunning
	if wasRunning {
		if err := a.manager.Stop(ctx); err != nil {
			if restartErr := a.restartMihomoAfterGeoUpdate(); restartErr != nil {
				return nil, fmt.Errorf("could not stop Mihomo for the Geo data swap and restart failed: %w", restartErr)
			}
			return nil, errors.New("could not stop Mihomo for the Geo data swap")
		}
	}

	metadataPath := geoDataMetadataPath(a.stateDir)
	oldMetadata, metadataErr := os.ReadFile(metadataPath)
	metadataExisted := metadataErr == nil
	if metadataErr != nil && !errors.Is(metadataErr, os.ErrNotExist) {
		if wasRunning {
			if restartErr := a.restartMihomoAfterGeoUpdate(); restartErr != nil {
				return nil, fmt.Errorf("could not read current Geo update state and Mihomo restart failed: %w", restartErr)
			}
		}
		return nil, errors.New("could not read current Geo update state")
	}
	swap, err := stageGeoData(a.manager.runtimeDir, candidates)
	if err != nil {
		if wasRunning {
			if restartErr := a.restartMihomoAfterGeoUpdate(); restartErr != nil {
				return nil, fmt.Errorf("could not stage Geo data and Mihomo restart failed: %w", restartErr)
			}
		}
		return nil, err
	}
	rollback := func() error {
		if wasRunning {
			stopCtx, stopCancel := context.WithTimeout(context.Background(), 15*time.Second)
			stopErr := a.manager.Stop(stopCtx)
			stopCancel()
			if stopErr != nil {
				return fmt.Errorf("could not stop Mihomo before Geo rollback: %w", stopErr)
			}
		}
		fileErr := swap.rollback()
		if fileErr != nil {
			return fileErr
		}
		if metadataExisted {
			fileErr = atomicWrite(metadataPath, oldMetadata, 0600)
		} else if err := os.Remove(metadataPath); err != nil && !errors.Is(err, os.ErrNotExist) && fileErr == nil {
			fileErr = err
		}
		if wasRunning {
			if err := a.restartMihomoAfterGeoUpdate(); fileErr == nil {
				fileErr = err
			}
		}
		return fileErr
	}
	if err := a.testConfig(ctx, config); err != nil {
		rollbackErr := rollback()
		if rollbackErr != nil {
			return nil, fmt.Errorf("Geo data validation failed and rollback was incomplete: %w", rollbackErr)
		}
		return nil, errors.New("Mihomo rejected the updated Geo data; previous files were restored")
	}
	publishedAt, _ := time.Parse(time.RFC3339, release.PublishedAt)
	metadata := geoDataMetadata{Tag: release.TagName, PublishedAt: publishedAt, UpdatedAt: time.Now().UTC(), Files: make(map[string]string, len(candidates))}
	for name, data := range candidates {
		digest := sha256.Sum256(data)
		metadata.Files[name] = hex.EncodeToString(digest[:])
	}
	metadataBytes, _ := json.MarshalIndent(metadata, "", "  ")
	if err := atomicWrite(metadataPath, append(metadataBytes, '\n'), 0600); err != nil {
		rollbackErr := rollback()
		if rollbackErr != nil {
			return nil, fmt.Errorf("could not save Geo update state and rollback was incomplete: %w", rollbackErr)
		}
		return nil, errors.New("could not save Geo update state; previous files were restored")
	}
	if wasRunning {
		if err := a.manager.Start(ctx); err != nil {
			rollbackErr := rollback()
			if rollbackErr != nil {
				return nil, fmt.Errorf("Mihomo failed to restart and Geo rollback was incomplete: %w", rollbackErr)
			}
			return nil, errors.New("Mihomo failed to restart; previous Geo data was restored")
		}
	}
	swap.commit()
	return map[string]any{"updated": true, "tag": release.TagName, "published_at": publishedAt, "updated_at": metadata.UpdatedAt, "files": files}, nil
}

func (a *API) restartMihomoAfterGeoUpdate() error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return a.manager.Start(ctx)
}
