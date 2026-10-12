package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	appReleaseRepository = "ch528/clash-for-inextos"
	appUpdateDirectory   = "/var/lib/inextos-clash-app-update"
	appUpdateUnit        = "inextos-clash-app-update.service"
	maxAppPackageBytes   = 128 << 20
	appUpdateTimeout     = 20 * time.Minute
)

var appReleaseTagPattern = regexp.MustCompile(`^v1\.0\.([0-9]+)$`)
var appVersionPattern = regexp.MustCompile(`^1\.0\.([0-9]+)$`)

type applicationUpdateStatus struct {
	State     string    `json:"state"`
	Current   string    `json:"current,omitempty"`
	Target    string    `json:"target,omitempty"`
	Message   string    `json:"message,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

func applicationReleaseURL(tag string) string {
	base := "https://api.github.com/repos/" + appReleaseRepository + "/releases"
	if tag == "" {
		return base + "/latest"
	}
	return base + "/tags/" + tag
}

func applicationReleaseAsset(release latestRelease) (releaseAsset, string, error) {
	match := appReleaseTagPattern.FindStringSubmatch(release.TagName)
	if len(match) != 2 || release.Draft || release.Prerelease {
		return releaseAsset{}, "", errors.New("application release is not a stable version")
	}
	appVersion := "1.0." + match[1]
	packageVersion, ok := debianPackageVersion(appVersion)
	if !ok {
		return releaseAsset{}, "", errors.New("application release version is invalid")
	}
	name := "inextos-clash_" + packageVersion + "_arm64.deb"
	expectedURL := "https://github.com/" + appReleaseRepository + "/releases/download/" + release.TagName + "/" + name
	var selected releaseAsset
	for _, asset := range release.Assets {
		if asset.Name != name {
			continue
		}
		if selected.Name != "" {
			return releaseAsset{}, "", errors.New("application release contains duplicate packages")
		}
		if asset.URL != expectedURL || asset.Size <= 0 || asset.Size > maxAppPackageBytes || !validSHA256Digest(asset.Digest) {
			return releaseAsset{}, "", errors.New("application package metadata is invalid")
		}
		selected = asset
	}
	if selected.Name == "" {
		return releaseAsset{}, "", errors.New("application release has no ARM64 package")
	}
	return selected, appVersion, nil
}

func debianPackageVersion(appVersion string) (string, bool) {
	match := appVersionPattern.FindStringSubmatch(appVersion)
	if len(match) != 2 {
		return "", false
	}
	patch, err := strconv.Atoi(match[1])
	if err != nil || patch < 1 || strconv.Itoa(patch) != match[1] {
		return "", false
	}
	return "1.0.0-" + strconv.Itoa(patch), true
}

func validSHA256Digest(digest string) bool {
	if !strings.HasPrefix(digest, "sha256:") {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(digest, "sha256:"))
	return err == nil && len(decoded) == sha256.Size
}

func applicationAssetDownloadSources(asset releaseAsset) []string {
	const officialPrefix = "https://github.com/" + appReleaseRepository + "/releases/download/"
	if !strings.HasPrefix(asset.URL, officialPrefix) {
		return nil
	}
	return []string{
		"https://gh-proxy.org/" + asset.URL,
		"https://ghfast.top/" + asset.URL,
		"https://ghproxy.net/" + asset.URL,
		asset.URL,
	}
}

func downloadApplicationPackage(ctx context.Context, client *http.Client, asset releaseAsset) ([]byte, error) {
	return downloadApplicationPackageFromSources(ctx, client, asset, applicationAssetDownloadSources(asset))
}

func downloadApplicationPackageFromSources(ctx context.Context, client *http.Client, asset releaseAsset, sources []string) ([]byte, error) {
	var lastErr error
	for _, source := range sources {
		sourceCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		request, err := http.NewRequestWithContext(sourceCtx, http.MethodGet, source, nil)
		if err == nil {
			request.Header.Set("User-Agent", "Clash-for-iNextOS")
			response, requestErr := client.Do(request)
			if requestErr == nil {
				data, readErr := io.ReadAll(io.LimitReader(response.Body, maxAppPackageBytes+1))
				_ = response.Body.Close()
				if readErr == nil && response.StatusCode == http.StatusOK && int64(len(data)) == asset.Size && verifySHA256(data, asset.Digest) {
					cancel()
					return data, nil
				}
				lastErr = errors.New("application package download or verification failed")
			} else {
				lastErr = errors.New("application package source is unavailable")
			}
		} else {
			lastErr = errors.New("application package source is invalid")
		}
		cancel()
		if ctx.Err() != nil {
			break
		}
	}
	if lastErr == nil {
		lastErr = errors.New("application package has no download source")
	}
	return nil, lastErr
}

func verifySHA256(data []byte, digest string) bool {
	if !validSHA256Digest(digest) {
		return false
	}
	want, _ := hex.DecodeString(strings.TrimPrefix(digest, "sha256:"))
	got := sha256.Sum256(data)
	return bytes.Equal(got[:], want)
}

func appPackageMetadataMatches(output, appVersion string) bool {
	wantVersion, ok := debianPackageVersion(appVersion)
	if !ok {
		return false
	}
	fields := strings.Split(strings.TrimSpace(output), "\n")
	want := []string{"Package: inextos-clash", "Version: " + wantVersion, "Architecture: arm64"}
	if len(fields) != len(want) {
		return false
	}
	for index := range fields {
		if strings.TrimSpace(fields[index]) != want[index] {
			return false
		}
	}
	return true
}

func verifyAppPackage(ctx context.Context, path, appVersion string) error {
	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	output, err := exec.CommandContext(probeCtx, "/usr/bin/dpkg-deb", "--field", path, "Package", "Version", "Architecture").CombinedOutput()
	if err != nil || !appPackageMetadataMatches(string(output), appVersion) {
		return errors.New("application package identity does not match its release")
	}
	return nil
}

func applicationUpdateStatusPath(directory string) string {
	return filepath.Join(directory, "status.json")
}

func writeApplicationUpdateStatus(directory string, status applicationUpdateStatus) error {
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("application update directory is unsafe")
	}
	if err := os.Chmod(directory, 0700); err != nil {
		return err
	}
	status.UpdatedAt = time.Now().UTC()
	data, err := json.Marshal(status)
	if err != nil {
		return err
	}
	return atomicWrite(applicationUpdateStatusPath(directory), append(data, '\n'), 0600)
}

func readApplicationUpdateStatus(directory string) (applicationUpdateStatus, error) {
	path := applicationUpdateStatusPath(directory)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return applicationUpdateStatus{State: "idle"}, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return applicationUpdateStatus{}, errors.New("application update status is unavailable")
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) > 4096 {
		return applicationUpdateStatus{}, errors.New("application update status is invalid")
	}
	var status applicationUpdateStatus
	if err := json.Unmarshal(data, &status); err != nil || status.State == "" {
		return applicationUpdateStatus{}, errors.New("application update status is invalid")
	}
	return status, nil
}

func runApplicationUpdateService() error {
	if os.Geteuid() != 0 {
		return errors.New("application update service requires root")
	}
	ctx, cancel := context.WithTimeout(context.Background(), appUpdateTimeout)
	defer cancel()
	status := applicationUpdateStatus{State: "checking", Current: appVersion, Message: "正在检查应用更新"}
	if err := writeApplicationUpdateStatus(appUpdateDirectory, status); err != nil {
		return err
	}
	fail := func(message string, err error) error {
		status.State, status.Message = "failed", message
		_ = writeApplicationUpdateStatus(appUpdateDirectory, status)
		return err
	}
	if applicationNetworkCaptureActive() {
		return fail("请先关闭网络接管后再更新", errors.New("network capture must be disabled before application update"))
	}
	currentPackageVersion, err := installedDebianVersion(ctx)
	if err != nil {
		return fail("无法读取当前安装版本", err)
	}
	expectedCurrent, ok := debianPackageVersion(appVersion)
	if !ok || currentPackageVersion != expectedCurrent {
		return fail("当前安装版本与应用版本不一致", errors.New("installed package version does not match the running application"))
	}
	client := newSubscriptionClient(nil, nil)
	client.Timeout = 10 * time.Second
	release, err := fetchLatestRelease(ctx, client, applicationReleaseURL(""))
	if err != nil {
		return fail("发布源暂不可用", err)
	}
	candidateAsset, targetVersion, err := applicationReleaseAsset(release)
	if err != nil {
		return fail("无法验证应用发布包", err)
	}
	if newer, valid := versionIsNewer(targetVersion, appVersion); !valid || !newer {
		status.State, status.Target, status.Message = "no_update", targetVersion, "当前已是最新版本"
		return writeApplicationUpdateStatus(appUpdateDirectory, status)
	}
	status.Target, status.State, status.Message = targetVersion, "downloading", "正在下载并验证更新包"
	if err := writeApplicationUpdateStatus(appUpdateDirectory, status); err != nil {
		return err
	}
	client.Timeout = 5 * time.Minute
	candidate, err := downloadApplicationPackage(ctx, client, candidateAsset)
	if err != nil {
		return fail("应用包下载或校验失败", err)
	}
	if err := ensureApplicationUpdateDirectory(appUpdateDirectory); err != nil {
		return fail("无法准备更新目录", err)
	}
	candidatePath := filepath.Join(appUpdateDirectory, "candidate.deb")
	if err := atomicWrite(candidatePath, candidate, 0600); err != nil {
		return fail("无法保存更新包", err)
	}
	if err := verifyAppPackage(ctx, candidatePath, targetVersion); err != nil {
		return fail("更新包与发布版本不匹配", err)
	}
	previousRelease, err := fetchLatestRelease(ctx, client, "https://api.github.com/repos/"+appReleaseRepository+"/releases/tags/v"+appVersion)
	if err != nil {
		return fail("无法准备当前版本的回滚包", err)
	}
	previousAsset, previousVersion, err := applicationReleaseAsset(previousRelease)
	if err != nil || previousVersion != appVersion {
		return fail("无法准备当前版本的回滚包", errors.New("current release package is unavailable"))
	}
	status.Message = "正在下载当前版本作为回滚保护"
	if err := writeApplicationUpdateStatus(appUpdateDirectory, status); err != nil {
		return err
	}
	previous, err := downloadApplicationPackage(ctx, client, previousAsset)
	if err != nil {
		return fail("无法准备当前版本的回滚包", err)
	}
	previousPath := filepath.Join(appUpdateDirectory, "previous.deb")
	if err := atomicWrite(previousPath, previous, 0600); err != nil {
		return fail("无法保存当前版本的回滚包", err)
	}
	if err := verifyAppPackage(ctx, previousPath, appVersion); err != nil {
		return fail("当前版本回滚包校验失败", err)
	}
	status.State, status.Message = "installing", "正在安装更新并重启服务"
	if err := writeApplicationUpdateStatus(appUpdateDirectory, status); err != nil {
		return err
	}
	rolledBack, installErr := applyApplicationUpdate(ctx, candidatePath, previousPath, targetVersion, appVersion, installDebianPackage, waitForApplicationVersion)
	if installErr != nil {
		if rolledBack {
			status.State, status.Message = "rolled_back", "新版本未通过启动检查，已恢复当前版本"
		} else {
			status.State, status.Message = "failed", "更新失败，自动恢复未能完成"
		}
		_ = writeApplicationUpdateStatus(appUpdateDirectory, status)
		return installErr
	}
	status.State, status.Message = "succeeded", "更新完成，当前版本 "+targetVersion
	return writeApplicationUpdateStatus(appUpdateDirectory, status)
}

func applicationNetworkCaptureActive() bool {
	if runtimeTunEnabled() {
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "/usr/bin/systemctl", "is-active", "--quiet", mihomoUnit).Run() == nil
}

func ensureApplicationUpdateDirectory(directory string) error {
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("application update directory is unsafe")
	}
	if err := os.Chmod(directory, 0700); err != nil {
		return err
	}
	return nil
}

func installedDebianVersion(ctx context.Context) (string, error) {
	output, err := exec.CommandContext(ctx, "/usr/bin/dpkg-query", "-W", "-f=${Version}", "inextos-clash").Output()
	if err != nil {
		return "", errors.New("could not read installed Debian package version")
	}
	return strings.TrimSpace(string(output)), nil
}

func installDebianPackage(ctx context.Context, path string) error {
	cmd := exec.CommandContext(ctx, "/usr/bin/dpkg", "--force-confold", "--install", path)
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	output, err := cmd.CombinedOutput()
	if err != nil {
		_ = output
		return errors.New("dpkg could not install the application package")
	}
	return nil
}

func waitForApplicationVersion(ctx context.Context, expectedVersion string) error {
	checkCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	settings, err := loadSettings(applicationConfig)
	if err != nil {
		return err
	}
	var healthURL string
	for _, listener := range settings.Server.Listeners {
		host, port, splitErr := splitListener(listener)
		if splitErr == nil {
			if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
				healthURL = "http://" + net.JoinHostPort(host, strconv.Itoa(port)) + "/api/health"
				break
			}
		}
	}
	if healthURL == "" {
		return errors.New("application loopback health endpoint is unavailable")
	}
	client := &http.Client{Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if version, versionErr := installedDebianVersion(checkCtx); versionErr == nil {
			want, ok := debianPackageVersion(expectedVersion)
			if ok && version == want {
				request, _ := http.NewRequestWithContext(checkCtx, http.MethodGet, healthURL, nil)
				if request != nil {
					if response, requestErr := client.Do(request); requestErr == nil {
						_ = response.Body.Close()
						if response.StatusCode == http.StatusOK {
							return nil
						}
					}
				}
			}
		}
		select {
		case <-checkCtx.Done():
			return errors.New("application did not pass its post-update health check")
		case <-ticker.C:
		}
	}
}

func applyApplicationUpdate(ctx context.Context, candidatePath, previousPath, targetVersion, previousVersion string, install func(context.Context, string) error, waitHealthy func(context.Context, string) error) (bool, error) {
	installErr := install(ctx, candidatePath)
	if installErr == nil {
		installErr = waitHealthy(ctx, targetVersion)
	}
	if installErr == nil {
		return false, nil
	}
	rollbackCtx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if err := install(rollbackCtx, previousPath); err != nil {
		return false, fmt.Errorf("application update failed and package rollback failed: %w", err)
	}
	if err := waitHealthy(rollbackCtx, previousVersion); err != nil {
		return false, fmt.Errorf("application package rolled back but health recovery failed: %w", err)
	}
	return true, fmt.Errorf("new application version failed health verification: %w", installErr)
}

func (a *API) updateApplication(w http.ResponseWriter, r *http.Request) {
	if networkCaptureActive(a.manager.RuntimeConfig()) {
		writeError(w, http.StatusConflict, "请先关闭网络接管，再更新 Clash for iNextOS")
		return
	}
	if _, err := callPrivilegedHelper(r.Context(), "app-update-start"); err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"started": true, "message": "应用更新已启动"})
}

func (a *API) applicationUpdateStatus(w http.ResponseWriter, r *http.Request) {
	response, err := callPrivilegedHelper(r.Context(), "app-update-status")
	if err != nil || response.ApplicationUpdate == nil {
		writeError(w, http.StatusServiceUnavailable, "无法读取应用更新状态")
		return
	}
	writeJSON(w, http.StatusOK, response.ApplicationUpdate)
}
