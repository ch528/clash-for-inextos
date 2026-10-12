package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func appReleaseFixture(version string) latestRelease {
	patch := strings.TrimPrefix(version, "1.0.")
	tag := "v" + version
	name := "inextos-clash_1.0.0-" + patch + "_arm64.deb"
	return latestRelease{
		TagName: tag,
		Assets: []releaseAsset{{
			Name:   name,
			URL:    "https://github.com/" + appReleaseRepository + "/releases/download/" + tag + "/" + name,
			Digest: "sha256:" + strings.Repeat("a", 64),
			Size:   1024,
		}},
	}
}

func TestApplicationReleaseAssetRequiresExactPackageAndDigest(t *testing.T) {
	release := appReleaseFixture("1.0.35")
	asset, version, err := applicationReleaseAsset(release)
	if err != nil || version != "1.0.35" || asset.Name != "inextos-clash_1.0.0-35_arm64.deb" {
		t.Fatalf("valid application release = (%+v, %q, %v)", asset, version, err)
	}

	invalid := []latestRelease{release, release, release, release, release}
	invalid[0].Assets[0].URL = "https://example.com/package.deb"
	invalid[1].Assets[0].Digest = ""
	invalid[2].TagName = "v1.1.35"
	invalid[3].Prerelease = true
	invalid[4].Assets = append(invalid[4].Assets, invalid[4].Assets[0])
	for _, candidate := range invalid {
		if _, _, err := applicationReleaseAsset(candidate); err == nil {
			t.Fatalf("invalid release accepted: %+v", candidate)
		}
	}
}

func TestDebianPackageVersionUsesAboutVersionRule(t *testing.T) {
	if got, ok := debianPackageVersion("1.0.35"); !ok || got != "1.0.0-35" {
		t.Fatalf("package version = (%q, %v)", got, ok)
	}
	for _, version := range []string{"1.0.0", "1.0.035", "1.1.35", "1.0.35-rc1"} {
		if _, ok := debianPackageVersion(version); ok {
			t.Errorf("invalid app version %q accepted", version)
		}
	}
}

func TestAppPackageMetadataMatchesReleaseVersion(t *testing.T) {
	valid := "Package: inextos-clash\nVersion: 1.0.0-35\nArchitecture: arm64\n"
	if !appPackageMetadataMatches(valid, "1.0.35") {
		t.Fatal("matching ARM64 package metadata was rejected")
	}
	for _, output := range []string{
		"Package: another-package\nVersion: 1.0.0-35\nArchitecture: arm64\n",
		"Package: inextos-clash\nVersion: 1.0.0-34\nArchitecture: arm64\n",
		"Package: inextos-clash\nVersion: 1.0.0-35\nArchitecture: amd64\n",
	} {
		if appPackageMetadataMatches(output, "1.0.35") {
			t.Errorf("mismatched package metadata accepted: %q", output)
		}
	}
}

func TestDownloadApplicationPackageChecksSizeAndSHA256(t *testing.T) {
	data := []byte("verified Debian package bytes")
	digest := sha256.Sum256(data)
	asset := releaseAsset{Size: int64(len(data)), Digest: "sha256:" + hex.EncodeToString(digest[:])}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Header.Get("User-Agent") != "Clash-for-iNextOS" {
			t.Errorf("unexpected package request: method=%q user-agent=%q", r.Method, r.Header.Get("User-Agent"))
		}
		_, _ = w.Write(data)
	}))
	defer server.Close()
	client := server.Client()
	got, err := downloadApplicationPackageFromSources(context.Background(), client, asset, []string{server.URL})
	if err != nil || string(got) != string(data) {
		t.Fatalf("verified download = %q, %v", got, err)
	}
	asset.Digest = "sha256:" + strings.Repeat("0", 64)
	if _, err := downloadApplicationPackageFromSources(context.Background(), client, asset, []string{server.URL}); err == nil {
		t.Fatal("package with mismatched digest was accepted")
	}
	asset.Size++
	if _, err := downloadApplicationPackageFromSources(context.Background(), client, asset, []string{server.URL}); err == nil {
		t.Fatal("package with mismatched size was accepted")
	}
}

func TestApplyApplicationUpdateRollsBackAfterHealthFailure(t *testing.T) {
	installed := "1.0.35"
	var installs []string
	install := func(_ context.Context, path string) error {
		installs = append(installs, filepath.Base(path))
		if strings.HasPrefix(filepath.Base(path), "candidate") {
			installed = "1.0.36"
		} else {
			installed = "1.0.35"
		}
		return nil
	}
	waitHealthy := func(_ context.Context, version string) error {
		if version == "1.0.36" {
			return fmt.Errorf("candidate health failure")
		}
		if installed != version {
			return fmt.Errorf("installed version mismatch")
		}
		return nil
	}
	rolledBack, err := applyApplicationUpdate(context.Background(), "/tmp/candidate.deb", "/tmp/previous.deb", "1.0.36", "1.0.35", install, waitHealthy)
	if err == nil || !rolledBack || installed != "1.0.35" {
		t.Fatalf("rollback result = (rolledBack=%v, installed=%q, err=%v)", rolledBack, installed, err)
	}
	if strings.Join(installs, ",") != "candidate.deb,previous.deb" {
		t.Fatalf("package installation order = %v", installs)
	}
}

func TestApplicationUpdateStatusRoundTripAndSafePath(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "update")
	want := applicationUpdateStatus{State: "downloading", Current: "1.0.35", Target: "1.0.36", Message: "正在下载并验证更新包"}
	if err := writeApplicationUpdateStatus(directory, want); err != nil {
		t.Fatal(err)
	}
	got, err := readApplicationUpdateStatus(directory)
	if err != nil || got.State != want.State || got.Current != want.Current || got.Target != want.Target {
		t.Fatalf("status = %+v, %v", got, err)
	}
	if got.UpdatedAt.IsZero() {
		t.Fatal("status timestamp is missing")
	}
	symlink := filepath.Join(t.TempDir(), "unsafe")
	if err := os.Symlink(t.TempDir(), symlink); err != nil {
		t.Fatal(err)
	}
	if err := writeApplicationUpdateStatus(symlink, want); err == nil {
		t.Fatal("symlink update directory was accepted")
	}
}
