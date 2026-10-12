package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func dashboardTestZIP(t *testing.T, extra string, symlink bool) ([]byte, string) {
	t.Helper()
	var buffer bytes.Buffer
	w := zip.NewWriter(&buffer)
	for name, data := range map[string]string{
		"dist/index.html":             `<html><head><script src="./assets/app.js"></script></head></html>`,
		"dist/assets/app.js":          "console.log('test')",
		"dist/THIRD_PARTY_NOTICES.md": "notices",
	} {
		file, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write([]byte(data)); err != nil {
			t.Fatal(err)
		}
	}
	if extra != "" {
		header := &zip.FileHeader{Name: extra}
		if symlink {
			header.SetMode(os.ModeSymlink | 0777)
		}
		file, err := w.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write([]byte("unsafe")); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	data := buffer.Bytes()
	return data, fmt.Sprintf("sha256:%x", sha256.Sum256(data))
}

func TestDashboardZIPRejectsUnsafeEntries(t *testing.T) {
	for _, test := range []struct {
		name    string
		symlink bool
	}{
		{"dist/../../escape", false}, {"/tmp/escape", false}, {"dist/../escape", false},
		{"dist/assets/app.js", false}, {"dist/assets/link", true}, {"dist/a\\b", false},
	} {
		archive, digest := dashboardTestZIP(t, test.name, test.symlink)
		if err := extractDashboardArchive(archive, digest, t.TempDir()); err == nil {
			t.Errorf("accepted %q", test.name)
		}
	}
}

func TestDashboardZIPChecksDigestAndReferencedResources(t *testing.T) {
	archive, digest := dashboardTestZIP(t, "", false)
	if err := extractDashboardArchive(archive, "sha256:"+fmt.Sprintf("%064x", 0), t.TempDir()); err == nil {
		t.Fatal("accepted wrong digest")
	}
	dir := t.TempDir()
	if err := extractDashboardArchive(archive, digest, dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "assets", "app.js")); err != nil {
		t.Fatal(err)
	}
	if err := validateDashboardDirectory(dir); err == nil {
		t.Fatal("accepted missing entry-point script")
	}
}

func TestPinnedOfficialDashboardZIPIsAccepted(t *testing.T) {
	archive, err := os.ReadFile("../vendor/zashboard/v3.29.1-dist.zip")
	if err != nil {
		t.Fatal(err)
	}
	if err := extractDashboardArchive(archive, "sha256:4f16cce229e223bd07b5a3daccfbfb8bf349d7335572d412959284ab6c9bab50", t.TempDir()); err != nil {
		t.Fatal(err)
	}
}

func TestDashboardAssetRequiresOfficialDistributionAndDigest(t *testing.T) {
	asset := releaseAsset{Name: "dist.zip", URL: "https://github.com/Zephyruso/zashboard/releases/download/v3.29.1/dist.zip", Digest: fmt.Sprintf("sha256:%064x", 1), Size: 100}
	release := latestRelease{TagName: "v3.29.1", Assets: []releaseAsset{asset}}
	if _, err := dashboardReleaseAsset(release); err != nil {
		t.Fatal(err)
	}
	release.Assets[0].URL = "https://example.com/dist.zip"
	if _, err := dashboardReleaseAsset(release); err == nil {
		t.Fatal("accepted third-party source")
	}
	release.Assets[0] = asset
	release.Assets[0].Digest = ""
	if _, err := dashboardReleaseAsset(release); err == nil {
		t.Fatal("accepted missing digest")
	}
}
