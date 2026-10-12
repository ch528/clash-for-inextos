package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

const maxDashboardArchiveBytes = 32 << 20
const maxDashboardExtractedBytes = 128 << 20

func dashboardReleaseAsset(release latestRelease) (releaseAsset, error) {
	if release.TagName == "" || release.Draft || release.Prerelease || versionPattern.FindString(release.TagName) != release.TagName {
		return releaseAsset{}, errors.New("Zashboard update requires a stable versioned release")
	}
	var selected releaseAsset
	for _, asset := range release.Assets {
		if asset.Name != "dist.zip" {
			continue
		}
		if selected.Name != "" {
			return releaseAsset{}, errors.New("duplicate Zashboard distribution assets")
		}
		if asset.URL != "https://github.com/Zephyruso/zashboard/releases/download/"+release.TagName+"/dist.zip" || asset.Size <= 0 || asset.Size > maxDashboardArchiveBytes {
			return releaseAsset{}, errors.New("Zashboard distribution metadata is invalid")
		}
		digest, err := hex.DecodeString(strings.TrimPrefix(asset.Digest, "sha256:"))
		if !strings.HasPrefix(asset.Digest, "sha256:") || err != nil || len(digest) != sha256.Size {
			return releaseAsset{}, errors.New("Zashboard distribution has no valid SHA-256 digest")
		}
		selected = asset
	}
	if selected.Name == "" {
		return releaseAsset{}, errors.New("Zashboard release has no dist.zip asset")
	}
	return selected, nil
}

// Destination is a new private staging directory; it is never the active panel.
func extractDashboardArchive(archive []byte, digest, destination string) error {
	if len(archive) > maxDashboardArchiveBytes {
		return errors.New("Zashboard archive exceeds the limit")
	}
	expected, err := hex.DecodeString(strings.TrimPrefix(digest, "sha256:"))
	actual := sha256.Sum256(archive)
	if !strings.HasPrefix(digest, "sha256:") || err != nil || !bytes.Equal(expected, actual[:]) {
		return errors.New("Zashboard SHA-256 verification failed")
	}
	reader, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil || len(reader.File) > 10000 {
		return errors.New("Zashboard ZIP is invalid or contains too many entries")
	}
	seen := make(map[string]bool)
	var total int64
	for _, entry := range reader.File {
		name := entry.Name
		if name == "dist/" && entry.FileInfo().IsDir() {
			continue
		}
		if !strings.HasPrefix(name, "dist/") || strings.Contains(name, "\\") || strings.ContainsRune(name, 0) {
			return errors.New("Zashboard ZIP contains an unsafe path")
		}
		rel := strings.TrimPrefix(name, "dist/")
		clean := path.Clean(rel)
		if clean == "." || strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "/") || strings.TrimSuffix(rel, "/") != clean || seen[clean] {
			return errors.New("Zashboard ZIP contains an unsafe or duplicate path")
		}
		seen[clean] = true
		if entry.Mode()&os.ModeSymlink != 0 || (!entry.FileInfo().IsDir() && !entry.Mode().IsRegular()) {
			return errors.New("Zashboard ZIP contains a special file")
		}
		target := filepath.Join(destination, filepath.FromSlash(clean))
		if entry.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0700); err != nil {
				return err
			}
			continue
		}
		if entry.UncompressedSize64 > maxDashboardExtractedBytes || total+int64(entry.UncompressedSize64) > maxDashboardExtractedBytes {
			return errors.New("Zashboard extracted files exceed the limit")
		}
		if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			return err
		}
		source, err := entry.Open()
		if err != nil {
			return errors.New("Zashboard ZIP entry is invalid")
		}
		data, readErr := io.ReadAll(io.LimitReader(source, maxDashboardExtractedBytes-total+1))
		_ = source.Close()
		if readErr != nil || int64(len(data))+total > maxDashboardExtractedBytes || uint64(len(data)) != entry.UncompressedSize64 {
			return errors.New("Zashboard ZIP entry is corrupt or oversized")
		}
		total += int64(len(data))
		if err := os.WriteFile(target, data, 0600); err != nil {
			return err
		}
	}
	return validateDashboardDirectory(destination)
}

var dashboardResourcePattern = regexp.MustCompile(`(?:src|href)="\./([^"?#]+)"`)

func validateDashboardDirectory(directory string) error {
	index, err := os.ReadFile(filepath.Join(directory, "index.html"))
	if err != nil || !bytes.Contains(index, []byte("</head>")) || !bytes.Contains(index, []byte("assets/")) {
		return errors.New("Zashboard entry page is missing or invalid")
	}
	hasScript := false
	for _, match := range dashboardResourcePattern.FindAllSubmatch(index, -1) {
		name := string(match[1])
		if strings.HasPrefix(name, "assets/") && strings.HasSuffix(name, ".js") {
			hasScript = true
		}
		if path.Clean(name) != name || strings.HasPrefix(name, "../") || strings.HasPrefix(name, "/") {
			return errors.New("Zashboard entry page references an unsafe resource")
		}
		info, err := os.Stat(filepath.Join(directory, filepath.FromSlash(name)))
		if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
			return errors.New("Zashboard entry page references a missing resource")
		}
	}
	if !hasScript {
		return errors.New("Zashboard entry script is missing")
	}
	info, err := os.Stat(filepath.Join(directory, "THIRD_PARTY_NOTICES.md"))
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		return errors.New("Zashboard third-party notices are missing")
	}
	return nil
}
