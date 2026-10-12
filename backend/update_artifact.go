package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	maxMihomoArchiveBytes    = 48 << 20
	maxMihomoBinaryBytes     = 128 << 20
	mihomoMirrorProbeTimeout = 5 * time.Second
	mihomoMirrorFetchTimeout = 2 * time.Minute
)

type releaseAsset struct {
	Name   string `json:"name"`
	URL    string `json:"browser_download_url"`
	Digest string `json:"digest"`
	Size   int64  `json:"size"`
}

func mihomoARM64Asset(release latestRelease) (releaseAsset, error) {
	if release.TagName == "" || release.Draft || release.Prerelease || versionPattern.FindString(release.TagName) != release.TagName {
		return releaseAsset{}, errors.New("Mihomo update requires a stable versioned release")
	}
	name := "mihomo-linux-arm64-" + release.TagName + ".gz"
	expectedURL := "https://github.com/MetaCubeX/mihomo/releases/download/" + release.TagName + "/" + name
	var selected releaseAsset
	found := false
	for _, asset := range release.Assets {
		if asset.Name != name {
			continue
		}
		if found {
			return releaseAsset{}, errors.New("Mihomo release contains duplicate ARM64 assets")
		}
		found = true
		u, err := url.Parse(asset.URL)
		if err != nil || u.String() != expectedURL || asset.Size <= 0 || asset.Size > maxMihomoArchiveBytes {
			return releaseAsset{}, errors.New("Mihomo ARM64 asset metadata is invalid")
		}
		digest, err := hex.DecodeString(strings.TrimPrefix(asset.Digest, "sha256:"))
		if !strings.HasPrefix(asset.Digest, "sha256:") || err != nil || len(digest) != sha256.Size {
			return releaseAsset{}, errors.New("Mihomo ARM64 asset has no valid SHA-256 digest")
		}
		selected = asset
	}
	if !found {
		return releaseAsset{}, errors.New("Mihomo release has no Linux ARM64 gzip asset")
	}
	return selected, nil
}

func mihomoAssetDownloadSources(asset releaseAsset) []string {
	const officialPrefix = "https://github.com/MetaCubeX/mihomo/releases/download/"
	if !strings.HasPrefix(asset.URL, officialPrefix) {
		return []string{asset.URL}
	}
	return []string{
		"https://gh-proxy.org/" + asset.URL,
		"https://ghfast.top/" + asset.URL,
		"https://ghproxy.net/" + asset.URL,
		asset.URL,
	}
}

// The caller uses a public-IP-pinned client and verifies every source against GitHub's digest.
func downloadMihomoArtifact(ctx context.Context, client *http.Client, asset releaseAsset) ([]byte, error) {
	return downloadMihomoArtifactFromSources(ctx, client, asset, mihomoAssetDownloadSources(asset))
}

func downloadMihomoArtifactFromSources(ctx context.Context, client *http.Client, asset releaseAsset, sources []string) ([]byte, error) {
	var lastErr error
	for index, source := range sources {
		sourceCtx := ctx
		cancel := func() {}
		if index < len(sources)-1 {
			sourceCtx, cancel = context.WithTimeout(ctx, mihomoMirrorFetchTimeout)
		}
		if err := probeMihomoArtifactSource(sourceCtx, client, source); err != nil {
			lastErr = err
			cancel()
			if ctx.Err() != nil {
				break
			}
			continue
		}
		binary, err := downloadMihomoArtifactFromSource(sourceCtx, client, source, asset)
		cancel()
		if err == nil {
			return binary, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	if lastErr == nil {
		lastErr = errors.New("Mihomo asset has no download sources")
	}
	return nil, lastErr
}

func probeMihomoArtifactSource(ctx context.Context, client *http.Client, source string) error {
	probeCtx, cancel := context.WithTimeout(ctx, mihomoMirrorProbeTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(probeCtx, http.MethodHead, source, nil)
	if err != nil {
		return errors.New("invalid Mihomo asset probe")
	}
	request.Header.Set("User-Agent", "Clash-for-iNextOS")
	response, err := client.Do(request)
	if err != nil {
		return errors.New("Mihomo asset source probe failed")
	}
	_ = response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return errors.New("Mihomo asset source is unavailable")
	}
	return nil
}

func downloadMihomoArtifactFromSource(ctx context.Context, client *http.Client, source string, asset releaseAsset) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return nil, errors.New("invalid Mihomo asset request")
	}
	request.Header.Set("User-Agent", "Clash-for-iNextOS")
	response, err := client.Do(request)
	if err != nil {
		return nil, errors.New("Mihomo asset download failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("Mihomo asset server did not return HTTP 200")
	}
	archive, err := io.ReadAll(io.LimitReader(response.Body, maxMihomoArchiveBytes+1))
	if err != nil {
		return nil, errors.New("Mihomo asset download was interrupted")
	}
	if len(archive) > maxMihomoArchiveBytes || int64(len(archive)) != asset.Size {
		return nil, fmt.Errorf("Mihomo asset size does not match release metadata (received %d, expected %d bytes)", len(archive), asset.Size)
	}
	return decodeMihomoArtifact(archive, asset.Digest)
}

func decodeMihomoArtifact(archive []byte, digest string) ([]byte, error) {
	if len(archive) > maxMihomoArchiveBytes {
		return nil, errors.New("Mihomo archive exceeds the limit")
	}
	expected, err := hex.DecodeString(strings.TrimPrefix(digest, "sha256:"))
	actual := sha256.Sum256(archive)
	if !strings.HasPrefix(digest, "sha256:") || err != nil || !bytes.Equal(expected, actual[:]) {
		return nil, errors.New("Mihomo asset SHA-256 verification failed")
	}
	reader, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, errors.New("Mihomo asset is not a valid gzip archive")
	}
	defer reader.Close()
	binary, err := io.ReadAll(io.LimitReader(reader, maxMihomoBinaryBytes+1))
	if err != nil || len(binary) > maxMihomoBinaryBytes {
		return nil, errors.New("Mihomo binary exceeds the limit or is corrupt")
	}
	file, err := elf.NewFile(bytes.NewReader(binary))
	if err != nil {
		return nil, errors.New("Mihomo asset is not an ELF executable")
	}
	defer file.Close()
	if file.Class != elf.ELFCLASS64 || file.Data != elf.ELFDATA2LSB || file.Machine != elf.EM_AARCH64 || (file.Type != elf.ET_EXEC && file.Type != elf.ET_DYN) {
		return nil, errors.New("Mihomo executable is not Linux ARM64")
	}
	return binary, nil
}
