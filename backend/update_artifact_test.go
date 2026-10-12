package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func testARM64ELF() []byte {
	header := make([]byte, 64)
	copy(header, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(header[16:], 2)
	binary.LittleEndian.PutUint16(header[18:], 183)
	binary.LittleEndian.PutUint32(header[20:], 1)
	binary.LittleEndian.PutUint16(header[52:], 64)
	return header
}

func gzipArtifact(t *testing.T, data []byte) ([]byte, string) {
	t.Helper()
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	if _, err := writer.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	archive := buffer.Bytes()
	return archive, fmt.Sprintf("sha256:%x", sha256.Sum256(archive))
}

func TestMihomoAssetSelectionRejectsUntrustedMetadata(t *testing.T) {
	asset := releaseAsset{Name: "mihomo-linux-arm64-v1.2.3.gz", URL: "https://github.com/MetaCubeX/mihomo/releases/download/v1.2.3/mihomo-linux-arm64-v1.2.3.gz", Size: 100, Digest: fmt.Sprintf("sha256:%x", sha256.Sum256([]byte("data")))}
	release := latestRelease{TagName: "v1.2.3", Assets: []releaseAsset{asset}}
	if _, err := mihomoARM64Asset(release); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*latestRelease){
		func(r *latestRelease) { r.Prerelease = true },
		func(r *latestRelease) { r.TagName = "latest" },
		func(r *latestRelease) { r.Assets[0].URL = "https://example.com/mihomo.gz" },
		func(r *latestRelease) { r.Assets[0].Digest = "" },
		func(r *latestRelease) { r.Assets[0].Size = maxMihomoArchiveBytes + 1 },
		func(r *latestRelease) { r.Assets = append(r.Assets, r.Assets[0]) },
	} {
		candidate := latestRelease{TagName: release.TagName, Assets: append([]releaseAsset(nil), release.Assets...)}
		mutate(&candidate)
		if _, err := mihomoARM64Asset(candidate); err == nil {
			t.Fatal("accepted invalid release metadata")
		}
	}
}

func TestMihomoAssetDownloadSourcesMirrorOnlyOfficialAssets(t *testing.T) {
	asset := releaseAsset{URL: "https://github.com/MetaCubeX/mihomo/releases/download/v1.2.3/mihomo-linux-arm64-v1.2.3.gz"}
	sources := mihomoAssetDownloadSources(asset)
	if len(sources) != 4 || sources[0] != "https://gh-proxy.org/"+asset.URL || sources[1] != "https://ghfast.top/"+asset.URL || sources[2] != "https://ghproxy.net/"+asset.URL || sources[3] != asset.URL {
		t.Fatalf("unexpected official download sources: %v", sources)
	}
	untrusted := releaseAsset{URL: "https://example.com/file.gz"}
	if got := mihomoAssetDownloadSources(untrusted); len(got) != 1 || got[0] != untrusted.URL {
		t.Fatalf("untrusted URL was sent through a mirror: %v", got)
	}
}

func TestMihomoArtifactChecksDigestAndArchitecture(t *testing.T) {
	executable := testARM64ELF()
	archive, digest := gzipArtifact(t, executable)
	decoded, err := decodeMihomoArtifact(archive, digest)
	if err != nil || !bytes.Equal(decoded, executable) {
		t.Fatalf("valid ARM64 artifact rejected: %v", err)
	}
	if _, err := decodeMihomoArtifact(archive, "sha256:"+fmt.Sprintf("%064x", 0)); err == nil {
		t.Fatal("accepted checksum mismatch")
	}
	binary.LittleEndian.PutUint16(executable[18:], 62)
	wrong, wrongDigest := gzipArtifact(t, executable)
	if _, err := decodeMihomoArtifact(wrong, wrongDigest); err == nil {
		t.Fatal("accepted AMD64 executable")
	}
	corrupt, corruptDigest := gzipArtifact(t, []byte("not an executable"))
	if _, err := decodeMihomoArtifact(corrupt, corruptDigest); err == nil {
		t.Fatal("accepted non-ELF content")
	}
}

func TestMihomoDownloadRejectsTruncatedAsset(t *testing.T) {
	archive, digest := gzipArtifact(t, testARM64ELF())
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(archive) }))
	defer server.Close()
	asset := releaseAsset{URL: server.URL, Digest: digest, Size: int64(len(archive)) + 1}
	if _, err := downloadMihomoArtifact(context.Background(), server.Client(), asset); err == nil {
		t.Fatal("accepted truncated asset")
	}
	asset.Size--
	if _, err := downloadMihomoArtifact(context.Background(), server.Client(), asset); err != nil {
		t.Fatal(err)
	}
}

func TestMihomoDownloadFallsBackToAvailableMirror(t *testing.T) {
	archive, digest := gzipArtifact(t, testARM64ELF())
	var firstGets atomic.Int32
	failed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		firstGets.Add(1)
		_, _ = w.Write(archive)
	}))
	defer failed.Close()
	working := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(len(archive)))
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write(archive)
	}))
	defer working.Close()

	asset := releaseAsset{URL: "https://github.com/MetaCubeX/mihomo/releases/download/v1.2.3/mihomo-linux-arm64-v1.2.3.gz", Size: int64(len(archive)), Digest: digest}
	got, err := downloadMihomoArtifactFromSources(context.Background(), working.Client(), asset, []string{failed.URL, working.URL})
	if err != nil || !bytes.Equal(got, testARM64ELF()) {
		t.Fatalf("available source was not accepted: err=%v", err)
	}
	if firstGets.Load() != 0 {
		t.Fatal("downloaded from a source whose probe failed")
	}
}

func TestMihomoDownloadReportsInterruptedBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		_, _ = w.Write([]byte("partial"))
	}))
	defer server.Close()
	_, err := downloadMihomoArtifact(context.Background(), server.Client(), releaseAsset{URL: server.URL, Size: 100})
	if err == nil || !strings.Contains(err.Error(), "interrupted") {
		t.Fatalf("interrupted body error = %v", err)
	}
}
