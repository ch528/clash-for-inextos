package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestGeoDataFilesUseOnlyActiveRuleFormats(t *testing.T) {
	for _, test := range []struct {
		name   string
		config string
		want   []string
	}{
		{name: "unused", config: "rules:\n  - MATCH,DIRECT\n"},
		{name: "default-ip-database", config: "rules:\n  - GEOIP,CN,DIRECT\n", want: []string{"geoip.metadb"}},
		{name: "dat-ip-database", config: "geodata-mode: true\nrules:\n  - GEOIP,CN,DIRECT\n", want: []string{"geoip.dat"}},
		{name: "site-and-ip", config: "geodata-mode: true\nrules:\n  - GEOSITE,cn,DIRECT\n  - GEOIP,CN,DIRECT\n", want: []string{"geoip.dat", "geosite.dat"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := geoDataFilesUsed([]byte(test.config))
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(test.want) {
				t.Fatalf("files = %v, want %v", got, test.want)
			}
			for i := range got {
				if got[i] != test.want[i] {
					t.Fatalf("files = %v, want %v", got, test.want)
				}
			}
		})
	}
}

func TestGeoReleaseAssetRequiresFixedOfficialURLAndDigest(t *testing.T) {
	data := []byte("geo database")
	digest := sha256.Sum256(data)
	asset := releaseAsset{
		Name:   "geoip.metadb",
		URL:    "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.metadb",
		Digest: "sha256:" + hex.EncodeToString(digest[:]),
		Size:   int64(len(data)),
	}
	release := latestRelease{TagName: "latest", Assets: []releaseAsset{asset}}
	if _, err := geoDataReleaseAsset(release, "geoip.metadb"); err != nil {
		t.Fatalf("valid release asset rejected: %v", err)
	}
	if _, err := verifyGeoAsset(data, asset); err != nil {
		t.Fatalf("valid data rejected: %v", err)
	}
	asset.URL = "https://example.invalid/geoip.metadb"
	release.Assets = []releaseAsset{asset}
	if _, err := geoDataReleaseAsset(release, "geoip.metadb"); err == nil {
		t.Fatal("non-official asset URL accepted")
	}
	asset.URL = "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.metadb"
	asset.Digest = "sha256:" + hex.EncodeToString(make([]byte, sha256.Size))
	release.Assets = []releaseAsset{asset}
	if _, err := geoDataReleaseAsset(release, "geoip.metadb"); err != nil {
		t.Fatalf("well-formed digest metadata rejected: %v", err)
	}
	release.TagName = "../latest"
	if _, err := geoDataReleaseAsset(release, "geoip.metadb"); err == nil {
		t.Fatal("unsafe release tag accepted")
	}
	if _, err := verifyGeoAsset(data, asset); err == nil {
		t.Fatal("incorrect digest accepted")
	}
}

func TestGeoDataSwapRollsBackAllFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "geoip.metadb"), []byte("old-ip"), 0600); err != nil {
		t.Fatal(err)
	}
	swap, err := stageGeoData(dir, map[string][]byte{
		"geoip.metadb": []byte("new-ip"),
		"geosite.dat":  []byte("new-site"),
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"geoip.metadb": "new-ip", "geosite.dat": "new-site"} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || string(data) != want {
			t.Fatalf("staged %s = %q, error %v", name, data, err)
		}
	}
	if err := swap.rollback(); err != nil {
		t.Fatal(err)
	}
	ipData, err := os.ReadFile(filepath.Join(dir, "geoip.metadb"))
	if err != nil || string(ipData) != "old-ip" {
		t.Fatalf("old IP database not restored: %q, error %v", ipData, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "geosite.dat")); !os.IsNotExist(err) {
		t.Fatalf("new site database remains after rollback: %v", err)
	}
}

func TestGeoDataSwapCommitKeepsNewFiles(t *testing.T) {
	dir := t.TempDir()
	swap, err := stageGeoData(dir, map[string][]byte{"geosite.dat": []byte("site")})
	if err != nil {
		t.Fatal(err)
	}
	swap.commit()
	data, err := os.ReadFile(filepath.Join(dir, "geosite.dat"))
	if err != nil || string(data) != "site" {
		t.Fatalf("committed file = %q, error %v", data, err)
	}
	if _, err := os.Stat(swap.stageDir); !os.IsNotExist(err) {
		t.Fatalf("staging files remain after commit: %v", err)
	}
}

func TestGeoDataRollbackFailureRetainsPreviousFiles(t *testing.T) {
	dir := t.TempDir()
	oldPath := filepath.Join(dir, "geoip.metadb")
	if err := os.WriteFile(oldPath, []byte("old-ip"), 0600); err != nil {
		t.Fatal(err)
	}
	swap, err := stageGeoData(dir, map[string][]byte{"geoip.metadb": []byte("new-ip")})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(oldPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(oldPath, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(oldPath, "blocker"), []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := swap.rollback(); err == nil {
		t.Fatal("rollback unexpectedly succeeded")
	}
	backup := filepath.Join(swap.stageDir, "previous", "geoip.metadb")
	data, err := os.ReadFile(backup)
	if err != nil || string(data) != "old-ip" {
		t.Fatalf("previous Geo file was not retained: data %q, error %v", data, err)
	}
}
