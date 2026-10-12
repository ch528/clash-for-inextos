package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestVersionIsNewer(t *testing.T) {
	for _, test := range []struct {
		latest  string
		current string
		want    bool
		valid   bool
	}{
		{latest: "v1.19.30", current: "Mihomo Meta v1.19.23", want: true, valid: true},
		{latest: "v3.29.1", current: "3.29.1", want: false, valid: true},
		{latest: "v2.0.0", current: "v1.99.99", want: true, valid: true},
		{latest: "latest", current: "1.0.0", valid: false},
	} {
		got, valid := versionIsNewer(test.latest, test.current)
		if got != test.want || valid != test.valid {
			t.Errorf("versionIsNewer(%q, %q) = (%v, %v), want (%v, %v)", test.latest, test.current, got, valid, test.want, test.valid)
		}
	}
}

func TestVersionRelation(t *testing.T) {
	for _, test := range []struct {
		candidate string
		current   string
		want      int
		valid     bool
	}{
		{candidate: "1.0.46", current: "1.0.45", want: 1, valid: true},
		{candidate: "1.0.45", current: "1.0.45", want: 0, valid: true},
		{candidate: "1.0.44", current: "1.0.45", want: -1, valid: true},
		{candidate: "latest", current: "1.0.45", valid: false},
	} {
		got, valid := versionRelation(test.candidate, test.current)
		if got != test.want || valid != test.valid {
			t.Errorf("versionRelation(%q, %q) = (%d, %v), want (%d, %v)", test.candidate, test.current, got, valid, test.want, test.valid)
		}
	}
}

func TestGeoDataStatusFollowsActiveRules(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "mihomo.yaml")
	stateDir := filepath.Join(dir, "state")
	if err := os.WriteFile(config, []byte("rules:\n  - MATCH,DIRECT\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if current, status := geoDataStatus(config, dir, stateDir); current != "未启用" || status != "not_in_use" {
		t.Fatalf("unused Geo status = (%q, %q)", current, status)
	}
	if err := os.WriteFile(config, []byte("rules:\n  - GEOIP,CN,DIRECT\n  - GEOSITE,cn,DIRECT\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "geoip.dat"), []byte("unused format"), 0600); err != nil {
		t.Fatal(err)
	}
	if current, status := geoDataStatus(config, dir, stateDir); current != "未安装" || status != "in_use_missing" {
		t.Fatalf("missing Geo status = (%q, %q)", current, status)
	}
	if err := os.WriteFile(filepath.Join(dir, "geoip.metadb"), []byte("ip-data"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "geosite.dat"), []byte("site-data"), 0600); err != nil {
		t.Fatal(err)
	}
	if current, status := geoDataStatus(config, dir, stateDir); current != "版本未跟踪" || status != "installed_version_untracked" {
		t.Fatalf("untracked Geo status = (%q, %q)", current, status)
	}
	files, err := geoDataFilesUsed([]byte("geodata-mode: false\nrules:\n  - GEOIP,CN,DIRECT\n  - GEOSITE,cn,DIRECT\n"))
	if err != nil {
		t.Fatal(err)
	}
	metadata := geoDataMetadata{Tag: "latest", PublishedAt: time.Date(2026, 10, 10, 1, 0, 0, 0, time.UTC), Files: map[string]string{}}
	for _, name := range files {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(data)
		metadata.Files[name] = hex.EncodeToString(digest[:])
	}
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(metadata)
	if err := os.WriteFile(geoDataMetadataPath(stateDir), data, 0600); err != nil {
		t.Fatal(err)
	}
	if current, status := geoDataStatus(config, dir, stateDir); current != "2026-10-10" || status != "in_use" {
		t.Fatalf("tracked Geo status = (%q, %q)", current, status)
	}
}

func TestFetchLatestRelease(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "application/vnd.github+json" || r.Header.Get("User-Agent") != "Clash-for-iNextOS" {
			t.Errorf("missing release API headers")
		}
		_, _ = w.Write([]byte(`{"tag_name":"v1.2.3","published_at":"2026-10-01T12:00:00Z"}`))
	}))
	defer server.Close()

	release, err := fetchLatestRelease(context.Background(), server.Client(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if release.TagName != "v1.2.3" || release.PublishedAt != "2026-10-01T12:00:00Z" {
		t.Fatalf("unexpected release metadata: %+v", release)
	}
}

func TestUpdateCheckRequiresAuthentication(t *testing.T) {
	api := testAPI(t.TempDir())
	recorder := httptest.NewRecorder()
	request := apiRequest(http.MethodGet, "/api/updates/check", "", "http://127.0.0.1:18080")
	api.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("got status %d, want %d", recorder.Code, http.StatusUnauthorized)
	}
}

func TestGeoUpdateRequiresAuthentication(t *testing.T) {
	api := testAPI(t.TempDir())
	recorder := httptest.NewRecorder()
	request := apiRequest(http.MethodPost, "/api/updates/geo", "", "http://127.0.0.1:18080")
	api.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", recorder.Code)
	}
}

func TestMihomoUpdateRequiresAuthentication(t *testing.T) {
	api := testAPI(t.TempDir())
	recorder := httptest.NewRecorder()
	request := apiRequest(http.MethodPost, "/api/updates/mihomo", "", "http://127.0.0.1:18080")
	api.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", recorder.Code)
	}
}

func TestApplicationUpdateRoutesRequireAuthentication(t *testing.T) {
	api := testAPI(t.TempDir())
	for _, test := range []struct {
		method string
		path   string
	}{
		{method: http.MethodPost, path: "/api/updates/app"},
		{method: http.MethodGet, path: "/api/updates/app/status"},
	} {
		recorder := httptest.NewRecorder()
		request := apiRequest(test.method, test.path, "", "http://127.0.0.1:18080")
		api.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusUnauthorized {
			t.Errorf("%s %s returned %d, want 401", test.method, test.path, recorder.Code)
		}
	}
}

func TestFetchGeoReleaseAcceptsLatestTag(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"tag_name":"latest","published_at":"2026-10-01T12:00:00Z"}`))
	}))
	defer server.Close()
	release, err := fetchLatestRelease(context.Background(), server.Client(), server.URL)
	if err != nil || release.TagName != "latest" {
		t.Fatalf("Geo release = %+v, error = %v", release, err)
	}
}
