package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDashboardActivationAndRollbackPreserveBothVersions(t *testing.T) {
	updates, packaged := t.TempDir(), t.TempDir()
	archive, digest := dashboardTestZIP(t, "", false)
	if err := extractDashboardArchive(archive, digest, packaged); err != nil {
		t.Fatal(err)
	}
	a := &API{dashboardDir: packaged, dashboardUpdatesDir: updates}
	stage, err := os.MkdirTemp(updates, "release-")
	if err != nil {
		t.Fatal(err)
	}
	if err := extractDashboardArchive(archive, digest, stage); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(stage, "assets", "app.js"), filepath.Join(stage, "assets", "new.js")); err != nil {
		t.Fatal(err)
	}
	index, err := os.ReadFile(filepath.Join(stage, "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stage, "index.html"), []byte(strings.ReplaceAll(string(index), "app.js", "new.js")), 0600); err != nil {
		t.Fatal(err)
	}
	if err := a.commitDashboardCandidate(stage, "v9.0.0"); err != nil {
		t.Fatal(err)
	}
	if a.activeDashboardDirectory() != stage || a.installedDashboardVersion() != "v9.0.0" {
		t.Fatal("candidate was not activated")
	}
	oldResource := httptest.NewRecorder()
	a.dashboard(oldResource, httptest.NewRequest(http.MethodGet, "/dashboard/assets/app.js", nil))
	if oldResource.Code != http.StatusOK || !strings.Contains(oldResource.Body.String(), "console.log") {
		t.Fatal("old browser resource was not preserved")
	}
	w := httptest.NewRecorder()
	a.rollbackZashboard(w, httptest.NewRequest(http.MethodPost, "/api/updates/zashboard/rollback", nil))
	if w.Code != http.StatusOK || a.activeDashboardDirectory() != packaged {
		t.Fatalf("rollback failed: %d %s", w.Code, w.Body.String())
	}
	if _, err := os.Stat(filepath.Join(stage, "index.html")); err != nil {
		t.Fatal("rollback removed updated files")
	}
	current, err := a.dashboardInstallation("current.json")
	if err != nil || current.Previous == nil || current.Previous.Version != "v9.0.0" {
		t.Fatalf("atomic rollback record = %+v, error = %v", current, err)
	}
	if _, err := os.Stat(filepath.Join(updates, "previous.json")); !os.IsNotExist(err) {
		t.Fatal("rollback requires a second version-record write")
	}
}

func TestInvalidDashboardCandidateLeavesPackagedPanelActive(t *testing.T) {
	a := &API{dashboardDir: t.TempDir(), dashboardUpdatesDir: t.TempDir()}
	stage, err := os.MkdirTemp(a.dashboardUpdatesDir, "release-")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.commitDashboardCandidate(stage, "v9.0.0"); err == nil {
		t.Fatal("empty candidate accepted")
	}
	if a.activeDashboardDirectory() != a.dashboardDir {
		t.Fatal("invalid candidate changed active panel")
	}
	if _, err := os.Stat(filepath.Join(a.dashboardUpdatesDir, "current.json")); !os.IsNotExist(err) {
		t.Fatal("invalid candidate wrote version record")
	}
}

func TestDashboardUpdatesRequireAuthentication(t *testing.T) {
	a := testAPI(t.TempDir())
	for _, path := range []string{"/api/updates/zashboard", "/api/updates/zashboard/rollback"} {
		w := httptest.NewRecorder()
		a.Handler().ServeHTTP(w, apiRequest(http.MethodPost, path, "", "http://127.0.0.1:18080"))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("%s status %d", path, w.Code)
		}
	}
}
