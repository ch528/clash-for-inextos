package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMihomoCandidateVersionMustMatchRelease(t *testing.T) {
	for _, test := range []struct {
		output string
		want   bool
	}{
		{"Mihomo Meta v1.19.31 linux arm64", true},
		{"Mihomo Meta v1.19.30 linux arm64", false},
		{"unrelated v1.19.31", false},
		{"Mihomo Meta v1.19.310", false},
	} {
		if got := mihomoVersionMatches([]byte(test.output), "v1.19.31"); got != test.want {
			t.Errorf("version probe %q = %v, want %v", test.output, got, test.want)
		}
	}
}

func TestMihomoCandidateUsesExecutableInstallDirectory(t *testing.T) {
	wantDir := filepath.Join(installDir, "bin")
	if got := filepath.Dir(mihomoCandidatePath()); got != wantDir {
		t.Fatalf("Mihomo candidate directory = %q, want executable install directory %q", got, wantDir)
	}
}

func TestMihomoBinaryReplacementRetainsRollback(t *testing.T) {
	dir := t.TempDir()
	target, candidate := filepath.Join(dir, "mihomo"), filepath.Join(dir, "candidate")
	if err := os.WriteFile(target, []byte("original"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(candidate, []byte("updated"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := replaceMihomoBinary(target, candidate); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(target); string(data) != "updated" {
		t.Fatalf("installed = %q", data)
	}
	if data, _ := os.ReadFile(target + ".previous"); string(data) != "original" {
		t.Fatalf("backup = %q", data)
	}
	if err := restoreMihomoBinary(target); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(target); string(data) != "original" {
		t.Fatalf("restored = %q", data)
	}
	if _, err := os.Stat(target + ".previous"); err != nil {
		t.Fatal("rollback removed previous binary")
	}
}

func TestMihomoMissingCandidatePreservesInstalledBinary(t *testing.T) {
	target := filepath.Join(t.TempDir(), "mihomo")
	if err := os.WriteFile(target, []byte("original"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := replaceMihomoBinary(target, target+".missing"); err == nil {
		t.Fatal("missing candidate accepted")
	}
	if data, _ := os.ReadFile(target); string(data) != "original" {
		t.Fatalf("installed changed to %q", data)
	}
	if err := restoreMihomoBinary(target); err == nil {
		t.Fatal("missing rollback accepted")
	}
}
