package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadSettingsMergesDefaultsAndReadsYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.yaml")
	if err := os.WriteFile(path, []byte("server:\n  listeners:\n    - 127.0.0.1:18081\n    - 192.168.100.1:18081\n  management_interface: br-lan1\nsecurity:\n  frame_ancestors:\n    - http://192.168.100.1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := loadSettings(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Server.Listeners) != 2 || s.Server.Listeners[0] != "127.0.0.1:18081" || s.Security.FrameAncestors[0] != "http://192.168.100.1" {
		t.Fatalf("unexpected settings: %+v", s)
	}
}

func TestListenAddressRejectsWildcardsAndNonIPs(t *testing.T) {
	for _, address := range []string{"127.0.0.1:18080", "[::1]:18080", "192.168.100.1:18080"} {
		if err := validateListenAddress(address); err != nil {
			t.Errorf("%s rejected: %v", address, err)
		}
	}
	for _, address := range []string{"0.0.0.0:18080", "192.168.1.1:0", "localhost:18080", "*:18080", "192.168.1.1:18080junk"} {
		if err := validateListenAddress(address); err == nil {
			t.Errorf("%s should be rejected", address)
		}
	}
}

func TestSettingsRejectWildcardAndCrossPortListeners(t *testing.T) {
	for _, config := range []string{
		"server:\n  listeners: [127.0.0.1:18080, 0.0.0.0:18080]\n",
		"server:\n  listeners: [127.0.0.1:18080, 192.168.100.1:18081]\n",
	} {
		path := filepath.Join(t.TempDir(), "app.yaml")
		if err := os.WriteFile(path, []byte(config), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadSettings(path); err == nil {
			t.Fatalf("unsafe config accepted: %s", config)
		}
	}
}

func TestFirstAvailablePortSkipsBusyAndReservedPorts(t *testing.T) {
	port := firstAvailablePort(10, 14, 12, func(p int) bool { return p >= 14 })
	if port != 14 {
		t.Fatalf("selected port %d, want 14", port)
	}
	if got := firstAvailablePort(10, 12, 0, func(int) bool { return false }); got != 0 {
		t.Fatalf("got %d when range has no free port", got)
	}
}

func TestValidModeIsClosedEnum(t *testing.T) {
	for _, mode := range []string{"rule", "global", "direct"} {
		if !validMode(mode) {
			t.Errorf("mode %q rejected", mode)
		}
	}
	for _, mode := range []string{"", "Rule", "shell", "direct;whoami"} {
		if validMode(mode) {
			t.Errorf("mode %q accepted", mode)
		}
	}
}
