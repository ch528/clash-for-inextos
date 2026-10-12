package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGeneratedControllerSecretIsRandomAndPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "controller-secret")
	first, err := ensureSecret(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ensureSecret(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) < 32 || first != second {
		t.Fatalf("secret length or persistence is wrong")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("secret mode is %04o, want 0600", info.Mode().Perm())
	}
}

func TestMinimalConfigHasLoopbackOnlySafeDefaults(t *testing.T) {
	text := minimalConfig(RuntimeState{MixedPort: 17890, ControllerPort: 9091}, strings.Repeat("a", 64))
	for _, required := range []string{"mixed-port: 17890", "allow-lan: false", "bind-address: 127.0.0.1", "external-controller: 127.0.0.1:9091", "enable: false", "MATCH,DIRECT"} {
		if !strings.Contains(text, required) {
			t.Errorf("config missing %q", required)
		}
	}
	for _, forbidden := range []string{"0.0.0.0", "dns:", "redir-port:", "tproxy-port:"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("config contains forbidden setting %q", forbidden)
		}
	}
}

func TestMinimalConfigTUNUsesOnlySupportedFixedOptions(t *testing.T) {
	text := minimalConfig(RuntimeState{MixedPort: 17890, ControllerPort: 9091, Mode: "rule", TunEnabled: true, TunStack: "gvisor"}, strings.Repeat("b", 64))
	for _, required := range []string{"enable: true", "device: mihomo0", "stack: gvisor", "mtu: 1500", "auto-route: true", "auto-detect-interface: true", "strict-route: false"} {
		if !strings.Contains(text, required) {
			t.Errorf("TUN config missing %q", required)
		}
	}
	if strings.Contains(text, "auto-redirect: true") {
		t.Fatal("TUN config enabled auto-redirect without a setting")
	}
}

func TestRuntimePortChoicePersistsAcrossRestartAndConflict(t *testing.T) {
	dir := t.TempDir()
	requested := firstAvailablePort(18080, 18100, 0, func(port int) bool { return portAvailable(port, false) })
	if requested == 0 {
		t.Skip("no available port in the production candidate range")
	}
	first, err := allocateRuntime(dir, requested)
	if err != nil {
		t.Fatal(err)
	}
	if first.BackendPort != requested {
		t.Fatalf("backend port %d, want requested %d", first.BackendPort, requested)
	}
	blocker, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", fmt.Sprint(first.BackendPort)))
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	second, err := allocateRuntime(dir, min(requested+1, 18100))
	if err != nil {
		t.Fatal(err)
	}
	if second.BackendPort != first.BackendPort {
		t.Fatalf("persisted backend port changed from %d to %d after conflict", first.BackendPort, second.BackendPort)
	}
}

func TestRuntimeListenersKeepOnlyExactConfiguredAddresses(t *testing.T) {
	listeners := runtimeListeners([]string{"127.0.0.1:18080", "192.0.2.254:18080"}, 18081)
	if len(listeners) != 2 || listeners[0] != "127.0.0.1:18081" || listeners[1] != "192.0.2.254:18081" {
		t.Fatalf("unexpected configured listeners: %v", listeners)
	}
}

func TestLegacyRuntimeDefaultsToRunningRuleMode(t *testing.T) {
	dir := t.TempDir()
	legacy := `{"mixed_port":17890,"controller_port":9091,"backend_port":18080,"pid":0}`
	if err := os.WriteFile(filepath.Join(dir, "runtime.json"), []byte(legacy), 0600); err != nil {
		t.Fatal(err)
	}
	state, err := loadRuntimeState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !state.DesiredRunning || !state.AutoStart || !state.RestartOnFailure || state.Mode != "rule" {
		t.Fatalf("legacy state migrated to desired=%t autostart=%t restart=%t mode=%q", state.DesiredRunning, state.AutoStart, state.RestartOnFailure, state.Mode)
	}
	state.DesiredRunning = false
	state.Mode = "global"
	if err := saveRuntimeState(dir, state); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadRuntimeState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.DesiredRunning || loaded.Mode != "global" {
		t.Fatalf("saved state not restored: running=%t mode=%q", loaded.DesiredRunning, loaded.Mode)
	}
}
