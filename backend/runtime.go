package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

type RuntimeState struct {
	MixedPort        int              `json:"mixed_port"`
	ControllerPort   int              `json:"controller_port"`
	BackendPort      int              `json:"backend_port"`
	DesiredRunning   bool             `json:"desired_running"`
	AutoStart        bool             `json:"auto_start"`
	RestartOnFailure bool             `json:"restart_on_failure"`
	Mode             string           `json:"mode"`
	TunEnabled       bool             `json:"tun_enabled"`
	TunStack         string           `json:"tun_stack"`
	TunIPv4          bool             `json:"tun_ipv4"`
	TunIPv6          bool             `json:"tun_ipv6"`
	TunMTU           int              `json:"tun_mtu"`
	TunAutoRoute     bool             `json:"tun_auto_route"`
	TunAutoRedirect  bool             `json:"tun_auto_redirect"`
	TunStrictRoute   bool             `json:"tun_strict_route"`
	LANProxy         LANProxySettings `json:"lan_proxy"`
	DNS              DNSSettings      `json:"dns"`
	TunTestConfirmed bool             `json:"tun_test_confirmed"`
	PID              int              `json:"pid,omitempty"`
	StartedAt        time.Time        `json:"started_at,omitempty"`
}

func loadRuntimeState(stateDir string) (RuntimeState, error) {
	b, err := os.ReadFile(filepath.Join(stateDir, "runtime.json"))
	if err != nil {
		return RuntimeState{}, err
	}
	var s RuntimeState
	if err := json.Unmarshal(b, &s); err != nil {
		return RuntimeState{}, err
	}
	var saved map[string]json.RawMessage
	if err := json.Unmarshal(b, &saved); err != nil {
		return RuntimeState{}, err
	}
	if _, ok := saved["desired_running"]; !ok {
		s.DesiredRunning = true
	}
	if _, ok := saved["auto_start"]; !ok {
		s.AutoStart = true
	}
	if _, ok := saved["restart_on_failure"]; !ok {
		s.RestartOnFailure = true
	}
	if s.Mode == "" {
		s.Mode = "rule"
	}
	if s.TunStack == "" {
		s.TunStack = "system"
	}
	if _, ok := saved["tun_ipv4"]; !ok {
		s.TunIPv4 = true
		// Legacy builds always installed both address families when TUN was enabled.
		s.TunIPv6 = true
	}
	if s.TunMTU == 0 {
		s.TunMTU = 1500
	}
	if _, ok := saved["tun_auto_route"]; !ok {
		s.TunAutoRoute = true
	}
	if s.Mode != "rule" && s.Mode != "global" && s.Mode != "direct" {
		return RuntimeState{}, fmt.Errorf("invalid saved Mihomo mode")
	}
	if s.TunStack != "system" && s.TunStack != "gvisor" && s.TunStack != "mixed" {
		return RuntimeState{}, fmt.Errorf("invalid saved TUN stack")
	}
	if err := normalizeNetworkSettings(&s); err != nil {
		return RuntimeState{}, fmt.Errorf("invalid saved network settings: %w", err)
	}
	if s.MixedPort < 1 || s.ControllerPort < 1 || s.BackendPort < 18080 || s.BackendPort > 18100 || s.MixedPort == s.ControllerPort || s.MixedPort == s.BackendPort || s.ControllerPort == s.BackendPort {
		return RuntimeState{}, fmt.Errorf("invalid saved runtime ports")
	}
	return s, nil
}

func saveRuntimeState(stateDir string, s RuntimeState) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(stateDir, "runtime.json"), append(b, '\n'), 0600)
}

func ensureSecret(path string) (string, error) {
	if b, err := os.ReadFile(path); err == nil {
		secret := strings.TrimSpace(string(b))
		if len(secret) < 32 {
			return "", fmt.Errorf("controller secret is shorter than 32 bytes")
		}
		if err := os.Chmod(path, 0600); err != nil {
			return "", err
		}
		return secret, nil
	} else if !os.IsNotExist(err) {
		return "", err
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	secret := hex.EncodeToString(raw)
	if err := atomicWrite(path, []byte(secret+"\n"), 0600); err != nil {
		return "", err
	}
	return secret, nil
}

func allocateRuntime(stateDir string, backendPort int) (RuntimeState, error) {
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return RuntimeState{}, err
	}
	if old, err := loadRuntimeState(stateDir); err == nil {
		return old, nil
	} else if !os.IsNotExist(err) {
		return RuntimeState{}, fmt.Errorf("read saved runtime state: %w", err)
	}
	return allocateNewRuntime(stateDir, backendPort)
}

func allocateNewRuntime(stateDir string, backendPort int) (RuntimeState, error) {
	var state RuntimeState
	startBackendPort := backendPort
	if startBackendPort < 18080 {
		startBackendPort = 18080
	}
	endBackendPort := startBackendPort + 20
	if endBackendPort > 18100 {
		endBackendPort = 18100
	}
	state.DesiredRunning = true
	state.AutoStart = true
	state.RestartOnFailure = true
	state.Mode = "rule"
	state.TunStack = "system"
	state.TunIPv4 = true
	state.TunIPv6 = true
	state.TunMTU = 1500
	state.TunAutoRoute = true
	state.LANProxy = defaultLANProxySettings()
	state.DNS = defaultDNSSettings()
	state.BackendPort = firstAvailablePort(startBackendPort, endBackendPort, 0, func(port int) bool { return portAvailable(port, false) })
	state.MixedPort = firstAvailablePort(17890, 17920, state.BackendPort, func(port int) bool { return portAvailable(port, true) })
	state.ControllerPort = firstAvailablePort(9091, 9120, state.BackendPort, func(port int) bool { return portAvailable(port, false) })
	if state.MixedPort == 0 || state.ControllerPort == 0 || state.BackendPort == 0 {
		return RuntimeState{}, fmt.Errorf("no free ports in configured candidate ranges")
	}
	if err := saveRuntimeState(stateDir, state); err != nil {
		return RuntimeState{}, err
	}
	return state, nil
}

func firstAvailablePort(start, end, skip int, available func(int) bool) int {
	for port := start; port <= end; port++ {
		if port != skip && available(port) {
			return port
		}
	}
	return 0
}

func portAvailable(port int, udp bool) bool {
	address := net.JoinHostPort("127.0.0.1", fmt.Sprint(port))
	listener, err := net.Listen("tcp4", address)
	if err != nil {
		return false
	}
	_ = listener.Close()
	if udp {
		packet, err := net.ListenPacket("udp4", address)
		if err != nil {
			return false
		}
		_ = packet.Close()
	}
	return true
}

func runtimeListeners(configured []string, port int) []string {
	var listeners []string
	for _, raw := range configured {
		host, _, err := splitListener(raw)
		if err != nil {
			continue
		}
		ip := net.ParseIP(host)
		if ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
			continue
		}
		address := net.JoinHostPort(host, fmt.Sprint(port))
		listeners = append(listeners, address)
	}
	return listeners
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".write-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func minimalConfig(state RuntimeState, secret string) string {
	mode := state.Mode
	if mode == "" {
		mode = "rule"
	}
	rules := append(networkPolicyRules(state), "MATCH,DIRECT")
	config := map[string]any{
		"mixed-port":          state.MixedPort,
		"allow-lan":           false,
		"bind-address":        "127.0.0.1",
		"mode":                mode,
		"log-level":           "info",
		"external-controller": fmt.Sprintf("127.0.0.1:%d", state.ControllerPort),
		"secret":              secret,
		"ipv6":                state.TunIPv6 || state.TunEnabled || (state.DNS.Enabled && state.DNS.IPv6),
		"tun":                 networkTunnelConfig(state),
		"proxies":             []any{},
		"proxy-groups":        []any{},
		"rules":               rules,
	}
	if dns := networkDNSConfig(state); dns != nil {
		config["dns"] = dns
	}
	data, _ := yaml.Marshal(config)
	return string(data)
}

func writeMinimalConfig(path string, state RuntimeState, secret string) error {
	return atomicWrite(path, []byte(minimalConfig(state, secret)), 0600)
}
