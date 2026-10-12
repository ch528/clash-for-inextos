package main

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

const (
	installDir        = "/opt/inextos-clash"
	dashboardAssetDir = "/opt/inextos-clash/dashboard"
	configDir         = "/etc/inextos-clash"
	stateDir          = "/var/lib/inextos-clash/state"
	subscriptionsDir  = "/var/lib/inextos-clash/subscriptions"
	dashboardDir      = "/var/lib/inextos-clash/dashboard"
	mihomoDataDir     = "/var/lib/inextos-clash/mihomo"
	runDir            = "/run/inextos-clash"
	helperSocketDir   = "/run/inextos-clash-helper"
	helperSocketPath  = "/run/inextos-clash-helper/helper.sock"
	applicationConfig = "/etc/inextos-clash/app.yaml"
)

type Settings struct {
	Server struct {
		Listeners []string `yaml:"listeners"`
	} `yaml:"server"`
	Security struct {
		FrameAncestors []string `yaml:"frame_ancestors"`
	} `yaml:"security"`
}

func defaultSettings() Settings {
	var s Settings
	s.Server.Listeners = []string{"127.0.0.1:18080", "192.168.100.1:18080"}
	s.Security.FrameAncestors = []string{"'self'"}
	return s
}

func loadSettings(path string) (Settings, error) {
	s := defaultSettings()
	if path == "" {
		path = applicationConfig
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return s, err
	}
	if err := yaml.Unmarshal(b, &s); err != nil {
		return s, fmt.Errorf("read app config: %w", err)
	}
	if len(s.Server.Listeners) == 0 {
		return s, fmt.Errorf("server.listeners must include 127.0.0.1")
	}
	loopback, port := false, 0
	seen := make(map[string]struct{}, len(s.Server.Listeners))
	for _, address := range s.Server.Listeners {
		host, currentPort, err := splitListener(address)
		if err != nil {
			return s, err
		}
		if currentPort < 1 || currentPort > 65535 {
			return s, fmt.Errorf("invalid listener port in %q", address)
		}
		if port == 0 {
			port = currentPort
		} else if port != currentPort {
			return s, fmt.Errorf("all server.listeners must use the same port")
		}
		if currentPort < 18080 || currentPort > 18100 {
			return s, fmt.Errorf("backend listener port must be in the configured 18080-18100 range")
		}
		if _, exists := seen[address]; exists {
			return s, fmt.Errorf("duplicate server listener %q", address)
		}
		seen[address] = struct{}{}
		ip := net.ParseIP(host)
		if ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
			return s, fmt.Errorf("listener %q must use an exact IP address, not a wildcard or hostname", address)
		}
		if ip.IsLoopback() {
			loopback = true
		}
	}
	if !loopback {
		return s, fmt.Errorf("server.listeners must include a loopback address")
	}
	if err := validateFrameAncestors(s.Security.FrameAncestors); err != nil {
		return s, err
	}
	return s, nil
}

func splitListener(address string) (string, int, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, fmt.Errorf("invalid listener %q: %w", address, err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return "", 0, fmt.Errorf("invalid listener port in %q", address)
	}
	return host, port, nil
}

func validateListenAddress(address string) error {
	host, port, err := splitListener(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsUnspecified() || ip.IsMulticast() || port < 1 || port > 65535 {
		return fmt.Errorf("listener must use an exact IP address and a valid port")
	}
	return nil
}

func validateFrameAncestors(origins []string) error {
	for _, raw := range origins {
		if raw == "'self'" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || strings.Contains(raw, "*") {
			return fmt.Errorf("invalid frame ancestor origin %q", raw)
		}
	}
	return nil
}
