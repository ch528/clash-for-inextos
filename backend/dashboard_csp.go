package main

import (
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

func dashboardIconSources(configFile string) []string {
	config, err := os.ReadFile(configFile)
	if err != nil {
		return nil
	}
	var parsed struct {
		ProxyGroups []struct {
			Icon string `yaml:"icon"`
		} `yaml:"proxy-groups"`
	}
	if yaml.Unmarshal(config, &parsed) != nil {
		return nil
	}

	seen := make(map[string]struct{}, len(parsed.ProxyGroups))
	sources := make([]string, 0, len(parsed.ProxyGroups))
	for _, group := range parsed.ProxyGroups {
		source, ok := dashboardIconSource(group.Icon)
		if !ok {
			continue
		}
		if _, exists := seen[source]; exists {
			continue
		}
		seen[source] = struct{}{}
		sources = append(sources, source)
	}
	return sources
}

func dashboardIconSource(raw string) (string, bool) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Opaque != "" || parsed.User != nil || parsed.Fragment != "" {
		return "", false
	}
	host := strings.ToLower(parsed.Hostname())
	if !validDashboardIconHostname(host) {
		return "", false
	}
	port := parsed.Port()
	if port != "" {
		portNumber, err := strconv.Atoi(port)
		if err != nil || portNumber < 1 || portNumber > 65535 {
			return "", false
		}
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return "https://" + host, true
}

func validDashboardIconHostname(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
				return false
			}
		}
	}
	return true
}
