package main

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"sort"
	"strings"
	"unicode"
)

type LANClientPolicy struct {
	Name   string `json:"name,omitempty"`
	IP     string `json:"ip,omitempty"`
	MAC    string `json:"mac,omitempty"`
	Action string `json:"action"`
}

type LANProxySettings struct {
	Enabled     bool              `json:"enabled"`
	Mode        string            `json:"mode"`
	Clients     []LANClientPolicy `json:"clients"`
	BypassCIDRs []string          `json:"bypass_cidrs"`
}

type DNSSettings struct {
	Enabled           bool     `json:"enabled"`
	IPv6              bool     `json:"ipv6"`
	Mode              string   `json:"mode"`
	CustomNameservers []string `json:"custom_nameservers"`
}

type LANNeighbor struct {
	IP        string `json:"ip"`
	MAC       string `json:"mac"`
	Interface string `json:"interface"`
	State     string `json:"state"`
}

func defaultLANProxySettings() LANProxySettings {
	return LANProxySettings{Mode: "all", Clients: []LANClientPolicy{}, BypassCIDRs: []string{}}
}

func defaultDNSSettings() DNSSettings {
	return DNSSettings{Mode: "recommended", CustomNameservers: []string{}}
}

func normalizeNetworkSettings(state *RuntimeState) error {
	if state.LANProxy.Mode == "" {
		state.LANProxy.Mode = "all"
	}
	if state.LANProxy.Clients == nil {
		state.LANProxy.Clients = []LANClientPolicy{}
	}
	if state.LANProxy.BypassCIDRs == nil {
		state.LANProxy.BypassCIDRs = []string{}
	}
	if state.DNS.Mode == "" {
		state.DNS.Mode = "recommended"
	}
	if state.DNS.CustomNameservers == nil {
		state.DNS.CustomNameservers = []string{}
	}
	lan, err := normalizeLANProxySettings(state.LANProxy)
	if err != nil {
		return err
	}
	dns, err := normalizeDNSSettings(state.DNS)
	if err != nil {
		return err
	}
	state.LANProxy, state.DNS = lan, dns
	return nil
}

func normalizeLANProxySettings(settings LANProxySettings) (LANProxySettings, error) {
	if settings.Mode != "all" && settings.Mode != "selected" {
		return LANProxySettings{}, errors.New("LAN proxy mode must be all or selected")
	}
	if len(settings.Clients) > 128 || len(settings.BypassCIDRs) > 128 {
		return LANProxySettings{}, errors.New("LAN proxy settings exceed the device or bypass limit")
	}
	clients := make([]LANClientPolicy, 0, len(settings.Clients))
	seen := make(map[string]struct{}, len(settings.Clients)*2)
	proxyMACs := 0
	for _, client := range settings.Clients {
		client.Name = strings.TrimSpace(client.Name)
		if len(client.Name) > 80 || strings.IndexFunc(client.Name, unicode.IsControl) >= 0 {
			return LANProxySettings{}, errors.New("LAN client name is invalid")
		}
		client.Action = strings.ToLower(strings.TrimSpace(client.Action))
		if client.Action != "proxy" && client.Action != "direct" {
			return LANProxySettings{}, errors.New("LAN client action must be proxy or direct")
		}
		if client.IP != "" {
			ip := net.ParseIP(strings.TrimSpace(client.IP))
			if ip == nil || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
				return LANProxySettings{}, errors.New("LAN client IP must be a unicast address")
			}
			client.IP = ip.String()
			if _, ok := seen["ip:"+client.IP]; ok {
				return LANProxySettings{}, errors.New("LAN client IP is duplicated")
			}
			seen["ip:"+client.IP] = struct{}{}
		}
		if client.MAC != "" {
			mac, err := net.ParseMAC(strings.TrimSpace(client.MAC))
			if err != nil || len(mac) != 6 {
				return LANProxySettings{}, errors.New("LAN client MAC must be a six-byte address")
			}
			client.MAC = strings.ToLower(mac.String())
			if _, ok := seen["mac:"+client.MAC]; ok {
				return LANProxySettings{}, errors.New("LAN client MAC is duplicated")
			}
			seen["mac:"+client.MAC] = struct{}{}
		}
		if client.IP == "" && client.MAC == "" {
			return LANProxySettings{}, errors.New("LAN client requires an IP or MAC address")
		}
		if settings.Enabled && settings.Mode == "all" && client.Action == "direct" && client.IP == "" && client.MAC == "" {
			return LANProxySettings{}, errors.New("direct LAN clients require an IP or MAC address")
		}
		if settings.Enabled && settings.Mode == "selected" && client.Action == "proxy" {
			if client.MAC == "" {
				return LANProxySettings{}, errors.New("selected proxy clients require a MAC address")
			}
			proxyMACs++
		}
		clients = append(clients, client)
	}
	if settings.Enabled && settings.Mode == "selected" && proxyMACs == 0 {
		return LANProxySettings{}, errors.New("select at least one proxy client")
	}
	bypass := make([]string, 0, len(settings.BypassCIDRs))
	bypassSeen := make(map[string]struct{}, len(settings.BypassCIDRs))
	for _, raw := range settings.BypassCIDRs {
		_, network, err := net.ParseCIDR(strings.TrimSpace(raw))
		if err != nil {
			return LANProxySettings{}, errors.New("bypass entries must be valid IP networks")
		}
		value := network.String()
		if _, ok := bypassSeen[value]; !ok {
			bypassSeen[value] = struct{}{}
			bypass = append(bypass, value)
		}
	}
	sort.Strings(bypass)
	return LANProxySettings{
		Enabled: settings.Enabled, Mode: settings.Mode,
		Clients: clients, BypassCIDRs: bypass,
	}, nil
}

func normalizeDNSSettings(settings DNSSettings) (DNSSettings, error) {
	if settings.Mode != "recommended" && settings.Mode != "custom" {
		return DNSSettings{}, errors.New("DNS mode must be recommended or custom")
	}
	if len(settings.CustomNameservers) > 4 {
		return DNSSettings{}, errors.New("DNS supports at most four custom nameservers")
	}
	servers := make([]string, 0, len(settings.CustomNameservers))
	seen := make(map[string]struct{}, len(settings.CustomNameservers))
	for _, raw := range settings.CustomNameservers {
		ip, err := netip.ParseAddr(strings.TrimSpace(raw))
		if err != nil || !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
			return DNSSettings{}, errors.New("custom DNS upstreams must be unicast IP addresses")
		}
		value := ip.String()
		if _, ok := seen[value]; !ok {
			seen[value] = struct{}{}
			servers = append(servers, value)
		}
	}
	if settings.Enabled && settings.Mode == "custom" && len(servers) == 0 {
		return DNSSettings{}, errors.New("custom DNS mode requires at least one unicast IP upstream")
	}
	return DNSSettings{
		Enabled: settings.Enabled, IPv6: settings.IPv6,
		Mode: settings.Mode, CustomNameservers: servers,
	}, nil
}

func networkCaptureActive(state RuntimeState) bool {
	return state.TunEnabled || state.LANProxy.Enabled || state.DNS.Enabled
}

func networkDNSRequired(state RuntimeState) bool {
	return state.TunEnabled || state.DNS.Enabled
}

func sameNetworkSettings(a, b RuntimeState) bool {
	return a.TunEnabled == b.TunEnabled &&
		a.TunStack == b.TunStack &&
		a.TunIPv6 == b.TunIPv6 &&
		a.TunAutoRedirect == b.TunAutoRedirect &&
		reflect.DeepEqual(a.LANProxy, b.LANProxy) &&
		reflect.DeepEqual(a.DNS, b.DNS)
}

func safeClientDiscoveryError(err error) string {
	if err == nil {
		return ""
	}
	return "无法读取当前 LAN 客户端列表；仍可手动添加设备"
}

func reservedBypassCIDRs() []string {
	return []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
		"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16",
		"198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4", "::1/128",
		"fc00::/7", "fe80::/10", "ff00::/8",
	}
}

func networkTunnelConfig(state RuntimeState) map[string]any {
	if !networkCaptureActive(state) {
		return map[string]any{"enable": false}
	}
	stack := state.TunStack
	if stack != "system" && stack != "gvisor" && stack != "mixed" {
		stack = "system"
	}
	tun := map[string]any{
		"enable": true, "device": "mihomo0", "stack": stack, "mtu": 1500,
		"auto-route": true, "auto-detect-interface": true, "strict-route": false,
	}
	if state.TunAutoRedirect || state.LANProxy.Enabled || state.DNS.Enabled {
		tun["auto-redirect"] = true
	}
	if networkDNSRequired(state) {
		tun["dns-hijack"] = []string{"any:53", "tcp://any:53"}
	}
	if state.LANProxy.Enabled && state.LANProxy.Mode == "selected" {
		macs := make([]string, 0, len(state.LANProxy.Clients))
		for _, client := range state.LANProxy.Clients {
			if client.Action == "proxy" && client.MAC != "" {
				macs = append(macs, client.MAC)
			}
		}
		sort.Strings(macs)
		tun["include-mac-address"] = macs
	} else if state.LANProxy.Enabled {
		macs := make([]string, 0, len(state.LANProxy.Clients))
		for _, client := range state.LANProxy.Clients {
			if client.Action == "direct" && client.MAC != "" {
				macs = append(macs, client.MAC)
			}
		}
		if len(macs) > 0 {
			sort.Strings(macs)
			tun["exclude-mac-address"] = macs
		}
	}
	bypass := append(reservedBypassCIDRs(), state.LANProxy.BypassCIDRs...)
	sort.Strings(bypass)
	tun["route-exclude-address"] = uniqueStrings(bypass)
	return tun
}

func networkDNSConfig(state RuntimeState) map[string]any {
	if !networkDNSRequired(state) {
		return nil
	}
	servers := []string{"https://doh.pub/dns-query", "https://dns.alidns.com/dns-query"}
	if state.DNS.Mode == "custom" {
		servers = append([]string(nil), state.DNS.CustomNameservers...)
	}
	allowIPv6 := state.DNS.IPv6 || (state.TunEnabled && !state.DNS.Enabled)
	return map[string]any{
		"enable": true, "listen": "127.0.0.1:1053", "ipv6": allowIPv6,
		"enhanced-mode": "redir-host", "default-nameserver": []string{"223.5.5.5"},
		"nameserver": servers,
	}
}

func networkPolicyRules(state RuntimeState) []any {
	if !state.LANProxy.Enabled || state.LANProxy.Mode != "all" {
		return nil
	}
	var rules []any
	for _, client := range state.LANProxy.Clients {
		if client.Action != "direct" || client.IP == "" {
			continue
		}
		ip := net.ParseIP(client.IP)
		bits := 128
		if ip.To4() != nil {
			bits = 32
		}
		rules = append(rules, fmt.Sprintf("SRC-IP-CIDR,%s/%d,DIRECT", client.IP, bits))
	}
	return rules
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}
