package main

import (
	"reflect"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestNetworkSettingsValidateSelectedClientsAndAllowLANDNS(t *testing.T) {
	settings := LANProxySettings{
		Enabled: true, Mode: "selected",
		Clients: []LANClientPolicy{{IP: "192.168.100.22", Action: "proxy"}},
	}
	if _, err := normalizeLANProxySettings(settings); err == nil {
		t.Fatal("selected proxy without a MAC address was accepted")
	}

	dns, err := normalizeDNSSettings(DNSSettings{
		Enabled: true, Mode: "custom", CustomNameservers: []string{"192.168.100.1"},
	})
	if err != nil {
		t.Fatalf("private LAN DNS upstream was rejected: %v", err)
	}
	if len(dns.CustomNameservers) != 1 || dns.CustomNameservers[0] != "192.168.100.1" {
		t.Fatalf("custom DNS upstream was not normalized: %#v", dns.CustomNameservers)
	}
}

func TestNetworkConfigKeepsLANDirectAndPrivateBypassRules(t *testing.T) {
	state := RuntimeState{
		MixedPort: 17890, ControllerPort: 9091, Mode: "rule",
		TunStack: "system",
		LANProxy: LANProxySettings{
			Enabled: true, Mode: "all",
			Clients:     []LANClientPolicy{{IP: "192.168.100.42", MAC: "02:00:00:00:00:42", Action: "direct"}},
			BypassCIDRs: []string{"192.168.100.0/24"},
		},
	}
	var config map[string]any
	if err := yaml.Unmarshal([]byte(minimalConfig(state, "test-secret")), &config); err != nil {
		t.Fatal(err)
	}
	tun, ok := config["tun"].(map[string]any)
	if !ok || tun["enable"] != true || tun["auto-redirect"] != true {
		t.Fatalf("LAN proxy did not enable Mihomo redirect capture: %#v", config["tun"])
	}
	if !strings.Contains(minimalConfig(state, "test-secret"), "192.168.100.0/24") {
		t.Fatal("custom LAN bypass CIDR was omitted")
	}
	rules, ok := config["rules"].([]any)
	if !ok || len(rules) == 0 || rules[0] != "SRC-IP-CIDR,192.168.100.42/32,DIRECT" {
		t.Fatalf("direct device rule was not placed ahead of subscription rules: %#v", config["rules"])
	}
}

func TestNetworkConfigSupportsTUNIPv6AutoRedirectAndCustomBypass(t *testing.T) {
	state := RuntimeState{
		MixedPort: 17890, ControllerPort: 9091, Mode: "rule",
		TunEnabled: true, TunStack: "system", TunIPv6: true, TunAutoRedirect: true,
		LANProxy: LANProxySettings{Mode: "all", BypassCIDRs: []string{"198.51.100.0/24"}},
	}
	var config map[string]any
	if err := yaml.Unmarshal([]byte(minimalConfig(state, "test-secret")), &config); err != nil {
		t.Fatal(err)
	}
	if config["ipv6"] != true {
		t.Fatalf("TUN IPv6 preference was not applied: %#v", config["ipv6"])
	}
	tun, ok := config["tun"].(map[string]any)
	if !ok || tun["auto-route"] != true || tun["auto-redirect"] != true || tun["strict-route"] != false || tun["mtu"] != 1500 {
		t.Fatalf("TUN settings do not match the supported defaults: %#v", config["tun"])
	}
	if !strings.Contains(minimalConfig(state, "test-secret"), "198.51.100.0/24") {
		t.Fatal("custom bypass CIDR was omitted when LAN proxy was disabled")
	}
}

func TestTUNOnlyKeepsRouterDNSAndIPv6Available(t *testing.T) {
	state := RuntimeState{TunEnabled: true, TunStack: "system", DNS: defaultDNSSettings()}
	var config map[string]any
	if err := yaml.Unmarshal([]byte(minimalConfig(state, "test-secret")), &config); err != nil {
		t.Fatal(err)
	}
	if config["ipv6"] != true {
		t.Fatalf("TUN-only mode disabled core IPv6: %#v", config["ipv6"])
	}
	tun, ok := config["tun"].(map[string]any)
	if !ok || tun["auto-redirect"] != nil {
		t.Fatalf("TUN-only mode unexpectedly enabled LAN auto-redirect: %#v", config["tun"])
	}
	if got, want := tun["dns-hijack"], []any{"any:53", "tcp://any:53"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("TUN-only mode did not enable local DNS interception: got %#v want %#v", got, want)
	}
	dns, ok := config["dns"].(map[string]any)
	if !ok || dns["enable"] != true || dns["listen"] != "127.0.0.1:1053" || dns["ipv6"] != true {
		t.Fatalf("TUN-only mode did not keep the router DNS resolver active: %#v", config["dns"])
	}

	state.DNS = DNSSettings{Enabled: true, Mode: "recommended", IPv6: false}
	dns = networkDNSConfig(state)
	if dns["ipv6"] != false {
		t.Fatal("explicitly disabled DNS IPv6 was ignored")
	}
}

func TestParseLANClientsReturnsOnlyNeighborsOnNonWANSubnets(t *testing.T) {
	addresses := []byte(`[{"ifname":"eth0","addr_info":[{"family":"inet","local":"10.0.0.2","prefixlen":24,"scope":"global"}]},{"ifname":"br-lan","addr_info":[{"family":"inet","local":"192.168.100.1","prefixlen":24,"scope":"global"}]}]`)
	routes := []byte(`[{"dst":"default","dev":"eth0"}]`)
	neighbors := []byte(`[{"dst":"10.0.0.3","dev":"eth0","lladdr":"02:00:00:00:00:03","state":["REACHABLE"]},{"dst":"192.168.100.55","dev":"br-lan","lladdr":"02:00:00:00:00:55","state":["REACHABLE"]},{"dst":"192.168.100.66","dev":"br-lan","lladdr":"02:00:00:00:00:66","state":["FAILED"]}]`)
	clients, err := parseLANClients(addresses, routes, neighbors)
	if err != nil {
		t.Fatal(err)
	}
	if len(clients) != 1 || clients[0].IP != "192.168.100.55" || clients[0].MAC != "02:00:00:00:00:55" {
		t.Fatalf("unexpected LAN clients: %#v", clients)
	}
}
