package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os/exec"
	"sort"
	"strings"
)

type ipAddressDump struct {
	Interface   string `json:"ifname"`
	AddressInfo []struct {
		Family    string `json:"family"`
		Local     string `json:"local"`
		PrefixLen int    `json:"prefixlen"`
		Scope     string `json:"scope"`
	} `json:"addr_info"`
}

type ipRouteDump struct {
	Destination string `json:"dst"`
	Interface   string `json:"dev"`
}

type ipNeighborDump struct {
	Destination string   `json:"dst"`
	Interface   string   `json:"dev"`
	MAC         string   `json:"lladdr"`
	State       []string `json:"state"`
}

func readLANClients(ctx context.Context) ([]LANNeighbor, error) {
	addresses, err := readIPJSON(ctx, "-j", "address", "show", "up")
	if err != nil {
		return nil, err
	}
	routes, err := readIPJSON(ctx, "-j", "route", "show", "default")
	if err != nil {
		return nil, err
	}
	routes6, err := readIPJSON(ctx, "-j", "-6", "route", "show", "default")
	if err != nil {
		return nil, err
	}
	routes, err = combineIPRouteJSON(routes, routes6)
	if err != nil {
		return nil, errors.New("default route data is invalid")
	}
	neighbors, err := readIPJSON(ctx, "-j", "neigh", "show")
	if err != nil {
		return nil, err
	}
	return parseLANClients(addresses, routes, neighbors)
}

func readIPJSON(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "/usr/sbin/ip", args...)
	data, err := cmd.Output()
	if err != nil {
		return nil, errors.New("read-only LAN client discovery failed")
	}
	if len(data) > 1<<20 {
		return nil, errors.New("LAN client discovery response is too large")
	}
	return data, nil
}

func combineIPRouteJSON(first, second []byte) ([]byte, error) {
	var routes []ipRouteDump
	if err := json.Unmarshal(first, &routes); err != nil {
		return nil, err
	}
	var extra []ipRouteDump
	if err := json.Unmarshal(second, &extra); err != nil {
		return nil, err
	}
	return json.Marshal(append(routes, extra...))
}

func parseLANClients(addressData, routeData, neighborData []byte) ([]LANNeighbor, error) {
	var addresses []ipAddressDump
	var routes []ipRouteDump
	var neighbors []ipNeighborDump
	if err := json.Unmarshal(addressData, &addresses); err != nil {
		return nil, errors.New("LAN interface data is invalid")
	}
	if err := json.Unmarshal(routeData, &routes); err != nil {
		return nil, errors.New("default route data is invalid")
	}
	if err := json.Unmarshal(neighborData, &neighbors); err != nil {
		return nil, errors.New("LAN neighbor data is invalid")
	}
	defaultInterfaces := make(map[string]struct{}, len(routes))
	for _, route := range routes {
		if route.Destination == "default" && route.Interface != "" {
			defaultInterfaces[route.Interface] = struct{}{}
		}
	}
	type localNetwork struct {
		interfaceName string
		network       *net.IPNet
	}
	var localNetworks []localNetwork
	localAddresses := make(map[string]struct{})
	for _, item := range addresses {
		if item.Interface == "" || excludedLANInterface(item.Interface, defaultInterfaces) {
			continue
		}
		for _, info := range item.AddressInfo {
			if info.Scope != "global" || info.PrefixLen < 0 || info.PrefixLen > 128 {
				continue
			}
			ip := net.ParseIP(info.Local)
			if ip == nil || (info.Family == "inet" && ip.To4() == nil) || (info.Family == "inet6" && ip.To4() != nil) {
				continue
			}
			bits := 128
			if ip.To4() != nil {
				bits = 32
			}
			if info.PrefixLen > bits {
				continue
			}
			mask := net.CIDRMask(info.PrefixLen, bits)
			network := &net.IPNet{IP: ip.Mask(mask), Mask: mask}
			localNetworks = append(localNetworks, localNetwork{interfaceName: item.Interface, network: network})
			localAddresses[item.Interface+"/"+ip.String()] = struct{}{}
		}
	}
	result := make([]LANNeighbor, 0, len(neighbors))
	seen := make(map[string]struct{}, len(neighbors))
	for _, entry := range neighbors {
		if entry.Destination == "" || entry.Interface == "" || entry.MAC == "" || excludedNeighborState(entry.State) {
			continue
		}
		ip := net.ParseIP(entry.Destination)
		mac, err := net.ParseMAC(entry.MAC)
		if ip == nil || err != nil || len(mac) != 6 {
			continue
		}
		if _, ok := localAddresses[entry.Interface+"/"+ip.String()]; ok {
			continue
		}
		for _, local := range localNetworks {
			if local.interfaceName != entry.Interface || !local.network.Contains(ip) {
				continue
			}
			state := strings.Join(entry.State, ",")
			key := ip.String() + "/" + strings.ToLower(mac.String())
			if _, ok := seen[key]; ok {
				break
			}
			seen[key] = struct{}{}
			result = append(result, LANNeighbor{IP: ip.String(), MAC: strings.ToLower(mac.String()), Interface: entry.Interface, State: state})
			break
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Interface != result[j].Interface {
			return result[i].Interface < result[j].Interface
		}
		return result[i].IP < result[j].IP
	})
	return result, nil
}

func excludedLANInterface(name string, defaults map[string]struct{}) bool {
	if _, ok := defaults[name]; ok {
		return true
	}
	for _, prefix := range []string{"lo", "ppp", "docker", "veth", "tun", "wg", "mihomo", "tailscale", "zt"} {
		if name == prefix || strings.HasPrefix(name, prefix) {
			return true
		}
	}
	if strings.HasPrefix(name, "br-") && len(name) == len("br-")+12 {
		return true
	}
	return false
}

func excludedNeighborState(states []string) bool {
	for _, state := range states {
		if state == "FAILED" || state == "INCOMPLETE" || state == "NOARP" {
			return true
		}
	}
	return false
}
