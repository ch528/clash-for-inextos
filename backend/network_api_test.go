package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApplyNetworkSettingsPersistsDisabledPreferences(t *testing.T) {
	dir := t.TempDir()
	api := testAPI(dir)
	api.manager.configFile = filepath.Join(dir, "mihomo.yaml")
	api.manager.runtimeDir = dir
	api.manager.stateDir = api.stateDir
	api.manager.bin = filepath.Join(dir, "mihomo")
	if err := os.WriteFile(api.manager.bin, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(api.manager.configFile, []byte("previous config\n"), 0600); err != nil {
		t.Fatal(err)
	}

	state := api.manager.RuntimeConfig()
	state.TunStack = "system"
	state.LANProxy = LANProxySettings{Mode: "selected", Clients: []LANClientPolicy{{Name: "TV", IP: "192.168.100.22", MAC: "02:00:00:00:00:22", Action: "proxy"}}}
	state.DNS = DNSSettings{Mode: "custom", CustomNameservers: []string{"192.168.100.1"}}
	if err := api.applyNetworkSettings(context.Background(), state); err != nil {
		t.Fatal(err)
	}

	saved, err := loadRuntimeState(api.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if saved.LANProxy.Enabled || saved.DNS.Enabled || saved.LANProxy.Mode != "selected" || saved.DNS.Mode != "custom" {
		t.Fatalf("network preferences were not saved in the disabled state: %#v", saved)
	}
	config, err := os.ReadFile(api.manager.configFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(config), "enable: false") {
		t.Fatalf("disabled network preferences enabled TUN: %s", config)
	}
}

func TestApplyNetworkSettingsRejectsLiveCaptureReconfiguration(t *testing.T) {
	api := testAPI(t.TempDir())
	state := api.manager.RuntimeConfig()
	state.TunStack = "system"
	state.TunEnabled = true
	if err := api.manager.SetNetworkSettings(state); err != nil {
		t.Fatal(err)
	}
	candidate := api.manager.RuntimeConfig()
	candidate.LANProxy = LANProxySettings{Enabled: true, Mode: "all"}
	if err := api.applyNetworkSettings(context.Background(), candidate); err == nil || !strings.Contains(err.Error(), "请先关闭当前网络接管") {
		t.Fatalf("live capture reconfiguration was not refused: %v", err)
	}
}
