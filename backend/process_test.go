package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestProcessManagerDoesNotDuplicateAndStopsManagedChild(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "fake-mihomo")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexec /bin/sleep 60\n"), 0755); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "minimal-safe.yaml")
	if err := os.WriteFile(config, []byte("mode: rule\n"), 0600); err != nil {
		t.Fatal(err)
	}
	mixed := unusedPort(t)
	controller := unusedPort(t)
	state := RuntimeState{BackendPort: 18080, MixedPort: mixed, ControllerPort: controller, Mode: "rule", DesiredRunning: true}
	m := newProcessManager(bin, config, filepath.Join(dir, "runtime"), filepath.Join(dir, "state"), "unit-test-secret-not-for-api", state)
	m.controllerProbe = func(context.Context) error { return nil }
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	pid := m.proc.Pid
	m.mu.Unlock()
	if err := m.Start(ctx); err != nil {
		t.Fatalf("duplicate Start should be idempotent: %v", err)
	}
	m.mu.Lock()
	if m.proc == nil || m.proc.Pid != pid {
		t.Fatalf("duplicate Start created or lost the process: before=%d after=%v", pid, m.proc)
	}
	m.mu.Unlock()
	if err := m.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	saved, err := loadRuntimeState(m.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if saved.DesiredRunning {
		t.Fatal("manual stop left desired-running state enabled")
	}
	if err := m.Start(ctx); err != nil {
		t.Fatalf("Start after Stop failed: %v", err)
	}
	if err := m.StopForShutdown(ctx); err != nil {
		t.Fatal(err)
	}
	saved, err = loadRuntimeState(m.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if !saved.DesiredRunning {
		t.Fatal("backend shutdown cleared desired-running state")
	}
}

func TestStartupSettingsPersistAcrossRuntimeStateReload(t *testing.T) {
	dir := t.TempDir()
	state := RuntimeState{BackendPort: 18080, MixedPort: 17890, ControllerPort: 9091, DesiredRunning: true, AutoStart: true, RestartOnFailure: true, Mode: "rule", TunStack: "system"}
	m := newProcessManager("/unused", "/unused", "/unused", dir, "secret", state)
	if err := m.SetStartupSettings(false, false); err != nil {
		t.Fatal(err)
	}
	saved, err := loadRuntimeState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if saved.AutoStart || saved.RestartOnFailure || !saved.DesiredRunning {
		t.Fatalf("startup preferences were not persisted: %#v", saved)
	}
}

func TestTunConfirmationResetsWhenTunIsToggled(t *testing.T) {
	dir := t.TempDir()
	state := RuntimeState{BackendPort: 18080, MixedPort: 17890, ControllerPort: 9091, DesiredRunning: true, Mode: "rule", TunStack: "system"}
	m := newProcessManager("/unused", "/unused", "/unused", dir, "secret", state)
	if err := m.SetTunSettings(true, "system"); err != nil {
		t.Fatal(err)
	}
	if err := m.MarkTunTestConfirmed(); err != nil {
		t.Fatal(err)
	}
	if err := m.SetTunSettings(false, "system"); err != nil {
		t.Fatal(err)
	}
	if err := m.SetTunSettings(true, "system"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, confirmed := m.TunSettings(); confirmed {
		t.Fatal("a new TUN enable inherited confirmation from an earlier test")
	}
}

func unusedPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}
