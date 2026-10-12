package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func updateTestManager(t *testing.T) *ProcessManager {
	t.Helper()
	dir := t.TempDir()
	bin, config := filepath.Join(dir, "mihomo"), filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nif [ \"$1\" = \"-v\" ]; then echo 'Mihomo Meta v1.0'; exit 0; fi\nexec /bin/sleep 60\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, []byte("rules:\n  - MATCH,DIRECT\n"), 0600); err != nil {
		t.Fatal(err)
	}
	m := newProcessManager(bin, config, filepath.Join(dir, "data"), filepath.Join(dir, "state"), "test", RuntimeState{MixedPort: unusedPort(t), ControllerPort: unusedPort(t), Mode: "rule", TunStack: "system"})
	m.controllerProbe = func(context.Context) error { return nil }
	t.Cleanup(func() { _ = m.Stop(context.Background()) })
	return m
}

func TestMihomoUpdateRollsBackFailedCandidateAndRestartsOriginal(t *testing.T) {
	m := updateTestManager(t)
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	var actions []string
	helper := func(ctx context.Context, action string) (helperResponse, error) {
		actions = append(actions, action)
		switch action {
		case "mihomo-update-install":
			candidate := filepath.Join(filepath.Dir(m.bin), "candidate")
			if err := os.WriteFile(candidate, []byte("#!/bin/sh\nexit 1\n"), 0755); err != nil {
				return helperResponse{}, err
			}
			m.controllerProbe = func(context.Context) error { return errors.New("candidate unhealthy") }
			return helperResponse{}, replaceMihomoBinary(m.bin, candidate)
		case "mihomo-update-rollback":
			m.controllerProbe = func(context.Context) error { return nil }
			return helperResponse{}, restoreMihomoBinary(m.bin)
		}
		return helperResponse{OK: true}, nil
	}
	result, err := m.UpdateMihomo(context.Background(), helper)
	if err == nil || !result.RolledBack || !result.Running || result.Updated {
		t.Fatalf("result = %+v, error = %v", result, err)
	}
	if !reflect.DeepEqual(actions, []string{"mihomo-update-prepare", "mihomo-update-install", "mihomo-update-rollback"}) {
		t.Fatalf("actions = %v", actions)
	}
	status := m.Status(context.Background())
	if !status.ProcessAlive || !status.DesiredRunning {
		t.Fatalf("original not restored: %+v", status)
	}
}

func TestMihomoUpdateDownloadFailureKeepsRunningProcess(t *testing.T) {
	m := updateTestManager(t)
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	pid := m.Status(context.Background()).PID
	result, err := m.UpdateMihomo(context.Background(), func(ctx context.Context, action string) (helperResponse, error) {
		if action != "mihomo-update-prepare" {
			t.Fatalf("unexpected action %s", action)
		}
		return helperResponse{}, errors.New("download interrupted")
	})
	if err == nil || result.Updated || result.RolledBack {
		t.Fatalf("result = %+v, error = %v", result, err)
	}
	if status := m.Status(context.Background()); status.PID != pid || !status.ProcessAlive {
		t.Fatalf("download failure changed process: %+v", status)
	}
}

func TestMihomoUpdatePreservesStoppedStateAfterHealthCheck(t *testing.T) {
	m := updateTestManager(t)
	result, err := m.UpdateMihomo(context.Background(), func(context.Context, string) (helperResponse, error) { return helperResponse{OK: true}, nil })
	if err != nil || !result.Updated || result.Running {
		t.Fatalf("result = %+v, error = %v", result, err)
	}
	if state := m.RuntimeConfig(); state.DesiredRunning || state.PID != 0 {
		t.Fatalf("stopped state changed: %+v", state)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if status := m.Status(context.Background()); status.Error != "" {
			t.Fatalf("normal stop after health check was reported as an error: %+v", status)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestMihomoUpdateCancellationStillRollsBack(t *testing.T) {
	m := updateTestManager(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rollbackCalled := false
	result, err := m.UpdateMihomo(ctx, func(actionCtx context.Context, action string) (helperResponse, error) {
		if action == "mihomo-update-install" {
			cancel()
		}
		if action == "mihomo-update-rollback" {
			rollbackCalled = true
			if actionCtx.Err() != nil {
				t.Fatal("recovery inherited cancelled request")
			}
		}
		return helperResponse{OK: true}, nil
	})
	if err == nil || !rollbackCalled || !result.RolledBack || result.Running {
		t.Fatalf("result = %+v, rollback = %v, error = %v", result, rollbackCalled, err)
	}
	if m.RuntimeConfig().DesiredRunning {
		t.Fatal("cancelled update changed stopped state")
	}
}

func TestMihomoUpdateDoesNotStartUnconfirmedOrStoppedTun(t *testing.T) {
	for _, state := range []RuntimeState{{TunEnabled: true, DesiredRunning: true}, {TunEnabled: true, TunTestConfirmed: true}} {
		m := updateTestManager(t)
		m.state = state
		_, err := m.UpdateMihomo(context.Background(), func(context.Context, string) (helperResponse, error) {
			t.Fatal("unsafe TUN state reached update helper")
			return helperResponse{}, nil
		})
		if err == nil {
			t.Fatal("unsafe TUN state accepted")
		}
		m.state.TunEnabled = false
	}
}
