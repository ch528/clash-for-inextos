package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"
)

type mihomoUpdateResult struct {
	Updated    bool `json:"updated"`
	RolledBack bool `json:"rolled_back"`
	Running    bool `json:"running"`
}

func (m *ProcessManager) UpdateMihomo(ctx context.Context, helper func(context.Context, string) (helperResponse, error)) (mihomoUpdateResult, error) {
	var result mihomoUpdateResult
	if err := ctx.Err(); err != nil {
		return result, err
	}
	before := m.RuntimeConfig()
	if networkCaptureActive(before) && (!before.TunTestConfirmed || !before.DesiredRunning) {
		return result, errors.New("turn off network capture before updating while its test is unconfirmed or Mihomo is stopped")
	}
	if _, err := helper(ctx, "mihomo-update-prepare"); err != nil {
		return result, err
	}
	m.operationMu.Lock()
	defer m.operationMu.Unlock()
	if err := ctx.Err(); err != nil {
		return result, err
	}
	before = m.RuntimeConfig()
	if networkCaptureActive(before) && (!before.TunTestConfirmed || !before.DesiredRunning) {
		return result, errors.New("turn off network capture before updating while its test is unconfirmed or Mihomo is stopped")
	}
	config, err := os.ReadFile(m.configFile)
	if err != nil {
		return result, err
	}
	if err := m.stopProcess(ctx); err != nil {
		return result, err
	}
	if _, err := helper(ctx, "mihomo-update-install"); err != nil {
		if before.DesiredRunning {
			restoreCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			if restoreErr := m.start(restoreCtx); restoreErr != nil {
				return result, fmt.Errorf("update installation failed: %v; restarting installed version failed: %w", err, restoreErr)
			}
		}
		return result, err
	}
	err = m.start(ctx)
	if err == nil && !before.DesiredRunning {
		err = m.stop(ctx)
	}
	if err == nil {
		result.Updated, result.Running = true, before.DesiredRunning
		return result, nil
	} else {
		// Recovery must finish even if the browser disconnected or its request expired.
		restoreCtx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		if stopErr := m.stopProcess(restoreCtx); stopErr != nil {
			return result, fmt.Errorf("candidate startup failed: %v; stopping candidate failed: %w", err, stopErr)
		}
		if _, rollbackErr := helper(restoreCtx, "mihomo-update-rollback"); rollbackErr != nil {
			return result, fmt.Errorf("candidate startup failed: %v; binary rollback failed: %w", err, rollbackErr)
		}
		result.RolledBack = true
		if configErr := atomicWrite(m.configFile, config, 0600); configErr != nil {
			return result, fmt.Errorf("binary rolled back; config restore failed: %w", configErr)
		}
		m.mu.Lock()
		before.PID, before.StartedAt = 0, time.Time{}
		m.state, m.proc = before, nil
		stateErr := saveRuntimeState(m.stateDir, before)
		m.mu.Unlock()
		if stateErr != nil {
			return result, fmt.Errorf("binary rolled back; runtime restore failed: %w", stateErr)
		}
		if before.DesiredRunning {
			if restartErr := m.start(restoreCtx); restartErr != nil {
				return result, fmt.Errorf("binary rolled back; previous version startup failed: %w", restartErr)
			}
			result.Running = true
		}
		return result, fmt.Errorf("candidate startup failed; previous version restored: %w", err)
	}
}
