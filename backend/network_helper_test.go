package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestNetworkOperationLockHonorsContextWhileBusy(t *testing.T) {
	directory := t.TempDir()
	locked := make(chan struct{})
	release := make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- withNetworkOperationLock(context.Background(), directory, func() error {
			close(locked)
			<-release
			return nil
		})
	}()
	<-locked

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	secondRan := false
	err := withNetworkOperationLock(ctx, directory, func() error {
		secondRan = true
		return nil
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiting for the network lock returned %v, want deadline exceeded", err)
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatalf("first network operation failed: %v", err)
	}
	if secondRan {
		t.Fatal("network operation ran after its context expired")
	}
}

func TestNetworkTestConfirmationRequiresRunningCapture(t *testing.T) {
	valid := RuntimeState{TunEnabled: true, DesiredRunning: true}
	if err := validateNetworkTestConfirmation(valid, true, true); err != nil {
		t.Fatalf("active Mihomo capture was rejected: %v", err)
	}

	cases := []struct {
		name         string
		state        RuntimeState
		mihomoActive bool
		interfaceUp  bool
	}{
		{name: "capture disabled", state: RuntimeState{DesiredRunning: true}, mihomoActive: true, interfaceUp: true},
		{name: "desired stopped", state: RuntimeState{TunEnabled: true}, interfaceUp: true},
		{name: "service stopped", state: RuntimeState{TunEnabled: true, DesiredRunning: true}, interfaceUp: true},
		{name: "tun interface unavailable", state: valid, mihomoActive: true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if err := validateNetworkTestConfirmation(test.state, test.mihomoActive, test.interfaceUp); err == nil {
				t.Fatal("invalid network test state was accepted")
			}
		})
	}
}

func TestTunReadinessRequiresControllerAndInterface(t *testing.T) {
	if err := validateTunReadiness(nil, true); err != nil {
		t.Fatalf("ready TUN was rejected: %v", err)
	}
	if err := validateTunReadiness(nil, false); err == nil {
		t.Fatal("controller-only readiness was accepted without the TUN interface")
	}
	controllerErr := errors.New("controller unavailable")
	if err := validateTunReadiness(controllerErr, true); !errors.Is(err, controllerErr) {
		t.Fatalf("controller failure was not preserved: %v", err)
	}
}
