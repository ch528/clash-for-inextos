package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"go.yaml.in/yaml/v3"
)

const (
	mihomoUnit          = "inextos-clash-mihomo.service"
	backendUnit         = "inextos-clash.service"
	networkRollbackUnit = "inextos-clash-network-rollback.timer"
	rollbackConfig      = "/var/lib/inextos-clash/state/pre-tun-config.yaml"
	rollbackState       = "/var/lib/inextos-clash/state/pre-tun-runtime.json"
)

func runHelperDaemon() error {
	if os.Geteuid() != 0 {
		return errors.New("helper daemon requires root")
	}
	if err := os.MkdirAll(helperSocketDir, 0750); err != nil {
		return err
	}
	if info, err := os.Lstat(helperSocketPath); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return errors.New("helper socket path is not a socket")
		}
		if err := os.Remove(helperSocketPath); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	listener, err := net.Listen("unix", helperSocketPath)
	if err != nil {
		return err
	}
	defer func() {
		_ = listener.Close()
		_ = os.Remove(helperSocketPath)
	}()
	if err := os.Chmod(helperSocketPath, 0660); err != nil {
		return err
	}
	group, err := user.LookupGroup("inextos-clash")
	if err != nil {
		return err
	}
	groupID, err := strconv.Atoi(group.Gid)
	if err != nil {
		return err
	}
	if err := os.Chown(helperSocketPath, 0, groupID); err != nil {
		return err
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go serveHelperConn(conn)
	}
}

func serveHelperConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	action, err := decodeHelperRequest(io.LimitReader(conn, 4097))
	if err != nil {
		_ = json.NewEncoder(conn).Encode(helperResponse{Status: "invalid helper request"})
		return
	}
	response := executeHelperAction(action)
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_ = json.NewEncoder(conn).Encode(response)
}

func executeHelperAction(action string) helperResponse {
	if _, ok := fixedHelperActions[action]; !ok {
		return helperResponse{Status: "unsupported action"}
	}
	timeout := 45 * time.Second
	if action == "mihomo-update-prepare" {
		timeout = mihomoPrepareTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var err error
	switch action {
	case "mihomo-update-prepare":
		err = prepareMihomoCandidate(ctx)
	case "mihomo-update-install":
		err = installMihomoCandidate(ctx, false)
	case "mihomo-update-rollback":
		err = installMihomoCandidate(ctx, true)
	case "app-update-start":
		if applicationNetworkCaptureActive() {
			return helperResponse{Status: "Turn off network capture before updating the application"}
		}
		if _, err := exec.CommandContext(ctx, "/usr/bin/systemctl", "is-active", "--quiet", appUpdateUnit).CombinedOutput(); err == nil {
			return helperResponse{OK: true, Status: "already running"}
		}
		err = helperSystemctl(ctx, "start", "--no-block", appUpdateUnit)
	case "app-update-status":
		status, statusErr := readApplicationUpdateStatus(appUpdateDirectory)
		if statusErr != nil {
			return helperResponse{Status: "application update status is unavailable"}
		}
		return helperResponse{OK: true, Status: "ok", ApplicationUpdate: &status}
	case "mihomo-start", "tun-enable":
		if !runtimeTunEnabled() {
			return helperResponse{Status: "TUN is not enabled in the saved application state"}
		}
		if err = validateTunConfig(); err == nil {
			err = helperSystemctl(ctx, "start", mihomoUnit)
		}
	case "mihomo-stop", "tun-disable":
		err = helperSystemctl(ctx, "stop", mihomoUnit)
	case "mihomo-restart":
		if !runtimeTunEnabled() {
			return helperResponse{Status: "TUN is not enabled in the saved application state"}
		}
		if err = validateTunConfig(); err == nil {
			err = helperSystemctl(ctx, "restart", mihomoUnit)
		}
	case "tun-status":
		return helperTunStatus(ctx, false)
	case "tun-diagnostics":
		return helperTunStatus(ctx, true)
	case "network-prepare":
		err = withNetworkOperationLock(ctx, stateDir, func() error { return prepareNetworkRollback(ctx) })
	case "network-confirm":
		err = withNetworkOperationLock(ctx, stateDir, func() error { return confirmNetworkTest(ctx) })
	case "network-abort":
		err = withNetworkOperationLock(ctx, stateDir, func() error { return abortNetworkTest(ctx) })
	case "network-rollback":
		err = withNetworkOperationLock(ctx, stateDir, func() error { return rollbackNetwork(ctx) })
		if err != nil {
			_ = recordSystemEvent(systemEventsPath(stateDir), "network_rollback_failed", time.Now())
		} else {
			_ = recordSystemEvent(systemEventsPath(stateDir), "network_rollback", time.Now())
		}
	}
	if err != nil {
		return helperResponse{Status: safeHelperError(err)}
	}
	return helperResponse{OK: true, Status: "ok"}
}

func withNetworkOperationLock(ctx context.Context, directory string, operation func() error) error {
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	lock, err := os.OpenFile(filepath.Join(directory, "network-operation.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	return operation()
}

func helperSystemctl(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, "/usr/bin/systemctl", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if len(message) > 240 {
			message = message[:240]
		}
		if message == "" {
			return fmt.Errorf("systemd operation failed: %s", strings.Join(args, " "))
		}
		return fmt.Errorf("systemd operation failed: %s", message)
	}
	return nil
}

func safeHelperError(err error) string {
	message := strings.TrimSpace(err.Error())
	if len(message) > 240 {
		message = message[:240]
	}
	return message
}

func runtimeTunEnabled() bool {
	state, err := loadRuntimeState(stateDir)
	return err == nil && networkCaptureActive(state)
}

func validateTunConfig() error {
	data, err := os.ReadFile(filepath.Join(runDir, "mihomo.yaml"))
	if err != nil {
		return err
	}
	var config struct {
		Tun struct {
			Enable bool   `yaml:"enable"`
			Stack  string `yaml:"stack"`
		} `yaml:"tun"`
	}
	if err := yaml.Unmarshal(data, &config); err != nil {
		return errors.New("Mihomo config is invalid")
	}
	if !config.Tun.Enable || (config.Tun.Stack != "system" && config.Tun.Stack != "gvisor" && config.Tun.Stack != "mixed") {
		return errors.New("Mihomo TUN settings are invalid")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(installDir, "bin", "mihomo"), "-t", "-f", filepath.Join(runDir, "mihomo.yaml"), "-d", mihomoDataDir)
	if output, err := cmd.CombinedOutput(); err != nil {
		_ = output
		return errors.New("Mihomo rejected the TUN configuration")
	}
	return nil
}

func helperTunStatus(ctx context.Context, diagnostics bool) helperResponse {
	data, err := os.ReadFile(filepath.Join(stateDir, "runtime.json"))
	if err != nil {
		return helperResponse{Status: "runtime state unavailable"}
	}
	var state RuntimeState
	if err := json.Unmarshal(data, &state); err != nil {
		return helperResponse{Status: "runtime state invalid"}
	}
	if _, err := exec.CommandContext(ctx, "/usr/bin/systemctl", "cat", mihomoUnit).CombinedOutput(); err != nil {
		return helperResponse{Status: "Mihomo TUN service is unavailable"}
	}
	status := "supported"
	if diagnostics {
		if _, err := exec.CommandContext(ctx, "/usr/bin/systemctl", "is-active", "--quiet", mihomoUnit).CombinedOutput(); err == nil {
			status = "enabled and running"
		} else if networkCaptureActive(state) {
			status = "enabled but stopped"
		} else {
			status = "disabled"
		}
	}
	return helperResponse{OK: true, Status: status, TunEnabled: networkCaptureActive(state), TunTestConfirmed: state.TunTestConfirmed, Supported: true, Stacks: []string{"system", "gvisor", "mixed"}}
}

func prepareNetworkRollback(ctx context.Context) error {
	state, err := loadRuntimeState(stateDir)
	if err != nil {
		return err
	}
	if networkCaptureActive(state) {
		return errors.New("network rollback preparation requires TUN, LAN proxy, and DNS takeover to be disabled")
	}
	configPath := filepath.Join(runDir, "mihomo.yaml")
	config, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	stateData, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if err := atomicWrite(rollbackConfig, config, 0600); err != nil {
		return err
	}
	if err := atomicWrite(rollbackState, append(stateData, '\n'), 0600); err != nil {
		_ = os.Remove(rollbackConfig)
		return err
	}
	if err := helperSystemctl(ctx, "restart", networkRollbackUnit); err != nil {
		_ = os.Remove(rollbackConfig)
		_ = os.Remove(rollbackState)
		return err
	}
	return nil
}

func confirmNetworkTest(ctx context.Context) error {
	state, err := loadRuntimeState(stateDir)
	if err != nil {
		return err
	}
	_, activeErr := exec.CommandContext(ctx, "/usr/bin/systemctl", "is-active", "--quiet", mihomoUnit).CombinedOutput()
	if err := validateNetworkTestConfirmation(state, activeErr == nil, tunInterfacePresent()); err != nil {
		return err
	}
	state.TunTestConfirmed = true
	if err := saveAppRuntimeState(state); err != nil {
		return err
	}
	if err := helperSystemctl(ctx, "stop", networkRollbackUnit); err != nil {
		return err
	}
	_ = os.Remove(rollbackConfig)
	_ = os.Remove(rollbackState)
	return nil
}

func validateNetworkTestConfirmation(state RuntimeState, mihomoActive, interfacePresent bool) error {
	if !networkCaptureActive(state) {
		return errors.New("cannot confirm a network test while TUN, LAN proxy, and DNS takeover are disabled")
	}
	if !state.DesiredRunning || !mihomoActive {
		return errors.New("cannot confirm a network test while Mihomo is stopped")
	}
	if !interfacePresent {
		return errors.New("cannot confirm a network test while the Mihomo TUN interface is unavailable")
	}
	return nil
}

func abortNetworkTest(ctx context.Context) error {
	if err := helperSystemctl(ctx, "stop", networkRollbackUnit); err != nil {
		return err
	}
	_ = os.Remove(rollbackConfig)
	_ = os.Remove(rollbackState)
	return nil
}

func rollbackNetwork(ctx context.Context) error {
	currentState, err := loadRuntimeState(stateDir)
	if err != nil {
		return err
	}
	if currentState.TunTestConfirmed {
		if err := helperSystemctl(ctx, "stop", networkRollbackUnit); err != nil {
			return err
		}
		_ = os.Remove(rollbackConfig)
		_ = os.Remove(rollbackState)
		return nil
	}
	config, err := os.ReadFile(rollbackConfig)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	stateData, err := os.ReadFile(rollbackState)
	if err != nil {
		return err
	}
	var state RuntimeState
	if err := json.Unmarshal(stateData, &state); err != nil {
		return err
	}
	if err := helperSystemctl(ctx, "stop", mihomoUnit); err != nil {
		return err
	}
	if err := writeAppFile(filepath.Join(runDir, "mihomo.yaml"), config, 0600); err != nil {
		return err
	}
	state.TunEnabled = false
	state.LANProxy.Enabled = false
	state.DNS.Enabled = false
	state.TunTestConfirmed = false
	state.PID = 0
	state.StartedAt = time.Time{}
	if err := saveAppRuntimeState(state); err != nil {
		return err
	}
	if err := helperSystemctl(ctx, "stop", networkRollbackUnit); err != nil {
		return err
	}
	_ = os.Remove(rollbackConfig)
	_ = os.Remove(rollbackState)
	return helperSystemctl(ctx, "restart", backendUnit)
}

func saveAppRuntimeState(state RuntimeState) error {
	if err := saveRuntimeState(stateDir, state); err != nil {
		return err
	}
	return chownAppFile(filepath.Join(stateDir, "runtime.json"))
}

func writeAppFile(path string, data []byte, mode os.FileMode) error {
	if err := atomicWrite(path, data, mode); err != nil {
		return err
	}
	return chownAppFile(path)
}

func chownAppFile(path string) error {
	account, err := user.Lookup("inextos-clash")
	if err != nil {
		return err
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		return err
	}
	group, err := user.LookupGroup("inextos-clash")
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil {
		return err
	}
	return os.Chown(path, uid, gid)
}

func callPrivilegedHelper(ctx context.Context, action string) (helperResponse, error) {
	if _, ok := fixedHelperActions[action]; !ok {
		return helperResponse{}, errors.New("unsupported privileged helper action")
	}
	conn, err := (&net.Dialer{Timeout: 4 * time.Second}).DialContext(ctx, "unix", helperSocketPath)
	if err != nil {
		return helperResponse{}, errors.New("privileged network helper is unavailable")
	}
	defer conn.Close()
	timeout := 45 * time.Second
	if action == "mihomo-update-prepare" {
		timeout = mihomoPrepareTimeout + 5*time.Second
	}
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return helperResponse{}, context.DeadlineExceeded
		}
		if remaining < timeout {
			timeout = remaining
		}
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if err := json.NewEncoder(conn).Encode(helperRequest{Action: action}); err != nil {
		return helperResponse{}, errors.New("could not contact privileged network helper")
	}
	var response helperResponse
	if err := json.NewDecoder(io.LimitReader(conn, 4097)).Decode(&response); err != nil {
		return helperResponse{}, errors.New("privileged network helper returned an invalid response")
	}
	if !response.OK {
		return response, errors.New(response.Status)
	}
	return response, nil
}

func runHelperAction(args []string) error {
	if os.Geteuid() != 0 {
		return errors.New("helper-action requires root")
	}
	if len(args) != 1 {
		return errors.New("helper-action requires one fixed action")
	}
	response := executeHelperAction(args[0])
	if !response.OK {
		return errors.New(response.Status)
	}
	fmt.Println(response.Status)
	return nil
}
