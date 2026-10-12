package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var errPortConflict = errors.New("selected port is already in use by another process")

type ProcessManager struct {
	operationMu      sync.Mutex
	mu               sync.Mutex
	bin              string
	configFile       string
	runtimeDir       string
	stateDir         string
	secret           string
	state            RuntimeState
	proc             *os.Process
	expectedStop     *os.Process
	startedAt        time.Time
	lastError        string
	restartOnFailure bool
	controllerProbe  func(context.Context) error
}

type MihomoStatus struct {
	Running             bool   `json:"running"`
	DesiredRunning      bool   `json:"desired_running"`
	ProcessAlive        bool   `json:"process_alive"`
	PID                 int    `json:"pid"`
	Version             string `json:"version"`
	UptimeSeconds       int64  `json:"uptime_seconds"`
	ControllerAvailable bool   `json:"controller_available"`
	Error               string `json:"error,omitempty"`
}

func newProcessManager(bin, configFile, runtimeDir, stateDir, secret string, state RuntimeState) *ProcessManager {
	return &ProcessManager{bin: bin, configFile: configFile, runtimeDir: runtimeDir, stateDir: stateDir, secret: secret, state: state, startedAt: state.StartedAt, restartOnFailure: state.RestartOnFailure}
}

func (m *ProcessManager) Reconcile() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	pid := m.state.PID
	if pid == 0 || !managedProcess(pid, m.bin, m.configFile, m.runtimeDir) {
		pid = findManagedProcess(m.bin, m.configFile, m.runtimeDir)
	}
	if pid > 0 {
		p, err := os.FindProcess(pid)
		if err == nil && processAlive(p) {
			m.proc = p
			m.state.PID = pid
			if err := saveRuntimeState(m.stateDir, m.state); err != nil {
				return err
			}
			return nil
		}
	}
	m.proc = nil
	m.state.PID = 0
	m.state.StartedAt = time.Time{}
	if !portAvailable(m.state.MixedPort, true) || !portAvailable(m.state.ControllerPort, false) {
		return errPortConflict
	}
	return saveRuntimeState(m.stateDir, m.state)
}

func (m *ProcessManager) Start(ctx context.Context) error {
	m.operationMu.Lock()
	defer m.operationMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	return m.start(ctx)
}

func (m *ProcessManager) start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	if m.proc != nil && processAlive(m.proc) {
		m.state.DesiredRunning = true
		if err := saveRuntimeState(m.stateDir, m.state); err != nil {
			m.mu.Unlock()
			return err
		}
		m.mu.Unlock()
		if err := m.checkController(ctx); err == nil {
			return nil
		}
		return errors.New("managed Mihomo is alive but Controller is unavailable")
	}
	m.proc = nil
	m.state.PID = 0
	if networkCaptureActive(m.state) {
		m.state.DesiredRunning = true
		if err := saveRuntimeState(m.stateDir, m.state); err != nil {
			m.mu.Unlock()
			return err
		}
		m.mu.Unlock()
		if err := m.startTunService(ctx); err != nil {
			return m.fallbackFromTun(err)
		}
		return nil
	}
	if !portAvailable(m.state.MixedPort, true) || !portAvailable(m.state.ControllerPort, false) {
		m.mu.Unlock()
		return errPortConflict
	}
	if st, err := os.Stat(m.bin); err != nil || st.IsDir() || st.Mode()&0111 == 0 {
		m.mu.Unlock()
		return errors.New("Mihomo binary is missing or not executable")
	}
	m.state.DesiredRunning = true
	if err := saveRuntimeState(m.stateDir, m.state); err != nil {
		m.mu.Unlock()
		return err
	}
	logPath := filepath.Join(m.stateDir, "mihomo.log")
	if err := os.MkdirAll(m.stateDir, 0700); err != nil {
		m.mu.Unlock()
		return err
	}
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	cmd := exec.Command(m.bin, "-f", m.configFile, "-d", m.runtimeDir)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		m.lastError = "Mihomo failed to start"
		m.mu.Unlock()
		return errors.New("Mihomo failed to start")
	}
	_ = logFile.Close()
	m.proc = cmd.Process
	m.startedAt = time.Now()
	m.lastError = ""
	m.state.PID = cmd.Process.Pid
	m.state.StartedAt = m.startedAt
	if err := saveRuntimeState(m.stateDir, m.state); err != nil {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		_ = cmd.Wait()
		m.proc = nil
		m.state.PID = 0
		m.state.StartedAt = time.Time{}
		m.mu.Unlock()
		return err
	}
	m.mu.Unlock()
	go m.wait(cmd)

	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if err := m.checkController(ctx); err == nil {
			return nil
		}
		if !processAlive(cmd.Process) {
			break
		}
		time.Sleep(150 * time.Millisecond)
	}
	_ = m.stop(context.Background())
	m.mu.Lock()
	m.lastError = "Mihomo Controller did not become ready"
	m.mu.Unlock()
	return errors.New("Mihomo Controller did not become ready; see the bounded log endpoint")
}

func (m *ProcessManager) wait(cmd *exec.Cmd) {
	err := cmd.Wait()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.proc == cmd.Process {
		m.proc = nil
		m.state.PID = 0
		m.state.StartedAt = time.Time{}
		expectedStop := m.expectedStop == cmd.Process
		if expectedStop {
			m.expectedStop = nil
		}
		if err != nil && !expectedStop && m.lastError == "" {
			m.lastError = "Mihomo exited unexpectedly"
		}
		_ = saveRuntimeState(m.stateDir, m.state)
	}
}

func (m *ProcessManager) startTunService(ctx context.Context) error {
	if _, err := callPrivilegedHelper(ctx, "mihomo-start"); err != nil {
		return err
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if err := m.checkTunReadiness(ctx); err == nil {
			_ = m.Reconcile()
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(150 * time.Millisecond):
		}
	}
	return errors.New("Mihomo Controller did not become ready; see the bounded log endpoint")
}

func (m *ProcessManager) fallbackFromTun(cause error) error {
	_, _ = callPrivilegedHelper(context.Background(), "mihomo-stop")
	state := m.RuntimeConfig()
	state.TunEnabled = false
	state.LANProxy.Enabled = false
	state.DNS.Enabled = false
	state.TunTestConfirmed = false
	if err := m.SetNetworkSettings(state); err != nil {
		return fmt.Errorf("network capture failed (%v); could not disable saved capture state: %w", cause, err)
	}
	if err := disableTunInConfig(m.configFile); err != nil {
		return fmt.Errorf("TUN failed (%v); could not restore the non-TUN config: %w", cause, err)
	}
	_, _ = callPrivilegedHelper(context.Background(), "network-abort")
	startCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := m.start(startCtx); err != nil {
		return fmt.Errorf("TUN failed (%v); normal Mihomo fallback failed: %w", cause, err)
	}
	m.mu.Lock()
	m.lastError = "network capture startup failed; TUN, LAN proxy, and DNS takeover were disabled"
	m.mu.Unlock()
	return fmt.Errorf("network capture failed and was disabled; normal Mihomo is running: %w", cause)
}

func (m *ProcessManager) Stop(ctx context.Context) error {
	m.operationMu.Lock()
	defer m.operationMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	return m.stop(ctx)
}

func (m *ProcessManager) stop(ctx context.Context) error {
	m.mu.Lock()
	m.state.DesiredRunning = false
	if err := saveRuntimeState(m.stateDir, m.state); err != nil {
		m.mu.Unlock()
		return err
	}
	m.mu.Unlock()
	return m.stopProcess(ctx)
}

func (m *ProcessManager) StopForShutdown(ctx context.Context) error {
	m.operationMu.Lock()
	defer m.operationMu.Unlock()
	m.mu.Lock()
	tunEnabled := networkCaptureActive(m.state)
	m.mu.Unlock()
	if tunEnabled {
		return nil
	}
	return m.stopProcess(ctx)
}

func (m *ProcessManager) stopProcess(ctx context.Context) error {
	m.mu.Lock()
	p := m.proc
	tunEnabled := networkCaptureActive(m.state)
	if tunEnabled {
		m.mu.Unlock()
		if _, err := callPrivilegedHelper(ctx, "mihomo-stop"); err != nil {
			return err
		}
		deadline := time.Now().Add(5 * time.Second)
		for p != nil && processAlive(p) && time.Now().Before(deadline) {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(100 * time.Millisecond):
			}
		}
		m.mu.Lock()
		m.proc = nil
		m.state.PID = 0
		m.state.StartedAt = time.Time{}
		_ = saveRuntimeState(m.stateDir, m.state)
		m.mu.Unlock()
		if p != nil && processAlive(p) {
			return errors.New("Mihomo TUN service did not stop")
		}
		return nil
	}
	if p == nil || !processAlive(p) {
		m.proc = nil
		m.state.PID = 0
		m.state.StartedAt = time.Time{}
		if m.expectedStop == p {
			m.expectedStop = nil
		}
		_ = saveRuntimeState(m.stateDir, m.state)
		m.mu.Unlock()
		return nil
	}
	m.expectedStop = p
	if err := p.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
		if m.expectedStop == p {
			m.expectedStop = nil
		}
		m.mu.Unlock()
		return err
	}
	m.mu.Unlock()
	deadline := time.Now().Add(4 * time.Second)
	for processAlive(p) && time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	if processAlive(p) {
		_ = p.Signal(syscall.SIGKILL)
		for i := 0; i < 20 && processAlive(p); i++ {
			time.Sleep(100 * time.Millisecond)
		}
	}
	m.mu.Lock()
	if m.proc == p && !processAlive(p) {
		m.proc = nil
		m.state.PID = 0
		m.state.StartedAt = time.Time{}
		if m.expectedStop == p {
			m.expectedStop = nil
		}
		_ = saveRuntimeState(m.stateDir, m.state)
	}
	m.mu.Unlock()
	if processAlive(p) {
		return errors.New("Mihomo did not stop")
	}
	return nil
}

func (m *ProcessManager) Restart(ctx context.Context) error {
	m.operationMu.Lock()
	defer m.operationMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	m.state.DesiredRunning = true
	tunEnabled := networkCaptureActive(m.state)
	err := saveRuntimeState(m.stateDir, m.state)
	m.mu.Unlock()
	if err != nil {
		return err
	}
	if tunEnabled {
		if _, err := callPrivilegedHelper(ctx, "mihomo-restart"); err != nil {
			return err
		}
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if err := m.checkTunReadiness(ctx); err == nil {
				_ = m.Reconcile()
				return nil
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(150 * time.Millisecond):
			}
		}
		return errors.New("Mihomo TUN service restarted but Controller is unavailable")
	}
	if err := m.stopProcess(ctx); err != nil {
		return err
	}
	return m.start(ctx)
}

func (m *ProcessManager) TunSettings() (enabled bool, stack string, desiredRunning bool, confirmed bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state.TunEnabled, m.state.TunStack, m.state.DesiredRunning, m.state.TunTestConfirmed
}

func (m *ProcessManager) RuntimeConfig() RuntimeState {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state
}

func (m *ProcessManager) SetTunSettings(enabled bool, stack string) error {
	if stack != "system" && stack != "gvisor" && stack != "mixed" {
		return errors.New("TUN stack must be system, gvisor, or mixed")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	previous := m.state
	if previous.TunEnabled != enabled {
		m.state.TunTestConfirmed = false
	}
	m.state.TunEnabled = enabled
	m.state.TunStack = stack
	if err := saveRuntimeState(m.stateDir, m.state); err != nil {
		m.state = previous
		return err
	}
	return nil
}

func (m *ProcessManager) SetNetworkSettings(state RuntimeState) error {
	if state.TunStack != "system" && state.TunStack != "gvisor" && state.TunStack != "mixed" {
		return errors.New("TUN stack must be system, gvisor, or mixed")
	}
	if err := normalizeNetworkSettings(&state); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	previous := m.state
	m.state.TunEnabled = state.TunEnabled
	m.state.TunStack = state.TunStack
	m.state.TunIPv6 = state.TunIPv6
	m.state.TunAutoRedirect = state.TunAutoRedirect
	m.state.LANProxy = state.LANProxy
	m.state.DNS = state.DNS
	m.state.TunTestConfirmed = state.TunTestConfirmed
	if err := saveRuntimeState(m.stateDir, m.state); err != nil {
		m.state = previous
		return err
	}
	return nil
}

func (m *ProcessManager) MarkTunTestConfirmed() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !networkCaptureActive(m.state) {
		return errors.New("cannot confirm a network test while TUN, LAN proxy, and DNS takeover are disabled")
	}
	m.state.TunTestConfirmed = true
	return saveRuntimeState(m.stateDir, m.state)
}

func (m *ProcessManager) SetMode(mode string) error {
	if !validMode(mode) {
		return errors.New("invalid Mihomo mode")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	previous := m.state.Mode
	m.state.Mode = mode
	if err := saveRuntimeState(m.stateDir, m.state); err != nil {
		m.state.Mode = previous
		return err
	}
	return nil
}

func (m *ProcessManager) StartupSettings() (autoStart, restartOnFailure, desiredRunning bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state.AutoStart, m.state.RestartOnFailure, m.state.DesiredRunning
}

func (m *ProcessManager) SetStartupSettings(autoStart, restartOnFailure bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	previous := m.state
	m.state.AutoStart = autoStart
	m.state.RestartOnFailure = restartOnFailure
	m.restartOnFailure = restartOnFailure
	if err := saveRuntimeState(m.stateDir, m.state); err != nil {
		m.state = previous
		m.restartOnFailure = previous.RestartOnFailure
		return err
	}
	return nil
}

func (m *ProcessManager) RestorePortableRuntime(state RuntimeState, config []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.proc != nil && processAlive(m.proc) {
		return errors.New("stop Mihomo before restoring a backup")
	}
	if len(config) == 0 || !validMode(state.Mode) || (state.TunStack != "system" && state.TunStack != "gvisor" && state.TunStack != "mixed") {
		return errors.New("portable backup runtime settings are invalid")
	}
	previous := m.state
	state.BackendPort = previous.BackendPort
	state.DesiredRunning = false
	state.TunEnabled = false
	state.LANProxy.Enabled = false
	state.DNS.Enabled = false
	state.TunTestConfirmed = false
	state.PID = 0
	state.StartedAt = time.Time{}
	if state.MixedPort < 17890 || state.MixedPort > 17920 || state.ControllerPort < 9091 || state.ControllerPort > 9120 || state.MixedPort == state.ControllerPort || state.MixedPort == state.BackendPort || state.ControllerPort == state.BackendPort {
		return errors.New("portable backup ports are invalid")
	}
	if !portAvailable(state.MixedPort, true) || !portAvailable(state.ControllerPort, false) {
		return errPortConflict
	}
	previousConfig, err := os.ReadFile(m.configFile)
	if err != nil {
		return err
	}
	if err := atomicWrite(m.configFile, config, 0600); err != nil {
		return err
	}
	if err := saveRuntimeState(m.stateDir, state); err != nil {
		_ = atomicWrite(m.configFile, previousConfig, 0600)
		return err
	}
	m.state = state
	m.proc = nil
	m.startedAt = time.Time{}
	m.restartOnFailure = state.RestartOnFailure
	m.lastError = ""
	return nil
}

func (m *ProcessManager) Supervise(ctx context.Context, logger *slog.Logger) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if !m.operationMu.TryLock() {
			continue
		}
		m.mu.Lock()
		shouldRun := m.state.DesiredRunning && m.restartOnFailure
		alive := m.proc != nil && processAlive(m.proc)
		m.mu.Unlock()
		if !shouldRun || alive {
			m.operationMu.Unlock()
			continue
		}
		startCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
		err := m.start(startCtx)
		cancel()
		m.operationMu.Unlock()
		_ = recordSystemEvent(systemEventsPath(m.stateDir), "mihomo_crashed", time.Now())
		if logger != nil {
			if err != nil {
				logger.Warn("Mihomo restart after failure failed", "reason", err.Error())
			} else {
				logger.Info("Mihomo restarted after failure")
			}
		}
	}
}

func (m *ProcessManager) Status(ctx context.Context) MihomoStatus {
	m.mu.Lock()
	p := m.proc
	started := m.startedAt
	lastErr := m.lastError
	m.mu.Unlock()
	version := m.version()
	m.mu.Lock()
	desired := m.state.DesiredRunning
	m.mu.Unlock()
	s := MihomoStatus{Version: version, Error: lastErr, DesiredRunning: desired}
	if p == nil || !processAlive(p) {
		if s.Error == "" && version == "" {
			s.Error = "Mihomo binary is not installed"
		}
		return s
	}
	s.ProcessAlive = true
	s.PID = p.Pid
	if !started.IsZero() {
		s.UptimeSeconds = int64(time.Since(started).Seconds())
	}
	if err := m.checkController(ctx); err == nil {
		s.Running = true
		s.ControllerAvailable = true
	} else if s.Error == "" {
		s.Error = "Mihomo Controller is unavailable"
	}
	return s
}

func (m *ProcessManager) checkController(ctx context.Context) error {
	if m.controllerProbe != nil {
		return m.controllerProbe(ctx)
	}
	_, err := m.controllerVersion(ctx)
	return err
}

func (m *ProcessManager) checkTunReadiness(ctx context.Context) error {
	return validateTunReadiness(m.checkController(ctx), tunInterfacePresent())
}

func validateTunReadiness(controllerErr error, interfacePresent bool) error {
	if controllerErr != nil {
		return controllerErr
	}
	if !interfacePresent {
		return errors.New("Mihomo TUN interface is not ready")
	}
	return nil
}

func tunInterfacePresent() bool {
	_, err := os.Stat("/sys/class/net/mihomo0")
	return err == nil
}

func (m *ProcessManager) version() string {
	if _, err := os.Stat(m.bin); err != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, m.bin, "-v").Output()
	if err != nil {
		return ""
	}
	return strings.SplitN(strings.TrimSpace(string(b)), "\n", 2)[0]
}

func (m *ProcessManager) controllerVersion(ctx context.Context) (map[string]any, error) {
	b, err := m.controller(ctx, http.MethodGet, "/version", nil)
	if err != nil {
		return nil, err
	}
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	return v, nil
}

func (m *ProcessManager) controller(ctx context.Context, method, path string, body io.Reader) ([]byte, error) {
	url := fmt.Sprintf("http://127.0.0.1:%d%s", m.state.ControllerPort, path)
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+m.secret)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("Mihomo Controller returned HTTP %d", resp.StatusCode)
	}
	return data, nil
}

func managedProcess(pid int, bin, configFile, runtimeDir string) bool {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	if err != nil {
		return false
	}
	args := strings.Split(strings.TrimRight(string(b), "\x00"), "\x00")
	if len(args) < 5 || args[0] != bin {
		return false
	}
	return hasArgumentPair(args, "-f", configFile) && hasArgumentPair(args, "-d", runtimeDir)
}

func hasArgumentPair(args []string, key, value string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == key && args[i+1] == value {
			return true
		}
	}
	return false
}

func findManagedProcess(bin, configFile, runtimeDir string) int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err == nil && pid > 1 && managedProcess(pid, bin, configFile, runtimeDir) {
			return pid
		}
	}
	return 0
}

func processAlive(p *os.Process) bool {
	if p == nil {
		return false
	}
	err := p.Signal(syscall.Signal(0))
	return err == nil || errors.Is(err, syscall.EPERM)
}

func readBoundedLines(path string, count int) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	const maxBytes = 1 << 20
	offset := st.Size() - maxBytes
	if offset < 0 {
		offset = 0
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return nil, err
	}
	if offset > 0 {
		_, _ = bufio.NewReader(f).ReadString('\n')
	}
	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4096), 64<<10)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
		if len(lines) > count {
			lines = lines[1:]
		}
	}
	return lines, scanner.Err()
}
