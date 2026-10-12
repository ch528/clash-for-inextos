package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

var (
	appVersion       = "1.0.0"
	upstreamRevision = "42c26d8ad44373980ef3e6c4113de3beedb3d876"
	dashboardVersion = "v3.29.1"
	buildDate        = "development"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "helperd" {
		if err := runHelperDaemon(); err != nil {
			fatal(err)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "helper-action" {
		if err := runHelperAction(os.Args[2:]); err != nil {
			fatal(err)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "app-update-run" {
		if err := runApplicationUpdateService(); err != nil {
			fatal(err)
		}
		return
	}
	if len(os.Args) > 1 && !strings.HasPrefix(os.Args[1], "-") {
		if err := runCLI(os.Args[1:]); err != nil {
			fatal(err)
		}
		return
	}
	if err := runServer(os.Args[1:]); err != nil {
		fatal(err)
	}
}

func runServer(args []string) error {
	flags := flag.NewFlagSet("inextos-clash-server", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	configPath := flags.String("config", applicationConfig, "application YAML configuration file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	settings, err := loadSettings(*configPath)
	if err != nil {
		return err
	}
	for _, dir := range []string{stateDir, subscriptionsDir, dashboardDir, mihomoDataDir} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}
	if err := os.Remove(filepath.Join(stateDir, bootstrapTokenFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(runDir, 0700); err != nil {
		return err
	}
	secret, err := ensureSecret(filepath.Join(stateDir, "controller-secret"))
	if err != nil {
		return err
	}
	_, backendPort, err := splitListener(settings.Server.Listeners[0])
	if err != nil {
		return err
	}
	state, err := allocateRuntime(stateDir, backendPort)
	if err != nil {
		return err
	}
	configFile := filepath.Join(runDir, "mihomo.yaml")
	if err := writeStartupConfig(configFile, subscriptionsDir, state, secret); err != nil {
		return err
	}
	bin := filepath.Join(installDir, "bin", "mihomo")
	manager := newProcessManager(bin, configFile, mihomoDataDir, stateDir, secret, state)
	if err := manager.Reconcile(); err != nil {
		return err
	}
	logFile, err := os.OpenFile(filepath.Join(stateDir, "backend.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer logFile.Close()
	logger := slog.New(slog.NewJSONHandler(logFile, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if manager.state.DesiredRunning && manager.state.AutoStart {
		startCtx, startCancel := context.WithTimeout(context.Background(), 12*time.Second)
		if err := manager.Start(startCtx); err != nil {
			logger.Warn("desired Mihomo startup failed", "reason", err.Error())
		}
		startCancel()
	}
	configured := runtimeListeners(settings.Server.Listeners, state.BackendPort)
	listeners := make([]net.Listener, 0, len(configured))
	allowedHosts := make(map[string]struct{}, len(configured))
	for _, address := range configured {
		listener, err := net.Listen("tcp", address)
		if err != nil {
			ip, _, _ := net.SplitHostPort(address)
			if parsed := net.ParseIP(ip); parsed != nil && parsed.IsLoopback() {
				for _, opened := range listeners {
					_ = opened.Close()
				}
				return fmt.Errorf("required localhost listener %s failed: %w", address, err)
			}
			logger.Warn("LAN listener failed", "address", address, "reason", err.Error())
			continue
		}
		listeners = append(listeners, listener)
		allowedHosts[strings.ToLower(listener.Addr().String())] = struct{}{}
		logger.Info("backend listening", "address", listener.Addr().String())
	}
	if len(listeners) == 0 {
		return errors.New("no backend listeners could be opened")
	}
	auth := newAuthManager(stateDir)
	api := &API{
		state: state, manager: manager, stateDir: stateDir, subscriptionsDir: subscriptionsDir,
		webDir: filepath.Join(installDir, "web"), dashboardDir: dashboardAssetDir, dashboardUpdatesDir: dashboardDir, logger: logger, auth: auth,
		allowedHosts: allowedHosts, frameAncestors: settings.Security.FrameAncestors,
		applicationVersion: appVersion, upstreamRevision: upstreamRevision,
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	go manager.Supervise(ctx, logger)
	go api.autoUpdateSubscriptions(ctx)
	errCh := make(chan error, len(listeners))
	servers := make([]*http.Server, 0, len(listeners))
	for _, listener := range listeners {
		host, _, _ := net.SplitHostPort(listener.Addr().String())
		scope := "lan"
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			scope = "loopback"
		}
		server := &http.Server{Handler: handlerForScope(scope, api.Handler()), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10}
		servers = append(servers, server)
		go func(listener net.Listener, server *http.Server) { errCh <- server.Serve(listener) }(listener, server)
	}
	select {
	case <-ctx.Done():
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			logger.Error("backend stopped", "error", err.Error())
			cancel()
		}
	}
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	for _, server := range servers {
		_ = server.Shutdown(shutdownCtx)
	}
	for _, listener := range listeners {
		_ = listener.Close()
	}
	if err := manager.StopForShutdown(context.Background()); err != nil {
		return err
	}
	return nil
}

func runCLI(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: inextos-clash {admin-status|setup-open|passwd|username|status|ports|version|logs|restart|network-confirm|network-rollback}")
	}
	switch args[0] {
	case "admin-status":
		if newAuthManager(stateDir).initialized() {
			fmt.Println("Administrator: initialized")
		} else {
			fmt.Println("Administrator: not initialized")
		}
	case "setup-open":
		if os.Geteuid() != 0 {
			return errors.New("setup-open requires root")
		}
		expires, err := newAuthManager(stateDir).setupOpen()
		if err != nil {
			return err
		}
		fmt.Printf("Public setup allowed until %s\n", expires.Format(time.RFC3339))
	case "passwd":
		if os.Geteuid() != 0 {
			return errors.New("passwd requires root")
		}
		return resetPasswordCLI(newAuthManager(stateDir))
	case "username":
		credential, err := newAuthManager(stateDir).credential()
		if err != nil {
			return errors.New("administrator is not initialized")
		}
		fmt.Printf("Administrator username: %s\n", credential.Username)
	case "network-confirm", "network-rollback":
		return runHelperAction([]string{args[0]})
	case "ports":
		state, err := loadRuntimeState(stateDir)
		if err != nil {
			return err
		}
		settings, err := loadSettings(applicationConfig)
		if err != nil {
			return err
		}
		listeners := runtimeListeners(settings.Server.Listeners, state.BackendPort)
		for _, address := range listeners {
			conn, err := net.DialTimeout("tcp", address, 400*time.Millisecond)
			if err != nil {
				continue
			}
			_ = conn.Close()
			host, _, _ := net.SplitHostPort(address)
			label := "Local URL"
			if ip := net.ParseIP(host); ip != nil && !ip.IsLoopback() {
				label = "Management URL"
			}
			fmt.Printf("%s: http://%s/\n", label, address)
		}
		fmt.Printf("Mixed: 127.0.0.1:%d\nController: 127.0.0.1:%d\n", state.MixedPort, state.ControllerPort)
	case "logs":
		lines, err := readBoundedLines(filepath.Join(stateDir, "backend.log"), 100)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		for _, line := range lines {
			fmt.Println(line)
		}
	case "restart":
		return exec.Command("systemctl", "restart", "inextos-clash.service").Run()
	case "status":
		active, _ := exec.Command("systemctl", "is-active", "inextos-clash.service").Output()
		state, stateErr := loadRuntimeState(stateDir)
		fmt.Printf("Service: %s\n", strings.TrimSpace(string(active)))
		if stateErr == nil {
			fmt.Printf("\nMihomo PID: %d\n", state.PID)
			fmt.Printf("Desired: %s\nMode: %s\n", map[bool]string{true: "running", false: "stopped"}[state.DesiredRunning], state.Mode)
		}
	case "version":
		fmt.Printf("Clash for iNextOS: %s\nclash-for-linux: %s\n", appVersion, upstreamRevision)
		fmt.Printf("Zashboard: %s\n", dashboardVersion)
		if b, err := exec.Command(filepath.Join(installDir, "bin", "mihomo"), "-v").Output(); err == nil {
			fmt.Printf("%s", b)
		}
	default:
		return errors.New("usage: inextos-clash {admin-status|setup-open|passwd|username|status|ports|version|logs|restart|network-confirm|network-rollback}")
	}
	return nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func resetPasswordCLI(auth *authManager) error {
	if _, err := os.Stat(filepath.Join(auth.stateDir, adminFile)); err != nil {
		return errors.New("administrator is not initialized")
	}
	if st, err := os.Stdin.Stat(); err != nil || st.Mode()&os.ModeCharDevice == 0 {
		return errors.New("passwd requires an interactive terminal")
	}
	fmt.Fprint(os.Stderr, "New administrator password: ")
	if err := exec.Command("stty", "-echo").Run(); err != nil {
		return err
	}
	defer exec.Command("stty", "echo").Run()
	reader := bufio.NewReader(os.Stdin)
	first, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	fmt.Fprint(os.Stderr, "\nConfirm password: ")
	second, err := reader.ReadString('\n')
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return err
	}
	if first != second {
		return errors.New("passwords do not match")
	}
	if err := auth.resetPassword(strings.TrimRight(first, "\r\n")); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Administrator password updated. Existing sessions were invalidated.")
	return nil
}
