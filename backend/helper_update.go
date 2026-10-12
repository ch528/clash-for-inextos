package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var mihomoCandidateMu sync.Mutex

const mihomoPrepareTimeout = 15 * time.Minute

func mihomoCandidatePath() string {
	return filepath.Join(installDir, "bin", "mihomo-candidate")
}

// Only the helper can write this directory; the backend never supplies executable bytes.
func prepareMihomoCandidate(ctx context.Context) error {
	if os.Geteuid() != 0 {
		return errors.New("Mihomo preparation requires root")
	}
	if !mihomoCandidateMu.TryLock() {
		return errors.New("Mihomo candidate preparation is already running")
	}
	defer mihomoCandidateMu.Unlock()
	candidate := mihomoCandidatePath()
	if err := os.Remove(candidate); err != nil && !os.IsNotExist(err) {
		return err
	}
	client := newSubscriptionClient(nil, nil)
	client.Timeout = mihomoPrepareTimeout - time.Minute
	release, err := fetchLatestRelease(ctx, client, "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest")
	if err != nil {
		return err
	}
	asset, err := mihomoARM64Asset(release)
	if err != nil {
		return err
	}
	binary, err := downloadMihomoArtifact(ctx, client, asset)
	if err != nil {
		return err
	}
	dir := filepath.Join(installDir, "bin")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	file, err := os.CreateTemp(dir, "mihomo-candidate-")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if _, err := file.Write(binary); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Chmod(0700); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	output, err := exec.CommandContext(probeCtx, name, "-v").CombinedOutput()
	if err != nil || !mihomoVersionMatches(output, release.TagName) {
		return errors.New("Mihomo candidate version probe failed")
	}
	return os.Rename(name, candidate)
}

func installMihomoCandidate(ctx context.Context, rollback bool) error {
	if os.Geteuid() != 0 {
		return errors.New("Mihomo installation requires root")
	}
	if !mihomoCandidateMu.TryLock() {
		return errors.New("Mihomo update is already running")
	}
	defer mihomoCandidateMu.Unlock()
	target := filepath.Join(installDir, "bin", "mihomo")
	if findManagedProcess(target, filepath.Join(runDir, "mihomo.yaml"), mihomoDataDir) != 0 {
		return errors.New("Mihomo must be stopped before replacing its binary")
	}
	if rollback {
		return restoreMihomoBinary(target)
	}
	candidate := mihomoCandidatePath()
	probeCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	defer os.Remove(candidate)
	if err := exec.CommandContext(probeCtx, candidate, "-t", "-f", filepath.Join(runDir, "mihomo.yaml"), "-d", mihomoDataDir).Run(); err != nil {
		return errors.New("Mihomo candidate rejected the active configuration")
	}
	return replaceMihomoBinary(target, candidate)
}

func replaceMihomoBinary(target, candidate string) error {
	current, err := os.ReadFile(target)
	if err != nil {
		return err
	}
	next, err := os.ReadFile(candidate)
	if err != nil {
		return err
	}
	if err := atomicWrite(target+".previous", current, 0755); err != nil {
		return err
	}
	return atomicWrite(target, next, 0755)
}

func restoreMihomoBinary(target string) error {
	previous, err := os.ReadFile(target + ".previous")
	if err != nil {
		return errors.New("previous Mihomo binary is unavailable")
	}
	return atomicWrite(target, previous, 0755)
}

func mihomoVersionMatches(output []byte, tag string) bool {
	text := string(output)
	return strings.Contains(text, "Mihomo") && versionPattern.FindString(text) == tag
}
