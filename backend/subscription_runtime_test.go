package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

func TestRenderSubscriptionKeepsNormalProxyBoundary(t *testing.T) {
	input := []byte(`mixed-port: 9999
allow-lan: true
external-controller: 0.0.0.0:9091
secret: exposed
tun:
  enable: true
dns:
  enable: true
proxies:
  - name: Example
    type: socks5
    server: example.com
    port: 1080
`)
	config, count, err := renderSubscription(input, RuntimeState{MixedPort: 17890, ControllerPort: 9091}, "private-secret")
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("node count: %d", count)
	}
	text := string(config)
	for _, required := range []string{"mixed-port: 17890", "127.0.0.1:9091", "private-secret", "enable: false", "Example", "MATCH,PROXY"} {
		if !strings.Contains(text, required) {
			t.Errorf("missing %q", required)
		}
	}
	for _, forbidden := range []string{"9999", "0.0.0.0", "exposed", "dns:"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("unexpected %q", forbidden)
		}
	}
}

func TestRenderSubscriptionRejectsNoNodes(t *testing.T) {
	_, _, err := renderSubscription([]byte("proxies: []\n"), RuntimeState{MixedPort: 17890, ControllerPort: 9091}, "secret")
	if err == nil {
		t.Fatal("empty subscription accepted")
	}
}

func TestRenderSubscriptionPreservesRuleProvidersAndRules(t *testing.T) {
	input := []byte(`proxies:
  - name: Example
    type: socks5
    server: example.com
    port: 1080
proxy-groups:
  - name: PROXY
    type: select
    proxies: [Example, DIRECT]
rule-providers:
  其它影音站点:
    type: http
    behavior: classical
    format: yaml
    url: https://rules.example/provider.yaml?token=private
    path: /etc/passwd
    interval: 86400
rules:
  - RULE-SET,其它影音站点,PROXY
  - MATCH,DIRECT
`)
	config, count, err := renderSubscription(input, RuntimeState{MixedPort: 17890, ControllerPort: 9091}, "private-secret")
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("node count: %d", count)
	}
	var rendered map[string]any
	if err := yaml.Unmarshal(config, &rendered); err != nil {
		t.Fatal(err)
	}
	providers, ok := rendered["rule-providers"].(map[string]any)
	if !ok {
		t.Fatalf("rule-providers missing from generated config: %s", config)
	}
	provider, ok := providers["其它影音站点"].(map[string]any)
	if !ok {
		t.Fatalf("named rule-provider missing: %s", config)
	}
	if provider["url"] != "https://rules.example/provider.yaml?token=private" {
		t.Fatalf("provider URL was not preserved: %#v", provider["url"])
	}
	providerPath, _ := provider["path"].(string)
	if !strings.HasPrefix(providerPath, "./rule-providers/") || strings.Contains(providerPath, "passwd") {
		t.Fatalf("unsafe provider path was not replaced: %q", providerPath)
	}
	otherInput := strings.Replace(string(input), "https://rules.example/provider.yaml?token=private", "https://rules.example/other.yaml?token=private", 1)
	otherConfig, _, err := renderSubscription([]byte(otherInput), RuntimeState{MixedPort: 17890, ControllerPort: 9091}, "private-secret")
	if err != nil {
		t.Fatal(err)
	}
	var otherRendered map[string]any
	if err := yaml.Unmarshal(otherConfig, &otherRendered); err != nil {
		t.Fatal(err)
	}
	otherProviders, ok := otherRendered["rule-providers"].(map[string]any)
	if !ok {
		t.Fatalf("rule-providers missing from second generated config: %s", otherConfig)
	}
	otherProvider, ok := otherProviders["其它影音站点"].(map[string]any)
	if !ok {
		t.Fatalf("named provider missing from second generated config: %s", otherConfig)
	}
	if otherPath, _ := otherProvider["path"].(string); providerPath == otherPath {
		t.Fatal("different provider URLs share the same cache path")
	}
	rules, ok := rendered["rules"].([]any)
	if !ok || len(rules) != 2 || rules[0] != "RULE-SET,其它影音站点,PROXY" {
		t.Fatalf("RULE-SET rules were not preserved: %#v", rendered["rules"])
	}
}

func TestRenderSubscriptionRejectsMissingRuleProvider(t *testing.T) {
	input := []byte(`proxies:
  - name: Example
    type: socks5
    server: example.com
    port: 1080
rules:
  - RULE-SET,其它影音站点,PROXY
`)
	_, _, err := renderSubscription(input, RuntimeState{MixedPort: 17890, ControllerPort: 9091}, "secret")
	if err == nil || !strings.Contains(err.Error(), `missing rule provider "其它影音站点"`) {
		t.Fatalf("expected precise missing provider error, got %v", err)
	}
}

func TestRenderSubscriptionRejectsUnsafeFileRuleProviderPath(t *testing.T) {
	input := []byte(`proxies:
  - name: Example
    type: socks5
    server: example.com
    port: 1080
rule-providers:
  local:
    type: file
    behavior: classical
    path: ../../etc/passwd
rules:
  - RULE-SET,local,PROXY
`)
	_, _, err := renderSubscription(input, RuntimeState{MixedPort: 17890, ControllerPort: 9091}, "secret")
	if err == nil || !strings.Contains(err.Error(), "requires a path under ./rule-providers/") {
		t.Fatalf("expected unsafe provider path rejection, got %v", err)
	}
}

func TestRuleProviderURLRejectsPrivateAddress(t *testing.T) {
	resolver := testResolver(func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("192.168.1.25")}}, nil
	})
	input := []byte(`proxies: []
rule-providers:
  local:
    type: http
    behavior: classical
    url: https://rules.example/provider.yaml
`)
	if err := validateRuleProviderURLs(context.Background(), input, resolver); err == nil || !strings.Contains(err.Error(), `rule provider "local" URL rejected: subscription URL resolves to a non-public address`) {
		t.Fatalf("expected private provider URL rejection, got %v", err)
	}
}

func TestRuleProviderURLRejectsPublicAndPrivateDNSAnswers(t *testing.T) {
	resolver := testResolver(func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{
			{IP: net.ParseIP("192.168.1.25")},
			{IP: net.ParseIP("93.184.216.34")},
		}, nil
	})
	input := []byte(`proxies: []
rule-providers:
  remote:
    type: http
    behavior: classical
    url: https://rules.example/provider.yaml
`)
	err := validateRuleProviderURLs(context.Background(), input, resolver)
	if err == nil || !strings.Contains(err.Error(), "resolves to a non-public address") {
		t.Fatalf("provider URL with a private DNS answer was accepted: %v", err)
	}
}

func TestRuleProviderURLReportsSafeValidationReason(t *testing.T) {
	resolver := testResolver(func(context.Context, string) ([]net.IPAddr, error) {
		return nil, fmt.Errorf("resolver unavailable")
	})
	input := []byte(`proxies: []
rule-providers:
  remote:
    type: http
    behavior: classical
    url: https://rules.example/provider.yaml?token=private
`)
	err := validateRuleProviderURLs(context.Background(), input, resolver)
	if err == nil || !strings.Contains(err.Error(), `rule provider "remote" URL rejected: subscription host lookup failed`) {
		t.Fatalf("expected a sanitized DNS error, got %v", err)
	}
	if strings.Contains(err.Error(), "provider.yaml") || strings.Contains(err.Error(), "private") {
		t.Fatalf("error leaked the provider URL or token: %v", err)
	}
}

func TestRenderedRuleProviderConfigAcceptedByMihomo(t *testing.T) {
	bin := os.Getenv("MIHOMO_TEST_BINARY")
	if bin == "" {
		t.Skip("set MIHOMO_TEST_BINARY to run the pinned Mihomo config test")
	}
	input := []byte(`proxies:
  - name: Example
    type: socks5
    server: 127.0.0.1
    port: 1080
rule-providers:
  local:
    type: inline
    behavior: classical
    payload:
      - DOMAIN-SUFFIX,example.com
rules:
  - RULE-SET,local,DIRECT
  - MATCH,DIRECT
`)
	config, _, err := renderSubscription(input, RuntimeState{MixedPort: 17890, ControllerPort: 9091}, "test-secret")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	configPath := filepath.Join(dir, "mihomo.yaml")
	if err := os.WriteFile(configPath, config, 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "-t", "-f", configPath, "-d", dir)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("pinned Mihomo rejected rendered rule-provider config: %s", redactMihomoOutput(output, "test-secret"))
	}
}

func TestRenderedHTTPRuleProviderAcceptedByMihomo(t *testing.T) {
	bin := os.Getenv("MIHOMO_TEST_BINARY")
	if bin == "" {
		t.Skip("set MIHOMO_TEST_BINARY to run the pinned Mihomo config test")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("payload:\n  - DOMAIN-SUFFIX,example.com\n"))
	}))
	defer server.Close()
	input := []byte(fmt.Sprintf(`proxies:
  - name: Example
    type: socks5
    server: 127.0.0.1
    port: 1080
rule-providers:
  local:
    type: http
    behavior: classical
    format: yaml
    url: %q
    path: /etc/passwd
    interval: 86400
rules:
  - RULE-SET,local,DIRECT
  - MATCH,DIRECT
`, server.URL))
	config, _, err := renderSubscription(input, RuntimeState{MixedPort: 17890, ControllerPort: 9091}, "test-secret")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	configPath := filepath.Join(dir, "mihomo.yaml")
	if err := os.WriteFile(configPath, config, 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "-t", "-f", configPath, "-d", dir)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("pinned Mihomo rejected rendered HTTP rule-provider config: %s", redactMihomoOutput(output, "test-secret"))
	}
}

func TestFailedSubscriptionUpdateRetainsLastKnownGoodConfig(t *testing.T) {
	dir := t.TempDir()
	api := testAPI(dir)
	api.manager.configFile = filepath.Join(dir, "mihomo.yaml")
	if err := os.MkdirAll(api.subscriptionsDir, 0700); err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(api.subscriptionsDir, "0123456789abcdef.yaml")
	previousProfile := []byte("proxies:\n  - name: last-known-good\n")
	previousConfig := []byte("mixed-port: 17890\nsecret: retained\n")
	if err := os.WriteFile(profilePath, previousProfile, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(api.manager.configFile, previousConfig, 0600); err != nil {
		t.Fatal(err)
	}
	previousUpdate := time.Now().Add(-24 * time.Hour).UTC().Truncate(time.Second)
	item := subscriptionRecord{
		ID: "0123456789abcdef", URL: "http://127.0.0.1/subscription.yaml", Enabled: true,
		LastUpdated: previousUpdate, Status: "ready", Current: true, NodeCount: 3, AutoUpdateHours: 12,
	}
	if err := api.saveSubscriptions([]subscriptionRecord{item}); err != nil {
		t.Fatal(err)
	}

	if _, err := api.performSubscriptionUpdate(item.ID, context.Background()); err == nil {
		t.Fatal("update to a private endpoint unexpectedly succeeded")
	}
	profile, err := os.ReadFile(profilePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(profile) != string(previousProfile) {
		t.Fatalf("last-known-good subscription was changed: %s", profile)
	}
	config, err := os.ReadFile(api.manager.configFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(config) != string(previousConfig) {
		t.Fatalf("active config was changed after the failed update: %s", config)
	}
	items, err := api.loadSubscriptions()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Status != "download failed" || items[0].NodeCount != item.NodeCount || !items[0].LastUpdated.Equal(previousUpdate) {
		t.Fatalf("failed update corrupted last-known-good metadata: %#v", items)
	}
	if items[0].NextUpdate == nil || time.Until(*items[0].NextUpdate) < subscriptionRetryDelay-time.Minute || time.Until(*items[0].NextUpdate) > subscriptionRetryDelay+time.Minute {
		t.Fatalf("failed update did not schedule a bounded retry: %#v", items[0].NextUpdate)
	}
}

func TestSubscriptionNextUpdate(t *testing.T) {
	now := time.Date(2026, 10, 11, 5, 0, 0, 0, time.UTC)
	last := now.Add(-7 * time.Hour)
	item := subscriptionRecord{Enabled: true, AutoUpdateHours: 6, LastUpdated: last}
	if got := subscriptionNextUpdate(item, now); got == nil || !got.Equal(last.Add(6*time.Hour)) {
		t.Fatalf("legacy schedule = %v, want last update plus interval", got)
	}
	item.NextUpdate = ptrTime(now.Add(10 * time.Minute))
	if got := subscriptionNextUpdate(item, now); got == nil || !got.Equal(*item.NextUpdate) {
		t.Fatalf("saved retry schedule = %v, want %v", got, item.NextUpdate)
	}
	item.AutoUpdateHours = 0
	if got := subscriptionNextUpdate(item, now); got != nil {
		t.Fatalf("disabled automatic schedule = %v, want nil", got)
	}
	item.AutoUpdateHours = 12
	item.NextUpdate = nil
	item.LastUpdated = time.Time{}
	if got := subscriptionNextUpdate(item, now); got == nil || !got.Equal(now) {
		t.Fatalf("never-updated schedule = %v, want immediate first attempt at %v", got, now)
	}
}

func ptrTime(value time.Time) *time.Time { return &value }

func TestRedactMihomoOutputHidesProviderURLs(t *testing.T) {
	output := []byte(`rule set failed for https://rules.example/provider.yaml?token=private and secret=swordfish password=proxy-pass token: api-token Authorization: Bearer auth-token`)
	got := redactMihomoOutput(output, "swordfish")
	want := "rule set failed for [URL redacted] and secret=[redacted] password=[redacted] token=[redacted] authorization=[redacted]"
	if got != want {
		t.Fatalf("redacted detail = %q, want %q", got, want)
	}
}

func TestDisableTunInConfigPreservesProxySettings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mihomo.yaml")
	original := "tun:\n  enable: true\n  stack: system\nproxies:\n  - name: sample\n"
	if err := os.WriteFile(path, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	if err := disableTunInConfig(path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "enable: true") || !strings.Contains(string(data), "enable: false") || !strings.Contains(string(data), "sample") {
		t.Fatalf("TUN fallback did not preserve the configuration: %s", data)
	}
}
