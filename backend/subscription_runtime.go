package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

var mihomoURLPattern = regexp.MustCompile(`https?://[^\s"'<>]+`)
var mihomoCredentialPattern = regexp.MustCompile(`(?i)\b(password|passwd|token|secret)\s*[:=]\s*[^\s,]+`)
var mihomoAuthorizationPattern = regexp.MustCompile(`(?im)\bauthorization\s*[:=]\s*[^\r\n]+`)

const subscriptionRetryDelay = 15 * time.Minute

func subscriptionNextUpdate(item subscriptionRecord, now time.Time) *time.Time {
	if !item.Enabled || item.AutoUpdateHours <= 0 {
		return nil
	}
	if item.NextUpdate != nil {
		next := item.NextUpdate.UTC()
		return &next
	}
	next := now.UTC()
	if !item.LastUpdated.IsZero() {
		next = item.LastUpdated.Add(time.Duration(item.AutoUpdateHours) * time.Hour).UTC()
	}
	return &next
}

func scheduleSubscriptionRetry(item *subscriptionRecord, now time.Time) {
	if !item.Enabled || item.AutoUpdateHours <= 0 {
		item.NextUpdate = nil
		return
	}
	next := now.Add(subscriptionRetryDelay).UTC()
	item.NextUpdate = &next
}

func scheduleSubscriptionSuccess(item *subscriptionRecord, now time.Time) {
	if !item.Enabled || item.AutoUpdateHours <= 0 {
		item.NextUpdate = nil
		return
	}
	next := now.Add(time.Duration(item.AutoUpdateHours) * time.Hour).UTC()
	item.NextUpdate = &next
}

func renderSubscription(body []byte, state RuntimeState, secret string) ([]byte, int, error) {
	var source map[string]any
	if err := yaml.Unmarshal(body, &source); err != nil {
		return nil, 0, fmt.Errorf("invalid YAML: %w", err)
	}
	proxies, ok := source["proxies"].([]any)
	if !ok || len(proxies) == 0 {
		return nil, 0, errors.New("subscription has no inline proxies")
	}
	names := make([]string, 0, len(proxies)+1)
	names = append(names, "DIRECT")
	for _, raw := range proxies {
		proxy, ok := raw.(map[string]any)
		if !ok {
			return nil, 0, errors.New("invalid proxy entry")
		}
		name, ok := proxy["name"].(string)
		if !ok || strings.TrimSpace(name) == "" {
			return nil, 0, errors.New("proxy name is missing")
		}
		names = append(names, name)
	}
	providers, err := renderRuleProviders(source["rule-providers"])
	if err != nil {
		return nil, 0, err
	}
	rules := []any{}
	if rawRules, exists := source["rules"]; exists {
		var ok bool
		rules, ok = rawRules.([]any)
		if !ok {
			return nil, 0, errors.New("subscription rules must be a list")
		}
	}
	if err := validateRuleSetReferences(rules, providers); err != nil {
		return nil, 0, err
	}
	rules = append(networkPolicyRules(state), rules...)
	var safe map[string]any
	if err := yaml.Unmarshal([]byte(minimalConfig(state, secret)), &safe); err != nil {
		return nil, 0, err
	}
	safe["proxies"] = proxies
	if len(providers) > 0 {
		safe["rule-providers"] = providers
	}
	if groups, ok := source["proxy-groups"].([]any); ok && len(groups) > 0 {
		safe["proxy-groups"] = groups
		if len(rules) > 0 {
			safe["rules"] = rules
		} else {
			safe["rules"] = []string{"MATCH,DIRECT"}
		}
	} else {
		safe["proxy-groups"] = []any{map[string]any{"name": "PROXY", "type": "select", "proxies": names}}
		if len(rules) > 0 {
			safe["rules"] = rules
		} else {
			safe["rules"] = []string{"MATCH,PROXY"}
		}
	}
	result, err := yaml.Marshal(safe)
	return result, len(proxies), err
}

func renderRuleProviders(raw any) (map[string]any, error) {
	if raw == nil {
		return nil, nil
	}
	providers, ok := raw.(map[string]any)
	if !ok {
		return nil, errors.New("rule-providers must be a mapping")
	}
	result := make(map[string]any, len(providers))
	for name, rawProvider := range providers {
		if strings.TrimSpace(name) != name || name == "" || len(name) > 128 {
			return nil, errors.New("rule-provider name is invalid")
		}
		provider, ok := rawProvider.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("rule-provider %q must be a mapping", name)
		}
		kind, _ := provider["type"].(string)
		behavior, _ := provider["behavior"].(string)
		if kind != "http" && kind != "file" && kind != "inline" {
			return nil, fmt.Errorf("rule-provider %q has unsupported type", name)
		}
		if behavior != "domain" && behavior != "ipcidr" && behavior != "classical" {
			return nil, fmt.Errorf("rule-provider %q has invalid behavior", name)
		}
		clean := make(map[string]any, len(provider)+1)
		for field, value := range provider {
			clean[field] = value
		}
		switch kind {
		case "http":
			providerURL, ok := provider["url"].(string)
			if !ok || !validRuleProviderURL(providerURL) {
				return nil, fmt.Errorf("rule-provider %q has invalid URL", name)
			}
			format, _ := provider["format"].(string)
			if format != "mrs" && format != "text" {
				format = "yaml"
			}
			digest := sha256.Sum256([]byte(providerURL))
			clean["path"] = "./rule-providers/" + hex.EncodeToString(digest[:8]) + "." + format
		case "file":
			pathValue, ok := provider["path"].(string)
			if !ok || !safeProviderRelativePath(pathValue) {
				return nil, fmt.Errorf("rule-provider %q requires a path under ./rule-providers/", name)
			}
			clean["path"] = "./" + filepath.ToSlash(filepath.Clean(pathValue))
		case "inline":
			payload, ok := provider["payload"].([]any)
			if !ok || len(payload) == 0 {
				return nil, fmt.Errorf("rule-provider %q has invalid inline payload", name)
			}
		}
		result[name] = clean
	}
	return result, nil
}

func safeProviderRelativePath(value string) bool {
	if value == "" || filepath.IsAbs(value) || strings.Contains(value, "\\") {
		return false
	}
	clean := filepath.Clean(filepath.FromSlash(value))
	return clean != "." && clean != ".." && !strings.HasPrefix(clean, ".."+string(filepath.Separator)) && filepath.ToSlash(clean) != "rule-providers" && strings.HasPrefix(filepath.ToSlash(clean), "rule-providers/")
}

func validRuleProviderURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Hostname() != "" && u.User == nil && u.Fragment == ""
}

func validateRuleSetReferences(rules []any, providers map[string]any) error {
	for _, raw := range rules {
		line, ok := raw.(string)
		if !ok {
			return errors.New("subscription rule is not a string")
		}
		upper := strings.ToUpper(line)
		for offset := 0; offset < len(upper); {
			relative := strings.Index(upper[offset:], "RULE-SET")
			if relative < 0 {
				break
			}
			start := offset + relative
			end := start + len("RULE-SET")
			if (start == 0 || strings.ContainsRune(" ,(", rune(upper[start-1]))) && end < len(upper) && upper[end] == ',' {
				tail := strings.TrimLeft(line[end+1:], " \t")
				nameEnd := strings.IndexAny(tail, ",) \t")
				if nameEnd < 0 {
					nameEnd = len(tail)
				}
				name := strings.Trim(tail[:nameEnd], "'\"")
				if name == "" {
					return errors.New("subscription has an empty RULE-SET provider name")
				}
				if _, exists := providers[name]; !exists {
					return fmt.Errorf("subscription references missing rule provider %q", name)
				}
			}
			offset = end
		}
	}
	return nil
}

func validateRuleProviderURLs(ctx context.Context, body []byte, resolver ipResolver) error {
	var source map[string]any
	if err := yaml.Unmarshal(body, &source); err != nil {
		return errors.New("invalid subscription YAML")
	}
	providers, ok := source["rule-providers"].(map[string]any)
	if !ok {
		return nil
	}
	for name, raw := range providers {
		provider, ok := raw.(map[string]any)
		if !ok || provider["type"] != "http" {
			continue
		}
		providerURL, _ := provider["url"].(string)
		if err := validateRuleProviderURL(ctx, providerURL, resolver); err != nil {
			return fmt.Errorf("rule provider %q URL rejected: %v", name, err)
		}
	}
	return nil
}

func redactMihomoOutput(output []byte, secret string) string {
	detail := strings.TrimSpace(strings.ReplaceAll(string(output), secret, "[redacted]"))
	detail = mihomoURLPattern.ReplaceAllString(detail, "[URL redacted]")
	detail = mihomoCredentialPattern.ReplaceAllString(detail, "$1=[redacted]")
	detail = mihomoAuthorizationPattern.ReplaceAllString(detail, "authorization=[redacted]")
	if len(detail) > 800 {
		detail = detail[:800]
	}
	return detail
}

func (a *API) testConfig(ctx context.Context, config []byte) error {
	file, err := os.CreateTemp(filepath.Dir(a.manager.configFile), ".subscription-*.yaml")
	if err != nil {
		return err
	}
	path := file.Name()
	defer os.Remove(path)
	if _, err := file.Write(config); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, a.manager.bin, "-t", "-f", path, "-d", a.manager.runtimeDir).CombinedOutput()
	if err != nil {
		detail := redactMihomoOutput(output, a.manager.secret)
		return fmt.Errorf("Mihomo config test failed: %s", detail)
	}
	return nil
}

func (a *API) activateConfig(ctx context.Context, config []byte) error {
	old, err := os.ReadFile(a.manager.configFile)
	if err != nil {
		return err
	}
	wasRunning := a.manager.Status(ctx).ProcessAlive
	if wasRunning {
		if err := a.manager.Stop(ctx); err != nil {
			return err
		}
	}
	if err := atomicWrite(a.manager.configFile, config, 0600); err != nil {
		if wasRunning {
			_ = a.manager.Start(context.Background())
		}
		return err
	}
	if !wasRunning {
		return nil
	}
	startCtx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	if err := a.manager.Start(startCtx); err != nil {
		_ = atomicWrite(a.manager.configFile, old, 0600)
		rollbackCtx, rollbackCancel := context.WithTimeout(context.Background(), 12*time.Second)
		defer rollbackCancel()
		if rollbackErr := a.manager.Start(rollbackCtx); rollbackErr != nil {
			a.recordEvent("config_rollback")
			return fmt.Errorf("new config failed (%v); rollback start failed (%v)", err, rollbackErr)
		}
		a.recordEvent("config_rollback")
		return fmt.Errorf("new config failed; previous running config restored: %w", err)
	}
	return nil
}

func writeStartupConfig(path, subscriptionsDir string, state RuntimeState, secret string) error {
	data, err := os.ReadFile(filepath.Join(subscriptionsDir, "subscriptions.json"))
	if err == nil {
		var items []subscriptionRecord
		if err := json.Unmarshal(data, &items); err != nil {
			return err
		}
		for _, item := range items {
			if item.Current && item.Enabled {
				body, err := os.ReadFile(filepath.Join(subscriptionsDir, item.ID+".yaml"))
				if err != nil {
					return err
				}
				config, _, err := renderSubscription(body, state, secret)
				if err != nil {
					return err
				}
				return atomicWrite(path, config, 0600)
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return writeMinimalConfig(path, state, secret)
}

func disableTunInConfig(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var config map[string]any
	if err := yaml.Unmarshal(data, &config); err != nil {
		return err
	}
	tun, ok := config["tun"].(map[string]any)
	if !ok {
		tun = map[string]any{}
		config["tun"] = tun
	}
	tun["enable"] = false
	tun["auto-redirect"] = false
	delete(tun, "dns-hijack")
	delete(tun, "include-mac-address")
	delete(tun, "exclude-mac-address")
	if dns, ok := config["dns"].(map[string]any); ok {
		dns["enable"] = false
	}
	updated, err := yaml.Marshal(config)
	if err != nil {
		return err
	}
	return atomicWrite(path, updated, 0600)
}

type subscriptionUpdateError struct {
	status  int
	message string
}

func (e *subscriptionUpdateError) Error() string { return e.message }

func (a *API) updateSubscriptionByID(w http.ResponseWriter, r *http.Request, id string) {
	item, err := a.performSubscriptionUpdate(id, r.Context())
	if err != nil {
		var updateErr *subscriptionUpdateError
		if errors.As(err, &updateErr) {
			writeError(w, updateErr.status, updateErr.message)
		} else {
			writeError(w, 500, "subscription update failed")
		}
		return
	}
	writeJSON(w, 200, item)
}

func (a *API) performSubscriptionUpdate(id string, requestContext context.Context) (result subscriptionView, resultErr error) {
	a.subOp.Lock()
	defer a.subOp.Unlock()
	defer func() {
		if resultErr == nil && result.ID != "" {
			a.recordEvent("subscription_updated")
			return
		}
		var updateErr *subscriptionUpdateError
		if errors.As(resultErr, &updateErr) && updateErr.status != http.StatusNotFound && updateErr.status != http.StatusConflict {
			a.recordEvent("subscription_failed")
		}
	}()
	items, err := a.loadSubscriptions()
	if err != nil {
		return subscriptionView{}, &subscriptionUpdateError{500, "could not read subscriptions"}
	}
	for i := range items {
		if items[i].ID == id {
			if !items[i].Enabled {
				return subscriptionView{}, &subscriptionUpdateError{409, "subscription is disabled"}
			}
			ctx, cancel := context.WithTimeout(requestContext, 22*time.Second)
			download, err := downloadSubscriptionWithUsage(ctx, items[i].URL, systemResolver{}, nil)
			if err != nil {
				cancel()
				items[i].Status = "download failed"
				scheduleSubscriptionRetry(&items[i], time.Now())
				_ = a.saveSubscriptions(items)
				return subscriptionView{}, &subscriptionUpdateError{502, err.Error()}
			}
			body := download.Body
			if err := validateRuleProviderURLs(ctx, body, systemResolver{}); err != nil {
				cancel()
				items[i].Status = "validation failed"
				scheduleSubscriptionRetry(&items[i], time.Now())
				_ = a.saveSubscriptions(items)
				return subscriptionView{}, &subscriptionUpdateError{422, err.Error()}
			}
			config, count, err := renderSubscription(body, a.manager.RuntimeConfig(), a.manager.secret)
			if err == nil {
				err = a.testConfig(requestContext, config)
			}
			if err != nil {
				items[i].Status = "validation failed"
				scheduleSubscriptionRetry(&items[i], time.Now())
				_ = a.saveSubscriptions(items)
				cancel()
				return subscriptionView{}, &subscriptionUpdateError{422, err.Error()}
			}
			cancel()
			path := filepath.Join(a.subscriptionsDir, id+".yaml")
			previous, _ := os.ReadFile(path)
			if err := atomicWrite(path, body, 0600); err != nil {
				return subscriptionView{}, &subscriptionUpdateError{500, "could not store subscription"}
			}
			if items[i].Current {
				if err := a.activateConfig(requestContext, config); err != nil {
					if len(previous) > 0 {
						_ = atomicWrite(path, previous, 0600)
					} else {
						_ = os.Remove(path)
					}
					items[i].Status = "activation failed"
					_ = a.saveSubscriptions(items)
					return subscriptionView{}, &subscriptionUpdateError{502, err.Error()}
				}
			}
			items[i].LastUpdated = time.Now().UTC()
			items[i].NodeCount = count
			items[i].Usage = download.Usage
			items[i].Status = "ready"
			scheduleSubscriptionSuccess(&items[i], items[i].LastUpdated)
			if err := a.saveSubscriptions(items); err != nil {
				return subscriptionView{}, &subscriptionUpdateError{500, "could not save subscription status"}
			}
			return viewSubscription(items[i]), nil
		}
	}
	return subscriptionView{}, &subscriptionUpdateError{404, "subscription not found"}
}

func (a *API) activateSubscriptionByID(w http.ResponseWriter, r *http.Request, id string) {
	a.subOp.Lock()
	defer a.subOp.Unlock()
	items, err := a.loadSubscriptions()
	if err != nil {
		writeError(w, 500, "could not read subscriptions")
		return
	}
	index := -1
	for i := range items {
		if items[i].ID == id {
			index = i
			break
		}
	}
	if index < 0 {
		writeError(w, 404, "subscription not found")
		return
	}
	if !items[index].Enabled {
		writeError(w, 409, "subscription is disabled")
		return
	}
	body, err := os.ReadFile(filepath.Join(a.subscriptionsDir, id+".yaml"))
	if err != nil {
		writeError(w, 409, "update subscription before switching")
		return
	}
	config, _, err := renderSubscription(body, a.manager.RuntimeConfig(), a.manager.secret)
	if err == nil {
		err = a.testConfig(r.Context(), config)
	}
	if err != nil {
		writeError(w, 422, err.Error())
		return
	}
	previous := append([]subscriptionRecord(nil), items...)
	for i := range items {
		items[i].Current = i == index
	}
	if err := a.saveSubscriptions(items); err != nil {
		writeError(w, 500, "could not save current subscription")
		return
	}
	if err := a.activateConfig(r.Context(), config); err != nil {
		_ = a.saveSubscriptions(previous)
		writeError(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, viewSubscription(items[index]))
}

func (a *API) autoUpdateSubscriptions(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now().UTC()
			items, err := a.loadSubscriptions()
			if err != nil {
				continue
			}
			for _, item := range items {
				next := subscriptionNextUpdate(item, now)
				if next != nil && !now.Before(*next) {
					if _, err := a.performSubscriptionUpdate(item.ID, ctx); err != nil {
						a.logger.Warn("automatic subscription update failed", "id", item.ID, "reason", err.Error())
					}
				}
			}
		}
	}
}
