package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const maxSubscriptionBytes = 8 << 20
const subscriptionUserAgent = "clash-verge/v2.4.0"

type ipResolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

type systemResolver struct{}

type subscriptionURLValidationError struct {
	err error
}

func (e subscriptionURLValidationError) Error() string { return e.err.Error() }

func (e subscriptionURLValidationError) Unwrap() error { return e.err }

func (systemResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	return net.DefaultResolver.LookupIPAddr(ctx, host)
}

var blockedIPRanges = mustPrefixes(
	"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24",
	"192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
	"224.0.0.0/4", "240.0.0.0/4", "64:ff9b::/96", "64:ff9b:1::/48",
	"100::/64", "2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20",
)

func mustPrefixes(values ...string) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefixes = append(prefixes, netip.MustParsePrefix(value))
	}
	return prefixes
}

func publicInternetIP(ip netip.Addr) bool {
	if !ip.IsValid() || ip.Zone() != "" {
		return false
	}
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	if ip.Is6() && !netip.MustParsePrefix("2000::/3").Contains(ip) {
		return false
	}
	for _, prefix := range blockedIPRanges {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

func validateSubscriptionURL(ctx context.Context, raw string, resolver ipResolver) error {
	return validatePublicHTTPURL(ctx, raw, resolver, false)
}

func validateRuleProviderURL(ctx context.Context, raw string, resolver ipResolver) error {
	return validatePublicHTTPURL(ctx, raw, resolver, true)
}

func validatePublicHTTPURL(ctx context.Context, raw string, resolver ipResolver, rejectAnyNonPublicAnswer bool) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil {
		return fmt.Errorf("subscription URL must be an http or https URL without credentials")
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	_, literalErr := netip.ParseAddr(host)
	literalIP := literalErr == nil
	if strings.Contains(host, "%") || (!literalIP && (!strings.Contains(host, ".") || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".lan") || strings.HasSuffix(host, ".internal") || strings.HasSuffix(host, ".home") || strings.HasSuffix(host, ".home.arpa"))) {
		return fmt.Errorf("local and single-label subscription hosts are not allowed")
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("invalid subscription URL port")
		}
	}
	if rejectAnyNonPublicAnswer {
		_, err = resolvePublicStrict(ctx, host, resolver)
	} else {
		_, err = resolvePublic(ctx, host, resolver)
	}
	return err
}

func resolvePublic(ctx context.Context, host string, resolver ipResolver) ([]netip.Addr, error) {
	return resolvePublicWithPolicy(ctx, host, resolver, false)
}

func resolvePublicStrict(ctx context.Context, host string, resolver ipResolver) ([]netip.Addr, error) {
	return resolvePublicWithPolicy(ctx, host, resolver, true)
}

func resolvePublicWithPolicy(ctx context.Context, host string, resolver ipResolver, rejectAnyNonPublicAnswer bool) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		if !publicInternetIP(ip) {
			return nil, fmt.Errorf("subscription URL resolves to a non-public address")
		}
		return []netip.Addr{ip.Unmap()}, nil
	}
	ips, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("subscription host lookup failed")
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("subscription host has no addresses")
	}
	checked := make([]netip.Addr, 0, len(ips))
	for _, item := range ips {
		ip, ok := netip.AddrFromSlice(item.IP)
		if !ok || !publicInternetIP(ip) {
			if rejectAnyNonPublicAnswer {
				return nil, fmt.Errorf("subscription URL resolves to a non-public address")
			}
			continue
		}
		checked = append(checked, ip.Unmap())
	}
	if len(checked) == 0 {
		return nil, fmt.Errorf("subscription URL resolves to no public addresses")
	}
	return checked, nil
}

func newSubscriptionClient(resolver ipResolver, dial func(context.Context, string, string) (net.Conn, error)) *http.Client {
	if resolver == nil {
		resolver = systemResolver{}
	}
	if dial == nil {
		d := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
		dial = d.DialContext
	}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			ips, err := resolvePublic(ctx, host, resolver)
			if err != nil {
				return nil, err
			}
			var lastErr error
			for _, ip := range ips {
				conn, err := dial(ctx, network, net.JoinHostPort(ip.String(), port))
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			return nil, lastErr
		},
	}
	return &http.Client{
		Transport: transport,
		Timeout:   20 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return subscriptionURLValidationError{err: fmt.Errorf("too many subscription redirects")}
			}
			if err := validateSubscriptionURL(req.Context(), req.URL.String(), resolver); err != nil {
				return subscriptionURLValidationError{err: err}
			}
			return nil
		},
	}
}

type subscriptionDownloadResult struct {
	Body  []byte
	Usage *subscriptionUsage
}

func downloadSubscription(ctx context.Context, raw string, resolver ipResolver, dial func(context.Context, string, string) (net.Conn, error)) ([]byte, error) {
	result, err := downloadSubscriptionWithUsage(ctx, raw, resolver, dial)
	return result.Body, err
}

func downloadSubscriptionWithUsage(ctx context.Context, raw string, resolver ipResolver, dial func(context.Context, string, string) (net.Conn, error)) (subscriptionDownloadResult, error) {
	if resolver == nil {
		resolver = systemResolver{}
	}
	if err := validateSubscriptionURL(ctx, raw, resolver); err != nil {
		return subscriptionDownloadResult{}, err
	}
	client := newSubscriptionClient(resolver, dial)
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
		if err != nil {
			return subscriptionDownloadResult{}, fmt.Errorf("invalid subscription URL")
		}
		req.Header.Set("User-Agent", subscriptionUserAgent)
		resp, err := client.Do(req)
		if err != nil {
			var validationErr subscriptionURLValidationError
			if errors.As(err, &validationErr) {
				return subscriptionDownloadResult{}, fmt.Errorf("subscription download failed")
			}
			if attempt == 0 && ctx.Err() == nil {
				continue
			}
			return subscriptionDownloadResult{}, fmt.Errorf("subscription download failed")
		}
		if resp.StatusCode >= 500 && attempt == 0 {
			_ = resp.Body.Close()
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			_ = resp.Body.Close()
			return subscriptionDownloadResult{}, fmt.Errorf("subscription server returned HTTP %d", resp.StatusCode)
		}
		usage := parseSubscriptionUserinfo(resp.Header.Get("Subscription-Userinfo"))
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxSubscriptionBytes+1))
		_ = resp.Body.Close()
		if err != nil {
			if attempt == 0 && ctx.Err() == nil {
				continue
			}
			return subscriptionDownloadResult{}, fmt.Errorf("subscription response could not be read")
		}
		if len(body) > maxSubscriptionBytes {
			return subscriptionDownloadResult{}, fmt.Errorf("subscription response exceeds the size limit")
		}
		return subscriptionDownloadResult{Body: body, Usage: usage}, nil
	}
	return subscriptionDownloadResult{}, fmt.Errorf("subscription download failed")
}
