package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type testResolver func(context.Context, string) ([]net.IPAddr, error)

func (f testResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	return f(ctx, host)
}

func TestPublicInternetIPRejectsLocalAndSpecialRanges(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "::1", "169.254.10.20", "fe80::1", "10.1.2.3", "172.20.1.1",
		"192.168.1.1", "100.64.0.1", "100.100.100.200", "::ffff:127.0.0.1", "224.0.0.1",
		"192.0.2.5", "198.18.0.1", "2001:db8::1", "fc00::1", "ff02::1", "0.0.0.0",
	}
	for _, raw := range blocked {
		if publicInternetIP(netip.MustParseAddr(raw)) {
			t.Errorf("unsafe address %s accepted", raw)
		}
	}
	for _, raw := range []string{"8.8.8.8", "93.184.216.34", "2001:4860:4860::8888"} {
		if !publicInternetIP(netip.MustParseAddr(raw)) {
			t.Errorf("public address %s rejected", raw)
		}
	}
}

func TestSubscriptionURLRejectsPrivateDNSAnswer(t *testing.T) {
	resolver := testResolver(func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("192.168.1.25")}}, nil
	})
	if err := validateSubscriptionURL(context.Background(), "https://subscription.example/config", resolver); err == nil {
		t.Fatal("private DNS answer was accepted")
	}
}

func TestResolvePublicKeepsOnlyPublicDNSAnswers(t *testing.T) {
	resolver := testResolver(func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{
			{IP: net.ParseIP("192.168.1.25")},
			{IP: net.ParseIP("93.184.216.34")},
		}, nil
	})
	ips, err := resolvePublic(context.Background(), "provider.example", resolver)
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || ips[0] != netip.MustParseAddr("93.184.216.34") {
		t.Fatalf("got public addresses %v, want only 93.184.216.34", ips)
	}
}

func TestSubscriptionDialFallsBackAcrossPublicDNSAnswers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()
	resolver := testResolver(func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{
			{IP: net.ParseIP("192.168.1.25")},
			{IP: net.ParseIP("2001:4860:4860::8888")},
			{IP: net.ParseIP("93.184.216.34")},
		}, nil
	})
	var dialed []string
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		dialed = append(dialed, address)
		if strings.HasPrefix(address, "[2001:4860:4860::8888]:") {
			return nil, fmt.Errorf("IPv6 route unavailable")
		}
		if strings.HasPrefix(address, "93.184.216.34:") {
			return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		}
		t.Fatalf("attempted to dial non-public or unexpected address %q", address)
		return nil, fmt.Errorf("unexpected address")
	}
	body, err := downloadSubscription(context.Background(), "http://provider.example/config", resolver, dial)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "ok" {
		t.Fatalf("got response %q, want ok", body)
	}
	if len(dialed) != 2 {
		t.Fatalf("attempted %d addresses, want IPv6 failure then IPv4", len(dialed))
	}
}

func TestSubscriptionDownloadSetsUserAgentAndRetriesServerErrors(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.UserAgent(); got != subscriptionUserAgent {
			t.Errorf("User-Agent = %q, want %q", got, subscriptionUserAgent)
		}
		if hits.Add(1) == 1 {
			http.Error(w, "temporary", http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()
	resolver := testResolver(func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
	})
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	body, err := downloadSubscription(context.Background(), "http://provider.example/config", resolver, dial)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "ok" {
		t.Fatalf("got response %q, want ok", body)
	}
	if hits.Load() != 2 {
		t.Fatalf("got %d HTTP requests, want one retry", hits.Load())
	}
}

func TestSubscriptionDownloadFallsBackToLocalMihomoProxy(t *testing.T) {
	var hits atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Host != "provider.example" || r.URL.Path != "/config" {
			t.Errorf("proxied request target = %q%q", r.URL.Host, r.URL.Path)
		}
		_, _ = w.Write([]byte("proxied subscription"))
	}))
	defer proxy.Close()
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	resolver := testResolver(func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
	})
	proxyAddress := proxy.Listener.Addr().String()
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != proxyAddress {
			return nil, fmt.Errorf("unexpected proxy dial address %q", address)
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	result, err := downloadSubscriptionWithProxyFallback(context.Background(), "http://provider.example/config", resolver, dial, proxyURL)
	if err != nil {
		t.Fatal(err)
	}
	if string(result.Body) != "proxied subscription" || hits.Load() != 1 {
		t.Fatalf("result=%q requests=%d", result.Body, hits.Load())
	}
}

func TestSubscriptionProxyRejectsNonPublicDNSBeforeRequest(t *testing.T) {
	var hits atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer proxy.Close()
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	resolver := testResolver(func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("192.168.1.25")}}, nil
	})
	result, err := downloadSubscriptionThroughProxy(context.Background(), "http://provider.example/config", resolver, nil, proxyURL)
	if err == nil || result.Body != nil {
		t.Fatalf("non-public DNS answer was accepted: body=%q err=%v", result.Body, err)
	}
	if hits.Load() != 0 {
		t.Fatalf("proxy received %d requests for a non-public destination", hits.Load())
	}
}

func TestSubscriptionProxyRedirectRejectsNonPublicDestination(t *testing.T) {
	var hits atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Redirect(w, r, "http://127.0.0.1:81/blocked", http.StatusFound)
	}))
	defer proxy.Close()
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	resolver := testResolver(func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
	})
	result, err := downloadSubscriptionThroughProxy(context.Background(), "http://provider.example/config", resolver, nil, proxyURL)
	if err == nil || result.Body != nil {
		t.Fatalf("redirect to loopback was accepted: body=%q err=%v", result.Body, err)
	}
	if hits.Load() != 1 {
		t.Fatalf("proxy received %d requests, want only the initial request", hits.Load())
	}
}

func TestSubscriptionDownloadFallsBackToDirectWhenProxyFails(t *testing.T) {
	var proxyHits, directHits atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxyHits.Add(1)
		http.Error(w, "proxy unavailable", http.StatusBadGateway)
	}))
	defer proxy.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		directHits.Add(1)
		_, _ = w.Write([]byte("direct subscription"))
	}))
	defer origin.Close()
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	resolver := testResolver(func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
	})
	proxyAddress := proxy.Listener.Addr().String()
	originAddress := origin.Listener.Addr().String()
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		if address == proxyAddress {
			return (&net.Dialer{}).DialContext(ctx, network, address)
		}
		if address == "93.184.216.34:80" {
			return (&net.Dialer{}).DialContext(ctx, network, originAddress)
		}
		return nil, fmt.Errorf("unexpected dial address %q", address)
	}
	result, err := downloadSubscriptionWithProxyFallback(context.Background(), "http://provider.example/config", resolver, dial, proxyURL)
	if err != nil {
		t.Fatal(err)
	}
	if string(result.Body) != "direct subscription" || proxyHits.Load() != 2 || directHits.Load() != 1 {
		t.Fatalf("result=%q proxy requests=%d direct requests=%d", result.Body, proxyHits.Load(), directHits.Load())
	}
}

func TestSubscriptionDownloadReturnsQuotaHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Subscription-Userinfo", "upload=120; download=340; total=1000; expire=1893456000")
		_, _ = w.Write([]byte("subscription-body"))
	}))
	defer server.Close()
	resolver := testResolver(func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
	})
	dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}

	result, err := downloadSubscriptionWithUsage(context.Background(), "http://provider.example/config", resolver, dial)
	if err != nil {
		t.Fatal(err)
	}
	if string(result.Body) != "subscription-body" || result.Usage == nil || result.Usage.Upload != 120 || result.Usage.Download != 340 || result.Usage.Total != 1000 || result.Usage.Expire == nil || !result.Usage.Expire.Equal(time.Unix(1893456000, 0).UTC()) {
		t.Fatalf("download result = %#v", result)
	}
}

func TestSubscriptionRedirectToLoopbackIsBlocked(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "http://127.0.0.1:81/blocked", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	resolver := testResolver(func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
	})
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	body, err := downloadSubscription(context.Background(), "http://public.example/redirect", resolver, dial)
	if err == nil || body != nil {
		t.Fatalf("redirect to loopback was not rejected: body=%q err=%v", body, err)
	}
	if hits.Load() != 1 {
		t.Fatalf("got %d HTTP requests, want only the first", hits.Load())
	}
}

func TestSubscriptionDialRechecksDNSBeforeConnecting(t *testing.T) {
	var lookups atomic.Int32
	var dialed atomic.Bool
	resolver := testResolver(func(context.Context, string) ([]net.IPAddr, error) {
		if lookups.Add(1) == 1 {
			return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
		}
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	})
	dial := func(context.Context, string, string) (net.Conn, error) {
		dialed.Store(true)
		return nil, context.DeadlineExceeded
	}
	_, err := downloadSubscription(context.Background(), "http://public.example/config", resolver, dial)
	if err == nil {
		t.Fatal("rebinding DNS result was accepted")
	}
	if dialed.Load() {
		t.Fatal("dialer was called with a rebinding address")
	}
}
