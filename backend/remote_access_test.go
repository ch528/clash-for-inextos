package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestFindPublicWANIPv6PrefersPPPAndSkipsPrivateAddresses(t *testing.T) {
	interfaces := []net.Interface{
		{Index: 1, Name: "ppp0", Flags: net.FlagUp},
		{Index: 2, Name: "wan0", Flags: net.FlagUp},
		{Index: 3, Name: "down0"},
	}
	addresses := map[string][]net.Addr{
		"ppp0":  {mustIPNet("2409:8a1e:9101::2/64"), mustIPNet("fe80::2/64")},
		"wan0":  {mustIPNet("2409:8a1e:9101::3/64")},
		"down0": {mustIPNet("2409:8a1e:9101::4/64")},
	}
	lookup := func(iface net.Interface) ([]net.Addr, error) { return addresses[iface.Name], nil }

	got := findPublicWANIPv6(defaultIPv6Route("wan0", 1), interfaces, lookup)
	if got.String() != "2409:8a1e:9101::2" {
		t.Fatalf("selected IPv6 %q, want ppp0's global address", got)
	}

	addresses["ppp0"] = []net.Addr{mustIPNet("fd00::2/64")}
	got = findPublicWANIPv6(defaultIPv6Route("wan0", 1), interfaces, lookup)
	if got.String() != "2409:8a1e:9101::3" {
		t.Fatalf("fallback IPv6 %q, want address from default-route interface", got)
	}
}

func TestCertificateStatusChecksIPv6SANAndValidity(t *testing.T) {
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	address := netip.MustParseAddr("2409:8a1e:9101::2")
	matching := &x509.Certificate{
		IPAddresses: []net.IP{net.ParseIP(address.String())},
		NotBefore:   now.Add(-time.Hour),
		NotAfter:    now.Add(time.Hour),
	}
	if got := certificateStatus(address, matching, now); got.CertificateStatus != "ready" || !got.CertificateSANMatch {
		t.Fatalf("matching certificate status = %#v", got)
	}
	if got := certificateStatus(address, &x509.Certificate{DNSNames: []string{"router.example"}, NotAfter: now.Add(time.Hour)}, now); got.CertificateStatus != "needs_certificate_refresh" || got.CertificateSANMatch {
		t.Fatalf("non-matching certificate status = %#v", got)
	}
	expired := *matching
	expired.NotAfter = now
	if got := certificateStatus(address, &expired, now); got.CertificateStatus != "certificate_expired" || !got.CertificateSANMatch {
		t.Fatalf("expired matching certificate status = %#v", got)
	}
}

func TestReadLoopbackCertificateReadsLocalHTTPSOnly(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	certificate, err := readLoopbackCertificate(ctx, server.Listener.Addr().String(), "")
	if err != nil {
		t.Fatal(err)
	}
	if certificate == nil || len(certificate.DNSNames) == 0 {
		t.Fatalf("got no local HTTPS certificate: %#v", certificate)
	}
	if _, err := readLoopbackCertificate(ctx, "example.com:443", "example.com"); err == nil {
		t.Fatal("accepted a non-loopback certificate endpoint")
	}
}

func defaultIPv6Route(iface string, metric uint32) []byte {
	return []byte(fmt.Sprintf("%s 00 %s 00 %s %08x 00000000 00000000 00000001 %s\n",
		strings.Repeat("0", 32), strings.Repeat("0", 32), strings.Repeat("0", 32), metric, iface))
}

func mustIPNet(value string) net.Addr {
	address, prefix, err := net.ParseCIDR(value)
	if err != nil {
		panic(err)
	}
	return &net.IPNet{IP: address, Mask: prefix.Mask}
}
