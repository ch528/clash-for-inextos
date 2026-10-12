package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

type remoteAccessStatus struct {
	CurrentPublicIPv6   string `json:"current_public_ipv6,omitempty"`
	CertificateStatus   string `json:"certificate_status"`
	CertificateSANMatch bool   `json:"certificate_san_matches"`
	CertificateNotAfter string `json:"certificate_not_after,omitempty"`
}

func (a *API) remoteAccess(w http.ResponseWriter, _ *http.Request) {
	status := inspectRemoteAccess()
	if status.CertificateStatus != "ready" {
		a.recordEvent("certificate_warning")
	}
	writeJSON(w, http.StatusOK, status)
}

func inspectRemoteAccess() remoteAccessStatus {
	routes, _ := os.ReadFile("/proc/net/ipv6_route")
	interfaces, _ := net.Interfaces()
	address := findPublicWANIPv6(routes, interfaces, func(iface net.Interface) ([]net.Addr, error) {
		return iface.Addrs()
	})
	if !address.IsValid() {
		return remoteAccessStatus{CertificateStatus: "public_ipv6_unavailable"}
	}

	status := remoteAccessStatus{CurrentPublicIPv6: address.String()}
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	certificate, err := readLoopbackCertificate(ctx, "[::1]:8844", address.String())
	if err != nil {
		status.CertificateStatus = "certificate_unavailable"
		return status
	}
	return certificateStatus(address, certificate, time.Now())
}

func findPublicWANIPv6(routes []byte, interfaces []net.Interface, lookup func(net.Interface) ([]net.Addr, error)) netip.Addr {
	byName := make(map[string]net.Interface, len(interfaces))
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp != 0 {
			byName[iface.Name] = iface
		}
	}

	names := make([]string, 0, len(byName))
	if _, ok := byName["ppp0"]; ok {
		names = append(names, "ppp0")
	}
	type route struct {
		name   string
		metric uint64
	}
	defaults := make([]route, 0)
	for _, line := range strings.Split(string(routes), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 || fields[1] != "00" || strings.Trim(fields[0], "0") != "" {
			continue
		}
		flags, flagErr := strconv.ParseUint(fields[8], 16, 32)
		metric, metricErr := strconv.ParseUint(fields[5], 16, 32)
		if flagErr != nil || metricErr != nil || flags&1 == 0 {
			continue
		}
		if _, ok := byName[fields[9]]; ok {
			defaults = append(defaults, route{name: fields[9], metric: metric})
		}
	}
	sort.SliceStable(defaults, func(i, j int) bool { return defaults[i].metric < defaults[j].metric })
	for _, candidate := range defaults {
		if !containsString(names, candidate.name) {
			names = append(names, candidate.name)
		}
	}

	for _, name := range names {
		iface := byName[name]
		addresses, err := lookup(iface)
		if err != nil {
			continue
		}
		for _, address := range addresses {
			ip := interfaceAddress(address)
			if ip.Is6() && publicInternetIP(ip) {
				return ip
			}
		}
	}
	return netip.Addr{}
}

func interfaceAddress(address net.Addr) netip.Addr {
	if prefix, err := netip.ParsePrefix(address.String()); err == nil {
		return prefix.Addr().Unmap()
	}
	if ip, err := netip.ParseAddr(address.String()); err == nil {
		return ip.Unmap()
	}
	return netip.Addr{}
}

func containsString(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

func readLoopbackCertificate(ctx context.Context, endpoint, serverName string) (*x509.Certificate, error) {
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, err
	}
	address, err := netip.ParseAddr(host)
	if err != nil || !address.IsLoopback() {
		return nil, fmt.Errorf("certificate endpoint must be a loopback address")
	}
	connection, err := (&net.Dialer{Timeout: 1 * time.Second}).DialContext(ctx, "tcp", endpoint)
	if err != nil {
		return nil, err
	}
	defer connection.Close()

	// The endpoint is fixed to local Nginx. Verification is performed against the
	// returned certificate's SAN below; no user-controlled remote host is dialed.
	tlsConnection := tls.Client(connection, &tls.Config{ServerName: serverName, InsecureSkipVerify: true}) //nolint:gosec
	defer tlsConnection.Close()
	if err := tlsConnection.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	certificates := tlsConnection.ConnectionState().PeerCertificates
	if len(certificates) == 0 {
		return nil, fmt.Errorf("local HTTPS endpoint did not return a certificate")
	}
	return certificates[0], nil
}

func certificateStatus(address netip.Addr, certificate *x509.Certificate, now time.Time) remoteAccessStatus {
	status := remoteAccessStatus{CurrentPublicIPv6: address.String()}
	if certificate == nil {
		status.CertificateStatus = "certificate_unavailable"
		return status
	}
	status.CertificateNotAfter = certificate.NotAfter.UTC().Format(time.RFC3339)
	status.CertificateSANMatch = certificate.VerifyHostname(address.String()) == nil
	if !status.CertificateSANMatch {
		status.CertificateStatus = "needs_certificate_refresh"
		return status
	}
	if now.Before(certificate.NotBefore) {
		status.CertificateStatus = "certificate_not_yet_valid"
		return status
	}
	if !now.Before(certificate.NotAfter) {
		status.CertificateStatus = "certificate_expired"
		return status
	}
	status.CertificateStatus = "ready"
	return status
}
