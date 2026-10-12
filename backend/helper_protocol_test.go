package main

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"
)

func TestHelperProtocolHasOnlyFixedActions(t *testing.T) {
	for _, action := range []string{"tun-enable", "tun-disable", "tun-status", "tun-diagnostics", "mihomo-update-prepare", "mihomo-update-install", "mihomo-update-rollback", "app-update-start", "app-update-status"} {
		var output bytes.Buffer
		if err := handleHelperProtocol(strings.NewReader(`{"action":"`+action+`"}`+"\n"), &output); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(output.String(), "unsupported action") {
			t.Fatalf("fixed action rejected: %s", action)
		}
	}
	for _, body := range []string{`{"action":"exec","command":"id"}`, `{"action":"tun-enable","shell":"id"}`, `{"action":"mihomo-update-prepare","url":"https://example.com/binary"}`, `{"action":"mihomo-update-prepare","path":"/tmp/binary"}`, `{"action":"app-update-start","url":"https://example.com/package.deb"}`, `{"action":"app-update-start","path":"/tmp/package.deb"}`} {
		if err := handleHelperProtocol(strings.NewReader(body), &bytes.Buffer{}); err == nil {
			t.Fatalf("unsafe request accepted: %s", body)
		}
	}
}

func TestHelperRequestDoesNotWaitForClientEOF(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	_ = server.SetReadDeadline(time.Now().Add(time.Second))
	go func() { _, _ = client.Write([]byte("{\"action\":\"tun-status\"}\n")) }()
	action, err := decodeHelperRequest(server)
	if err != nil {
		t.Fatal(err)
	}
	if action != "tun-status" {
		t.Fatalf("decoded action %q", action)
	}
}
