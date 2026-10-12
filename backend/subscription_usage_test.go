package main

import (
	"testing"
	"time"
)

func TestParseSubscriptionUserinfo(t *testing.T) {
	expire := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	usage := parseSubscriptionUserinfo("upload=1048576; download=2097152; total=10485760; expire=1893456000; source=provider")
	if usage == nil || usage.Upload != 1048576 || usage.Download != 2097152 || usage.Total != 10485760 || usage.Expire == nil || !usage.Expire.Equal(expire) {
		t.Fatalf("parsed usage = %#v", usage)
	}
	view := viewSubscriptionUsage(usage)
	if view == nil || view.Upload != "1048576" || view.Download != "2097152" || view.Total != "10485760" {
		t.Fatalf("usage view lost exact byte counts: %#v", view)
	}
}

func TestParseSubscriptionUserinfoIgnoresMissingOrMalformedQuota(t *testing.T) {
	for _, header := range []string{
		"",
		"upload=10; download=20",
		"upload=10; download=nope; total=30",
		"upload=10; download=20; total=30; expire=-1",
		"upload=10; download=20; total=30; expire=253402300800",
		"upload=10; upload=20; download=30; total=40",
	} {
		if got := parseSubscriptionUserinfo(header); got != nil {
			t.Errorf("malformed or incomplete header %q returned %#v", header, got)
		}
	}
	usage := parseSubscriptionUserinfo("UPLOAD=1; DOWNLOAD=2; TOTAL=0; EXPIRE=0")
	if usage == nil || usage.Total != 0 || usage.Expire != nil {
		t.Fatalf("unlimited quota header parsed incorrectly: %#v", usage)
	}
}
