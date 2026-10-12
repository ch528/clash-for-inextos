package main

import (
	"strconv"
	"strings"
	"time"
)

type subscriptionUsage struct {
	Upload   uint64     `json:"upload"`
	Download uint64     `json:"download"`
	Total    uint64     `json:"total"`
	Expire   *time.Time `json:"expire,omitempty"`
}

type subscriptionUsageView struct {
	Upload   string     `json:"upload"`
	Download string     `json:"download"`
	Total    string     `json:"total"`
	Expire   *time.Time `json:"expire,omitempty"`
}

func parseSubscriptionUserinfo(value string) *subscriptionUsage {
	var usage subscriptionUsage
	seen := make(map[string]bool, 4)
	haveUpload, haveDownload, haveTotal := false, false, false
	for _, field := range strings.Split(value, ";") {
		key, raw, ok := strings.Cut(strings.TrimSpace(field), "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		raw = strings.TrimSpace(raw)
		if key != "upload" && key != "download" && key != "total" && key != "expire" {
			continue
		}
		if seen[key] || raw == "" {
			return nil
		}
		seen[key] = true
		switch key {
		case "upload":
			parsed, err := strconv.ParseUint(raw, 10, 64)
			if err != nil {
				return nil
			}
			usage.Upload, haveUpload = parsed, true
		case "download":
			parsed, err := strconv.ParseUint(raw, 10, 64)
			if err != nil {
				return nil
			}
			usage.Download, haveDownload = parsed, true
		case "total":
			parsed, err := strconv.ParseUint(raw, 10, 64)
			if err != nil {
				return nil
			}
			usage.Total, haveTotal = parsed, true
		case "expire":
			parsed, err := strconv.ParseInt(raw, 10, 64)
			if err != nil || parsed < 0 || parsed > 253402300799 {
				return nil
			}
			if parsed > 0 {
				expire := time.Unix(parsed, 0).UTC()
				usage.Expire = &expire
			}
		}
	}
	if !haveUpload || !haveDownload || !haveTotal {
		return nil
	}
	return &usage
}

func viewSubscriptionUsage(usage *subscriptionUsage) *subscriptionUsageView {
	if usage == nil {
		return nil
	}
	return &subscriptionUsageView{
		Upload: strconv.FormatUint(usage.Upload, 10), Download: strconv.FormatUint(usage.Download, 10),
		Total: strconv.FormatUint(usage.Total, 10), Expire: usage.Expire,
	}
}
